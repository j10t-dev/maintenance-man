from datetime import UTC, datetime

import pytest

from maintenance_man import paths
from maintenance_man.deployer import BuildError, DeployError, HealthCheckResult
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.config import DefaultsConfig, MmConfig
from maintenance_man.models.events import (
    DeployStep,
    DeployStepFailed,
    DeployStepStarted,
    DeployStepSucceeded,
    HealthChecked,
    HealthcheckUnconfigured,
    ProjectSkipped,
    ProjectStarted,
    SkipReason,
)
from maintenance_man.services import WorkflowError
from maintenance_man.services import deploy as deploy_service
from maintenance_man.storage import load_activity
from maintenance_man.vcs import RevisionError
from tests.conftest import make_project
from tests.fake_vcs import FakeJjState
from tests.fakes import RecordingEmit


def _activity(*, success: bool, commit_id: str | None) -> dict[str, ProjectActivity]:
    return {
        "app": ProjectActivity(
            last_deploy=ActivityEvent(
                timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                success=success,
                branch="main",
                commit_id=commit_id,
            )
        )
    }


@pytest.mark.parametrize(
    "resolved, prior, force, expected",
    [
        (True, "same-success", False, deploy_service.GateDecision.SKIP_UNCHANGED),
        (True, "old-success", False, deploy_service.GateDecision.DEPLOY),
        (True, "same-failure", False, deploy_service.GateDecision.DEPLOY),
        (True, "missing-id", False, deploy_service.GateDecision.DEPLOY),
        (True, "none", False, deploy_service.GateDecision.DEPLOY),
        (False, "none", False, deploy_service.GateDecision.SKIP_BLOCKED),
        (True, "same-success", True, deploy_service.GateDecision.DEPLOY),
        (False, "none", True, deploy_service.GateDecision.DEPLOY),
    ],
)
def test_gate_decision(tmp_path, resolved, prior, force, expected) -> None:
    project_path = tmp_path / "project"
    state = FakeJjState()
    repo = state.seed_repository(project_path, files={})
    expected_id = repo.resolve_revision(revision="main") if resolved else None
    if not resolved:
        state.fail(
            "resolve_revision",
            error=RevisionError("no main"),
            path=project_path,
        )
    activity = {
        "same-success": _activity(success=True, commit_id=expected_id),
        "old-success": _activity(success=True, commit_id="OLD"),
        "same-failure": _activity(success=False, commit_id=expected_id),
        "missing-id": _activity(success=True, commit_id=None),
        "none": {},
    }[prior]

    decision, current_id = deploy_service.should_deploy(
        "app", project_path, activity, force=force, vcs=state.services()
    )

    assert decision is expected
    assert current_id == expected_id


def test_last_build_only_does_not_gate(tmp_path) -> None:
    project_path = tmp_path / "project"
    state = FakeJjState()
    repo = state.seed_repository(project_path, files={})
    main_id = repo.resolve_revision(revision="main")
    activity = {
        "app": ProjectActivity(
            last_build=ActivityEvent(
                timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                success=True,
                branch="main",
                commit_id=main_id,
            )
        )
    }

    decision, current_id = deploy_service.should_deploy(
        "app", project_path, activity, force=False, vcs=state.services()
    )

    assert decision is deploy_service.GateDecision.DEPLOY
    assert current_id == main_id


def test_build_launch_failure_records_a_failed_build(mm_home, tmp_path) -> None:
    missing = tmp_path / "missing"
    state = FakeJjState()
    state.seed_repository(missing, files={})
    missing.rmdir()
    project = make_project(missing, build_command="true")

    with pytest.raises(BuildError):
        deploy_service.build_project("demo", project, vcs=state.services())

    recorded = load_activity(paths.activity_path())["demo"].last_build
    assert recorded is not None
    assert recorded.success is False


def test_deploy_all_reports_gates_steps_results_and_activity(
    tmp_path, monkeypatch
) -> None:
    state = FakeJjState()
    projects = {
        "a": make_project(
            tmp_path / "a", build_command="build", deploy_command="deploy"
        ),
        "b": make_project(
            tmp_path / "b", build_command="build", deploy_command="deploy"
        ),
        "c": make_project(tmp_path / "c", deploy_command="deploy"),
        "d": make_project(tmp_path / "d", deploy_command="deploy"),
        "e": make_project(tmp_path / "e", deployable=False, deploy_command="deploy"),
        "f": make_project(tmp_path / "f"),
    }
    main_ids = {
        name: state.seed_repository(projects[name].path, files={}).resolve_revision(
            revision="main"
        )
        for name in ("a", "b", "c")
    }
    state.fail(
        "resolve_revision",
        error=RevisionError("no main"),
        path=projects["c"].path,
    )
    monkeypatch.setattr(deploy_service, "run_build", lambda *args: None)
    monkeypatch.setattr(deploy_service, "run_deploy", lambda *args: None)
    monkeypatch.setattr(
        deploy_service,
        "load_activity",
        lambda path: {
            "b": ProjectActivity(
                last_deploy=ActivityEvent(
                    timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                    success=True,
                    branch="main",
                    commit_id=main_ids["b"],
                )
            )
        },
    )
    emit = RecordingEmit()

    results = deploy_service.deploy_all(
        MmConfig(projects=projects),
        check=False,
        force=False,
        vcs=state.services(),
        emit=emit,
    )

    assert results == (
        deploy_service.DeployResult("a", "pass", "pass"),
        deploy_service.DeployResult("b", "skip", "unchanged"),
        deploy_service.DeployResult("c", "skip", "blocked"),
        deploy_service.DeployResult("d", "skip", "fail"),
    )
    assert emit.events == [
        ProjectStarted("a"),
        DeployStepStarted("a", DeployStep.BUILD),
        DeployStepSucceeded("a", DeployStep.BUILD),
        DeployStepStarted("a", DeployStep.DEPLOY),
        DeployStepSucceeded("a", DeployStep.DEPLOY),
        ProjectSkipped("b", SkipReason.UNCHANGED),
        ProjectSkipped("c", SkipReason.BLOCKED),
        ProjectSkipped("d", SkipReason.PATH_MISSING, str(projects["d"].path)),
        ProjectSkipped("e", SkipReason.NOT_DEPLOYABLE),
    ]
    recorded = load_activity(paths.activity_path())["a"].last_deploy
    assert recorded is not None
    assert recorded.success is True
    assert recorded.commit_id == main_ids["a"]


def test_deploy_all_checks_health_after_success(tmp_path, monkeypatch) -> None:
    state = FakeJjState()
    project = make_project(tmp_path / "a", deploy_command="deploy")
    state.seed_repository(project.path, files={})
    monkeypatch.setattr(deploy_service, "run_deploy", lambda *args: None)
    monkeypatch.setattr(
        deploy_service,
        "check_health",
        lambda *args: HealthCheckResult(is_up=True),
    )
    emit = RecordingEmit()

    result = deploy_service.deploy_all(
        MmConfig(
            defaults=DefaultsConfig(healthcheck_url="http://health"),
            projects={"a": project},
        ),
        check=True,
        force=False,
        vcs=state.services(),
        emit=emit,
    )

    assert result == (deploy_service.DeployResult("a", "skip", "pass"),)
    assert emit.events[-2:] == [
        DeployStepStarted("a", DeployStep.HEALTH),
        HealthChecked("a", True, None),
    ]


def test_deploy_all_build_failure_stops_project_and_records_failure(
    tmp_path, monkeypatch
) -> None:
    state = FakeJjState()
    project = make_project(
        tmp_path / "a", build_command="build", deploy_command="deploy"
    )
    state.seed_repository(project.path, files={})
    monkeypatch.setattr(
        deploy_service,
        "run_build",
        lambda *args: (_ for _ in ()).throw(BuildError("build failed")),
    )
    deployed: list[str] = []
    monkeypatch.setattr(
        deploy_service, "run_deploy", lambda name, *args: deployed.append(name)
    )
    emit = RecordingEmit()

    results = deploy_service.deploy_all(
        MmConfig(projects={"a": project}),
        check=False,
        force=False,
        vcs=state.services(),
        emit=emit,
    )

    assert results == (deploy_service.DeployResult("a", "fail", "skip"),)
    assert deployed == []
    assert emit.events[-1] == DeployStepFailed("a", DeployStep.BUILD, "build failed")
    recorded = load_activity(paths.activity_path())["a"].last_build
    assert recorded is not None
    assert recorded.success is False


def test_deploy_project_refuses_missing_command(tmp_path) -> None:
    state = FakeJjState()
    project = make_project(tmp_path / "api")
    state.seed_repository(project.path, files={})

    with pytest.raises(
        WorkflowError,
        match=r"^No deploy_command configured for api\. Add deploy_command to "
        r"\[projects\.api\] in ~/\.mm/config\.toml\.$",
    ):
        deploy_service.deploy_project(
            "api",
            project,
            healthcheck_url=None,
            build=False,
            check=False,
            force=False,
            vcs=state.services(),
            emit=RecordingEmit(),
        )


def test_deploy_project_refuses_unresolvable_main_without_force(
    tmp_path, monkeypatch
) -> None:
    state = FakeJjState()
    project = make_project(tmp_path / "api", deploy_command="deploy")
    state.seed_repository(project.path, files={})
    state.fail("resolve_revision", error=RevisionError("no main"), path=project.path)
    monkeypatch.setattr(deploy_service, "run_deploy", lambda *args: None)

    with pytest.raises(
        WorkflowError,
        match=r"^Could not resolve main revision for api; refusing to deploy "
        r"unverified state \(use --force to override\)\.$",
    ):
        deploy_service.deploy_project(
            "api",
            project,
            healthcheck_url=None,
            build=False,
            check=False,
            force=False,
            vcs=state.services(),
            emit=RecordingEmit(),
        )


def test_deploy_project_force_allows_unresolvable_main(tmp_path, monkeypatch) -> None:
    state = FakeJjState()
    project = make_project(tmp_path / "api", deploy_command="deploy")
    state.seed_repository(project.path, files={})
    state.fail("resolve_revision", error=RevisionError("no main"), path=project.path)
    deployed: list[str] = []
    monkeypatch.setattr(
        deploy_service, "run_deploy", lambda name, *args: deployed.append(name)
    )

    result = deploy_service.deploy_project(
        "api",
        project,
        healthcheck_url=None,
        build=False,
        check=False,
        force=True,
        vcs=state.services(),
        emit=RecordingEmit(),
    )

    assert result == deploy_service.DeployResult("api", "skip", "pass")
    assert deployed == ["api"]
    recorded = load_activity(paths.activity_path())["api"].last_deploy
    assert recorded is not None
    assert recorded.commit_id is None


def test_deploy_project_skips_not_deployable(tmp_path) -> None:
    project = make_project(tmp_path / "api", deployable=False, deploy_command="deploy")
    emit = RecordingEmit()

    result = deploy_service.deploy_project(
        "api",
        project,
        healthcheck_url=None,
        build=False,
        check=False,
        force=False,
        vcs=FakeJjState().services(),
        emit=emit,
    )

    assert result == deploy_service.DeployResult("api", "skip", "skip")
    assert emit.events == [ProjectSkipped("api", SkipReason.NOT_DEPLOYABLE)]


@pytest.mark.parametrize("healthcheck_url", [None, ""])
def test_deploy_project_reports_unconfigured_health_after_success(
    tmp_path, monkeypatch, healthcheck_url
) -> None:
    state = FakeJjState()
    project = make_project(tmp_path / "api", deploy_command="deploy")
    state.seed_repository(project.path, files={})
    monkeypatch.setattr(deploy_service, "run_deploy", lambda *args: None)
    health_checks: list[tuple[str, str]] = []

    def check_health(url: str, name: str) -> HealthCheckResult:
        health_checks.append((url, name))
        return HealthCheckResult(is_up=True)

    monkeypatch.setattr(deploy_service, "check_health", check_health)
    emit = RecordingEmit()

    result = deploy_service.deploy_project(
        "api",
        project,
        healthcheck_url=healthcheck_url,
        build=False,
        check=True,
        force=False,
        vcs=state.services(),
        emit=emit,
    )

    assert result == deploy_service.DeployResult("api", "skip", "pass")
    assert emit.events[-2:] == [
        DeployStepSucceeded("api", DeployStep.DEPLOY),
        HealthcheckUnconfigured(),
    ]
    assert health_checks == []
    assert not emit.of_type(HealthChecked)
    assert all(
        event.step is not DeployStep.HEALTH for event in emit.of_type(DeployStepStarted)
    )


@pytest.mark.parametrize("healthcheck_url", [None, ""])
def test_deploy_all_leaves_unconfigured_health_to_the_cli(
    tmp_path, monkeypatch, healthcheck_url
) -> None:
    state = FakeJjState()
    project = make_project(tmp_path / "api", deploy_command="deploy")
    state.seed_repository(project.path, files={})
    monkeypatch.setattr(deploy_service, "run_deploy", lambda *args: None)
    health_checks: list[tuple[str, str]] = []

    def check_health(url: str, name: str) -> HealthCheckResult:
        health_checks.append((url, name))
        return HealthCheckResult(is_up=True)

    monkeypatch.setattr(deploy_service, "check_health", check_health)
    emit = RecordingEmit()

    result = deploy_service.deploy_all(
        MmConfig(
            defaults=DefaultsConfig(healthcheck_url=healthcheck_url),
            projects={"api": project},
        ),
        check=True,
        force=False,
        vcs=state.services(),
        emit=emit,
    )

    assert result == (deploy_service.DeployResult("api", "skip", "pass"),)
    assert health_checks == []
    assert not emit.of_type(HealthcheckUnconfigured)
    assert not emit.of_type(HealthChecked)
    assert all(
        event.step is not DeployStep.HEALTH for event in emit.of_type(DeployStepStarted)
    )


@pytest.mark.parametrize(
    "failure, error, expected_statuses",
    [
        ("run_build", BuildError("build failed"), ("fail", "skip")),
        ("run_deploy", DeployError("deploy failed"), ("pass", "fail")),
    ],
)
def test_failed_deploy_has_no_health_hint(
    tmp_path, monkeypatch, failure, error, expected_statuses
) -> None:
    state = FakeJjState()
    project = make_project(
        tmp_path / "api", build_command="build", deploy_command="deploy"
    )
    state.seed_repository(project.path, files={"dep.txt": "version=1\n"})
    monkeypatch.setattr(deploy_service, "run_build", lambda *args: None)
    monkeypatch.setattr(deploy_service, "run_deploy", lambda *args: None)

    def fail(*args):
        raise error

    monkeypatch.setattr(deploy_service, failure, fail)
    emit = RecordingEmit()
    result = deploy_service.deploy_project(
        "api",
        project,
        healthcheck_url=None,
        build=True,
        check=True,
        force=True,
        vcs=state.services(),
        emit=emit,
    )

    assert (result.build_status, result.deploy_status) == expected_statuses
    assert isinstance(emit.events[-1], DeployStepFailed)
    assert not emit.of_type(HealthcheckUnconfigured)
    assert not emit.of_type(HealthChecked)
    assert all(
        event.step is not DeployStep.HEALTH for event in emit.of_type(DeployStepStarted)
    )
