from datetime import UTC, datetime

import pytest

from maintenance_man import paths
from maintenance_man.deployer import BuildError, DeployError, HealthCheckResult
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.config import DefaultsConfig, MmConfig
from maintenance_man.models.events import (
    DeployStep,
    DeployStepFailed,
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
from tests.fakes import RecordingEmit
from tests.support.projects import make_activity, make_project
from tests.support.repository import copy_jj_repository, fail_repository_method


@pytest.mark.parametrize(
    "resolved, prior, force, expected",
    [
        (True, "same-success", False, SkipReason.UNCHANGED),
        (True, "old-success", False, None),
        (True, "same-failure", False, None),
        (True, "missing-id", False, None),
        (True, "none", False, None),
        (False, "none", False, SkipReason.BLOCKED),
        (True, "last-build-only", False, None),
        (True, "same-success", True, None),
        (False, "none", True, None),
    ],
)
def test_gate_decision(tmp_path, monkeypatch, resolved, prior, force, expected) -> None:
    project_path = tmp_path / "project"
    repo = copy_jj_repository(project_path)
    expected_id = repo.resolve_revision(revision="main") if resolved else None
    if not resolved:
        fail_repository_method(
            monkeypatch, project_path, "resolve_revision", RevisionError("no main")
        )
    activity = {
        "same-success": make_activity(success=True, commit_id=expected_id),
        "old-success": make_activity(success=True, commit_id="OLD"),
        "same-failure": make_activity(success=False, commit_id=expected_id),
        "missing-id": make_activity(success=True, commit_id=None),
        "last-build-only": {
            "app": ProjectActivity(
                last_build=ActivityEvent(
                    timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                    success=True,
                    branch="main",
                    commit_id=expected_id,
                )
            )
        },
        "none": {},
    }[prior]

    skip, current_id = deploy_service.should_deploy(
        "app", project_path, activity, force=force
    )

    assert skip is expected
    assert current_id == expected_id


def test_build_launch_failure_records_a_failed_build(mm_home, tmp_path) -> None:
    missing = tmp_path / "missing"
    project = make_project(missing, build_command="true")

    with pytest.raises(BuildError):
        deploy_service.build_project("demo", project)

    recorded = load_activity(paths.activity_path())["demo"].last_build
    assert recorded is not None
    assert recorded.success is False


def test_deploy_all_reports_gates_steps_results_and_activity(
    tmp_path, monkeypatch
) -> None:
    projects = {
        "deployed": make_project(
            tmp_path / "deployed", build_command="build", deploy_command="deploy"
        ),
        "unchanged": make_project(
            tmp_path / "unchanged", build_command="build", deploy_command="deploy"
        ),
        "missing_revision": make_project(
            tmp_path / "missing_revision", deploy_command="deploy"
        ),
        "missing_path": make_project(
            tmp_path / "missing_path", deploy_command="deploy"
        ),
        "disabled": make_project(
            tmp_path / "disabled", deployable=False, deploy_command="deploy"
        ),
        "no_deploy_command": make_project(tmp_path / "no_deploy_command"),
    }
    main_ids = {
        name: copy_jj_repository(projects[name].path).resolve_revision(revision="main")
        for name in ("deployed", "unchanged", "missing_revision")
    }
    fail_repository_method(
        monkeypatch,
        projects["missing_revision"].path,
        "resolve_revision",
        RevisionError("no main"),
    )
    runs: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        deploy_service,
        "run_shell_command",
        lambda *args, **kwargs: runs.append((args, kwargs)),
    )
    monkeypatch.setattr(
        deploy_service,
        "load_activity",
        lambda path: {
            "unchanged": ProjectActivity(
                last_deploy=ActivityEvent(
                    timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                    success=True,
                    branch="main",
                    commit_id=main_ids["unchanged"],
                )
            )
        },
    )
    emit = RecordingEmit()

    results = deploy_service.deploy_all(
        MmConfig(projects=projects),
        check=False,
        force=False,
        emit=emit,
    )

    assert results == (
        deploy_service.DeployResult("deployed", "passed", "passed"),
        deploy_service.DeployResult("disabled", "skipped", "skipped"),
        deploy_service.DeployResult("missing_path", "skipped", "failed"),
        deploy_service.DeployResult("missing_revision", "skipped", "blocked"),
        deploy_service.DeployResult("unchanged", "skipped", "unchanged"),
    )
    assert runs == [
        (
            ("build", projects["deployed"].path),
            {"timeout": 600, "label": "Build for deployed", "error": BuildError},
        ),
        (
            ("deploy", projects["deployed"].path),
            {"timeout": 600, "label": "Deploy for deployed", "error": DeployError},
        ),
    ]
    assert emit.events == [
        ProjectStarted("deployed"),
        DeployStepSucceeded("deployed", DeployStep.BUILD),
        DeployStepSucceeded("deployed", DeployStep.DEPLOY),
        ProjectSkipped("disabled", SkipReason.NOT_DEPLOYABLE),
        ProjectSkipped(
            "missing_path", SkipReason.PATH_MISSING, str(projects["missing_path"].path)
        ),
        ProjectSkipped("missing_revision", SkipReason.BLOCKED),
        ProjectSkipped("unchanged", SkipReason.UNCHANGED),
    ]
    recorded = load_activity(paths.activity_path())["deployed"].last_deploy
    assert recorded is not None
    assert recorded.success is True
    assert recorded.commit_id == main_ids["deployed"]


def test_deploy_all_checks_health_after_success(tmp_path, monkeypatch) -> None:
    project = make_project(tmp_path / "a", deploy_command="deploy")
    copy_jj_repository(project.path)
    monkeypatch.setattr(
        deploy_service, "run_shell_command", lambda *args, **kwargs: None
    )
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
        emit=emit,
    )

    assert result == (deploy_service.DeployResult("a", "skipped", "passed"),)
    assert emit.events[-2:] == [
        DeployStepSucceeded("a", DeployStep.DEPLOY),
        HealthChecked("a", True, None),
    ]


def test_deploy_all_build_failure_stops_project_and_records_failure(
    tmp_path, monkeypatch
) -> None:
    project = make_project(
        tmp_path / "a", build_command="build", deploy_command="deploy"
    )
    copy_jj_repository(project.path)
    error = BuildError("build failed")

    def run(command, path, **kwargs):
        if kwargs["error"] is BuildError:
            raise error
        deployed.append(command)

    deployed: list[str] = []
    monkeypatch.setattr(deploy_service, "run_shell_command", run)
    emit = RecordingEmit()

    results = deploy_service.deploy_all(
        MmConfig(projects={"a": project}),
        check=False,
        force=False,
        emit=emit,
    )

    assert results == (deploy_service.DeployResult("a", "failed", "skipped"),)
    assert deployed == []
    assert emit.events[-1] == DeployStepFailed("a", DeployStep.BUILD, "build failed")
    recorded = load_activity(paths.activity_path())["a"].last_build
    assert recorded is not None
    assert recorded.success is False


def test_deploy_project_refuses_missing_command(tmp_path) -> None:
    project = make_project(tmp_path / "api")

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
            emit=RecordingEmit(),
        )


def test_deploy_project_refuses_unresolvable_main_without_force(
    tmp_path, monkeypatch
) -> None:
    project = make_project(tmp_path / "api", deploy_command="deploy")
    copy_jj_repository(project.path)
    fail_repository_method(
        monkeypatch, project.path, "resolve_revision", RevisionError("no main")
    )
    deployed: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        deploy_service,
        "run_shell_command",
        lambda *args, **kwargs: deployed.append(args),
    )

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
            emit=RecordingEmit(),
        )
    assert deployed == []


def test_deploy_project_force_allows_unresolvable_main(tmp_path, monkeypatch) -> None:
    project = make_project(tmp_path / "api", deploy_command="deploy")
    copy_jj_repository(project.path)
    fail_repository_method(
        monkeypatch, project.path, "resolve_revision", RevisionError("no main")
    )
    deployed: list[str] = []
    monkeypatch.setattr(
        deploy_service,
        "run_shell_command",
        lambda command, *args, **kwargs: deployed.append(command),
    )

    result = deploy_service.deploy_project(
        "api",
        project,
        healthcheck_url=None,
        build=False,
        check=False,
        force=True,
        emit=RecordingEmit(),
    )

    assert result == deploy_service.DeployResult("api", "skipped", "passed")
    assert deployed == ["deploy"]
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
        emit=emit,
    )

    assert result == deploy_service.DeployResult("api", "skipped", "skipped")
    assert emit.events == [ProjectSkipped("api", SkipReason.NOT_DEPLOYABLE)]


@pytest.mark.parametrize("healthcheck_url", [None, ""])
def test_deploy_project_reports_unconfigured_health_after_success(
    tmp_path, monkeypatch, healthcheck_url
) -> None:
    project = make_project(tmp_path / "api", deploy_command="deploy")
    copy_jj_repository(project.path)
    monkeypatch.setattr(
        deploy_service, "run_shell_command", lambda *args, **kwargs: None
    )
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
        emit=emit,
    )

    assert result == deploy_service.DeployResult("api", "skipped", "passed")
    assert emit.events[-2:] == [
        DeployStepSucceeded("api", DeployStep.DEPLOY),
        HealthcheckUnconfigured(),
    ]
    assert health_checks == []
    assert not emit.of_type(HealthChecked)
