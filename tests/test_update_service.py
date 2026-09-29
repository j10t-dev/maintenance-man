from pathlib import Path

import pytest

from maintenance_man import paths
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    FindingsProcessed,
    MissingTestConfig,
    Operation,
    OperationFailed,
    Outcome,
    ProcessingStarted,
    ProjectSkipped,
    ProjectStarted,
    Promoted,
    ScanReported,
    SkipReason,
)
from maintenance_man.models.scan import UpdateResult, UpdateStatus, Workflow
from maintenance_man.services import update as update_service
from maintenance_man.services.flows import FlowConflictError
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs import RevisionError
from tests.conftest import (
    make_config,
    make_project,
    make_scan_result,
    make_update,
    make_vuln,
)
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeFindingProcessor, RecordingEmit, pick_findings


def _seed_project(
    tmp_path: Path,
    name: str,
    scan,
    *,
    test_unit: str | None = "pytest",
) -> tuple[FakeJjState, ProjectConfig]:
    project = make_project(tmp_path / name, test_unit=test_unit)
    state = FakeJjState()
    state.seed_repository(project.path, files={"dep.txt": "version=1\n"})
    state.register_files(
        project.path,
        "mm-fixture-pkg-a.txt",
        "mm-fixture-pkg-b.txt",
    )
    scan.project = name
    save_scan_results(name, scan)
    return state, project


def test_update_processes_in_managed_workspace(tmp_path: Path, monkeypatch) -> None:
    state = FakeJjState()
    project = make_project(tmp_path / "api")
    state.seed_repository(project.path, files={"dep.txt": "version=1\n"})
    state.register_files(project.path, "mm-fixture-pkg-a.txt")
    original = project.model_copy(deep=True)
    scan = make_scan_result(vulns=[], updates=[make_update(pkg_name="pkg-a")])
    scan.project = "api"
    save_scan_results("api", scan)
    processor = FakeFindingProcessor({"pkg-a": (True, None)})
    seen: list[ProjectConfig] = []

    def process(findings, work_config, **kwargs):
        seen.append(work_config)
        assert work_config.path == paths.workspaces_dir() / "api"
        assert work_config.path != project.path
        return processor(findings, work_config, **kwargs)

    monkeypatch.setattr(update_service, "process_findings", process)
    result = update_service.update_project(
        "api",
        project,
        minimum_age_days=7,
        choose=None,
        choose_gradle=None,
        vcs=state.services(),
        emit=RecordingEmit(),
    )

    assert result.outcome is Outcome.SUCCEEDED
    assert len(seen) == 1
    assert project == original
    assert not load_scan_results("api").updates
    assert not (paths.workspaces_dir() / "api").exists()


def test_update_emits_processing_result_and_promotion_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(pkg_name="pkg-a"),
            make_update(pkg_name="pkg-b"),
        ],
    )
    state, project = _seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-b": (True, None)}),
    )
    emit = RecordingEmit()

    result = update_service.update_project(
        "api",
        project,
        minimum_age_days=7,
        choose=pick_findings("pkg-b"),
        choose_gradle=None,
        vcs=state.services(),
        emit=emit,
    )

    expected_result = UpdateResult("pkg-b", "update", True)
    assert result == update_service.ProjectUpdate(
        "api",
        update_service.UpdateRoute.FINDINGS,
        Outcome.SUCCEEDED,
        (expected_result,),
    )
    assert isinstance(emit.events[0], ScanReported)
    assert emit.events[1:] == [
        ProcessingStarted(0, 1),
        FindingsProcessed((expected_result,)),
        Promoted("mm/update-dependencies"),
    ]
    assert [item.pkg_name for item in load_scan_results("api").updates] == ["pkg-a"]
    repo = state.services().repository(project.path)
    assert repo.same_revision(left="main", right="@-")
    assert not repo.bookmark_exists(bookmark="mm/update-dependencies")
    assert "mm-api" not in repo.workspace_names()


def test_typed_equal_risk_selection_order_reaches_processor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(pkg_name="pkg-a"), make_update(pkg_name="pkg-b")],
    )
    state, project = _seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None), "pkg-b": (True, None)}),
    )

    result = update_service.update_project(
        "api",
        project,
        minimum_age_days=7,
        choose=pick_findings("pkg-b", "pkg-a"),
        choose_gradle=None,
        vcs=state.services(),
        emit=RecordingEmit(),
    )

    assert [item.pkg_name for item in result.results] == ["pkg-b", "pkg-a"]


def test_update_no_scan_results_is_a_success(tmp_path: Path) -> None:
    project = make_project(tmp_path / "api")
    emit = RecordingEmit()

    result = update_service.update_project(
        "api",
        project,
        minimum_age_days=7,
        choose=None,
        choose_gradle=None,
        vcs=FakeJjState().services(),
        emit=emit,
    )

    assert result.outcome is Outcome.SUCCEEDED
    assert emit.events == [ProjectSkipped("api", SkipReason.NO_SCAN_RESULTS)]


def test_update_nothing_actionable_is_a_success(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[make_vuln(fixed_version=None)],
        updates=[],
    )
    state, project = _seed_project(tmp_path, "api", scan)
    emit = RecordingEmit()

    result = update_service.update_project(
        "api",
        project,
        minimum_age_days=7,
        choose=None,
        choose_gradle=None,
        vcs=state.services(),
        emit=emit,
    )

    assert result.outcome is Outcome.SUCCEEDED
    assert emit.events == [ProjectSkipped("api", SkipReason.NOTHING_TO_DO, "update")]


def test_missing_test_config_is_reported_before_workspace_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, project = _seed_project(
        tmp_path,
        "api",
        make_scan_result(vulns=[], updates=[make_update()]),
        test_unit=None,
    )
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )
    emit = RecordingEmit()
    observed: list[object] = []
    state.hook(
        "add_workspace",
        phase="before",
        path=project.path,
        action=lambda: observed.extend(emit.events),
    )

    update_service.update_project(
        "api",
        project,
        minimum_age_days=7,
        choose=None,
        choose_gradle=None,
        vcs=state.services(),
        emit=emit,
    )

    assert observed == [MissingTestConfig("api")]


def test_update_rejects_findings_owned_by_resolve(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    state, project = _seed_project(tmp_path, "api", scan)

    with pytest.raises(
        FlowConflictError,
        match=(
            "Cannot run update on api: 1 finding\\(s\\) owned by the 'resolve' flow"
        ),
    ):
        update_service.update_project(
            "api",
            project,
            minimum_age_days=7,
            choose=None,
            choose_gradle=None,
            vcs=state.services(),
            emit=RecordingEmit(),
        )


def test_missing_progress_bookmark_requires_rescan(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.UPDATE)],
    )
    state, project = _seed_project(tmp_path, "api", scan)

    with pytest.raises(
        update_service.UpdateSetupError,
        match=r"update bookmark 'mm/update-dependencies' is missing.*rescan required",
    ):
        update_service.update_project(
            "api",
            project,
            minimum_age_days=7,
            choose=None,
            choose_gradle=None,
            vcs=state.services(),
            emit=RecordingEmit(),
        )


def test_workspace_revision_error_is_wrapped_with_cause(tmp_path: Path) -> None:
    state, project = _seed_project(
        tmp_path, "api", make_scan_result(vulns=[], updates=[make_update()])
    )
    original = RevisionError("locked")
    state.fail("add_workspace", error=original, path=project.path)

    with pytest.raises(update_service.UpdateSetupError, match="locked") as exc_info:
        update_service.update_project(
            "api",
            project,
            minimum_age_days=7,
            choose=None,
            choose_gradle=None,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

    assert exc_info.value.__cause__ is original


@pytest.mark.parametrize(
    ("method", "operation"),
    [
        ("promote_bookmark_to_main", Operation.PROMOTE),
        ("forget_workspace", Operation.WORKSPACE_CLEANUP),
        ("delete_bookmark", Operation.BOOKMARK_CLEANUP),
    ],
)
def test_finalisation_failures_emit_operation_and_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    operation: Operation,
) -> None:
    state, project = _seed_project(
        tmp_path, "api", make_scan_result(vulns=[], updates=[make_update()])
    )
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )
    state.fail(method, error=RevisionError("blocked"), path=project.path)
    emit = RecordingEmit()

    result = update_service.update_project(
        "api",
        project,
        minimum_age_days=7,
        choose=None,
        choose_gradle=None,
        vcs=state.services(),
        emit=emit,
    )

    assert result.outcome is Outcome.FAILED
    assert OperationFailed(operation, "api", "blocked") in emit.events
    if operation is Operation.PROMOTE:
        repo = state.services().repository(project.path)
        assert repo.bookmark_exists(bookmark="mm/update-dependencies")
        assert load_scan_results("api").updates[0].update_status is UpdateStatus.READY


def test_existing_update_failure_blocks_single_and_batch_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = FakeJjState()
    projects: dict[str, ProjectConfig] = {}
    for name in ("single", "batch"):
        project = make_project(tmp_path / name, test_unit="pytest")
        projects[name] = project
        state.seed_repository(project.path, files={"dep.txt": "version=1\n"})
        state.register_files(project.path, "mm-fixture-pkg-a.txt")
        state.services().repository(project.path).set_bookmark(
            bookmark="mm/update-dependencies", revision="main"
        )
        scan = make_scan_result(
            vulns=[
                make_vuln(
                    fixed_version=None,
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.UPDATE,
                )
            ],
            updates=[make_update()],
        )
        scan.project = name
        save_scan_results(name, scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )

    single = update_service.update_project(
        "single",
        projects["single"],
        minimum_age_days=7,
        choose=None,
        choose_gradle=None,
        vcs=state.services(),
        emit=RecordingEmit(),
    )
    batch = update_service.update_projects(
        make_config(projects={"batch": projects["batch"]}),
        ["batch"],
        vcs=state.services(),
        emit=RecordingEmit(),
    )

    assert single.outcome is Outcome.FAILED
    assert batch.projects[0].outcome is Outcome.FAILED
    assert batch.outcome is Outcome.FAILED
    for project in projects.values():
        assert not any(
            call.method == "promote_bookmark_to_main"
            and call.path == project.path.resolve()
            for call in state.attempts
        )


def test_batch_reports_success_conflict_missing_path_and_gradle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = FakeJjState()
    projects = {
        "a": make_project(tmp_path / "a", test_unit="pytest"),
        "b": make_project(tmp_path / "b", test_unit="pytest"),
        "c": make_project(tmp_path / "missing", test_unit="pytest"),
        "g": make_project(tmp_path / "g", package_manager="gradle"),
    }
    for name in ("a", "b", "g"):
        state.seed_repository(projects[name].path, files={"dep.txt": "version=1\n"})
    state.register_files(projects["a"].path, "mm-fixture-pkg-a.txt")
    passing = make_scan_result(vulns=[], updates=[make_update()])
    passing.project = "a"
    save_scan_results("a", passing)
    conflict = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    conflict.project = "b"
    save_scan_results("b", conflict)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )
    monkeypatch.setattr(
        update_service.gradle_workflow,
        "run_gradle_flow",
        lambda *args, **kwargs: Outcome.SUCCEEDED,
    )
    emit = RecordingEmit()

    result = update_service.update_projects(
        make_config(projects=projects),
        ["a", "b", "c", "g"],
        vcs=state.services(),
        emit=emit,
    )

    assert result.had_errors is True
    assert [project.project for project in result.projects] == ["a", "g"]
    assert result.projects[-1].route is update_service.UpdateRoute.GRADLE
    assert ProjectStarted("a") in emit.events
    assert ProjectStarted("b") in emit.events
    assert ProjectStarted("g") in emit.events
    missing = ProjectSkipped("c", SkipReason.PATH_MISSING, str(projects["c"].path))
    assert missing in emit.events
    assert emit.events.index(missing) < emit.events.index(ProjectStarted("g"))
    assert not any(
        isinstance(event, ProjectStarted) and event.project == "c"
        for event in emit.events
    )
    assert any(
        isinstance(event, ProjectSkipped)
        and event.project == "b"
        and event.reason is SkipReason.FLOW_CONFLICT
        and event.detail is not None
        and "owned by the 'resolve' flow" in event.detail
        for event in emit.events
    )
