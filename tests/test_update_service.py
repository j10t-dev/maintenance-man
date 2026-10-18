from pathlib import Path

import pytest

from maintenance_man import gradle, paths, updater
from maintenance_man.gradle import GRADLE_CATALOGUE_RELPATH
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
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeFindingProcessor, RecordingEmit, pick_findings
from tests.support.findings import (
    make_gradle_target,
    make_scan_result,
    make_update,
    make_vuln,
)
from tests.support.gradle import GRADLE_FIXTURES, catalogue_apply_task
from tests.support.process import refuse_new_processes
from tests.support.projects import make_config, make_project, seed_project


def test_update_processes_in_managed_workspace(tmp_path: Path, monkeypatch) -> None:
    state = FakeJjState()
    project = make_project(tmp_path / "api", test_unit="pytest")
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
        choose=None,
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
    state, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-b": (True, None)}),
    )
    emit = RecordingEmit()

    result = update_service.update_project(
        "api",
        project,
        choose=pick_findings("pkg-b"),
        vcs=state.services(),
        emit=emit,
    )

    expected_result = UpdateResult("pkg-b", "update", True)
    assert result == update_service.ProjectUpdate(
        "api",
        Outcome.SUCCEEDED,
        (expected_result,),
    )
    assert isinstance(emit.events[0], ScanReported)
    assert emit.events[1:] == [
        ProcessingStarted(0, 1),
        FindingsProcessed((expected_result,), blocked=0),
        Promoted(),
    ]
    assert [item.pkg_name for item in load_scan_results("api").updates] == ["pkg-a"]
    repo = state.services().repository(project.path)
    assert repo.same_revision(left="main", right="@-")
    assert not repo.bookmark_exists(bookmark="mm/update-dependencies")
    assert "mm-api" not in repo.workspace_names()


def test_given_blocked_and_passing_rows_when_updating_then_passing_rows_promote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(pkg_name="pkg-a"),
            make_update(pkg_name="stuck", blocked_reason="too young"),
        ],
    )
    state, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )
    emit = RecordingEmit()

    result = update_service.update_project(
        "api",
        project,
        choose=pick_findings("pkg-a"),
        vcs=state.services(),
        emit=emit,
    )

    passed = UpdateResult("pkg-a", "update", True)
    assert result == update_service.ProjectUpdate(
        "api", Outcome.SUCCEEDED, (passed,), blocked=1
    )
    assert emit.of_type(FindingsProcessed) == [FindingsProcessed((passed,), blocked=1)]
    assert emit.of_type(Promoted) == [Promoted()]
    assert [row.pkg_name for row in load_scan_results("api").updates] == ["stuck"]
    assert (
        state.services().repository(project.path).same_revision(left="main", right="@-")
    )


def test_given_only_blocked_rows_when_updating_then_success_without_workspace(
    tmp_path: Path,
) -> None:
    scan = make_scan_result(vulns=[], updates=[make_update(blocked_reason="too young")])
    state, project = seed_project(tmp_path, "api", scan, test_unit=None)
    emit = RecordingEmit()

    result = update_service.update_project(
        "api", project, choose=None, vcs=state.services(), emit=emit
    )

    assert result == update_service.ProjectUpdate(
        "api", Outcome.SUCCEEDED, (), blocked=1
    )
    assert emit.events == [ScanReported(load_scan_results("api"))]
    assert not any(call.method == "add_workspace" for call in state.attempts)


def test_given_failed_row_when_update_finishes_then_promotion_is_reported_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(
                pkg_name="pkg-a",
                update_status=UpdateStatus.READY,
                flow=Workflow.UPDATE,
            ),
            make_update(
                pkg_name="pkg-b",
                update_status=UpdateStatus.FAILED,
                flow=Workflow.UPDATE,
                failed_phase="unit",
            ),
        ],
    )
    state, project = seed_project(tmp_path, "api", scan)
    state.services().repository(project.path).set_bookmark(
        bookmark="mm/update-dependencies", revision="main"
    )
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-b": (False, "unit")}),
    )
    emit = RecordingEmit()

    result = update_service.update_project(
        "api", project, choose=None, vcs=state.services(), emit=emit
    )

    assert result.outcome is Outcome.FAILED
    assert emit.of_type(OperationFailed) == [
        OperationFailed(
            Operation.PROMOTE,
            "api",
            "failed updates remain pending · rerun mm update api "
            "or repair with mm resolve api",
        )
    ]
    assert not any(call.method == "promote_bookmark_to_main" for call in state.attempts)


def test_resume_new_change_failure_removes_workspace(
    tmp_path: Path,
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.READY, flow=Workflow.UPDATE)],
    )
    state, project = seed_project(tmp_path, "api", scan)
    repo = state.repository(project.path)
    repo.create_bookmark(bookmark="mm/update-dependencies", revision="main")
    workspace = paths.workspaces_dir() / "api"
    original = RevisionError("stale lock")
    state.fail("new_change", error=original, path=workspace)

    with pytest.raises(update_service.UpdateSetupError) as caught:
        update_service.update_project(
            "api",
            project,
            choose=None,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

    assert caught.value.__cause__ is original
    assert "mm-api" not in repo.workspace_names()
    assert not workspace.exists()
    assert load_scan_results("api").updates[0].update_status is UpdateStatus.READY


def test_typed_equal_risk_selection_order_reaches_processor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(pkg_name="pkg-a"), make_update(pkg_name="pkg-b")],
    )
    state, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None), "pkg-b": (True, None)}),
    )

    result = update_service.update_project(
        "api",
        project,
        choose=pick_findings("pkg-b", "pkg-a"),
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
        choose=None,
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
    state, project = seed_project(tmp_path, "api", scan)
    emit = RecordingEmit()

    result = update_service.update_project(
        "api",
        project,
        choose=None,
        vcs=state.services(),
        emit=emit,
    )

    assert result.outcome is Outcome.SUCCEEDED
    assert emit.events == [ProjectSkipped("api", SkipReason.NOTHING_TO_DO, "update")]


def test_given_no_test_phase_when_updating_then_project_fails_before_effects(
    tmp_path: Path,
) -> None:
    state, project = seed_project(
        tmp_path,
        "api",
        make_scan_result(vulns=[], updates=[make_update()]),
        test_unit=None,
    )
    emit = RecordingEmit()

    result = update_service.update_project(
        "api", project, choose=None, vcs=state.services(), emit=emit
    )

    assert result == update_service.ProjectUpdate("api", Outcome.FAILED, ())
    assert emit.events == [MissingTestConfig("api")]
    assert state.effects == []


def test_given_one_row_of_a_shared_target_chosen_when_updating_then_both_rows_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_gradle_target()
    scan = make_scan_result(
        vulns=[
            make_vuln(
                vuln_id="CVE-1",
                pkg_name="androidx.room:room-runtime",
                fixed_version="2.8.5",
                gradle_target=target,
            )
        ],
        updates=[make_update(pkg_name="room", gradle_target=target)],
    )
    state, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"room": (True, None)}),
    )

    result = update_service.update_project(
        "api",
        project,
        choose=pick_findings("room"),
        vcs=state.services(),
        emit=RecordingEmit(),
    )

    assert result.results == (UpdateResult("room", "vuln", True),)
    saved = load_scan_results("api")
    assert (saved.vulnerabilities, saved.updates) == ([], [])


def test_update_rejects_findings_owned_by_resolve(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    state, project = seed_project(tmp_path, "api", scan)

    with pytest.raises(
        FlowConflictError,
        match=(
            "Cannot run update on api: 1 finding\\(s\\) owned by the 'resolve' flow"
        ),
    ):
        update_service.update_project(
            "api",
            project,
            choose=None,
            vcs=state.services(),
            emit=RecordingEmit(),
        )


def test_missing_progress_bookmark_requires_rescan(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.UPDATE)],
    )
    state, project = seed_project(tmp_path, "api", scan)

    with pytest.raises(
        update_service.UpdateSetupError,
        match=r"update bookmark 'mm/update-dependencies' is missing.*rescan required",
    ):
        update_service.update_project(
            "api",
            project,
            choose=None,
            vcs=state.services(),
            emit=RecordingEmit(),
        )


def test_workspace_revision_error_is_wrapped_with_cause(tmp_path: Path) -> None:
    state, project = seed_project(
        tmp_path, "api", make_scan_result(vulns=[], updates=[make_update()])
    )
    original = RevisionError("locked")
    state.fail("add_workspace", error=original, path=project.path)

    with pytest.raises(update_service.UpdateSetupError, match="locked") as exc_info:
        update_service.update_project(
            "api",
            project,
            choose=None,
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
    state, project = seed_project(
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
        choose=None,
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
        choose=None,
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


def test_batch_reports_success_conflict_and_missing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = FakeJjState()
    projects = {
        "a": make_project(tmp_path / "a", test_unit="pytest"),
        "b": make_project(tmp_path / "b", test_unit="pytest"),
        "c": make_project(tmp_path / "missing", test_unit="pytest"),
    }
    for name in ("a", "b"):
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
    emit = RecordingEmit()

    result = update_service.update_projects(
        make_config(projects=projects),
        ["a", "b", "c"],
        vcs=state.services(),
        emit=emit,
    )

    assert result.had_errors is True
    assert [project.project for project in result.projects] == ["a"]
    assert ProjectStarted("a") in emit.events
    assert ProjectStarted("b") in emit.events
    missing = ProjectSkipped("c", SkipReason.PATH_MISSING, str(projects["c"].path))
    assert missing in emit.events
    assert emit.events.index(ProjectStarted("b")) < emit.events.index(missing)
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


@pytest.mark.parametrize(
    "android_home, tracked, inspection_error, refusal",
    [
        (None, False, None, "is not a tracked regular file"),
        (None, True, None, None),
        ("/opt/android", False, None, None),
        (None, True, RevisionError("inspection failed"), "inspection failed"),
    ],
)
def test_given_local_properties_when_update_starts_then_untracked_sdk_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    android_home: str | None,
    tracked: bool,
    inspection_error: RevisionError | None,
    refusal: str | None,
) -> None:
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    if android_home:
        monkeypatch.setenv("ANDROID_HOME", android_home)
    else:
        monkeypatch.delenv("ANDROID_HOME", raising=False)
    project = make_project(tmp_path / "api", test_unit="pytest")
    files = {"dep.txt": "version=1\n"} | (
        {"local.properties": "sdk.dir=/x\n"} if tracked else {}
    )
    state = FakeJjState()
    state.seed_repository(project.path, files=files)
    state.register_files(project.path, "mm-fixture-pkg-a.txt")
    (project.path / "local.properties").write_text("sdk.dir=/x\n")
    if inspection_error is not None:
        state.fail("revision_file", error=inspection_error, path=project.path)
    scan = make_scan_result(vulns=[], updates=[make_update()])
    scan.project = "api"
    save_scan_results("api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )
    state.clear_calls()

    if refusal is not None:
        with pytest.raises(update_service.UpdateSetupError, match=refusal):
            update_service.update_project(
                "api", project, choose=None, vcs=state.services(), emit=RecordingEmit()
            )
        assert state.effects == []
    else:
        result = update_service.update_project(
            "api", project, choose=None, vcs=state.services(), emit=RecordingEmit()
        )
        assert result.outcome is Outcome.SUCCEEDED


@pytest.mark.parametrize("flow", ["update"])
def test_given_flow_when_run_then_no_scan_discovery_build_or_push_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flow: str
) -> None:
    state = FakeJjState()
    project = _seed_gradle_project(
        tmp_path, state, "api", build_command="./gradlew assembleDebug"
    )
    repo = state.services().repository(project.path)
    before = repo.resolve_revision(revision="main")
    commands: list[str] = []
    refuse_new_processes(monkeypatch)
    monkeypatch.setattr(gradle, "run_gradle", catalogue_apply_task())
    monkeypatch.setattr(
        updater, "run_shell_command", lambda command, *_, **__: commands.append(command)
    )
    run = {"update": update_service.update_project}[flow]

    result = run(
        "api", project, choose=None, vcs=state.services(), emit=RecordingEmit()
    )

    assert commands == ["./gradlew test"]
    assert not any(call.method == "push_bookmark" for call in state.attempts)
    assert result.outcome is Outcome.SUCCEEDED
    assert repo.resolve_revision(revision="main") != before
    assert repo.is_ancestor(ancestor=before, descendant="main")


def test_given_bun_and_gradle_projects_when_batch_updated_then_both_promote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = FakeJjState()
    android = _seed_gradle_project(tmp_path, state, "android")
    web = make_project(tmp_path / "web", package_manager="bun", test_unit="true")
    state.seed_repository(web.path, files={"package.json": "{}\n"})
    state.register_files(web.path, "deps-pkg-a.txt")
    scan = make_scan_result(vulns=[], updates=[make_update(pkg_name="pkg-a")])
    scan.project = "web"
    save_scan_results("web", scan)
    monkeypatch.setattr(gradle, "run_gradle", catalogue_apply_task())
    monkeypatch.setattr(updater, "run_shell_command", lambda *_, **__: None)
    bun_commands: list[list[str]] = []

    def run_bun(command: list[str], cwd: Path, **_: object) -> None:
        bun_commands.append(command)
        (cwd / "deps-pkg-a.txt").write_text(command[-1], encoding="utf-8")

    monkeypatch.setattr(updater, "run_logged", run_bun)
    emit = RecordingEmit()

    batch = update_service.update_projects(
        make_config(projects={"web": web, "android": android}),
        ["web", "android"],
        vcs=state.services(),
        emit=emit,
    )

    assert [(item.project, item.outcome) for item in batch.projects] == [
        ("web", Outcome.SUCCEEDED),
        ("android", Outcome.SUCCEEDED),
    ]
    assert emit.of_type(Promoted) == [Promoted(), Promoted()]
    assert bun_commands == [["bun", "add", "pkg-a@1.0.1"]]
    catalogue = (GRADLE_FIXTURES / "libs.versions.toml").read_text(encoding="utf-8")
    assert state.repository(android.path).file_text(
        revision="main", filename=GRADLE_CATALOGUE_RELPATH
    ) == catalogue.replace('room = "2.8.4"', 'room = "2.8.5"', 1)


def test_given_cleanup_failure_when_batch_updated_then_next_project_still_promotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = FakeJjState()
    projects = {
        name: _seed_gradle_project(tmp_path, state, name) for name in ("api", "web")
    }
    state.fail(
        "forget_workspace", error=RevisionError("busy"), path=projects["api"].path
    )
    monkeypatch.setattr(gradle, "run_gradle", catalogue_apply_task())
    monkeypatch.setattr(updater, "run_shell_command", lambda *_, **__: None)
    emit = RecordingEmit()

    batch = update_service.update_projects(
        make_config(projects=projects), ["api", "web"], vcs=state.services(), emit=emit
    )

    assert [(item.project, item.outcome) for item in batch.projects] == [
        ("api", Outcome.FAILED),
        ("web", Outcome.SUCCEEDED),
    ]
    assert OperationFailed(Operation.WORKSPACE_CLEANUP, "api", "busy") in emit.events
    assert 'room = "2.8.5"' in _catalogue_text(projects["web"])


def test_given_refresh_failure_when_rerun_then_promotion_completes_without_reapply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(vulns=[], updates=[make_update(pkg_name="pkg-a")])
    state, project = seed_project(tmp_path, "api", scan)
    processor = FakeFindingProcessor({"pkg-a": (True, None)})
    calls: list[list[str]] = []

    def process(findings, work_config, **kwargs):
        calls.append([finding.pkg_name for finding in findings])
        return processor(findings, work_config, **kwargs)

    monkeypatch.setattr(update_service, "process_findings", process)
    state.fail("rebase_working_copy", error=RevisionError("locked"), path=project.path)
    first_emit = RecordingEmit()

    first = update_service.update_project(
        "api", project, choose=None, vcs=state.services(), emit=first_emit
    )

    repo = state.services().repository(project.path)
    assert first.outcome is Outcome.FAILED
    assert OperationFailed(Operation.REFRESH, "api", "locked") in first_emit.events
    assert [row.update_status for row in load_scan_results("api").updates] == [
        UpdateStatus.READY
    ]
    assert repo.bookmark_exists(bookmark="mm/update-dependencies")

    second = update_service.update_project(
        "api", project, choose=None, vcs=state.services(), emit=RecordingEmit()
    )

    assert second.outcome is Outcome.SUCCEEDED
    assert calls == [["pkg-a"]]
    assert load_scan_results("api").updates == []
    assert not repo.bookmark_exists(bookmark="mm/update-dependencies")


def test_given_fresh_scan_and_stale_bookmark_when_updating_then_work_starts_from_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(vulns=[], updates=[make_update(pkg_name="pkg-a")])
    state, project = seed_project(tmp_path, "api", scan)
    repo = state.services().repository(project.path)
    state.register_files(project.path, "mm-fixture-stale.txt")
    (project.path / "mm-fixture-stale.txt").write_text("old", encoding="utf-8")
    repo.commit(message="stale update")
    stale = repo.resolve_revision(revision="@-")
    repo.set_bookmark(bookmark="mm/update-dependencies", revision=stale)
    repo.new_change(revision="main")
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )

    result = update_service.update_project(
        "api", project, choose=None, vcs=state.services(), emit=RecordingEmit()
    )

    assert result.outcome is Outcome.SUCCEEDED
    assert not repo.is_ancestor(ancestor=stale, descendant="main")
    assert (project.path / "mm-fixture-pkg-a.txt").is_file()
    assert not (project.path / "mm-fixture-stale.txt").exists()


def _seed_gradle_project(
    tmp_path: Path, state: FakeJjState, name: str, **overrides: object
) -> ProjectConfig:
    project = make_project(
        tmp_path / name,
        package_manager="gradle",
        test_unit="./gradlew test",
        **overrides,
    )
    catalogue = (GRADLE_FIXTURES / "libs.versions.toml").read_text(encoding="utf-8")
    state.seed_repository(
        project.path,
        files={"gradlew": "#!/bin/sh\nexit 0\n", GRADLE_CATALOGUE_RELPATH: catalogue},
    )
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(pkg_name="room", gradle_target=make_gradle_target())],
    )
    scan.project = name
    save_scan_results(name, scan)
    return project


def _catalogue_text(project: ProjectConfig) -> str:
    return (project.path / GRADLE_CATALOGUE_RELPATH).read_text(encoding="utf-8")
