from pathlib import Path

import pytest

from maintenance_man import gradle, paths, updater
from maintenance_man.gradle import GRADLE_CATALOGUE_RELPATH
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    Emit,
    OperationFailed,
    Outcome,
    ProcessingStarted,
    ProjectSkipped,
    ProjectStarted,
    Promoted,
    PromotionFailed,
    ScanReported,
    SkipReason,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    Failed,
    GradleBlock,
    Ready,
    UpdateFinding,
    UpdateResult,
    VulnFinding,
    Workflow,
)
from maintenance_man.services import resolve as resolve_service
from maintenance_man.services import update as update_service
from maintenance_man.storage import (
    CorruptScanResultsError,
    load_scan_results,
    save_scan_results,
)
from maintenance_man.vcs import JjRepository, RevisionError
from tests.fakes import FakeFindingProcessor, RecordingEmit
from tests.support.findings import (
    make_gradle_target,
    make_scan_result,
    make_update,
    make_vuln,
)
from tests.support.gradle import GRADLE_FIXTURES, catalogue_apply_task
from tests.support.process import refuse_new_processes
from tests.support.projects import (
    make_config,
    make_project,
    seed_gradle_project,
    seed_project,
    write_bun_manifest,
)
from tests.support.repository import (
    MANAGED,
    commit_file,
    commit_to_main,
    copy_jj_repository,
    fail_repository_method,
    operation_id,
    remote_bookmark_target,
    run_jj,
    write_file,
)


def pick_findings(*pkg_names: str) -> update_service.FindingChooser:
    def choose(
        vulns: list[VulnFinding], updates: list[UpdateFinding]
    ) -> tuple[list[VulnFinding], list[UpdateFinding]]:
        selected_vulns: list[VulnFinding] = []
        selected_updates: list[UpdateFinding] = []
        findings = [*vulns, *updates]
        for pkg_name in pkg_names:
            finding = next(item for item in findings if item.pkg_name == pkg_name)
            if isinstance(finding, VulnFinding):
                selected_vulns.append(finding)
            else:
                selected_updates.append(finding)
        return selected_vulns, selected_updates

    return choose


def _update_api(
    project: ProjectConfig,
    *,
    choose: update_service.FindingChooser | None = None,
    emit: Emit | None = None,
) -> update_service.ProjectUpdate:
    return update_service.update_project(
        "api",
        project,
        choose=choose,
        emit=emit or RecordingEmit(),
    )


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
    repo, project = seed_project(tmp_path, "api", scan)
    original = project.model_copy(deep=True)
    processor = FakeFindingProcessor({"pkg-b": (True, None)})
    workspaces: list[Path] = []

    def process(findings, work_config, **kwargs):
        workspaces.append(work_config.path)
        return processor(findings, work_config, **kwargs)

    monkeypatch.setattr(update_service, "process_findings", process)
    emit = RecordingEmit()

    result = _update_api(project, choose=pick_findings("pkg-b"), emit=emit)

    expected_result = UpdateResult("pkg-b", "update", True)
    assert result == update_service.ProjectUpdate(
        "api",
        Outcome.SUCCEEDED,
        (expected_result,),
    )
    assert isinstance(emit.events[0], ScanReported)
    assert emit.events[1:] == [
        ProcessingStarted(0, 1),
        Promoted(),
    ]
    assert [item.pkg_name for item in load_scan_results("api").updates] == ["pkg-a"]
    assert repo.same_revision(left="main", right="@-")
    assert not repo.bookmark_exists(bookmark=MANAGED)
    assert "mm-api" not in repo.workspace_names()
    assert workspaces == [paths.workspaces_dir() / "api"]
    assert project == original
    assert not (paths.workspaces_dir() / "api").exists()


def test_given_scan_saved_under_another_manager_when_loaded_then_corrupt(
    tmp_path: Path,
) -> None:
    scan = make_scan_result(package_manager="bun")
    _, project = seed_project(tmp_path, "api", scan)

    with pytest.raises(CorruptScanResultsError) as raised:
        _update_api(project)

    assert raised.value.detail == "saved under bun, but the project is configured as uv"
    assert load_scan_results("api") == scan


def test_given_blocked_and_passing_rows_when_updating_then_passing_rows_promote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(pkg_name="pkg-a"),
            make_update(
                pkg_name="stuck", state=GradleBlock(kind="age", reason="too young")
            ),
        ],
    )
    repo, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )
    emit = RecordingEmit()

    result = _update_api(project, choose=pick_findings("pkg-a"), emit=emit)

    passed = UpdateResult("pkg-a", "update", True)
    assert result == update_service.ProjectUpdate(
        "api", Outcome.SUCCEEDED, (passed,), blocked=1
    )
    assert emit.of_type(Promoted) == [Promoted()]
    assert [row.pkg_name for row in load_scan_results("api").updates] == ["stuck"]
    assert repo.same_revision(left="main", right="@-")


def test_given_only_blocked_rows_when_updating_then_success_without_workspace(
    tmp_path: Path,
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(state=GradleBlock(kind="age", reason="too young"))],
    )
    repo, project = seed_project(tmp_path, "api", scan, test_unit=None)
    before = operation_id(repo)
    emit = RecordingEmit()

    result = _update_api(project, emit=emit)

    assert result == update_service.ProjectUpdate(
        "api", Outcome.SUCCEEDED, (), blocked=1
    )
    assert emit.events == [ScanReported(load_scan_results("api"))]
    assert operation_id(repo) == before


def test_given_failed_row_when_update_finishes_then_promotion_is_reported_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(pkg_name="pkg-a", state=Ready(flow=Workflow.UPDATE)),
            make_update(
                pkg_name="pkg-b", state=Failed(flow=Workflow.UPDATE, phase="unit")
            ),
        ],
    )
    repo, project = seed_project(tmp_path, "api", scan)
    repo.set_bookmark(bookmark=MANAGED, revision="main")
    main_before = repo.resolve_revision(revision="main")
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-b": (False, "unit")}),
    )
    emit = RecordingEmit()

    result = _update_api(project, emit=emit)

    assert result.outcome is Outcome.FAILED
    assert emit.of_type(PromotionFailed) == [
        PromotionFailed(
            "api",
            "failed updates remain pending · rerun mm update api "
            "or repair with mm resolve api",
        )
    ]
    assert repo.resolve_revision(revision="main") == main_before


def test_typed_equal_risk_selection_order_reaches_processor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(pkg_name="pkg-a"), make_update(pkg_name="pkg-b")],
    )
    _, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None), "pkg-b": (True, None)}),
    )

    result = _update_api(project, choose=pick_findings("pkg-b", "pkg-a"))

    assert [item.pkg_name for item in result.results] == ["pkg-b", "pkg-a"]


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
    _, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"room": (True, None)}),
    )

    result = _update_api(project, choose=pick_findings("room"))

    assert result.results == (UpdateResult("room", "vuln", True),)
    saved = load_scan_results("api")
    assert (saved.vulnerabilities, saved.updates) == ([], [])


@pytest.mark.parametrize(
    ("ready_work", "method", "in_workspace", "message"),
    [
        pytest.param(True, "new_change", True, "stale lock", id="resume-new-change"),
        pytest.param(False, "add_workspace", False, "locked", id="add-workspace"),
    ],
)
def test_given_workspace_setup_failure_when_updating_then_setup_error_and_no_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ready_work: bool,
    method: str,
    in_workspace: bool,
    message: str,
) -> None:
    update = (
        make_update(state=Ready(flow=Workflow.UPDATE)) if ready_work else make_update()
    )
    repo, project = seed_project(
        tmp_path, "api", make_scan_result(vulns=[], updates=[update])
    )
    if ready_work:
        repo.set_bookmark(bookmark=MANAGED, revision="main", allow_backwards=True)
    workspace = paths.workspaces_dir() / "api"
    original = RevisionError(message)
    fail_repository_method(
        monkeypatch, workspace if in_workspace else project.path, method, original
    )
    saved_before = load_scan_results("api")

    with pytest.raises(update_service.UpdateSetupError, match=message) as caught:
        _update_api(project)

    assert caught.value.__cause__ is original
    assert "mm-api" not in repo.workspace_names()
    assert not workspace.exists()
    assert load_scan_results("api") == saved_before


@pytest.mark.parametrize(
    ("method", "expected"),
    [
        (
            "promote_bookmark_to_main",
            PromotionFailed(
                "api",
                "blocked · rebase with jj rebase -b mm/update-dependencies -d main, "
                "then rerun",
            ),
        ),
        ("forget_workspace", OperationFailed("workspace cleanup", "api", "blocked")),
        ("delete_bookmark", OperationFailed("bookmark cleanup", "api", "blocked")),
    ],
)
def test_finalisation_failures_emit_operation_and_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    expected: PromotionFailed | OperationFailed,
) -> None:
    repo, project = seed_project(
        tmp_path, "api", make_scan_result(vulns=[], updates=[make_update()])
    )
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )
    fail_repository_method(monkeypatch, project.path, method, RevisionError("blocked"))
    emit = RecordingEmit()

    result = _update_api(project, emit=emit)

    assert result.outcome is Outcome.FAILED
    assert expected in emit.events
    if isinstance(expected, PromotionFailed):
        assert repo.bookmark_exists(bookmark=MANAGED)
        assert load_scan_results("api").updates[0].state == Ready(flow=Workflow.UPDATE)


def test_existing_update_failure_blocks_single_and_batch_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects: dict[str, ProjectConfig] = {}
    main_before: dict[str, str] = {}
    for name in ("single", "batch"):
        scan = make_scan_result(
            vulns=[
                make_vuln(
                    fixed_version=None,
                    state=Failed(flow=Workflow.UPDATE, phase="unit"),
                )
            ],
            updates=[make_update()],
        )
        repo, projects[name] = seed_project(tmp_path, name, scan)
        repo.set_bookmark(bookmark=MANAGED, revision="main")
        main_before[name] = repo.resolve_revision(revision="main")
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )

    single = update_service.update_project(
        "single",
        projects["single"],
        choose=None,
        emit=RecordingEmit(),
    )
    batch = update_service.update_projects(
        make_config(projects={"batch": projects["batch"]}),
        ["batch"],
        emit=RecordingEmit(),
    )

    assert single.outcome is Outcome.FAILED
    assert batch.projects[0].outcome is Outcome.FAILED
    assert batch.outcome is Outcome.FAILED
    assert {
        name: JjRepository(project.path).resolve_revision(revision="main")
        for name, project in projects.items()
    } == main_before


def test_batch_reports_success_conflict_and_missing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, project_a = seed_project(
        tmp_path, "a", make_scan_result(vulns=[], updates=[make_update()])
    )
    _, project_b = seed_project(
        tmp_path,
        "b",
        make_scan_result(
            vulns=[],
            updates=[make_update(state=Failed(flow=Workflow.RESOLVE, phase="unit"))],
        ),
    )
    projects = {
        "a": project_a,
        "b": project_b,
        "c": make_project(tmp_path / "missing", test_unit="pytest"),
    }
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )
    emit = RecordingEmit()

    result = update_service.update_projects(
        make_config(projects=projects),
        ["a", "b", "c"],
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
        (None, False, None, "exists in the source checkout but is not tracked"),
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
    repo, project = seed_project(
        tmp_path, "api", make_scan_result(vulns=[], updates=[make_update()])
    )
    write_file(repo, "local.properties", "sdk.dir=/x\n")
    if tracked:
        commit_to_main(repo, "track local properties")
    if inspection_error is not None:
        fail_repository_method(
            monkeypatch, project.path, "has_regular_file", inspection_error
        )
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )
    before = operation_id(repo)

    if refusal is not None:
        with pytest.raises(update_service.UpdateSetupError, match=refusal):
            _update_api(project)
        assert operation_id(repo) == before
    else:
        assert _update_api(project).outcome is Outcome.SUCCEEDED


@pytest.mark.parametrize("flow", ["update", "resolve"])
def test_given_flow_when_run_then_no_scan_discovery_build_or_push_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flow: str
) -> None:
    project = seed_gradle_project(
        tmp_path, "api", build_command="./gradlew assembleDebug"
    )
    repo = JjRepository(project.path)
    before = repo.resolve_revision(revision="main")
    main_origin = repo.resolve_revision(revision="main@origin")
    commands: list[str] = []
    refuse_new_processes(monkeypatch)
    monkeypatch.setattr(gradle, "run_gradle", catalogue_apply_task())
    monkeypatch.setattr(
        updater, "run_shell_command", lambda command, *_, **__: commands.append(command)
    )
    run = {
        "update": lambda: _update_api(project).outcome,
        "resolve": lambda: resolve_service.resolve_project(
            "api",
            project,
            continue_=False,
            emit=RecordingEmit(),
        ),
    }[flow]

    outcome = run()

    assert commands == ["./gradlew test"]
    assert remote_bookmark_target(repo, "main") == main_origin
    assert remote_bookmark_target(repo, WORKFLOW_BOOKMARKS[Workflow(flow)]) is None
    assert outcome is Outcome.SUCCEEDED
    assert repo.resolve_revision(revision="main") != before
    assert repo.is_ancestor(ancestor=before, descendant="main")


def test_given_bun_and_gradle_projects_when_batch_updated_then_both_promote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    android = seed_gradle_project(tmp_path, "android")
    web = make_project(tmp_path / "web", package_manager="bun", test_unit="true")
    web_repo = copy_jj_repository(web.path)
    write_bun_manifest(web_repo, {"pkg-a": "1.0.0"})
    commit_to_main(web_repo, "bun project")
    scan = make_scan_result(
        vulns=[], updates=[make_update(pkg_name="pkg-a")], package_manager="bun"
    )
    scan.project = "web"
    save_scan_results("web", scan)
    monkeypatch.setattr(gradle, "run_gradle", catalogue_apply_task())
    monkeypatch.setattr(updater, "run_shell_command", lambda *_, **__: None)
    bun_commands: list[list[str]] = []

    def run_bun(command: list[str], cwd: Path, **_: object) -> None:
        bun_commands.append(command)
        (cwd / "deps-pkg-a.txt").write_text(command[-1], encoding="utf-8")

    monkeypatch.setattr(updater, "run_logged", run_bun)
    monkeypatch.setattr(
        "maintenance_man.package_managers.resolved_bun_versions",
        lambda _path: {"pkg-a": "1.0.0"},
    )
    emit = RecordingEmit()

    batch = update_service.update_projects(
        make_config(projects={"web": web, "android": android}),
        ["web", "android"],
        emit=emit,
    )

    assert [(item.project, item.outcome) for item in batch.projects] == [
        ("web", Outcome.SUCCEEDED),
        ("android", Outcome.SUCCEEDED),
    ]
    assert emit.of_type(Promoted) == [Promoted(), Promoted()]
    assert bun_commands == [["bun", "add", "pkg-a@1.0.1"]]
    catalogue = (GRADLE_FIXTURES / "libs.versions.toml").read_text(encoding="utf-8")
    assert _main_catalogue_text(android) == catalogue.replace(
        'room = "2.8.4"', 'room = "2.8.5"', 1
    )


def test_given_refresh_failure_when_rerun_then_promotion_completes_without_reapply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(vulns=[], updates=[make_update(pkg_name="pkg-a")])
    repo, project = seed_project(tmp_path, "api", scan)
    processor = FakeFindingProcessor({"pkg-a": (True, None)})
    calls: list[list[str]] = []

    def process(findings, work_config, **kwargs):
        calls.append([finding.pkg_name for finding in findings])
        return processor(findings, work_config, **kwargs)

    monkeypatch.setattr(update_service, "process_findings", process)
    fail_repository_method(
        monkeypatch, project.path, "rebase_working_copy", RevisionError("locked")
    )
    first_emit = RecordingEmit()

    first = _update_api(project, emit=first_emit)

    assert first.outcome is Outcome.FAILED
    assert OperationFailed("workspace refresh", "api", "locked") in first_emit.events
    assert [row.state for row in load_scan_results("api").updates] == [
        Ready(flow=Workflow.UPDATE)
    ]
    assert repo.bookmark_exists(bookmark=MANAGED)

    second = _update_api(project)

    assert second.outcome is Outcome.SUCCEEDED
    assert calls == [["pkg-a"]]
    assert load_scan_results("api").updates == []
    assert not repo.bookmark_exists(bookmark=MANAGED)


def test_given_fresh_scan_and_stale_bookmark_when_updating_then_work_starts_from_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(vulns=[], updates=[make_update(pkg_name="pkg-a")])
    repo, project = seed_project(tmp_path, "api", scan)
    stale = commit_file(repo, "mm-fixture-stale.txt", "old", "stale update")
    repo.set_bookmark(bookmark=MANAGED, revision=stale)
    repo.new_change(revision="main")
    monkeypatch.setattr(
        update_service,
        "process_findings",
        FakeFindingProcessor({"pkg-a": (True, None)}),
    )

    result = _update_api(project)

    assert result.outcome is Outcome.SUCCEEDED
    assert not repo.is_ancestor(ancestor=stale, descendant="main")
    assert (project.path / "mm-fixture-pkg-a.txt").is_file()
    assert not (project.path / "mm-fixture-stale.txt").exists()


def _main_catalogue_text(project: ProjectConfig) -> str:
    shown = run_jj(
        project.path,
        "file",
        "show",
        "-r",
        "main",
        f"root-file:{GRADLE_CATALOGUE_RELPATH}",
    )
    assert shown.returncode == 0, shown.stderr
    return shown.stdout


def _catalogue_text(project: ProjectConfig) -> str:
    return (project.path / GRADLE_CATALOGUE_RELPATH).read_text(encoding="utf-8")
