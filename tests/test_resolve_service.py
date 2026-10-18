from pathlib import Path

import pytest

from maintenance_man.models.events import (
    BlockersStillFailing,
    FindingPassed,
    FindingsBlocked,
    FindingStepFailed,
    FindingStepKind,
    MissingTestConfig,
    Operation,
    OperationFailed,
    Outcome,
    Promoted,
    ResolvePaused,
)
from maintenance_man.models.scan import ScanResult, UpdateStatus, Workflow
from maintenance_man.services import WorkflowError
from maintenance_man.services import resolve as resolve_service
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs import RevisionError
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeFindingProcessor, RecordingEmit
from tests.support.findings import (
    make_scan_result,
    make_update,
    make_vuln,
)
from tests.support.projects import seed_gradle_project, seed_project

_BOOKMARK = "mm/resolve-dependencies"
_UPDATE_BOOKMARK = "mm/update-dependencies"


def _record_tip_at_promotion(state: FakeJjState, path: Path) -> list[str]:
    tips: list[str] = []
    state.hook(
        "promote_bookmark_to_main",
        phase="before",
        action=lambda: tips.append(
            state.repository(path).resolve_revision(revision=_BOOKMARK)
        ),
        path=path,
    )
    return tips


def _pending_stack_scan() -> ScanResult:
    return make_scan_result(
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
            make_update(
                pkg_name="pkg-c",
                update_status=UpdateStatus.READY,
                flow=Workflow.UPDATE,
            ),
        ],
    )


def _stack_update_commits(state: FakeJjState, path: Path, *packages: str) -> str:
    repo = state.services().repository(path)
    for package in packages:
        (path / f"mm-fixture-{package}.txt").write_text("1.0.1", encoding="utf-8")
        repo.commit(message=f"fixture: update {package}")
    repo.set_bookmark(bookmark=_UPDATE_BOOKMARK, revision="@-")
    return repo.resolve_revision(revision=_UPDATE_BOOKMARK)


def _commit_repair(state: FakeJjState, path: Path) -> None:
    (path / "dep.txt").write_text("repaired\n", encoding="utf-8")
    state.services().repository(path).commit(message="repair")


class TestResolveCandidates:
    def test_given_pending_update_stack_when_resolving_then_resolve_owns_it_at_same_tip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state, project = seed_project(tmp_path, "api", _pending_stack_scan())
        update_tip = _stack_update_commits(state, project.path, "pkg-a", "pkg-c")
        processed: list[tuple[str, ...]] = []
        processor = FakeFindingProcessor({"pkg-b": (False, "unit")})

        def process(findings, project_config, **kwargs):
            processed.append(tuple(finding.pkg_name for finding in findings))
            return processor(findings, project_config, **kwargs)

        monkeypatch.setattr(resolve_service, "process_findings", process)

        outcome = resolve_service.resolve_project(
            "api",
            project,
            continue_=False,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

        assert outcome is Outcome.FAILED
        assert processed == [("pkg-b",)]
        assert [
            (row.pkg_name, row.flow, row.update_status)
            for row in load_scan_results("api").updates
        ] == [
            ("pkg-a", Workflow.RESOLVE, UpdateStatus.READY),
            ("pkg-b", Workflow.RESOLVE, UpdateStatus.FAILED),
            ("pkg-c", Workflow.RESOLVE, UpdateStatus.READY),
        ]
        repo = state.services().repository(project.path)
        assert repo.resolve_revision(revision=_BOOKMARK) == update_tip
        assert repo.same_revision(left="@-", right=_BOOKMARK)
        assert not repo.bookmark_exists(bookmark=_UPDATE_BOOKMARK)

    def test_given_interrupted_takeover_when_resolving_again_then_failure_is_retried(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state, project = seed_project(tmp_path, "api", _pending_stack_scan())
        update_tip = _stack_update_commits(state, project.path, "pkg-a", "pkg-c")
        rows_after_takeover: list[
            list[tuple[UpdateStatus | None, Workflow | None]]
        ] = []

        def interrupted(findings, project_config, **kwargs):
            rows_after_takeover.append(
                [
                    (row.update_status, row.flow)
                    for row in load_scan_results("api").updates
                ]
            )
            raise KeyboardInterrupt

        monkeypatch.setattr(resolve_service, "process_findings", interrupted)
        with pytest.raises(KeyboardInterrupt):
            resolve_service.resolve_project(
                "api",
                project,
                continue_=False,
                vcs=state.services(),
                emit=RecordingEmit(),
            )
        processed: list[tuple[str, ...]] = []
        processor = FakeFindingProcessor({"pkg-b": (True, None)})

        def process(findings, project_config, **kwargs):
            processed.append(tuple(finding.pkg_name for finding in findings))
            return processor(findings, project_config, **kwargs)

        monkeypatch.setattr(resolve_service, "process_findings", process)

        outcome = resolve_service.resolve_project(
            "api",
            project,
            continue_=False,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

        assert rows_after_takeover == [
            [
                (UpdateStatus.READY, Workflow.RESOLVE),
                (None, Workflow.RESOLVE),
                (UpdateStatus.READY, Workflow.RESOLVE),
            ]
        ]
        assert outcome is Outcome.SUCCEEDED
        assert processed == [("pkg-b",)]
        assert load_scan_results("api").findings == ()
        repo = state.services().repository(project.path)
        assert repo.is_ancestor(ancestor=update_tip, descendant="main")

    @pytest.mark.parametrize(
        ("dirty", "update_bookmark", "message"),
        [
            pytest.param(
                True,
                True,
                "Resolve cannot take over pending updates while {path} has "
                "uncommitted changes. Commit or discard them, then run mm "
                "resolve api again.",
                id="uncommitted-changes",
            ),
            pytest.param(
                False,
                False,
                "Resolve cannot take over pending updates: bookmark "
                "mm/update-dependencies is missing. Run mm scan api to start "
                "again from main.",
                id="update-bookmark-missing",
            ),
        ],
    )
    def test_given_unsafe_state_when_taking_over_then_nothing_changes(
        self, tmp_path: Path, dirty: bool, update_bookmark: bool, message: str
    ) -> None:
        state, project = seed_project(tmp_path, "api", _pending_stack_scan())
        if update_bookmark:
            _stack_update_commits(state, project.path, "pkg-a", "pkg-c")
        if dirty:
            (project.path / "dep.txt").write_text("dirty\n", encoding="utf-8")
        saved_before = load_scan_results("api")
        state.clear_calls()

        with pytest.raises(WorkflowError) as raised:
            resolve_service.resolve_project(
                "api",
                project,
                continue_=False,
                vcs=state.services(),
                emit=RecordingEmit(),
            )

        assert str(raised.value) == message.format(path=project.path.resolve())
        assert load_scan_results("api") == saved_before
        assert state.effects == []

    @pytest.mark.parametrize("continue_", [False, True], ids=["resolve", "continue"])
    def test_given_update_and_resolve_progress_when_run_then_resolve_refuses_unchanged(
        self, tmp_path: Path, continue_: bool
    ) -> None:
        scan = _pending_stack_scan()
        scan.updates.append(
            make_update(
                pkg_name="pkg-d",
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="unit",
            )
        )
        state, project = seed_project(tmp_path, "api", scan)
        _stack_update_commits(state, project.path, "pkg-a", "pkg-c")
        saved_before = load_scan_results("api")
        state.clear_calls()

        with pytest.raises(WorkflowError) as raised:
            resolve_service.resolve_project(
                "api",
                project,
                continue_=continue_,
                vcs=state.services(),
                emit=RecordingEmit(),
            )

        assert str(raised.value) == (
            "Resolve cannot take over pending updates while resolve progress "
            "also exists for api. Run mm scan api to start again from main."
        )
        assert load_scan_results("api") == saved_before
        assert state.effects == []

    def test_given_ready_finding_when_resolve_runs_then_it_is_promoted_and_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scan = make_scan_result(
            vulns=[],
            updates=[
                make_update(
                    pkg_name="pkg-a",
                    update_status=UpdateStatus.READY,
                    flow=Workflow.RESOLVE,
                ),
            ],
        )
        state, project = seed_project(tmp_path, "api", scan)
        state.register_files(project.path, "mm-fixture-pkg-a.txt")
        (project.path / "mm-fixture-pkg-a.txt").write_text("1.0.1", encoding="utf-8")
        repo = state.services().repository(project.path)
        repo.commit(message="fixture: update pkg-a")
        repo.set_bookmark(bookmark=_BOOKMARK, revision="@-")
        resolve_tip = repo.resolve_revision(revision=_BOOKMARK)
        monkeypatch.setattr(
            resolve_service, "process_findings", FakeFindingProcessor({})
        )
        emit = RecordingEmit()

        outcome = resolve_service.resolve_project(
            "api",
            project,
            continue_=False,
            vcs=state.services(),
            emit=emit,
        )

        assert outcome is Outcome.SUCCEEDED
        assert emit.events[-1] == Promoted()
        assert load_scan_results("api").findings == ()
        assert repo.same_revision(left="main", right=resolve_tip)
        assert not repo.bookmark_exists(bookmark=_BOOKMARK)


def test_fresh_resolve_promotes_and_removes_completed_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result()
    state, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (True, None), "pkg-a": (True, None)}),
    )
    resolve_tips = _record_tip_at_promotion(state, project.path)
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.SUCCEEDED
    assert emit.events[-1] == Promoted()
    assert load_scan_results("api").findings == ()
    created = [call for call in state.effects if call.method == "create_bookmark"]
    assert len(created) == 1
    assert dict(created[0].arguments) == {
        "bookmark": _BOOKMARK,
        "revision": "main",
    }
    repo = state.services().repository(project.path)
    assert repo.same_revision(left="main", right=resolve_tips[0])
    assert not repo.bookmark_exists(bookmark=_BOOKMARK)


def test_failed_candidate_pauses_without_promoting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, project = seed_project(tmp_path, "api", make_scan_result())
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (False, "unit"), "pkg-a": (True, None)}),
    )
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.FAILED
    assert emit.events[-1] == ResolvePaused("api")
    saved = load_scan_results("api")
    assert saved.vulnerabilities[0].update_status is UpdateStatus.FAILED
    assert saved.vulnerabilities[0].failed_phase == "unit"
    assert not any(call.method == "push_bookmark" for call in state.attempts)
    assert Promoted() not in emit.events


def test_given_blocked_and_ready_rows_when_resolve_completes_then_it_promotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[
            make_vuln(pkg_name="some-pkg"),
            make_vuln(
                pkg_name="blocked",
                vuln_id="CVE-blocked",
                fixed_version=None,
                blocked_reason="No published fix",
            ),
        ],
        updates=[],
    )
    state, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (True, None)}),
    )
    resolve_tips = _record_tip_at_promotion(state, project.path)
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.SUCCEEDED
    assert emit.of_type(FindingsBlocked) == [
        FindingsBlocked((("blocked", "No published fix"),))
    ]
    assert emit.events[-1] == Promoted()
    assert [
        (row.pkg_name, row.update_status) for row in load_scan_results("api").findings
    ] == [("blocked", None)]
    repo = state.services().repository(project.path)
    assert repo.same_revision(left="main", right=resolve_tips[0])
    assert not any(call.method == "push_bookmark" for call in state.attempts)


def test_given_row_blocked_during_run_when_resolve_completes_then_it_is_reported_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[
            make_vuln(pkg_name="some-pkg"),
            make_vuln(pkg_name="drifted", vuln_id="CVE-drifted"),
        ],
        updates=[],
    )
    state, project = seed_project(tmp_path, "api", scan)
    passing = FakeFindingProcessor({"some-pkg": (True, None)})

    def process_and_block_drifted(findings, *args, scan_result, emit, **kwargs):
        drifted = next(row for row in findings if row.pkg_name == "drifted")
        drifted.blocked_reason = "catalogue drifted"
        emit(FindingsBlocked((("drifted", "catalogue drifted"),)))
        ready = [row for row in findings if row is not drifted]
        return passing(ready, *args, scan_result=scan_result, emit=emit, **kwargs)

    monkeypatch.setattr(resolve_service, "process_findings", process_and_block_drifted)
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.SUCCEEDED
    assert emit.of_type(FindingsBlocked) == [
        FindingsBlocked((("drifted", "catalogue drifted"),))
    ]


def test_given_promotion_failure_when_resolve_completes_then_ready_and_bookmark_remain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, project = seed_project(tmp_path, "api", make_scan_result())
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (True, None), "pkg-a": (True, None)}),
    )
    state.fail(
        "promote_bookmark_to_main", error=RevisionError("denied"), path=project.path
    )
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.FAILED
    assert emit.events[-1] == OperationFailed(
        Operation.PROMOTE,
        "api",
        f"denied · rebase with jj rebase -b {_BOOKMARK} -d main, then rerun",
    )
    assert all(
        finding.update_status is UpdateStatus.READY
        for finding in load_scan_results("api").findings
    )
    assert state.services().repository(project.path).bookmark_exists(bookmark=_BOOKMARK)


def test_continue_failing_retest_persists_phase_and_reports_blockers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[
            make_vuln(
                update_status=UpdateStatus.FAILED,
                failed_phase="apply",
                flow=Workflow.RESOLVE,
            )
        ],
        updates=[],
    )
    state, project = seed_project(tmp_path, "api", scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    _commit_repair(state, project.path)
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: "unit"
    )
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        continue_=True,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.FAILED
    assert emit.events[-1] == BlockersStillFailing("unit", ("some-pkg",))
    saved = load_scan_results("api").vulnerabilities[0]
    assert (saved.update_status, saved.failed_phase, saved.flow) == (
        UpdateStatus.FAILED,
        "unit",
        Workflow.RESOLVE,
    )


def test_continue_passing_retest_marks_blocker_passed_then_promotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[
            make_vuln(
                update_status=UpdateStatus.FAILED,
                failed_phase="unit",
                flow=Workflow.RESOLVE,
            )
        ],
        updates=[make_update(pkg_name="pkg-a")],
    )
    state, project = seed_project(tmp_path, "api", scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    _commit_repair(state, project.path)
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: None
    )
    processor = FakeFindingProcessor({"pkg-a": (True, None)})
    processed: list[tuple[str, ...]] = []

    def process(findings, project_config, **kwargs):
        persisted = load_scan_results("api").vulnerabilities[0]
        assert (
            persisted.update_status,
            persisted.failed_phase,
            persisted.flow,
        ) == (UpdateStatus.READY, None, Workflow.RESOLVE)
        repo = state.services().repository(project.path)
        assert repo.same_revision(left=_BOOKMARK, right="@-")
        processed.append(tuple(finding.pkg_name for finding in findings))
        return processor(findings, project_config, **kwargs)

    monkeypatch.setattr(resolve_service, "process_findings", process)
    resolve_tips = _record_tip_at_promotion(state, project.path)
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        continue_=True,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.SUCCEEDED
    assert FindingPassed("some-pkg", False, "1.0.0", "1.0.1") in emit.events
    assert processed == [("pkg-a",)]
    assert emit.events[-1] == Promoted()
    assert load_scan_results("api").findings == ()
    repo = state.services().repository(project.path)
    assert repo.same_revision(left="main", right=resolve_tips[0])
    assert not repo.bookmark_exists(bookmark=_BOOKMARK)


def test_missing_resume_bookmark_raises_workflow_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.READY, flow=Workflow.RESOLVE)],
    )
    state, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(resolve_service, "process_findings", FakeFindingProcessor({}))

    with pytest.raises(
        WorkflowError,
        match=(
            "resolve bookmark 'mm/resolve-dependencies' is missing but "
            "in-progress state exists"
        ),
    ):
        resolve_service.resolve_project(
            "api",
            project,
            continue_=False,
            vcs=state.services(),
            emit=RecordingEmit(),
        )


def test_paused_resolve_requires_continue(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    state, project = seed_project(tmp_path, "api", scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )

    with pytest.raises(WorkflowError) as raised:
        resolve_service.resolve_project(
            "api",
            project,
            continue_=False,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

    assert str(raised.value) == "resolve already paused for api — rerun with --continue"


def test_continue_wraps_repository_inspection_error(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    state, project = seed_project(tmp_path, "api", scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    state.fail("has_changes", error=RevisionError("unknown"), path=project.path)

    with pytest.raises(WorkflowError) as raised:
        resolve_service.resolve_project(
            "api",
            project,
            continue_=True,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

    assert str(raised.value) == "Cannot inspect resolve work: unknown"
    assert isinstance(raised.value.__cause__, RevisionError)


def test_continue_refuses_dirty_current_change(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    state, project = seed_project(tmp_path, "api", scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    (project.path / "dep.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(WorkflowError) as raised:
        resolve_service.resolve_project(
            "api",
            project,
            continue_=True,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

    assert str(raised.value) == (
        "--continue requires an empty current jj change — commit or discard "
        "manual changes first"
    )


def test_prepare_failure_emits_then_raises_aborted(tmp_path: Path) -> None:
    state, project = seed_project(tmp_path, "api", make_scan_result())
    state.fail(
        "create_bookmark",
        error=RevisionError("cannot create"),
        path=project.path,
    )
    emit = RecordingEmit()

    with pytest.raises(WorkflowError, match="aborted resolve for api"):
        resolve_service.resolve_project(
            "api",
            project,
            continue_=False,
            vcs=state.services(),
            emit=emit,
        )

    assert emit.events[-1] == OperationFailed(
        Operation.RESOLVE_SETUP, "api", "cannot create"
    )


def test_given_bookmark_move_failure_when_continuing_then_repair_base_is_saved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[
            make_vuln(
                update_status=UpdateStatus.FAILED,
                failed_phase="unit",
                flow=Workflow.RESOLVE,
            )
        ],
        updates=[],
    )
    state, project = seed_project(tmp_path, "api", scan)
    repo = state.services().repository(project.path)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    base = repo.resolve_revision(revision="main")
    _commit_repair(state, project.path)
    state.fail(
        "set_bookmark",
        error=RevisionError("cannot move"),
        path=project.path,
    )
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: None
    )

    with pytest.raises(WorkflowError) as raised:
        resolve_service.resolve_project(
            "api",
            project,
            continue_=True,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

    assert str(raised.value) == (
        "could not move mm/resolve-dependencies to the committed manual fix"
    )
    saved = load_scan_results("api")
    assert saved.resolve_repair_base == base
    assert (
        saved.vulnerabilities[0].update_status,
        saved.vulnerabilities[0].failed_phase,
    ) == (UpdateStatus.FAILED, "unit")
    assert repo.resolve_revision(revision=_BOOKMARK) == base


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        pytest.param(
            [(UpdateStatus.FAILED, Workflow.UPDATE)],
            "Pending update work exists for api. Run mm resolve api without "
            "--continue to take it over first.",
            id="update-owned-row",
        ),
        pytest.param(
            [(UpdateStatus.READY, Workflow.RESOLVE)],
            "No paused resolve failure is saved for api. Run mm resolve api to "
            "start resolving.",
            id="no-saved-failure",
        ),
        pytest.param(
            [(UpdateStatus.FAILED, Workflow.RESOLVE)],
            "--continue needs a committed repair on top of "
            "mm/resolve-dependencies. Commit the repair with jj commit, then "
            "run mm resolve api --continue again.",
            id="uncommitted-repair",
        ),
    ],
)
def test_given_unsafe_state_when_continuing_then_resolve_refuses_before_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rows: list[tuple[UpdateStatus, Workflow]],
    message: str,
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(pkg_name=f"pkg-{index}", update_status=status, flow=flow)
            for index, (status, flow) in enumerate(rows)
        ],
    )
    state, project = seed_project(tmp_path, "api", scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    saved_before = load_scan_results("api")
    state.clear_calls()
    monkeypatch.setattr(
        resolve_service,
        "run_test_phases",
        lambda *_args, **_kwargs: pytest.fail("tests ran before the refusal"),
    )

    with pytest.raises(WorkflowError) as raised:
        resolve_service.resolve_project(
            "api",
            project,
            continue_=True,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

    assert str(raised.value) == message
    assert load_scan_results("api") == saved_before
    assert state.effects == []


def test_given_ready_write_interrupted_when_continuing_again_then_same_repair_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    state, project = seed_project(tmp_path, "api", scan)
    repo = state.services().repository(project.path)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    scan.resolve_repair_base = repo.resolve_revision(revision="main")
    save_scan_results("api", scan)
    _commit_repair(state, project.path)
    repair = repo.resolve_revision(revision="@-")
    repo.set_bookmark(bookmark=_BOOKMARK, revision="@-")
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(resolve_service, "process_findings", FakeFindingProcessor({}))
    bases_at_promotion: list[str | None] = []
    state.hook(
        "promote_bookmark_to_main",
        phase="before",
        action=lambda: bases_at_promotion.append(
            load_scan_results("api").resolve_repair_base
        ),
        path=project.path,
    )

    outcome = resolve_service.resolve_project(
        "api",
        project,
        continue_=True,
        vcs=state.services(),
        emit=RecordingEmit(),
    )

    assert outcome is Outcome.SUCCEEDED
    assert bases_at_promotion == [None]
    assert repo.resolve_revision(revision="main") == repair
    assert load_scan_results("api").findings == ()


def test_given_repair_missing_saved_target_when_continuing_then_bookmark_stays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = FakeJjState()
    project = seed_gradle_project(tmp_path, state, "api")
    state.register_files(project.path, "repair.txt")
    scan = load_scan_results("api")
    row = scan.updates[0]
    row.update_status = UpdateStatus.FAILED
    row.failed_phase = "unit"
    row.flow = Workflow.RESOLVE
    save_scan_results("api", scan)
    repo = state.services().repository(project.path)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    base = repo.resolve_revision(revision="main")
    (project.path / "repair.txt").write_text("unrelated\n", encoding="utf-8")
    repo.commit(message="repair")
    monkeypatch.setattr(
        resolve_service,
        "run_test_phases",
        lambda *_args, **_kwargs: pytest.fail("tests ran for a wrong repair"),
    )
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api", project, continue_=True, vcs=state.services(), emit=emit
    )

    assert outcome is Outcome.FAILED
    assert emit.of_type(FindingStepFailed) == [
        FindingStepFailed(
            FindingStepKind.PREPARE,
            "The committed repair does not set the saved catalogue target: "
            "'room-runtime' is at 2.8.4, expected 2.8.5; the catalogue no longer "
            "matches the scan; note that an uncommitted catalogue edit is not "
            "visible in the update workspace. Rescan required",
        )
    ]
    saved = load_scan_results("api").updates[0]
    assert (saved.update_status, saved.failed_phase) == (UpdateStatus.FAILED, "unit")
    assert repo.resolve_revision(revision=_BOOKMARK) == base


def test_given_no_test_phase_when_resolving_then_project_fails_before_effects(
    tmp_path: Path,
) -> None:
    state, project = seed_project(tmp_path, "api", make_scan_result(), test_unit=None)
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api", project, continue_=False, vcs=state.services(), emit=emit
    )

    assert outcome is Outcome.FAILED
    assert emit.events == [MissingTestConfig("api")]
    assert state.effects == []
