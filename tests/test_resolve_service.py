from pathlib import Path

import pytest

from maintenance_man.models.events import (
    BlockersStillFailing,
    FindingPassed,
    FindingsBlocked,
    MissingTestConfig,
    Operation,
    OperationFailed,
    Outcome,
    Promoted,
    ResolvePaused,
)
from maintenance_man.models.scan import UpdateStatus, Workflow
from maintenance_man.services import WorkflowError
from maintenance_man.services import resolve as resolve_service
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs import RevisionError
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeFindingProcessor, RecordingEmit
from tests.support.findings import make_scan_result, make_update, make_vuln
from tests.support.projects import seed_project

_BOOKMARK = "mm/resolve-dependencies"


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


class TestResolveCandidates:
    def test_given_other_flow_when_resolve_runs_then_scan_is_rejected_unchanged(
        self, tmp_path: Path
    ) -> None:
        scan = make_scan_result(
            vulns=[
                make_vuln(pkg_name="pkg-a", vuln_id="CVE-1"),
                make_vuln(
                    pkg_name="pkg-b",
                    vuln_id="CVE-2",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                ),
            ],
            updates=[
                make_update(
                    pkg_name="pkg-c",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.UPDATE,
                    failed_phase="apply",
                ),
                make_update(
                    pkg_name="pkg-d",
                    update_status=UpdateStatus.READY,
                    flow=Workflow.RESOLVE,
                ),
                make_update(pkg_name="pkg-e"),
            ],
        )

        state, project = seed_project(tmp_path, "api", scan)
        saved_before = load_scan_results("api")

        with pytest.raises(resolve_service.flows.FlowConflictError):
            resolve_service.resolve_project(
                "api",
                project,
                continue_=False,
                vcs=state.services(),
                emit=RecordingEmit(),
            )

        assert load_scan_results("api") == saved_before

    def test_given_claimable_failure_when_resolve_runs_then_it_is_completed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scan = make_scan_result(
            vulns=[],
            updates=[
                make_update(
                    pkg_name="pkg-a",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.UPDATE,
                    failed_phase="unit",
                )
            ],
        )

        state, project = seed_project(tmp_path, "api", scan)
        processed: list[tuple[str, ...]] = []
        processor = FakeFindingProcessor({"pkg-a": (True, None)})

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

        assert outcome is Outcome.SUCCEEDED
        assert processed == [("pkg-a",)]
        assert load_scan_results("api").findings == ()

    def test_given_mixed_failures_when_continuing_then_only_resolve_failure_is_retested(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scan = make_scan_result(
            vulns=[
                make_vuln(
                    pkg_name="some-pkg",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                    failed_phase="apply",
                )
            ],
            updates=[
                make_update(
                    pkg_name="pkg-a",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.UPDATE,
                    failed_phase="unit",
                ),
            ],
        )
        state, project = seed_project(tmp_path, "api", scan)
        state.services().repository(project.path).set_bookmark(
            bookmark=_BOOKMARK, revision="main"
        )
        monkeypatch.setattr(
            resolve_service, "run_test_phases", lambda *_args, **_kwargs: None
        )
        processed: list[tuple[str, ...]] = []
        processor = FakeFindingProcessor({"pkg-a": (True, None)})

        def process(findings, project_config, **kwargs):
            processed.append(tuple(finding.pkg_name for finding in findings))
            return processor(findings, project_config, **kwargs)

        monkeypatch.setattr(resolve_service, "process_findings", process)
        emit = RecordingEmit()

        outcome = resolve_service.resolve_project(
            "api",
            project,
            continue_=True,
            vcs=state.services(),
            emit=emit,
        )

        assert outcome is Outcome.SUCCEEDED
        assert emit.of_type(FindingPassed) == [
            FindingPassed("some-pkg", False, "1.0.0", "1.0.1")
        ]
        assert processed == [("pkg-a",)]
        assert load_scan_results("api").findings == ()

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


def test_blocked_finding_is_saved_and_reported(
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
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.FAILED
    assert emit.events[-1:] == [FindingsBlocked((("blocked", "No published fix"),))]
    assert [finding.pkg_name for finding in load_scan_results("api").findings] == [
        "some-pkg",
        "blocked",
    ]
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


def test_bookmark_move_failure_saves_before_refusal(
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
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    state.fail(
        "set_bookmark",
        error=RevisionError("cannot move"),
        path=project.path,
    )
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: None
    )
    saves: list[tuple[UpdateStatus | None, str | None, Workflow | None]] = []

    def save_after_move_attempt(name, result):
        assert state.attempts[-1].method == "set_bookmark"
        blocker = result.vulnerabilities[0]
        saves.append((blocker.update_status, blocker.failed_phase, blocker.flow))
        save_scan_results(name, result)

    monkeypatch.setattr(resolve_service, "save_scan_results", save_after_move_attempt)

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
    assert saves == [(UpdateStatus.FAILED, "unit", Workflow.RESOLVE)]
    saved = load_scan_results("api").vulnerabilities[0]
    assert saved.update_status is UpdateStatus.FAILED
    assert saved.failed_phase == "unit"


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
