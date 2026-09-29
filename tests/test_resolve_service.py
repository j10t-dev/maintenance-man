from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.github import CodeHostError
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    BlockersStillFailing,
    FindingPassed,
    FindingsBlocked,
    Operation,
    OperationFailed,
    Outcome,
    PullRequestOutput,
    ResolvePaused,
)
from maintenance_man.models.scan import UpdateStatus, Workflow
from maintenance_man.services import WorkflowError
from maintenance_man.services import resolve as resolve_service
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs import RevisionError
from tests.conftest import make_project, make_scan_result, make_update, make_vuln
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeFindingProcessor, RecordingEmit

_BOOKMARK = "mm/resolve-dependencies"


def _seed_project(
    tmp_path: Path,
    scan,
    *,
    name: str = "api",
) -> tuple[FakeJjState, ProjectConfig]:
    project = make_project(tmp_path / name, test_unit="pytest")
    state = FakeJjState()
    state.seed_repository(project.path, files={"dep.txt": "version=1\n"})
    state.register_files(
        project.path,
        "mm-fixture-some-pkg.txt",
        "mm-fixture-pkg-a.txt",
    )
    scan.project = name
    save_scan_results(name, scan)
    return state, project


class TestResolveCandidates:
    def test_candidates_exclude_other_flow_progress(self) -> None:
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

        candidates = resolve_service._ordered_resolve_candidates(scan)

        assert {finding.pkg_name for finding in candidates} == {
            "pkg-a",
            "pkg-b",
            "pkg-e",
        }

    def test_candidates_include_update_owned_test_failures(self) -> None:
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

        assert [
            finding.pkg_name
            for finding in resolve_service._ordered_resolve_candidates(scan)
        ] == ["pkg-a"]

    def test_failed_findings_only_include_resolve_failures(self) -> None:
        scan = make_scan_result(
            vulns=[],
            updates=[
                make_update(
                    pkg_name="keep",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                ),
                make_update(
                    pkg_name="skip-flow",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.UPDATE,
                ),
                make_update(
                    pkg_name="skip-status",
                    update_status=UpdateStatus.READY,
                    flow=Workflow.RESOLVE,
                ),
                make_update(pkg_name="skip-none"),
            ],
        )

        assert [
            finding.pkg_name
            for finding in resolve_service._ordered_failed_findings(scan)
        ] == ["keep"]

    def test_ready_findings_only_include_requested_flow(self) -> None:
        scan = make_scan_result(
            vulns=[],
            updates=[
                make_update(
                    pkg_name="keep",
                    update_status=UpdateStatus.READY,
                    flow=Workflow.RESOLVE,
                ),
                make_update(
                    pkg_name="skip-update-ready",
                    update_status=UpdateStatus.READY,
                    flow=Workflow.UPDATE,
                ),
                make_update(
                    pkg_name="skip-failed",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                ),
            ],
        )

        assert [
            finding.pkg_name
            for finding in resolve_service._ordered_ready_findings(
                scan, flow=Workflow.RESOLVE
            )
        ] == ["keep"]


def test_fresh_resolve_submits_and_removes_completed_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result()
    state, project = _seed_project(tmp_path, scan)
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (True, None), "pkg-a": (True, None)}),
    )
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        minimum_age_days=7,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.SUCCEEDED
    assert emit.events[-1] == PullRequestOutput("PR #1")
    assert load_scan_results("api").findings == ()
    created = [call for call in state.effects if call.method == "create_bookmark"]
    assert len(created) == 1
    assert dict(created[0].arguments) == {
        "bookmark": _BOOKMARK,
        "revision": "main",
    }
    host = state.code_host(project.path)
    assert sum(call.method == "create_pr" for call in host.attempts) == 1


def test_failed_candidate_pauses_without_submitting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, project = _seed_project(tmp_path, make_scan_result())
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (False, "unit"), "pkg-a": (True, None)}),
    )
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        minimum_age_days=7,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.FAILED
    assert emit.events[-1] == ResolvePaused("api")
    saved = load_scan_results("api")
    assert saved.vulnerabilities[0].update_status is UpdateStatus.FAILED
    assert saved.vulnerabilities[0].failed_phase == "unit"
    assert not any(
        call.method == "create_pr" for call in state.code_host(project.path).attempts
    )


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
    state, project = _seed_project(tmp_path, scan)
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (True, None)}),
    )
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        minimum_age_days=7,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.FAILED
    assert emit.events[-1] == FindingsBlocked((("blocked", "No published fix"),))
    assert [finding.pkg_name for finding in load_scan_results("api").findings] == [
        "some-pkg",
        "blocked",
    ]


def test_host_failure_after_push_emits_submit_failure_and_keeps_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, project = _seed_project(tmp_path, make_scan_result())
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (True, None), "pkg-a": (True, None)}),
    )
    state.code_host(project.path).fail("create_pr", error=CodeHostError("denied"))
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        minimum_age_days=7,
        continue_=False,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.FAILED
    assert emit.events[-1] == OperationFailed(Operation.SUBMIT, "api", "denied")
    assert all(
        finding.update_status is UpdateStatus.READY
        for finding in load_scan_results("api").findings
    )
    assert state.remote_bookmark_targets(project.path, bookmark=_BOOKMARK)


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
    state, project = _seed_project(tmp_path, scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: (False, "unit")
    )
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        minimum_age_days=7,
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


def test_continue_passing_retest_marks_blocker_passed_then_submits(
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
    state, project = _seed_project(tmp_path, scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: (True, None)
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
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "api",
        project,
        minimum_age_days=7,
        continue_=True,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.SUCCEEDED
    assert FindingPassed("some-pkg", False) in emit.events
    assert processed == [("pkg-a",)]
    assert emit.events[-1] == PullRequestOutput("PR #1")
    assert load_scan_results("api").findings == ()


def test_missing_resume_bookmark_raises_workflow_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.READY, flow=Workflow.RESOLVE)],
    )
    state, project = _seed_project(tmp_path, scan)
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
            minimum_age_days=7,
            continue_=False,
            vcs=state.services(),
            emit=RecordingEmit(),
        )


def test_paused_resolve_requires_continue(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    state, project = _seed_project(tmp_path, scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )

    with pytest.raises(WorkflowError) as raised:
        resolve_service.resolve_project(
            "api",
            project,
            minimum_age_days=7,
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
    state, project = _seed_project(tmp_path, scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    state.fail("has_changes", error=RevisionError("unknown"), path=project.path)

    with pytest.raises(WorkflowError) as raised:
        resolve_service.resolve_project(
            "api",
            project,
            minimum_age_days=7,
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
    state, project = _seed_project(tmp_path, scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    (project.path / "dep.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(WorkflowError) as raised:
        resolve_service.resolve_project(
            "api",
            project,
            minimum_age_days=7,
            continue_=True,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

    assert str(raised.value) == (
        "--continue requires an empty current jj change — commit or discard "
        "manual changes first"
    )


def test_prepare_failure_emits_then_raises_aborted(tmp_path: Path) -> None:
    state, project = _seed_project(tmp_path, make_scan_result())
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
            minimum_age_days=7,
            continue_=False,
            vcs=state.services(),
            emit=emit,
        )

    assert emit.events[-1] == OperationFailed(
        Operation.RESOLVE_SETUP, "api", "cannot create"
    )


def test_pruning_failure_is_chained_as_workflow_error(tmp_path: Path) -> None:
    state, project = _seed_project(tmp_path, make_scan_result())
    state.fail("fetch", error=RevisionError("cannot fetch"), path=project.path)

    with pytest.raises(WorkflowError) as raised:
        resolve_service.resolve_project(
            "api",
            project,
            minimum_age_days=7,
            continue_=False,
            vcs=state.services(),
            emit=RecordingEmit(),
        )

    assert str(raised.value) == "cannot fetch"
    assert isinstance(raised.value.__cause__, RevisionError)


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
    state, project = _seed_project(tmp_path, scan)
    state.services().repository(project.path).set_bookmark(
        bookmark=_BOOKMARK, revision="main"
    )
    state.fail(
        "set_bookmark",
        error=RevisionError("cannot move"),
        path=project.path,
    )
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: (True, None)
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
            minimum_age_days=7,
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


@pytest.mark.parametrize("continue_", [False, True])
def test_gradle_project_routes_to_gradle_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, continue_: bool
) -> None:
    project = make_project(tmp_path, package_manager="gradle")
    state = FakeJjState()
    state.seed_repository(project.path, files={"settings.gradle": ""})
    run = MagicMock(return_value=Outcome.FAILED)
    monkeypatch.setattr(resolve_service.gradle_workflow, "run_gradle_flow", run)
    emit = RecordingEmit()

    outcome = resolve_service.resolve_project(
        "android",
        project,
        minimum_age_days=9,
        continue_=continue_,
        vcs=state.services(),
        emit=emit,
    )

    assert outcome is Outcome.FAILED
    run.assert_called_once_with(
        "android",
        project,
        Workflow.RESOLVE,
        minimum_age_days=9,
        continue_=continue_,
        choose=None,
        vcs=state.services(),
        emit=emit,
    )
