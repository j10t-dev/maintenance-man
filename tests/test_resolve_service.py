from collections.abc import Callable
from pathlib import Path

import pytest

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    BlockersStillFailing,
    Emit,
    FindingPassed,
    FindingsBlocked,
    FindingStepFailed,
    OperationFailed,
    Outcome,
    Promoted,
    PromotionFailed,
    ResolvePaused,
)
from maintenance_man.models.scan import ScanResult, SemverTier, UpdateStatus, Workflow
from maintenance_man.services import WorkflowError
from maintenance_man.services import resolve as resolve_service
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs import JjRepository, RevisionError
from tests.fakes import FakeFindingProcessor, RecordingEmit
from tests.support.findings import (
    make_scan_result,
    make_update,
    make_vuln,
)
from tests.support.projects import seed_gradle_project, seed_project
from tests.support.repository import (
    commit_descriptions,
    commit_file,
    fail_repository_method,
    operation_id,
    write_file,
)

_BOOKMARK = "mm/resolve-dependencies"
_UPDATE_BOOKMARK = "mm/update-dependencies"


def _resolve(
    project: ProjectConfig, *, continue_: bool = False, emit: Emit | None = None
) -> Outcome:
    return resolve_service.resolve_project(
        "api",
        project,
        continue_=continue_,
        emit=emit or RecordingEmit(),
    )


def _before_promotion(
    monkeypatch: pytest.MonkeyPatch, path: Path, action: Callable[[], None]
) -> None:
    promote = JjRepository.promote_bookmark_to_main

    def wrapper(repository: JjRepository, *, bookmark: str) -> None:
        if repository.path.resolve() == path.resolve():
            action()
        promote(repository, bookmark=bookmark)

    monkeypatch.setattr(JjRepository, "promote_bookmark_to_main", wrapper)


def _record_tip_at_promotion(
    monkeypatch: pytest.MonkeyPatch, repo: JjRepository
) -> list[str]:
    tips: list[str] = []
    _before_promotion(
        monkeypatch,
        repo.path,
        lambda: tips.append(repo.resolve_revision(revision=_BOOKMARK)),
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


def _stack_update_commits(repo: JjRepository, *packages: str) -> str:
    for package in packages:
        commit_file(
            repo, f"mm-fixture-{package}.txt", "1.0.1", f"fixture: update {package}"
        )
    repo.set_bookmark(bookmark=_UPDATE_BOOKMARK, revision="@-")
    return repo.resolve_revision(revision=_UPDATE_BOOKMARK)


def _commit_repair(repo: JjRepository) -> None:
    commit_file(repo, "dep.txt", "repaired\n", "repair")


class TestResolveCandidates:
    def test_given_interrupted_takeover_when_resolving_again_then_failure_is_retried(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo, project = seed_project(tmp_path, "api", _pending_stack_scan())
        update_tip = _stack_update_commits(repo, "pkg-a", "pkg-c")
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
            _resolve(project)
        processed: list[tuple[str, ...]] = []
        processor = FakeFindingProcessor({"pkg-b": (True, None)})

        def process(findings, project_config, **kwargs):
            processed.append(tuple(finding.pkg_name for finding in findings))
            return processor(findings, project_config, **kwargs)

        monkeypatch.setattr(resolve_service, "process_findings", process)

        outcome = _resolve(project)

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
        repo, project = seed_project(tmp_path, "api", _pending_stack_scan())
        if update_bookmark:
            _stack_update_commits(repo, "pkg-a", "pkg-c")
        if dirty:
            write_file(repo, "dep.txt", "dirty\n")
        saved_before = load_scan_results("api")
        before = operation_id(repo)

        with pytest.raises(WorkflowError) as raised:
            _resolve(project)

        assert str(raised.value) == message.format(path=project.path.resolve())
        assert load_scan_results("api") == saved_before
        assert operation_id(repo) == before

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
        repo, project = seed_project(tmp_path, "api", scan)
        _stack_update_commits(repo, "pkg-a", "pkg-c")
        saved_before = load_scan_results("api")
        before = operation_id(repo)

        with pytest.raises(WorkflowError) as raised:
            _resolve(project, continue_=continue_)

        assert str(raised.value) == (
            "Resolve cannot take over pending updates while resolve progress "
            "also exists for api. Run mm scan api to start again from main."
        )
        assert load_scan_results("api") == saved_before
        assert operation_id(repo) == before

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
        repo, project = seed_project(tmp_path, "api", scan)
        commit_file(repo, "mm-fixture-pkg-a.txt", "1.0.1", "fixture: update pkg-a")
        repo.set_bookmark(bookmark=_BOOKMARK, revision="@-")
        resolve_tip = repo.resolve_revision(revision=_BOOKMARK)
        monkeypatch.setattr(
            resolve_service, "process_findings", FakeFindingProcessor({})
        )
        emit = RecordingEmit()

        outcome = _resolve(project, emit=emit)

        assert outcome is Outcome.SUCCEEDED
        assert emit.events[-1] == Promoted()
        assert load_scan_results("api").findings == ()
        assert repo.same_revision(left="main", right=resolve_tip)
        assert not repo.bookmark_exists(bookmark=_BOOKMARK)


@pytest.mark.parametrize(
    ("scan", "expected_events"),
    [
        pytest.param(
            make_scan_result(
                vulns=[
                    make_vuln(
                        pkg_name="blocked",
                        vuln_id="CVE-blocked",
                        fixed_version="1.0.1",
                        blocked_reason="too young",
                    )
                ],
                updates=[],
            ),
            [FindingsBlocked((("blocked", "too young"),))],
            id="blocked-vulnerability",
        ),
        pytest.param(
            make_scan_result(
                vulns=[], updates=[make_update(blocked_reason="too young")]
            ),
            [FindingsBlocked((("pkg-a", "too young"),))],
            id="blocked-update",
        ),
    ],
)
def test_given_only_blocked_rows_when_resolving_then_repository_is_untouched(
    tmp_path: Path, scan: ScanResult, expected_events: list[FindingsBlocked]
) -> None:
    repo, project = seed_project(tmp_path, "api", scan)
    before = operation_id(repo)
    emit = RecordingEmit()

    outcome = _resolve(project, emit=emit)

    assert outcome is Outcome.SUCCEEDED
    assert emit.events == expected_events
    assert operation_id(repo) == before
    assert not repo.bookmark_exists(bookmark=_BOOKMARK)


@pytest.mark.parametrize(
    "ready_work",
    [
        pytest.param(False, id="fresh-start"),
        pytest.param(True, id="ready-work-and-new-candidate"),
    ],
)
def test_given_uncommitted_changes_when_resolve_moves_working_copy_then_it_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ready_work: bool
) -> None:
    updates = [make_update(SemverTier.MINOR)]
    if ready_work:
        updates.append(
            make_update(update_status=UpdateStatus.READY, flow=Workflow.RESOLVE)
        )
    repo, project = seed_project(
        tmp_path, "api", make_scan_result(vulns=[], updates=updates)
    )
    if ready_work:
        repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    write_file(repo, "dep.txt", "dirty\n")
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"pkg-b": (True, None)}),
    )
    saved_before = load_scan_results("api")
    before = operation_id(repo)

    with pytest.raises(WorkflowError) as raised:
        _resolve(project)

    assert str(raised.value) == (
        f"Resolve cannot start while {project.path} has uncommitted changes. "
        "Commit or discard them, then run mm resolve api again."
    )
    assert load_scan_results("api") == saved_before
    assert operation_id(repo) == before
    assert (repo.path / "dep.txt").read_text(encoding="utf-8") == "dirty\n"


def test_fresh_resolve_promotes_and_removes_completed_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result()
    repo, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (True, None), "pkg-a": (True, None)}),
    )
    resolve_tips = _record_tip_at_promotion(monkeypatch, repo)
    main_before = repo.resolve_revision(revision="main")
    emit = RecordingEmit()

    outcome = _resolve(project, emit=emit)

    assert outcome is Outcome.SUCCEEDED
    assert emit.events[-1] == Promoted()
    assert load_scan_results("api").findings == ()
    assert commit_descriptions(repo, f"{main_before}..main") == [
        "fixture: update some-pkg",
        "fixture: update pkg-a",
    ]
    assert repo.same_revision(left="main", right=resolve_tips[0])
    assert not repo.bookmark_exists(bookmark=_BOOKMARK)


def test_failed_candidate_pauses_without_promoting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, project = seed_project(tmp_path, "api", make_scan_result())
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (False, "unit"), "pkg-a": (True, None)}),
    )
    emit = RecordingEmit()

    outcome = _resolve(project, emit=emit)

    assert outcome is Outcome.FAILED
    assert emit.events[-1] == ResolvePaused("api")
    saved = load_scan_results("api")
    assert saved.vulnerabilities[0].update_status is UpdateStatus.FAILED
    assert saved.vulnerabilities[0].failed_phase == "unit"
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
    repo, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (True, None)}),
    )
    resolve_tips = _record_tip_at_promotion(monkeypatch, repo)
    emit = RecordingEmit()

    outcome = _resolve(project, emit=emit)

    assert outcome is Outcome.SUCCEEDED
    assert emit.of_type(FindingsBlocked) == [
        FindingsBlocked((("blocked", "No published fix"),))
    ]
    assert emit.events[-1] == Promoted()
    assert [
        (row.pkg_name, row.update_status) for row in load_scan_results("api").findings
    ] == [("blocked", None)]
    assert repo.same_revision(left="main", right=resolve_tips[0])


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
    _, project = seed_project(tmp_path, "api", scan)
    passing = FakeFindingProcessor({"some-pkg": (True, None)})

    def process_and_block_drifted(findings, *args, scan_result, emit, **kwargs):
        drifted = next(row for row in findings if row.pkg_name == "drifted")
        drifted.blocked_reason = "catalogue drifted"
        emit(FindingsBlocked((("drifted", "catalogue drifted"),)))
        ready = [row for row in findings if row is not drifted]
        return passing(ready, *args, scan_result=scan_result, emit=emit, **kwargs)

    monkeypatch.setattr(resolve_service, "process_findings", process_and_block_drifted)
    emit = RecordingEmit()

    outcome = _resolve(project, emit=emit)

    assert outcome is Outcome.SUCCEEDED
    assert emit.of_type(FindingsBlocked) == [
        FindingsBlocked((("drifted", "catalogue drifted"),))
    ]


def test_given_promotion_failure_when_resolve_completes_then_ready_and_bookmark_remain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, project = seed_project(tmp_path, "api", make_scan_result())
    monkeypatch.setattr(
        resolve_service,
        "process_findings",
        FakeFindingProcessor({"some-pkg": (True, None), "pkg-a": (True, None)}),
    )
    fail_repository_method(
        monkeypatch, project.path, "promote_bookmark_to_main", RevisionError("denied")
    )
    emit = RecordingEmit()

    outcome = _resolve(project, emit=emit)

    assert outcome is Outcome.FAILED
    assert emit.of_type(PromotionFailed) == [
        PromotionFailed(
            "api",
            "denied · rebase with jj rebase -b mm/resolve-dependencies -d main, "
            "then rerun",
        )
    ]
    assert [
        (row.pkg_name, row.flow, row.update_status)
        for row in load_scan_results("api").findings
    ] == [
        ("some-pkg", Workflow.RESOLVE, UpdateStatus.READY),
        ("pkg-a", Workflow.RESOLVE, UpdateStatus.READY),
    ]
    assert repo.bookmark_exists(bookmark=_BOOKMARK)


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
    repo, project = seed_project(tmp_path, "api", scan)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    _commit_repair(repo)
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: "unit"
    )
    emit = RecordingEmit()

    outcome = _resolve(project, continue_=True, emit=emit)

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
    repo, project = seed_project(tmp_path, "api", scan)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    _commit_repair(repo)
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
        assert repo.same_revision(left=_BOOKMARK, right="@-")
        processed.append(tuple(finding.pkg_name for finding in findings))
        return processor(findings, project_config, **kwargs)

    monkeypatch.setattr(resolve_service, "process_findings", process)
    resolve_tips = _record_tip_at_promotion(monkeypatch, repo)
    emit = RecordingEmit()

    outcome = _resolve(project, continue_=True, emit=emit)

    assert outcome is Outcome.SUCCEEDED
    assert FindingPassed("some-pkg", False, "1.0.0", "1.0.1") in emit.events
    assert processed == [("pkg-a",)]
    assert emit.events[-1] == Promoted()
    assert load_scan_results("api").findings == ()
    assert repo.same_revision(left="main", right=resolve_tips[0])
    assert not repo.bookmark_exists(bookmark=_BOOKMARK)


def test_missing_resume_bookmark_raises_workflow_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.READY, flow=Workflow.RESOLVE)],
    )
    _, project = seed_project(tmp_path, "api", scan)
    monkeypatch.setattr(resolve_service, "process_findings", FakeFindingProcessor({}))

    with pytest.raises(
        WorkflowError,
        match=(
            "resolve bookmark 'mm/resolve-dependencies' is missing but "
            "in-progress state exists"
        ),
    ):
        _resolve(project)


def test_continue_wraps_repository_inspection_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    repo, project = seed_project(tmp_path, "api", scan)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    fail_repository_method(
        monkeypatch, project.path, "has_changes", RevisionError("unknown")
    )

    with pytest.raises(WorkflowError) as raised:
        _resolve(project, continue_=True)

    assert str(raised.value) == "Cannot inspect resolve work: unknown"
    assert isinstance(raised.value.__cause__, RevisionError)


def test_continue_refuses_dirty_current_change(tmp_path: Path) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    repo, project = seed_project(tmp_path, "api", scan)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    write_file(repo, "dep.txt", "dirty\n")

    with pytest.raises(WorkflowError) as raised:
        _resolve(project, continue_=True)

    assert str(raised.value) == (
        "--continue requires an empty current jj change — commit or discard "
        "manual changes first"
    )


def test_prepare_failure_emits_then_raises_aborted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, project = seed_project(tmp_path, "api", make_scan_result())
    fail_repository_method(
        monkeypatch, project.path, "set_bookmark", RevisionError("cannot create")
    )
    emit = RecordingEmit()

    with pytest.raises(WorkflowError, match="aborted resolve for api"):
        _resolve(project, emit=emit)

    assert emit.events[-1] == OperationFailed("resolve setup", "api", "cannot create")


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
    repo, project = seed_project(tmp_path, "api", scan)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    base = repo.resolve_revision(revision="main")
    _commit_repair(repo)
    fail_repository_method(
        monkeypatch, project.path, "set_bookmark", RevisionError("cannot move")
    )
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: None
    )

    with pytest.raises(WorkflowError) as raised:
        _resolve(project, continue_=True)

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
    repo, project = seed_project(tmp_path, "api", scan)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    saved_before = load_scan_results("api")
    before = operation_id(repo)
    monkeypatch.setattr(
        resolve_service,
        "run_test_phases",
        lambda *_args, **_kwargs: pytest.fail("tests ran before the refusal"),
    )

    with pytest.raises(WorkflowError) as raised:
        _resolve(project, continue_=True)

    assert str(raised.value) == message
    assert load_scan_results("api") == saved_before
    assert operation_id(repo) == before


def test_given_ready_write_interrupted_when_continuing_again_then_same_repair_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.RESOLVE)],
    )
    repo, project = seed_project(tmp_path, "api", scan)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    scan.resolve_repair_base = repo.resolve_revision(revision="main")
    save_scan_results("api", scan)
    _commit_repair(repo)
    repair = repo.resolve_revision(revision="@-")
    repo.set_bookmark(bookmark=_BOOKMARK, revision="@-")
    monkeypatch.setattr(
        resolve_service, "run_test_phases", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(resolve_service, "process_findings", FakeFindingProcessor({}))
    bases_at_promotion: list[str | None] = []
    _before_promotion(
        monkeypatch,
        project.path,
        lambda: bases_at_promotion.append(load_scan_results("api").resolve_repair_base),
    )

    outcome = _resolve(project, continue_=True)

    assert outcome is Outcome.SUCCEEDED
    assert bases_at_promotion == [None]
    assert repo.resolve_revision(revision="main") == repair
    assert load_scan_results("api").findings == ()


def test_given_repair_missing_saved_target_when_continuing_then_bookmark_stays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = seed_gradle_project(tmp_path, "api")
    repo = JjRepository(project.path)
    scan = load_scan_results("api")
    row = scan.updates[0]
    row.update_status = UpdateStatus.FAILED
    row.failed_phase = "unit"
    row.flow = Workflow.RESOLVE
    save_scan_results("api", scan)
    repo.set_bookmark(bookmark=_BOOKMARK, revision="main")
    base = repo.resolve_revision(revision="main")
    commit_file(repo, "repair.txt", "unrelated\n", "repair")
    monkeypatch.setattr(
        resolve_service,
        "run_test_phases",
        lambda *_args, **_kwargs: pytest.fail("tests ran for a wrong repair"),
    )
    emit = RecordingEmit()

    outcome = _resolve(project, continue_=True, emit=emit)

    assert outcome is Outcome.FAILED
    assert emit.of_type(FindingStepFailed) == [
        FindingStepFailed(
            "prepare",
            "The committed repair does not set the saved catalogue target: "
            "'room-runtime' is at 2.8.4, expected 2.8.5; the catalogue no longer "
            "matches the scan; note that an uncommitted catalogue edit is not "
            "visible in the update workspace. Rescan required",
        )
    ]
    saved = load_scan_results("api").updates[0]
    assert (saved.update_status, saved.failed_phase) == (UpdateStatus.FAILED, "unit")
    assert repo.resolve_revision(revision=_BOOKMARK) == base
