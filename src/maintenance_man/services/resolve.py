from maintenance_man.gradle import validate_gradle_recovery
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    BlockersStillFailing,
    Emit,
    FindingPassed,
    FindingsBlocked,
    FindingStepFailed,
    OperationFailed,
    Outcome,
    ResolvePaused,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    Failed,
    GradleBlock,
    Ready,
    ScanResult,
    UpdateFinding,
    VulnFinding,
    Workflow,
)
from maintenance_man.services import WorkflowError, flows
from maintenance_man.storage import save_scan_results
from maintenance_man.updater import (
    FindingGroup,
    group_findings,
    process_findings,
    run_test_phases,
)
from maintenance_man.vcs import JjRepository, RevisionError
from maintenance_man.vcs_workflow import ensure_main_bookmark


def resolve_project(
    project_name: str, project: ProjectConfig, *, continue_: bool, emit: Emit
) -> Outcome:
    scan_result = flows.load_validated_scan(
        project_name, project, Workflow.RESOLVE, emit=emit
    )
    if scan_result is None:
        return Outcome.SUCCEEDED
    if continue_:
        if flows.report_missing_test_config(project_name, project, emit=emit):
            return Outcome.FAILED
        return _handle_continue(project_name, project, scan_result, emit=emit)
    _refuse_mixed_ownership(project_name, scan_result)
    if flows.has_owned(scan_result, Workflow.RESOLVE, Failed):
        msg = f"resolve already paused for {project_name} — rerun with --continue"
        raise WorkflowError(msg)
    takes_over = flows.has_owned(scan_result, Workflow.UPDATE, Ready, Failed)
    if not takes_over and not flows.has_work(scan_result, Workflow.RESOLVE):
        _report_blocked(scan_result.blocked_findings, emit=emit)
        return Outcome.SUCCEEDED
    if flows.report_missing_test_config(project_name, project, emit=emit):
        return Outcome.FAILED

    repo = JjRepository(project.path)
    try:
        ensure_main_bookmark(repo=repo)
    except RevisionError as exc:
        raise WorkflowError(str(exc)) from exc
    if takes_over:
        _take_over_update_progress(project_name, repo, scan_result)
    candidates = _select_resolve_candidates(scan_result)
    if not takes_over and not _prepare_resolve_bookmark(
        project_name, repo, scan_result, candidates, emit=emit
    ):
        msg = f"aborted resolve for {project_name}"
        raise WorkflowError(msg)
    return _run_candidates(project_name, project, scan_result, candidates, emit=emit)


def _select_resolve_candidates(scan_result: ScanResult) -> list[FindingGroup]:
    vulns = [
        finding
        for finding in scan_result.vulnerabilities
        if flows.is_candidate(finding, Workflow.RESOLVE)
    ]
    updates = [
        finding
        for finding in scan_result.updates
        if flows.is_candidate(finding, Workflow.RESOLVE)
    ]
    return group_findings([*vulns, *updates])


def _refuse_mixed_ownership(project_name: str, scan_result: ScanResult) -> None:
    if flows.has_owned(scan_result, Workflow.UPDATE, Ready, Failed) and flows.has_owned(
        scan_result, Workflow.RESOLVE, Ready, Failed
    ):
        msg = (
            "Resolve cannot take over pending updates while resolve progress also "
            f"exists for {project_name}. Run mm scan {project_name} to start again "
            "from main."
        )
        raise WorkflowError(msg)


def _take_over_update_progress(
    project_name: str, repo: JjRepository, scan_result: ScanResult
) -> None:
    """Move the accepted update tip and every update-owned row to resolve.

    Errors before the scan is saved leave the bookmark and rows untouched. After it,
    every row is resolve-owned (accepted Ready or pending), so the next run
    continues from the resolve bookmark; a failed deletion of the update bookmark
    is reported as WorkflowError.
    """
    update_bookmark = WORKFLOW_BOOKMARKS[Workflow.UPDATE]
    resolve_bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    try:
        _require_clean_working_copy(
            project_name, repo, "Resolve cannot take over pending updates"
        )
        if not repo.bookmark_exists(bookmark=update_bookmark):
            msg = (
                "Resolve cannot take over pending updates: bookmark "
                f"{update_bookmark} is missing. Run mm scan {project_name} "
                "to start again from main."
            )
            raise WorkflowError(msg)
        repo.set_bookmark(
            bookmark=resolve_bookmark, revision=update_bookmark, allow_backwards=True
        )
        repo.new_change(revision=resolve_bookmark)
        for finding in scan_result.findings:
            match finding.state:
                case Ready(flow=Workflow.UPDATE):
                    finding.state = Ready(flow=Workflow.RESOLVE)
                case Failed(flow=Workflow.UPDATE):
                    finding.state = None
        save_scan_results(project_name, scan_result)
        repo.delete_bookmark(bookmark=update_bookmark)
    except RevisionError as exc:
        msg = f"Cannot take over pending updates for {project_name}: {exc}"
        raise WorkflowError(msg) from exc


def _require_clean_working_copy(
    project_name: str, repo: JjRepository, action: str
) -> None:
    """Refuse to move the source working copy while it holds uncommitted changes."""
    if repo.has_changes():
        msg = (
            f"{action} while {repo.path} has uncommitted changes. Commit or discard "
            f"them, then run mm resolve {project_name} again."
        )
        raise WorkflowError(msg)


def _prepare_resolve_bookmark(
    project_name: str,
    repo: JjRepository,
    scan_result: ScanResult,
    candidates: list[FindingGroup],
    *,
    emit: Emit,
) -> bool:
    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    try:
        if flows.has_owned(scan_result, Workflow.RESOLVE, Ready):
            if not repo.bookmark_exists(bookmark=bookmark):
                msg = (
                    f"resolve bookmark '{bookmark}' is missing but in-progress "
                    "state exists — rescan or recover the bookmark manually"
                )
                raise WorkflowError(msg)
            if candidates:
                _require_clean_working_copy(project_name, repo, "Resolve cannot start")
                repo.new_change(revision=bookmark)
            return True
        _require_clean_working_copy(project_name, repo, "Resolve cannot start")
        repo.set_bookmark(bookmark=bookmark, revision="main", allow_backwards=True)
        repo.new_change(revision=bookmark)
    except RevisionError as exc:
        emit(OperationFailed("resolve setup", project_name, str(exc)))
        return False
    return True


def _run_candidates(
    project_name: str,
    project: ProjectConfig,
    scan_result: ScanResult,
    candidates: list[FindingGroup],
    *,
    emit: Emit,
) -> Outcome:
    blocked_before_run = scan_result.blocked_findings
    results = process_findings(
        candidates,
        project,
        flow=Workflow.RESOLVE,
        scan_result=scan_result,
        emit=emit,
    )
    if any(not result.passed for result in results) or flows.has_owned(
        scan_result, Workflow.RESOLVE, Failed
    ):
        emit(ResolvePaused(project_name))
        return Outcome.FAILED
    _report_blocked(blocked_before_run, emit=emit)
    return flows.finalise_local_changes(
        project.path, scan_result, project_name, Workflow.RESOLVE, emit=emit
    )


def _report_blocked(findings: list[VulnFinding | UpdateFinding], *, emit: Emit) -> None:
    reasons = tuple(
        (finding.pkg_name, finding.state.reason)
        for finding in findings
        if isinstance(finding.state, GradleBlock)
    )
    if reasons:
        emit(FindingsBlocked(reasons))


def _handle_continue(
    project_name: str,
    project: ProjectConfig,
    scan_result: ScanResult,
    *,
    emit: Emit,
) -> Outcome:
    _refuse_mixed_ownership(project_name, scan_result)
    if flows.has_owned(scan_result, Workflow.UPDATE, Ready, Failed):
        msg = (
            f"Pending update work exists for {project_name}. "
            f"Run mm resolve {project_name} without --continue to take it over first."
        )
        raise WorkflowError(msg)
    failed = group_findings(
        [
            finding
            for finding in scan_result.findings
            if flows.is_owned(finding, Workflow.RESOLVE, Failed)
        ]
    )
    if not failed:
        msg = (
            f"No paused resolve failure is saved for {project_name}. Run mm resolve "
            f"{project_name} to start resolving."
        )
        raise WorkflowError(msg)
    repo = JjRepository(project.path)
    repair_base = _check_resumable(
        project_name,
        repo,
        WORKFLOW_BOOKMARKS[Workflow.RESOLVE],
        scan_result.resolve_repair_base,
    )
    if not _retest_blockers(
        project_name,
        project,
        scan_result,
        failed,
        repair_base=repair_base,
        repo=repo,
        emit=emit,
    ):
        return Outcome.FAILED
    return _run_candidates(
        project_name,
        project,
        scan_result,
        _select_resolve_candidates(scan_result),
        emit=emit,
    )


def _check_resumable(
    project_name: str, repo: JjRepository, bookmark: str, saved: str | None
) -> str:
    try:
        repair_base = saved or repo.resolve_revision(revision=bookmark)
        if not repo.is_ancestor(ancestor=bookmark, descendant="@"):
            msg = f"--continue requires current jj change to descend from {bookmark}"
            raise WorkflowError(msg)
        if repo.has_changes():
            msg = (
                "--continue requires an empty current jj change — commit or discard "
                "manual changes first"
            )
            raise WorkflowError(msg)
        if repo.same_revision(left="@-", right=repair_base):
            msg = (
                f"--continue needs a committed repair on top of {bookmark}. Commit "
                f"the repair with jj commit, then run mm resolve {project_name} "
                "--continue again."
            )
            raise WorkflowError(msg)
    except RevisionError as exc:
        msg = f"Cannot inspect resolve work: {exc}"
        raise WorkflowError(msg) from exc
    return repair_base


def _retest_blockers(
    project_name: str,
    project: ProjectConfig,
    scan_result: ScanResult,
    failed: list[FindingGroup],
    *,
    repair_base: str,
    repo: JjRepository,
    emit: Emit,
) -> bool:
    if not _repair_sets_saved_targets(project, failed, emit=emit):
        return False
    failed_phase = run_test_phases(project, project.path, emit=emit)
    if failed_phase is not None:
        for blocker in failed:
            blocker.record(Failed(flow=Workflow.RESOLVE, phase=failed_phase))
        save_scan_results(project_name, scan_result)
        emit(
            BlockersStillFailing(
                failed_phase, tuple(blocker.pkg_name for blocker in failed)
            )
        )
        return False

    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    scan_result.resolve_repair_base = repair_base
    save_scan_results(project_name, scan_result)
    try:
        repo.set_bookmark(bookmark=bookmark, revision="@-")
    except RevisionError as exc:
        msg = f"could not move {bookmark} to the committed manual fix"
        raise WorkflowError(msg) from exc
    for blocker in failed:
        blocker.record(Ready(flow=Workflow.RESOLVE))
    scan_result.resolve_repair_base = None
    save_scan_results(project_name, scan_result)
    for blocker in failed:
        emit(
            FindingPassed(
                blocker.pkg_name,
                False,
                blocker.installed_version,
                blocker.target_version,
            )
        )
    return True


def _repair_sets_saved_targets(
    project: ProjectConfig, failed: list[FindingGroup], *, emit: Emit
) -> bool:
    for blocker in failed:
        if blocker.gradle_target is None:
            continue
        block = validate_gradle_recovery(project, blocker.gradle_target)
        if block is not None:
            emit(
                FindingStepFailed(
                    "prepare",
                    "The committed repair does not set the saved catalogue "
                    f"target: {block.reason}",
                )
            )
            return False
    return True
