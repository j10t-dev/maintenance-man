from pathlib import Path

from maintenance_man import gradle_workflow
from maintenance_man.github import CodeHostError
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    BlockersStillFailing,
    Emit,
    FindingPassed,
    FindingsBlocked,
    Operation,
    OperationFailed,
    Outcome,
    PullRequestOutput,
    ResolvePaused,
    SubmissionBlocked,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    ScanResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.services import WorkflowError, flows
from maintenance_man.storage import save_scan_results
from maintenance_man.updater import (
    Finding,
    consolidate_vulns,
    process_findings,
    remove_completed_findings,
    run_test_phases,
    sort_updates_by_risk,
)
from maintenance_man.vcs import Repository, RevisionError
from maintenance_man.vcs_workflow import (
    VcsServices,
    ensure_main_bookmark,
    prune_stale_bookmarks,
    push_bookmark_and_create_pr,
)


def _ordered_resolve_candidates(scan_result: ScanResult) -> list[Finding]:
    candidate_vulns = [
        finding
        for finding in scan_result.vulnerabilities
        if finding.actionable
        and (
            (finding.flow is None and finding.update_status is None)
            or (
                finding.flow is Workflow.RESOLVE
                and finding.update_status is UpdateStatus.FAILED
            )
            or flows.is_resolve_claimable_failure(finding, Workflow.RESOLVE)
        )
    ]
    candidate_updates = [
        finding
        for finding in scan_result.updates
        if (finding.flow is None and finding.update_status is None)
        or (
            finding.flow is Workflow.RESOLVE
            and finding.update_status is UpdateStatus.FAILED
        )
        or flows.is_resolve_claimable_failure(finding, Workflow.RESOLVE)
    ]
    return [
        *consolidate_vulns(candidate_vulns),
        *sort_updates_by_risk(candidate_updates),
    ]


def _ordered_failed_findings(scan_result: ScanResult) -> list[Finding]:
    failed_vulns = [
        finding
        for finding in scan_result.vulnerabilities
        if finding.update_status is UpdateStatus.FAILED
        and finding.flow is Workflow.RESOLVE
    ]
    failed_updates = [
        finding
        for finding in scan_result.updates
        if finding.update_status is UpdateStatus.FAILED
        and finding.flow is Workflow.RESOLVE
    ]
    return [
        *consolidate_vulns(failed_vulns),
        *sort_updates_by_risk(failed_updates),
    ]


def _ordered_ready_findings(
    scan_result: ScanResult, *, flow: Workflow
) -> list[Finding]:
    ready_vulns = [
        finding
        for finding in scan_result.vulnerabilities
        if finding.update_status is UpdateStatus.READY and finding.flow is flow
    ]
    ready_updates = [
        finding
        for finding in scan_result.updates
        if finding.update_status is UpdateStatus.READY and finding.flow is flow
    ]
    return [
        *consolidate_vulns(ready_vulns),
        *sort_updates_by_risk(ready_updates),
    ]


def _has_ready_resolve_progress(scan_result: ScanResult) -> bool:
    return any(
        finding.update_status is UpdateStatus.READY and finding.flow is Workflow.RESOLVE
        for finding in scan_result.findings
    )


def _blocked_rows(scan_result: ScanResult) -> tuple[tuple[str, str], ...]:
    return tuple(
        (finding.pkg_name, finding.blocked_reason or "")
        for finding in scan_result.blocked_findings
    )


def _prepare_resolve_bookmark(
    name: str,
    project_path: Path,
    scan_result: ScanResult,
    candidates: list[Finding],
    *,
    vcs: VcsServices,
    emit: Emit,
) -> bool:
    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    repo = vcs.repository(project_path)
    try:
        if _has_ready_resolve_progress(scan_result):
            if not repo.bookmark_exists(bookmark=bookmark):
                msg = (
                    f"resolve bookmark '{bookmark}' is missing but in-progress "
                    "state exists — rescan or recover the bookmark manually"
                )
                raise WorkflowError(msg)
            if candidates:
                repo.new_change(revision=bookmark)
            return True

        if repo.bookmark_exists(bookmark=bookmark):
            repo.delete_bookmark(bookmark=bookmark)
        repo.create_bookmark(bookmark=bookmark, revision="main")
        repo.new_change(revision=bookmark)
    except RevisionError as exc:
        emit(OperationFailed(Operation.RESOLVE_SETUP, name, str(exc)))
        return False
    return True


def _submit(
    name: str,
    project_path: Path,
    scan_result: ScanResult,
    ready_findings: list[Finding],
    *,
    vcs: VcsServices,
    emit: Emit,
) -> Outcome:
    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    if scan_result.blocked_findings:
        emit(FindingsBlocked(_blocked_rows(scan_result)))
        emit(SubmissionBlocked(name))
        save_scan_results(name, scan_result)
        return Outcome.FAILED

    for finding in ready_findings:
        finding.failed_phase = None

    try:
        output = push_bookmark_and_create_pr(
            repo=vcs.repository(project_path),
            host=vcs.code_host(project_path),
            bookmark=bookmark,
        )
    except (RevisionError, CodeHostError) as exc:
        save_scan_results(name, scan_result)
        emit(OperationFailed(Operation.SUBMIT, name, str(exc)))
        return Outcome.FAILED
    if output:
        emit(PullRequestOutput(output))

    for finding in ready_findings:
        finding.update_status = UpdateStatus.COMPLETED
        finding.failed_phase = None
        finding.flow = None
    remove_completed_findings(scan_result)
    save_scan_results(name, scan_result)
    return Outcome.SUCCEEDED


def _run_candidates(
    name: str,
    project: ProjectConfig,
    scan_result: ScanResult,
    candidates: list[Finding],
    *,
    vcs: VcsServices,
    emit: Emit,
) -> Outcome:
    results = process_findings(
        candidates,
        project,
        flow=Workflow.RESOLVE,
        scan_result=scan_result,
        project_name=name,
        on_failure="stop",
        vcs=vcs,
        emit=emit,
    )
    if any(not result.passed for result in results) or _ordered_failed_findings(
        scan_result
    ):
        emit(ResolvePaused(name))
        return Outcome.FAILED

    ready = _ordered_ready_findings(scan_result, flow=Workflow.RESOLVE)
    if scan_result.blocked_findings:
        emit(FindingsBlocked(_blocked_rows(scan_result)))
        save_scan_results(name, scan_result)
        return Outcome.FAILED
    if not ready:
        return Outcome.SUCCEEDED
    return _submit(name, project.path, scan_result, ready, vcs=vcs, emit=emit)


def _check_resumable(repo: Repository, bookmark: str) -> None:
    try:
        if not repo.is_ancestor(ancestor=bookmark, descendant="@"):
            msg = f"--continue requires current jj change to descend from {bookmark}"
            raise WorkflowError(msg)
        has_changes = repo.has_changes()
    except RevisionError as exc:
        msg = f"Cannot inspect resolve work: {exc}"
        raise WorkflowError(msg) from exc
    if has_changes:
        msg = (
            "--continue requires an empty current jj change — commit or discard "
            "manual changes first"
        )
        raise WorkflowError(msg)


def _retest_blockers(
    name: str,
    project: ProjectConfig,
    scan_result: ScanResult,
    failed: list[Finding],
    *,
    repo: Repository,
    emit: Emit,
) -> bool:
    passed, failed_phase = run_test_phases(project, project.path, emit=emit)
    for blocker in failed:
        blocker.flow = Workflow.RESOLVE
        if not passed:
            blocker.update_status = UpdateStatus.FAILED
            blocker.failed_phase = failed_phase
    if not passed:
        save_scan_results(name, scan_result)
        emit(
            BlockersStillFailing(
                failed_phase or "", tuple(blocker.pkg_name for blocker in failed)
            )
        )
        return False

    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    try:
        repo.set_bookmark(bookmark=bookmark, revision="@-")
    except RevisionError as exc:
        save_scan_results(name, scan_result)
        msg = f"could not move {bookmark} to the committed manual fix"
        raise WorkflowError(msg) from exc
    for blocker in failed:
        blocker.update_status = UpdateStatus.READY
        blocker.failed_phase = None
    save_scan_results(name, scan_result)
    for blocker in failed:
        emit(FindingPassed(blocker.pkg_name, False))
    return True


def _handle_continue(
    name: str,
    project: ProjectConfig,
    scan_result: ScanResult,
    *,
    vcs: VcsServices,
    emit: Emit,
) -> Outcome:
    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    repo = vcs.repository(project.path)
    _check_resumable(repo, bookmark)
    failed = _ordered_failed_findings(scan_result)
    if failed and not _retest_blockers(
        name, project, scan_result, failed, repo=repo, emit=emit
    ):
        return Outcome.FAILED
    return _run_candidates(
        name,
        project,
        scan_result,
        _ordered_resolve_candidates(scan_result),
        vcs=vcs,
        emit=emit,
    )


def resolve_project(
    name: str,
    project: ProjectConfig,
    *,
    minimum_age_days: int,
    continue_: bool,
    vcs: VcsServices,
    emit: Emit,
) -> Outcome:
    if project.package_manager == "gradle":
        return gradle_workflow.run_gradle_flow(
            name,
            project,
            Workflow.RESOLVE,
            minimum_age_days=minimum_age_days,
            continue_=continue_,
            choose=None,
            vcs=vcs,
            emit=emit,
        )

    scan_result = flows.load_validated_scan(name, project, Workflow.RESOLVE, emit=emit)
    if scan_result is None:
        return Outcome.SUCCEEDED
    if continue_:
        return _handle_continue(name, project, scan_result, vcs=vcs, emit=emit)

    candidates = _ordered_resolve_candidates(scan_result)
    repo = vcs.repository(project.path)
    try:
        prune_stale_bookmarks(repo=repo, host=vcs.code_host(project.path))
        ensure_main_bookmark(repo=repo)
    except (RevisionError, CodeHostError) as exc:
        raise WorkflowError(str(exc)) from exc
    if _ordered_failed_findings(scan_result):
        msg = f"resolve already paused for {name} — rerun with --continue"
        raise WorkflowError(msg)
    if not _prepare_resolve_bookmark(
        name,
        project.path,
        scan_result,
        candidates,
        vcs=vcs,
        emit=emit,
    ):
        msg = f"aborted resolve for {name}"
        raise WorkflowError(msg)
    return _run_candidates(name, project, scan_result, candidates, vcs=vcs, emit=emit)
