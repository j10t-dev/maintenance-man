from pathlib import Path

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    Emit,
    MissingTestConfig,
    Operation,
    OperationFailed,
    ProjectSkipped,
    Promoted,
    SkipReason,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    ScanResult,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    Workflow,
)
from maintenance_man.services import WorkflowError
from maintenance_man.storage import (
    NoScanResultsError,
    load_scan_results,
    save_scan_results,
)
from maintenance_man.updater import (
    Finding,
    consolidate_vulns,
    remove_completed_findings,
    sort_updates_by_risk,
)
from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import VcsServices, refresh_working_copy_from_main


class FlowConflictError(WorkflowError):
    """Scan-result state belongs to another workflow."""


def load_validated_scan(
    project: str,
    project_config: ProjectConfig,
    workflow: Workflow,
    *,
    emit: Emit,
) -> ScanResult | None:
    try:
        scan_result = load_scan_results(project)
    except NoScanResultsError:
        emit(ProjectSkipped(project, SkipReason.NO_SCAN_RESULTS))
        return None

    _assert_supported_in_progress_state(scan_result, project)
    _assert_no_conflicting_flow(scan_result, workflow, project)

    if not scan_result.has_actionable_vulns and not scan_result.updates:
        emit(ProjectSkipped(project, SkipReason.NOTHING_TO_DO, workflow.value))
        return None
    if not project_config.test_phases:
        emit(MissingTestConfig(project))
    return scan_result


def ordered_findings(
    vulns: list[VulnFinding], updates: list[UpdateFinding]
) -> list[Finding]:
    """Return consolidated vulns then risk-ordered updates, retaining source refs."""
    return [*consolidate_vulns(vulns), *sort_updates_by_risk(updates)]


def complete_ready_findings(
    scan_result: ScanResult, name: str, *, flow: Workflow
) -> None:
    """Complete and remove a flow's ready findings, then persist the mutated scan."""
    for finding in scan_result.findings:
        if finding.update_status is UpdateStatus.READY and finding.flow is flow:
            finding.update_status = UpdateStatus.COMPLETED
    remove_completed_findings(scan_result)
    save_scan_results(name, scan_result)


def finalise_local_changes(
    project_path: Path,
    scan_result: ScanResult,
    name: str,
    flow: Workflow,
    *,
    vcs: VcsServices,
    emit: Emit,
) -> bool:
    """Promote the flow's bookmark to local main, then complete its READY findings.

    Each failure is emitted as OperationFailed and returns False. A promotion or
    refresh failure leaves the READY findings and the bookmark for a later retry;
    a bookmark-cleanup failure after completion is reported and the next run
    recreates the bookmark.
    """
    bookmark = WORKFLOW_BOOKMARKS[flow]
    repo = vcs.repository(project_path)
    try:
        repo.promote_bookmark_to_main(bookmark=bookmark)
    except RevisionError as exc:
        emit(
            OperationFailed(
                Operation.PROMOTE,
                name,
                f"{exc} · rebase with jj rebase -b {bookmark} -d main, then rerun",
            )
        )
        return False
    try:
        refresh_working_copy_from_main(repo=repo)
    except RevisionError as exc:
        emit(OperationFailed(Operation.REFRESH, name, str(exc)))
        return False
    complete_ready_findings(scan_result, name, flow=flow)
    emit(Promoted())
    try:
        repo.delete_bookmark(bookmark=bookmark)
    except RevisionError as exc:
        emit(OperationFailed(Operation.BOOKMARK_CLEANUP, name, str(exc)))
        return False
    return True


def _assert_supported_in_progress_state(scan_result: ScanResult, project: str) -> None:
    for finding in scan_result.findings:
        if finding.update_status is not None and finding.flow is None:
            msg = (
                f"{project} has in-progress findings without flow ownership — "
                "please rescan the project."
            )
            raise FlowConflictError(msg)


_RESOLVE_CLAIMABLE_TEST_PHASES = {"unit", "integration", "component"}


def is_resolve_claimable_failure(finding: Finding, active_flow: Workflow) -> bool:
    return (
        active_flow is Workflow.RESOLVE
        and finding.flow is Workflow.UPDATE
        and finding.update_status is UpdateStatus.FAILED
        and finding.failed_phase in _RESOLVE_CLAIMABLE_TEST_PHASES
    )


def _assert_no_conflicting_flow(
    scan_result: ScanResult,
    active_flow: Workflow,
    project: str,
) -> None:
    conflicts = [
        finding
        for finding in scan_result.findings
        if finding.update_status is not None
        and finding.flow is not None
        and finding.flow is not active_flow
        and not is_resolve_claimable_failure(finding, active_flow)
    ]
    if conflicts:
        other_flow = conflicts[0].flow
        assert other_flow is not None
        msg = (
            f"Cannot run {active_flow.value} on {project}: {len(conflicts)} "
            f"finding(s) owned by the '{other_flow.value}' flow. Complete or "
            "abandon that flow first."
        )
        raise FlowConflictError(msg)
