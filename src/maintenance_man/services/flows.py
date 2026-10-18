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
    UpdateStatus,
    Workflow,
)
from maintenance_man.services import WorkflowError
from maintenance_man.storage import (
    NoScanResultsError,
    load_scan_results,
    save_scan_results,
)
from maintenance_man.updater import remove_completed_findings
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
    return scan_result


def report_missing_test_config(
    name: str, project: ProjectConfig, *, emit: Emit
) -> bool:
    """Emit MissingTestConfig and return True when the project has no configured
    test phase."""
    if project.test_phases:
        return False
    emit(MissingTestConfig(name))
    return True


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


def _assert_no_conflicting_flow(
    scan_result: ScanResult,
    active_flow: Workflow,
    project: str,
) -> None:
    """Update may not touch resolve-owned work; resolve takes over update-owned work."""
    if active_flow is Workflow.RESOLVE:
        return
    conflicts = [
        finding
        for finding in scan_result.findings
        if finding.update_status is not None
        and finding.flow is not None
        and finding.flow is not active_flow
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
