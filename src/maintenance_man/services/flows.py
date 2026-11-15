from pathlib import Path

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    Emit,
    MissingTestConfig,
    OperationFailed,
    Outcome,
    ProjectSkipped,
    Promoted,
    PromotionFailed,
    SkipReason,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    Failed,
    Ready,
    ScanResult,
    UpdateFinding,
    VulnFinding,
    Workflow,
)
from maintenance_man.services import WorkflowError
from maintenance_man.storage import (
    CorruptScanResultsError,
    NoScanResultsError,
    load_scan_results,
    save_scan_results,
)
from maintenance_man.updater import is_eligible
from maintenance_man.vcs import JjRepository, RevisionError
from maintenance_man.vcs_workflow import refresh_working_copy_from_main


class FlowConflictError(WorkflowError):
    """Scan-result state belongs to another workflow."""


def load_validated_scan(
    project_name: str,
    project: ProjectConfig,
    workflow: Workflow,
    *,
    emit: Emit,
) -> ScanResult | None:
    try:
        scan_result = load_scan_results(project_name)
    except NoScanResultsError:
        emit(ProjectSkipped(project_name, SkipReason.NO_SCAN_RESULTS))
        return None

    if scan_result.package_manager != project.package_manager:
        detail = (
            f"saved under {scan_result.package_manager}, but the project is "
            f"configured as {project.package_manager}"
        )
        raise CorruptScanResultsError(project_name, detail)

    _assert_no_conflicting_flow(scan_result, workflow, project_name)

    if not scan_result.has_actionable_vulns and not scan_result.updates:
        emit(ProjectSkipped(project_name, SkipReason.NOTHING_TO_DO, workflow.value))
        return None
    return scan_result


def report_missing_test_config(
    project_name: str, project: ProjectConfig, *, emit: Emit
) -> bool:
    """Emit MissingTestConfig and return True when the project has no configured
    test phase."""
    if project.test_phases:
        return False
    emit(MissingTestConfig(project_name))
    return True


def is_owned(
    finding: VulnFinding | UpdateFinding,
    flow: Workflow,
    *kinds: type[Ready] | type[Failed],
) -> bool:
    """Whether *flow* owns the finding in one of the lifecycle kinds."""
    return isinstance(finding.state, kinds) and finding.state.flow is flow


def has_owned(
    scan_result: ScanResult, flow: Workflow, *kinds: type[Ready] | type[Failed]
) -> bool:
    """Whether any saved finding is owned by *flow* in one of the lifecycle kinds."""
    return any(is_owned(finding, flow, *kinds) for finding in scan_result.findings)


def is_candidate(finding: VulnFinding | UpdateFinding, flow: Workflow) -> bool:
    """Whether the flow may apply the finding: eligible, and pending or failed in it."""
    return is_eligible(finding) and (
        finding.state is None or is_owned(finding, flow, Failed)
    )


def has_work(scan_result: ScanResult, flow: Workflow) -> bool:
    """Whether the flow has a finding to apply or Ready work to promote."""
    return any(
        is_candidate(finding, flow) or is_owned(finding, flow, Ready)
        for finding in scan_result.findings
    )


def complete_ready_findings(
    scan_result: ScanResult, project_name: str, *, flow: Workflow
) -> None:
    """Remove the flow's Ready findings, then persist the scan."""
    scan_result.vulnerabilities = [
        finding
        for finding in scan_result.vulnerabilities
        if not is_owned(finding, flow, Ready)
    ]
    scan_result.updates = [
        finding for finding in scan_result.updates if not is_owned(finding, flow, Ready)
    ]
    save_scan_results(project_name, scan_result)


def finalise_local_changes(
    project_path: Path,
    scan_result: ScanResult,
    project_name: str,
    flow: Workflow,
    *,
    emit: Emit,
) -> Outcome:
    """Promote the flow's bookmark to local main, then complete its Ready findings.

    Succeeds without effects when the flow has no Ready finding. Each failure is
    emitted as OperationFailed and returns FAILED. A promotion or refresh failure
    leaves the Ready findings and the bookmark for a later retry; a
    bookmark-cleanup failure after completion is reported and the next run
    recreates the bookmark.
    """
    if not has_owned(scan_result, flow, Ready):
        return Outcome.SUCCEEDED
    bookmark = WORKFLOW_BOOKMARKS[flow]
    repo = JjRepository(project_path)
    try:
        repo.promote_bookmark_to_main(bookmark=bookmark)
    except RevisionError as exc:
        emit(
            PromotionFailed(
                project_name,
                f"{exc} · rebase with jj rebase -b {bookmark} -d main, then rerun",
            )
        )
        return Outcome.FAILED
    try:
        refresh_working_copy_from_main(repo=repo)
    except RevisionError as exc:
        emit(OperationFailed("workspace refresh", project_name, str(exc)))
        return Outcome.FAILED
    complete_ready_findings(scan_result, project_name, flow=flow)
    emit(Promoted())
    try:
        repo.delete_bookmark(bookmark=bookmark)
    except RevisionError as exc:
        emit(OperationFailed("bookmark cleanup", project_name, str(exc)))
        return Outcome.FAILED
    return Outcome.SUCCEEDED


def _assert_no_conflicting_flow(
    scan_result: ScanResult,
    active_flow: Workflow,
    project_name: str,
) -> None:
    """Update may not touch resolve-owned work; resolve takes over update-owned work."""
    if active_flow is Workflow.RESOLVE:
        return
    conflicts = [
        state
        for finding in scan_result.findings
        if isinstance(state := finding.state, Ready | Failed)
        and state.flow is not active_flow
    ]
    if conflicts:
        msg = (
            f"Cannot run {active_flow.value} on {project_name}: {len(conflicts)} "
            f"finding(s) owned by the '{conflicts[0].flow.value}' flow. Complete or "
            "abandon that flow first."
        )
        raise FlowConflictError(msg)
