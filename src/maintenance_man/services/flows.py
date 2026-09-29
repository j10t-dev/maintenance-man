from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    Emit,
    MissingTestConfig,
    ProjectSkipped,
    SkipReason,
)
from maintenance_man.models.scan import ScanResult, UpdateStatus, Workflow
from maintenance_man.services import WorkflowError
from maintenance_man.storage import NoScanResultsError, load_scan_results
from maintenance_man.updater import Finding


class FlowConflictError(WorkflowError):
    """Scan-result state belongs to another workflow."""


def _assert_supported_in_progress_state(scan_result: ScanResult, project: str) -> None:
    for finding in scan_result.findings:
        if finding.update_status is not None and finding.flow is None:
            raise FlowConflictError(
                f"{project} has in-progress findings without flow ownership — "
                "please rescan the project."
            )


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
        raise FlowConflictError(
            f"Cannot run {active_flow.value} on {project}: {len(conflicts)} "
            f"finding(s) owned by the '{other_flow.value}' flow. Complete or "
            "abandon that flow first."
        )


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
