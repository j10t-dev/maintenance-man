import functools
from dataclasses import dataclass
from typing import Literal

from maintenance_man import output, vcs_workflow
from maintenance_man.models.events import (
    BlockersStillFailing,
    DeployStep,
    DeployStepFinished,
    Event,
    FindingFailed,
    FindingPassed,
    FindingsBlocked,
    FindingStarted,
    FindingStepFailed,
    HealthChecked,
    MissingTestConfig,
    OperationFailed,
    ProcessingStarted,
    ProjectSkipped,
    ProjectStarted,
    Promoted,
    PromotionFailed,
    ResolvePaused,
    ScanReported,
    SkipReason,
    Status,
    SyncCompleted,
    TestCommandStarted,
)
from maintenance_man.scan_table import print_blocked_findings, print_scan_result

type Flow = Literal["scan", "update", "resolve", "deploy"]


@dataclass(slots=True)
class EventRenderer:
    batch: bool
    project: str = ""
    flow: Flow = "update"

    @functools.singledispatchmethod
    def __call__(self, event: Event) -> None:
        raise NotImplementedError(type(event))

    @__call__.register
    def _render_project_skipped(self, event: ProjectSkipped) -> None:
        if event.reason in _DEPLOY_SKIPS:
            status, reason = _DEPLOY_SKIPS[event.reason]
            output.outcome(event.project, "deploy", status, "deploy", reason=reason)
            return
        match event.reason:
            case SkipReason.PATH_MISSING if self.flow == "deploy":
                output.outcome(
                    event.project,
                    "deploy",
                    "failed",
                    "deploy",
                    reason=f"path does not exist: {event.detail}",
                )
            case SkipReason.PATH_MISSING:
                output.diagnostic(
                    "warning", f"{event.project} · path does not exist: {event.detail}"
                )
            case SkipReason.FLOW_CONFLICT:
                output.diagnostic("warning", f"{event.project} · {event.detail}")
            case SkipReason.NO_SCAN_RESULTS if not self.batch:
                output.notice(f"No scan results for {event.project}")
            case SkipReason.NOTHING_TO_DO:
                output.notice(f"Nothing to {event.detail} in {event.project}")
            case SkipReason.CORRUPT_SCAN_RESULTS:
                output.diagnostic(
                    "warning",
                    f"{event.project} · corrupt scan results; "
                    f"run mm scan {event.project}",
                )

    @__call__.register
    def _render_operation_failed(self, event: OperationFailed) -> None:
        output.diagnostic(
            "error", f"{event.project} · {event.operation} · {event.error}"
        )

    @__call__.register
    def _render_promotion(self, event: Promoted | PromotionFailed) -> None:
        match event:
            case PromotionFailed(project=project, error=error):
                output.outcome(
                    project, "promotion", "failed", _LOCAL_MAIN, reason=error
                )
            case Promoted():
                output.outcome(self.project, "promotion", "passed", _LOCAL_MAIN)

    @__call__.register
    def _render_scan_reported(self, event: ScanReported) -> None:
        result = event.result
        if self.flow == "scan" or output.terminal():
            print_scan_result(result, elapsed_s=event.elapsed_s)
        else:
            print_blocked_findings(result, self.flow)
        if result.has_findings or self.batch:
            return
        if event.elapsed_s is None:
            output.notice(f"No findings in {result.project}")
        else:
            output.notice(
                f"No findings in {result.project} · scanned in {event.elapsed_s:.1f}s"
            )

    @__call__.register
    def _render_missing_test_config(self, event: MissingTestConfig) -> None:
        output.diagnostic(
            "error",
            f"{event.project} · no test configuration · automatic updates need "
            "test_unit, test_integration or test_component",
        )

    @__call__.register
    def _render_processing_started(self, event: ProcessingStarted) -> None:
        output.heading(
            self.project, f"{event.vulns} vulnerabilities · {event.updates} updates"
        )

    @__call__.register
    def _render_resolve_paused(self, event: ResolvePaused) -> None:
        output.notice("Resolve paused")
        output.diagnostic("hint", f"mm resolve {event.project} --continue")

    @__call__.register
    def _render_findings_blocked(self, event: FindingsBlocked) -> None:
        for package, reason in event.findings:
            output.outcome(self.project, self.flow, "blocked", package, reason=reason)

    @__call__.register
    def _render_blockers_still_failing(self, event: BlockersStillFailing) -> None:
        output.diagnostic(
            "error", f"{event.phase} · still blocking: {', '.join(event.pkgs)}"
        )

    @__call__.register
    def _render_sync_completed(self, event: SyncCompleted) -> None:
        if event.action == vcs_workflow.SyncAction.UNCHANGED:
            output.outcome(event.project, "sync", "unchanged", "main")
        else:
            output.outcome(event.project, "sync", "passed", "main", reason=event.action)

    @__call__.register
    def _render_project_started(self, event: ProjectStarted) -> None:
        self.project = event.project
        if self.flow == "deploy":
            output.heading(event.project)

    @__call__.register
    def _render_finding_started(self, event: FindingStarted) -> None:
        if output.stderr_terminal():
            output.notice(f"Updating {event.pkg} {event.installed} → {event.target}")

    @__call__.register
    def _render_test_command_started(self, event: TestCommandStarted) -> None:
        if output.is_verbose():
            output.notice(f"$ {event.command}")

    @__call__.register
    def _render_finding_step_failed(self, event: FindingStepFailed) -> None:
        prefix = f"{self.project} · " if self.project else ""
        output.diagnostic("error", f"{prefix}{event.step} · {event.error}")

    @__call__.register
    def _render_finding_outcome(self, event: FindingPassed | FindingFailed) -> None:
        match event:
            case FindingFailed(phase=phase):
                status, reason = "failed", f"{phase} failed"
            case FindingPassed(already_applied=applied):
                status, reason = "passed", "already applied" if applied else ""
        output.outcome(
            self.project,
            self.flow,
            status,
            event.pkg,
            installed=event.installed,
            target=event.target,
            reason=reason,
        )

    @__call__.register
    def _render_deploy_step_finished(self, event: DeployStepFinished) -> None:
        word = event.step.value
        if event.error is None:
            output.outcome(event.project, word, "passed", word)
            return
        output.outcome(event.project, word, "failed", word, reason=event.error)
        if event.step is DeployStep.BUILD:
            output.outcome(
                event.project, "deploy", "skipped", "deploy", reason="build failed"
            )

    @__call__.register
    def _render_health_checked(self, event: HealthChecked) -> None:
        if event.is_up:
            output.outcome(event.project, "health", "passed", "healthcheck")
        else:
            output.outcome(
                event.project,
                "health",
                "failed",
                "healthcheck",
                reason=event.error or "not healthy",
            )


_DEPLOY_SKIPS: dict[SkipReason, tuple[Status, str]] = {
    SkipReason.NOT_DEPLOYABLE: ("skipped", "not deployable"),
    SkipReason.UNCHANGED: (
        "unchanged",
        "unchanged since last deploy · use --force to redeploy",
    ),
    SkipReason.BLOCKED: (
        "blocked",
        "could not resolve main revision · use --force to deploy anyway",
    ),
}
_LOCAL_MAIN = "local main"
