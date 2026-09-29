from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    Emit,
    FindingFailed,
    FindingPassed,
    FindingStarted,
    FindingStepFailed,
    FindingStepKind,
    TestCommandStarted,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateKind,
    UpdateResult,
    UpdateStatus,
    VulnFinding,
    Workflow,
    highest_fix_version,
)
from maintenance_man.package_managers import (
    UnsupportedPackageManagerError,
    UpdateCommandError,
    package_manager_ops,
)
from maintenance_man.process import ProcessError, run_captured, run_live
from maintenance_man.storage import save_scan_results
from maintenance_man.vcs import Repository, RevisionError
from maintenance_man.vcs_workflow import VcsServices, make_vcs_services

FailureStrategy = Literal["continue", "stop"]


@dataclass(frozen=True, slots=True)
class FindingStep:
    failed_phase: str | None
    discardable: bool = True
    already_applied: bool = False

    @property
    def passed(self) -> bool:
        return self.failed_phase is None


class NextAction(StrEnum):
    CONTINUE = "continue"
    STOP = "stop"


def finding_transition(
    step: FindingStep, flow: Workflow
) -> tuple[UpdateStatus, str | None, Workflow]:
    if step.passed:
        return UpdateStatus.READY, None, flow
    return UpdateStatus.FAILED, step.failed_phase, flow


def should_discard(step: FindingStep, on_failure: FailureStrategy) -> bool:
    return not step.passed and step.discardable and on_failure == "continue"


def next_action(
    step: FindingStep, on_failure: FailureStrategy, discarded: bool | None
) -> NextAction:
    if step.passed:
        return NextAction.CONTINUE
    if not step.discardable or on_failure == "stop" or discarded is False:
        return NextAction.STOP
    return NextAction.CONTINUE


class Finding(Protocol):
    """Common interface for VulnFinding and UpdateFinding during update processing."""

    pkg_name: str
    installed_version: str
    update_status: UpdateStatus | None
    failed_phase: str | None
    flow: Workflow | None

    @property
    def target_version(self) -> str: ...

    @property
    def detail(self) -> str: ...


_COMMIT_FORMATS: dict[UpdateKind, str] = {
    "vuln": "fix: upgrade {pkg} {old} -> {new} for {detail}",
    "update": "chore: bump {pkg} {old} -> {new} ({detail})",
}

_RISK_ORDER = {
    SemverTier.PATCH: 0,
    SemverTier.MINOR: 1,
    SemverTier.MAJOR: 2,
    SemverTier.UNKNOWN: 3,
}


def _first_non_none(values: Sequence[str | Workflow | None]):
    return next((value for value in values if value is not None), None)


def _consolidated_lifecycle_state(
    group: Sequence[VulnFinding | UpdateFinding],
) -> tuple[UpdateStatus | None, str | None, Workflow | None]:
    """Collapse a group of consolidated VulnFindings into one lifecycle state.

    Findings that share a package and fix target are processed as a single
    upgrade; this helper picks the representative status (plus failed_phase
    and flow) for the whole group:

    * any FAILED  → FAILED with the first failed finding's phase/flow
    * else any READY → READY with the first ready finding's phase/flow
    * else all COMPLETED → COMPLETED
    * else (mixed/empty) → (None, None, None)
    """
    failed = [v for v in group if v.update_status == UpdateStatus.FAILED]
    if failed:
        return (
            UpdateStatus.FAILED,
            _first_non_none([v.failed_phase for v in failed]),
            _first_non_none([v.flow for v in failed]),
        )

    ready = [v for v in group if v.update_status == UpdateStatus.READY]
    if ready:
        return (
            UpdateStatus.READY,
            _first_non_none([v.failed_phase for v in ready]),
            _first_non_none([v.flow for v in ready]),
        )

    if group and all(v.update_status == UpdateStatus.COMPLETED for v in group):
        return (UpdateStatus.COMPLETED, None, None)

    return (None, None, None)


@dataclass
class _ConsolidatedVuln:
    """Proxy that groups several vulns for the same package into one finding.

    Satisfies the :class:`Finding` protocol so it can be used in the update
    processing flows.  Writes to :attr:`update_status`, :attr:`failed_phase`
    and :attr:`flow` are fanned out to every original :class:`VulnFinding` so
    that serialisation (which works on the originals) stays consistent.
    """

    pkg_name: str
    installed_version: str
    _target_version: str
    _detail: str
    _originals: list[VulnFinding] = field(repr=False)
    _update_status: UpdateStatus | None = None
    _failed_phase: str | None = None
    _flow: Workflow | None = None

    def __post_init__(self) -> None:
        self.update_status = self._update_status
        self.failed_phase = self._failed_phase
        self.flow = self._flow

    @property
    def target_version(self) -> str:
        return self._target_version

    @property
    def detail(self) -> str:
        return self._detail

    @property
    def update_status(self) -> UpdateStatus | None:
        return self._update_status

    @update_status.setter
    def update_status(self, value: UpdateStatus | None) -> None:
        self._update_status = value
        for orig in self._originals:
            orig.update_status = value

    @property
    def failed_phase(self) -> str | None:
        return self._failed_phase

    @failed_phase.setter
    def failed_phase(self, value: str | None) -> None:
        self._failed_phase = value
        for orig in self._originals:
            orig.failed_phase = value

    @property
    def flow(self) -> Workflow | None:
        return self._flow

    @flow.setter
    def flow(self, value: Workflow | None) -> None:
        self._flow = value
        for orig in self._originals:
            orig.flow = value


def consolidate_vulns(
    vulns: list[VulnFinding],
) -> list[_ConsolidatedVuln]:
    """Group actionable vulns by package and pick the highest fix version."""
    by_pkg: dict[str, list[VulnFinding]] = {}
    for v in vulns:
        by_pkg.setdefault(v.pkg_name, []).append(v)

    consolidated: list[_ConsolidatedVuln] = []
    for pkg, group in by_pkg.items():
        best_version = highest_fix_version(group)
        detail = ", ".join(v.vuln_id for v in group)
        update_status, failed_phase, flow = _consolidated_lifecycle_state(group)
        consolidated.append(
            _ConsolidatedVuln(
                pkg_name=pkg,
                installed_version=group[0].installed_version,
                _target_version=best_version,
                _detail=detail,
                _originals=group,
                _update_status=update_status,
                _failed_phase=failed_phase,
                _flow=flow,
            )
        )
    return consolidated


def sort_updates_by_risk(updates: list[UpdateFinding]) -> list[UpdateFinding]:
    """Sort updates risk-ascending: PATCH < MINOR < MAJOR < UNKNOWN."""
    return sorted(updates, key=lambda u: _RISK_ORDER[u.semver_tier])


def _keep_incomplete[F: Finding](findings: list[F]) -> list[F]:
    return [f for f in findings if f.update_status != UpdateStatus.COMPLETED]


def remove_completed_findings(scan_result: ScanResult) -> None:
    """Remove findings with COMPLETED status from the scan result in place."""
    scan_result.vulnerabilities = _keep_incomplete(scan_result.vulnerabilities)
    scan_result.updates = _keep_incomplete(scan_result.updates)


def run_test_phases(
    project_config: ProjectConfig, project_path: Path, *, emit: Emit
) -> tuple[bool, str | None]:
    """Run configured test phases sequentially. Returns (passed, failed_phase).

    Stops on first failure. Returns (True, None) if all phases pass.
    """
    for phase_name, command in project_config.test_phases:
        emit(TestCommandStarted(command))
        try:
            run_live(command, project_path, timeout=600, label=f"{phase_name} tests")
        except ProcessError as exc:
            emit(FindingStepFailed(FindingStepKind.TEST, str(exc)))
            return False, phase_name
    return True, None


def process_findings(
    findings: Sequence[Finding],
    project_config: ProjectConfig,
    *,
    flow: Workflow,
    on_failure: FailureStrategy = "continue",
    scan_result: ScanResult | None = None,
    project_name: str = "",
    vcs: VcsServices | None = None,
    emit: Emit,
) -> list[UpdateResult]:
    """Process findings on the current jj change.

    *on_failure* controls behaviour when an update or test fails:

    * ``"continue"`` — discard changes and move on to the next finding
      (used by ``mm update``).
    * ``"stop"`` — preserve changes for debugging and stop processing
      (used by ``mm resolve``).
    """
    results: list[UpdateResult] = []
    project_path = Path(project_config.path)
    vcs_services = vcs or make_vcs_services()
    repo = vcs_services.repository(project_path)
    for finding in findings:
        kind = _kind(finding)
        emit(
            FindingStarted(
                kind,
                finding.pkg_name,
                finding.installed_version,
                finding.target_version,
                finding.detail,
            )
        )
        step = _attempt_finding(finding, kind, project_config, repo, flow, emit)
        finding.update_status, finding.failed_phase, finding.flow = finding_transition(
            step, flow
        )
        _persist_status(scan_result, project_name)
        discarded = _discard(repo, emit) if should_discard(step, on_failure) else None
        results.append(
            UpdateResult(finding.pkg_name, kind, step.passed, step.failed_phase)
        )
        if next_action(step, on_failure, discarded) is NextAction.STOP:
            break

    return results


def _kind(finding: Finding) -> UpdateKind:
    return "vuln" if isinstance(finding, (VulnFinding, _ConsolidatedVuln)) else "update"


def _attempt_finding(
    finding: Finding,
    kind: UpdateKind,
    project_config: ProjectConfig,
    repo: Repository,
    flow: Workflow,
    emit: Emit,
) -> FindingStep:
    project_path = Path(project_config.path)
    if not _apply_update(
        project_config.package_manager,
        finding.pkg_name,
        finding.target_version,
        project_path,
        emit=emit,
    ):
        return FindingStep("apply")

    passed, failed_phase = run_test_phases(project_config, project_path, emit=emit)
    if not passed:
        phase = failed_phase or "test"
        emit(FindingFailed(finding.pkg_name, phase))
        return FindingStep(phase)

    try:
        has_changes = repo.has_changes()
    except RevisionError as exc:
        emit(FindingStepFailed(FindingStepKind.INSPECT, str(exc)))
        return FindingStep("commit", discardable=False)
    if not has_changes:
        emit(FindingPassed(finding.pkg_name, True))
        return FindingStep(None, already_applied=True)

    message = _COMMIT_FORMATS[kind].format(
        pkg=finding.pkg_name,
        old=finding.installed_version,
        new=finding.target_version,
        detail=finding.detail,
    )
    try:
        repo.commit(message=message)
    except RevisionError as exc:
        emit(FindingStepFailed(FindingStepKind.COMMIT, str(exc)))
        return FindingStep("commit")
    try:
        repo.set_bookmark(bookmark=WORKFLOW_BOOKMARKS[flow], revision="@-")
    except RevisionError as exc:
        emit(FindingStepFailed(FindingStepKind.BOOKMARK, str(exc)))
        return FindingStep("commit", discardable=False)
    emit(FindingPassed(finding.pkg_name, False))
    return FindingStep(None)


def _discard(repo: Repository, emit: Emit) -> bool:
    try:
        repo.discard()
    except RevisionError as exc:
        emit(FindingStepFailed(FindingStepKind.DISCARD, str(exc)))
        return False
    return True


def _persist_status(
    scan_result: ScanResult | None,
    project_name: str,
) -> None:
    """Save scan results when a scan result is provided."""
    if scan_result is not None:
        save_scan_results(project_name, scan_result)


def _apply_update(
    package_manager: str,
    pkg_name: str,
    version: str,
    project_path: Path,
    *,
    emit: Emit,
) -> bool:
    """Apply a single package update. Returns True on success."""
    try:
        commands = package_manager_ops(package_manager).update_commands(
            pkg_name, version, project_path
        )
    except (UnsupportedPackageManagerError, UpdateCommandError) as e:
        emit(FindingStepFailed(FindingStepKind.PREPARE, str(e)))
        return False

    for cmd in commands:
        try:
            run_captured(cmd, project_path, timeout=300, label=shlex.join(cmd))
        except ProcessError as e:
            emit(FindingStepFailed(FindingStepKind.PACKAGE_COMMAND, str(e)))
            return False
    return True
