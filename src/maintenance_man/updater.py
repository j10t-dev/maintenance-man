from __future__ import annotations

import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from maintenance_man import gradle
from maintenance_man.gradle import GradleError
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    Emit,
    FindingFailed,
    FindingPassed,
    FindingsBlocked,
    FindingStarted,
    FindingStepFailed,
    FindingStepKind,
    TestCommandStarted,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    GradleUpdateTarget,
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
from maintenance_man.process import ProcessError, run_logged, run_shell_command
from maintenance_man.storage import save_scan_results
from maintenance_man.vcs import Repository, RevisionError
from maintenance_man.vcs_workflow import VcsServices

FailureStrategy = Literal["continue", "stop"]


@dataclass(frozen=True, slots=True)
class FindingStep:
    failed_phase: str | None
    discardable: bool = True

    @property
    def passed(self) -> bool:
        return self.failed_phase is None


def finding_transition(step: FindingStep) -> tuple[UpdateStatus, str | None]:
    if step.passed:
        return UpdateStatus.READY, None
    return UpdateStatus.FAILED, step.failed_phase


def should_discard(step: FindingStep, on_failure: FailureStrategy) -> bool:
    return not step.passed and step.discardable and on_failure == "continue"


def should_stop(
    step: FindingStep, on_failure: FailureStrategy, discarded: bool | None
) -> bool:
    if step.passed:
        return False
    return not step.discardable or on_failure == "stop" or discarded is False


class Finding(Protocol):
    """Common interface for VulnFinding and UpdateFinding during update processing."""

    pkg_name: str
    installed_version: str
    update_status: UpdateStatus | None
    failed_phase: str | None
    flow: Workflow | None
    gradle_target: GradleUpdateTarget | None
    blocked_reason: str | None

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
class _FindingGroup:
    """Saved rows applied, tested and committed as one change; lifecycle and
    blocked-reason writes fan out to every original row."""

    pkg_name: str
    installed_version: str
    _target_version: str
    _detail: str
    _originals: Sequence[VulnFinding | UpdateFinding] = field(repr=False)
    kind: UpdateKind = "vuln"
    gradle_target: GradleUpdateTarget | None = None
    _update_status: UpdateStatus | None = None
    _failed_phase: str | None = None
    _flow: Workflow | None = None
    _blocked_reason: str | None = None

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

    @property
    def blocked_reason(self) -> str | None:
        return self._blocked_reason

    @blocked_reason.setter
    def blocked_reason(self, value: str | None) -> None:
        self._blocked_reason = value
        for orig in self._originals:
            orig.blocked_reason = value


def consolidate_vulns(
    vulns: list[VulnFinding],
) -> list[_FindingGroup]:
    """Group actionable vulns by package and pick the highest fix version."""
    by_pkg: dict[str, list[VulnFinding]] = {}
    for v in vulns:
        by_pkg.setdefault(v.pkg_name, []).append(v)

    consolidated: list[_FindingGroup] = []
    for pkg, group in by_pkg.items():
        best_version = highest_fix_version(group)
        detail = ", ".join(v.vuln_id for v in group)
        update_status, failed_phase, flow = _consolidated_lifecycle_state(group)
        consolidated.append(
            _FindingGroup(
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
) -> str | None:
    """Run configured test phases sequentially and return the failed phase.

    Stops on first failure. Returns ``None`` if all phases pass.
    """
    for phase_name, command in project_config.test_phases:
        emit(TestCommandStarted(command))
        try:
            run_shell_command(
                command, project_path, timeout=600, label=f"{phase_name} tests"
            )
        except ProcessError as exc:
            emit(FindingStepFailed(FindingStepKind.TEST, str(exc)))
            return phase_name
    return None


def is_eligible(finding: VulnFinding | UpdateFinding) -> bool:
    """Whether a saved row can be applied: not blocked, and with a version to apply."""
    if finding.blocked_reason is not None:
        return False
    return (
        not isinstance(finding, VulnFinding)
        or finding.actionable
        or finding.gradle_target is not None
    )


def group_findings(findings: Sequence[VulnFinding | UpdateFinding]) -> list[Finding]:
    """Group eligible rows into one change each: rows sharing a saved catalogue
    target, other vulnerabilities by package, then other updates risk-ascending.
    Ineligible rows are left out."""
    eligible = [finding for finding in findings if is_eligible(finding)]
    targets: dict[
        str, tuple[GradleUpdateTarget, list[VulnFinding | UpdateFinding]]
    ] = {}
    for finding in eligible:
        if finding.gradle_target is not None:
            key = finding.gradle_target.model_dump_json()
            targets.setdefault(key, (finding.gradle_target, []))[1].append(finding)
    return [
        *consolidate_vulns(
            [
                f
                for f in eligible
                if isinstance(f, VulnFinding) and f.gradle_target is None
            ]
        ),
        *(_target_group(target, rows) for target, rows in targets.values()),
        *sort_updates_by_risk(
            [
                f
                for f in eligible
                if isinstance(f, UpdateFinding) and f.gradle_target is None
            ]
        ),
    ]


@dataclass(frozen=True, slots=True)
class Applied:
    """The change is in the working copy, or was already there."""


@dataclass(frozen=True, slots=True)
class Blocked:
    """The saved target no longer matches the catalogue; nothing changed."""

    reason: str


@dataclass(frozen=True, slots=True)
class ApplyFailed:
    """Application failed and was reported; partial changes may remain."""


type ApplyOutcome = Applied | Blocked | ApplyFailed


def apply_finding(
    project: ProjectConfig, finding: Finding, *, emit: Emit
) -> ApplyOutcome:
    """Apply one finding in the project directory; Blocked means nothing changed,
    ApplyFailed means the failure was emitted and partial changes may remain."""
    if finding.gradle_target is None:
        applied = _apply_update(
            project.package_manager,
            finding.pkg_name,
            finding.target_version,
            project.path,
            emit=emit,
        )
        return Applied() if applied else ApplyFailed()
    return _apply_gradle_target(project, finding.gradle_target, emit=emit)


def process_findings(
    findings: Sequence[Finding],
    project_config: ProjectConfig,
    *,
    flow: Workflow,
    on_failure: FailureStrategy = "continue",
    scan_result: ScanResult,
    vcs: VcsServices,
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
    repo = vcs.repository(project_path)
    for finding in findings:
        kind = _kind(finding)
        emit(
            FindingStarted(
                finding.pkg_name,
                finding.installed_version,
                finding.target_version,
            )
        )
        outcome = apply_finding(project_config, finding, emit=emit)
        if isinstance(outcome, Blocked):
            _block(finding, outcome.reason, scan_result, emit)
            continue
        step = (
            FindingStep("apply")
            if isinstance(outcome, ApplyFailed)
            else _test_and_commit(finding, kind, project_config, repo, flow, emit)
        )
        if step.failed_phase is not None:
            emit(
                FindingFailed(
                    finding.pkg_name,
                    step.failed_phase,
                    finding.installed_version,
                    finding.target_version,
                )
            )
        finding.update_status, finding.failed_phase = finding_transition(step)
        finding.flow = flow
        save_scan_results(scan_result.project, scan_result)
        discarded = _discard(repo, emit) if should_discard(step, on_failure) else None
        results.append(
            UpdateResult(finding.pkg_name, kind, step.passed, step.failed_phase)
        )
        if should_stop(step, on_failure, discarded):
            break

    return results


def _kind(finding: Finding) -> UpdateKind:
    if isinstance(finding, _FindingGroup):
        return finding.kind
    return "vuln" if isinstance(finding, VulnFinding) else "update"


def _target_group(
    target: GradleUpdateTarget, rows: list[VulnFinding | UpdateFinding]
) -> _FindingGroup:
    update_status, failed_phase, flow = _consolidated_lifecycle_state(rows)
    return _FindingGroup(
        pkg_name=target.display_name,
        installed_version=target.members[0].installed_version,
        _target_version=target.target_version,
        _detail=", ".join(dict.fromkeys(row.detail for row in rows)),
        _originals=rows,
        kind="vuln" if any(isinstance(row, VulnFinding) for row in rows) else "update",
        gradle_target=target,
        _update_status=update_status,
        _failed_phase=failed_phase,
        _flow=flow,
    )


def _apply_gradle_target(
    project: ProjectConfig, target: GradleUpdateTarget, *, emit: Emit
) -> ApplyOutcome:
    try:
        if gradle.validate_gradle_recovery(project, target) is None:
            return Applied()
        block = gradle.apply_gradle_update(project, target)
    except GradleError as exc:
        emit(FindingStepFailed(FindingStepKind.PACKAGE_COMMAND, str(exc)))
        return ApplyFailed()
    return Applied() if block is None else Blocked(block.reason)


def _block(finding: Finding, reason: str, scan_result: ScanResult, emit: Emit) -> None:
    finding.blocked_reason = reason
    finding.update_status = None
    finding.failed_phase = None
    finding.flow = None
    save_scan_results(scan_result.project, scan_result)
    emit(FindingsBlocked(((finding.pkg_name, reason),)))


def _test_and_commit(
    finding: Finding,
    kind: UpdateKind,
    project_config: ProjectConfig,
    repo: Repository,
    flow: Workflow,
    emit: Emit,
) -> FindingStep:
    project_path = Path(project_config.path)
    failed_phase = run_test_phases(project_config, project_path, emit=emit)
    if failed_phase is not None:
        return FindingStep(failed_phase)

    try:
        has_changes = repo.has_changes()
    except RevisionError as exc:
        emit(FindingStepFailed(FindingStepKind.INSPECT, str(exc)))
        return FindingStep("commit", discardable=False)
    if not has_changes:
        emit(
            FindingPassed(
                finding.pkg_name,
                True,
                finding.installed_version,
                finding.target_version,
            )
        )
        return FindingStep(None)

    return _commit_finding(finding, kind, repo, flow, emit)


def _commit_finding(
    finding: Finding,
    kind: UpdateKind,
    repo: Repository,
    flow: Workflow,
    emit: Emit,
) -> FindingStep:
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
    emit(
        FindingPassed(
            finding.pkg_name, False, finding.installed_version, finding.target_version
        )
    )
    return FindingStep(None)


def _discard(repo: Repository, emit: Emit) -> bool:
    try:
        repo.discard()
    except RevisionError as exc:
        emit(FindingStepFailed(FindingStepKind.DISCARD, str(exc)))
        return False
    return True


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
            run_logged(
                cmd,
                project_path,
                timeout=300,
                label=shlex.join(cmd),
                stdin=subprocess.DEVNULL,
            )
        except ProcessError as e:
            emit(FindingStepFailed(FindingStepKind.PACKAGE_COMMAND, str(e)))
            return False
    return True
