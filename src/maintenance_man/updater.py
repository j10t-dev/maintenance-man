import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from maintenance_man import gradle
from maintenance_man.gradle import GradleError
from maintenance_man.models.config import PackageManager, ProjectConfig
from maintenance_man.models.events import (
    Emit,
    FindingFailed,
    FindingPassed,
    FindingsBlocked,
    FindingStarted,
    FindingStepFailed,
    TestCommandStarted,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    Failed,
    FindingState,
    GradleBlock,
    GradleUpdateTarget,
    Ready,
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateKind,
    UpdateResult,
    VulnFinding,
    Workflow,
)
from maintenance_man.package_managers import UpdateCommandError, update_commands
from maintenance_man.process import ProcessError, run_logged, run_shell_command
from maintenance_man.storage import save_scan_results
from maintenance_man.vcs import JjRepository, RevisionError


@dataclass(frozen=True, slots=True)
class FindingStep:
    failed_phase: str | None
    discardable: bool = True

    @property
    def passed(self) -> bool:
        return self.failed_phase is None


_COMMIT_FORMATS: dict[UpdateKind, str] = {
    "vuln": "fix: upgrade {pkg} {old} -> {new} for {detail}",
    "update": "chore: bump {pkg} {old} -> {new} ({detail})",
}

_RISK_ORDER = {tier: rank for rank, tier in enumerate(SemverTier)}


@dataclass
class FindingGroup:
    """Saved rows applied, tested and committed as one change."""

    pkg_name: str
    installed_version: str
    target_version: str
    detail: str
    originals: Sequence[VulnFinding | UpdateFinding] = field(repr=False)
    kind: UpdateKind = "vuln"
    gradle_target: GradleUpdateTarget | None = None

    def record(self, state: FindingState) -> None:
        """Set *state* on every row this group was applied for."""
        for original in self.originals:
            original.state = state


def consolidate_vulns(vulns: list[VulnFinding]) -> list[FindingGroup]:
    """One group per package, targeting the fix its advisories share. Raises
    ValueError when a package's advisories hold different fixes."""
    by_pkg: dict[str, list[VulnFinding]] = {}
    for v in vulns:
        by_pkg.setdefault(v.pkg_name, []).append(v)

    return [
        _group(
            group,
            pkg_name=pkg,
            installed_version=group[0].installed_version,
            target_version=_shared_fix(pkg, group),
            detail=", ".join(v.vuln_id for v in group),
        )
        for pkg, group in by_pkg.items()
    ]


def _shared_fix(pkg: str, group: list[VulnFinding]) -> str:
    fixes = {v.target_version for v in group}
    if len(fixes) > 1:
        msg = f"{pkg} advisories hold different fixes: {', '.join(sorted(fixes))}"
        raise ValueError(msg)
    return fixes.pop()


def sort_updates_by_risk(updates: list[UpdateFinding]) -> list[UpdateFinding]:
    """Sort updates risk-ascending: PATCH < MINOR < MAJOR < UNKNOWN."""
    return sorted(updates, key=lambda u: _RISK_ORDER[u.semver_tier])


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
            emit(FindingStepFailed("test", str(exc)))
            return phase_name
    return None


def is_eligible(finding: VulnFinding | UpdateFinding) -> bool:
    """Whether a saved row can be applied: not blocked, and with a version to apply."""
    if isinstance(finding.state, GradleBlock):
        return False
    return (
        not isinstance(finding, VulnFinding)
        or finding.actionable
        or finding.gradle_target is not None
    )


def group_findings(
    findings: Sequence[VulnFinding | UpdateFinding],
) -> list[FindingGroup]:
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
        *(
            _group(
                [update],
                pkg_name=update.pkg_name,
                installed_version=update.installed_version,
                target_version=update.latest_version,
                detail=update.detail,
                kind="update",
            )
            for update in sort_updates_by_risk(
                [
                    f
                    for f in eligible
                    if isinstance(f, UpdateFinding) and f.gradle_target is None
                ]
            )
        ),
    ]


@dataclass(frozen=True, slots=True)
class Applied:
    """The change is in the working copy, or was already there."""


@dataclass(frozen=True, slots=True)
class Blocked:
    """The adapter withheld the change; nothing was applied."""

    block: GradleBlock


@dataclass(frozen=True, slots=True)
class ApplyFailed:
    """Application failed and was reported; partial changes may remain.

    discardable is False when jj could not read or compare the working copy.
    """

    discardable: bool = True


type ApplyOutcome = Applied | Blocked | ApplyFailed


def apply_finding(
    project: ProjectConfig, group: FindingGroup, repo: JjRepository, *, emit: Emit
) -> ApplyOutcome:
    """Apply one group in the project directory; Blocked means nothing changed,
    ApplyFailed means the failure was emitted and partial changes may remain.

    For a package-command group, Applied means the commands succeeded and the
    working copy's files differ from the commit read before them. A Gradle group
    follows the Gradle adapter's own catalogue check.
    """
    if group.gradle_target is None:
        return _apply_package_commands(project, group, repo, emit=emit)
    return _apply_gradle_target(project, group.gradle_target, emit=emit)


def process_findings(
    groups: Sequence[FindingGroup],
    project_config: ProjectConfig,
    *,
    flow: Workflow,
    scan_result: ScanResult,
    emit: Emit,
) -> list[UpdateResult]:
    """Process groups on the current jj change.

    Update discards a failed group and continues; resolve keeps it and stops.
    """
    results: list[UpdateResult] = []
    repo = JjRepository(Path(project_config.path))
    for group in groups:
        emit(
            FindingStarted(
                group.pkg_name, group.installed_version, group.target_version
            )
        )
        outcome = apply_finding(project_config, group, repo, emit=emit)
        if isinstance(outcome, Blocked):
            group.record(outcome.block)
            save_scan_results(scan_result.project, scan_result)
            emit(FindingsBlocked(((group.pkg_name, outcome.block.reason),)))
            continue
        step = (
            FindingStep("apply", discardable=outcome.discardable)
            if isinstance(outcome, ApplyFailed)
            else _test_and_commit(group, project_config, repo, flow, emit)
        )
        if step.failed_phase is None:
            group.record(Ready(flow=flow))
        else:
            emit(
                FindingFailed(
                    group.pkg_name,
                    step.failed_phase,
                    group.installed_version,
                    group.target_version,
                )
            )
            group.record(Failed(flow=flow, phase=step.failed_phase))
        save_scan_results(scan_result.project, scan_result)
        results.append(
            UpdateResult(group.pkg_name, group.kind, step.passed, step.failed_phase)
        )
        if step.passed:
            continue
        if not (flow is Workflow.UPDATE and step.discardable and _discard(repo, emit)):
            break

    return results


def _target_group(
    target: GradleUpdateTarget, rows: list[VulnFinding | UpdateFinding]
) -> FindingGroup:
    return _group(
        rows,
        pkg_name=target.display_name,
        installed_version=target.members[0].installed_version,
        target_version=target.target_version,
        detail=", ".join(dict.fromkeys(row.detail for row in rows)),
        kind="vuln" if any(isinstance(row, VulnFinding) for row in rows) else "update",
        gradle_target=target,
    )


def _group(
    rows: Sequence[VulnFinding | UpdateFinding],
    *,
    pkg_name: str,
    installed_version: str,
    target_version: str,
    detail: str,
    kind: UpdateKind = "vuln",
    gradle_target: GradleUpdateTarget | None = None,
) -> FindingGroup:
    return FindingGroup(
        pkg_name=pkg_name,
        installed_version=installed_version,
        target_version=target_version,
        detail=detail,
        originals=rows,
        kind=kind,
        gradle_target=gradle_target,
    )


def _apply_package_commands(
    project: ProjectConfig, group: FindingGroup, repo: JjRepository, *, emit: Emit
) -> ApplyOutcome:
    try:
        before = repo.resolve_revision(revision="@")
        if not _apply_update(
            project.package_manager,
            group.pkg_name,
            group.installed_version,
            group.target_version,
            project.path,
            emit=emit,
        ):
            return ApplyFailed()
        changed = repo.has_file_changes_since(revision=before)
    except RevisionError as exc:
        emit(FindingStepFailed("inspect", str(exc)))
        return ApplyFailed(discardable=False)
    if changed:
        return Applied()
    emit(
        FindingStepFailed(
            "package command",
            f"Package commands for {group.pkg_name} changed no files; it may be "
            f"transitive or already at {group.target_version}. Run mm scan again.",
        )
    )
    return ApplyFailed()


def _apply_gradle_target(
    project: ProjectConfig, target: GradleUpdateTarget, *, emit: Emit
) -> ApplyOutcome:
    try:
        if gradle.validate_gradle_recovery(project, target) is None:
            return Applied()
        block = gradle.apply_gradle_update(project, target)
    except GradleError as exc:
        emit(FindingStepFailed("package command", str(exc)))
        return ApplyFailed()
    return Applied() if block is None else Blocked(block)


def _test_and_commit(
    group: FindingGroup,
    project_config: ProjectConfig,
    repo: JjRepository,
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
        emit(FindingStepFailed("inspect", str(exc)))
        return FindingStep("commit", discardable=False)
    if not has_changes:
        emit(
            FindingPassed(
                group.pkg_name, True, group.installed_version, group.target_version
            )
        )
        return FindingStep(None)

    return _commit_finding(group, repo, flow, emit)


def _commit_finding(
    group: FindingGroup, repo: JjRepository, flow: Workflow, emit: Emit
) -> FindingStep:
    message = _COMMIT_FORMATS[group.kind].format(
        pkg=group.pkg_name,
        old=group.installed_version,
        new=group.target_version,
        detail=group.detail,
    )
    try:
        repo.commit(message=message)
    except RevisionError as exc:
        emit(FindingStepFailed("commit", str(exc)))
        return FindingStep("commit")
    try:
        repo.set_bookmark(bookmark=WORKFLOW_BOOKMARKS[flow], revision="@-")
    except RevisionError as exc:
        emit(FindingStepFailed("bookmark", str(exc)))
        return FindingStep("commit", discardable=False)
    emit(
        FindingPassed(
            group.pkg_name, False, group.installed_version, group.target_version
        )
    )
    return FindingStep(None)


def _discard(repo: JjRepository, emit: Emit) -> bool:
    try:
        repo.discard()
    except RevisionError as exc:
        emit(FindingStepFailed("discard", str(exc)))
        return False
    return True


def _apply_update(
    package_manager: PackageManager,
    pkg_name: str,
    installed: str,
    version: str,
    project_path: Path,
    *,
    emit: Emit,
) -> bool:
    """Apply a single package update. Returns True on success."""
    try:
        commands = update_commands(
            package_manager, pkg_name, installed, version, project_path
        )
    except UpdateCommandError as e:
        emit(FindingStepFailed("prepare", str(e)))
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
            emit(FindingStepFailed("package command", str(e)))
            return False
    return True
