from __future__ import annotations

import hashlib
import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol

from packaging.version import InvalidVersion, Version
from rich import print as rprint

from maintenance_man import config as _config
from maintenance_man import sanitise_project_name
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    check_gradle_update_age,
    evaluate_gradle_candidate_age,
)
from maintenance_man.deployer import BuildError, run_build
from maintenance_man.env import project_env
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GradleError,
    apply_gradle_update,
    assert_safe_text,
    normalise_alias,
    parse_catalogue,
    reclaim_gradle_outputs,
    resolve_gradle_vulnerability_target,
    validate_gradle_recovery,
    validate_gradle_target,
    validate_gradle_target_shape,
)
from maintenance_man.gradle_resolution import (
    collect_gradle_resolution,
    gradle_routing_prerequisite,
)
from maintenance_man.gradle_verification import (
    compare_gradle_snapshots,
    context_inputs_valid,
    initialize_comparison_context,
    release_comparison_context,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    ApplyingAttempt,
    AttemptState,
    CheckEvidence,
    ComparisonContext,
    CompletedAttempt,
    FailedAttempt,
    GradleCandidate,
    GradleRun,
    GradleSnapshot,
    IncompleteResolution,
    PlannedAttempt,
    ReadyAttempt,
    VerificationReceipt,
    VerifiedComparison,
    WithheldAttempt,
)
from maintenance_man.models.scan import (
    GradleBlock,
    GradleUpdateTarget,
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    Workflow,
)
from maintenance_man.scanner import TrivyScanError, capture_gradle_snapshot
from maintenance_man.uv_dependencies import (
    UvDependencyError,
    UvDependencyLocation,
    get_uv_dependency_locations,
)
from maintenance_man.vcs import (
    _run,
    commit_current_change,
    create_or_reset_bookmark,
    current_change_has_changes,
    discard_current_change,
    edit_new_change,
    exact_commit_id,
    is_ancestor,
    revision_tree_id,
)


class NoScanResultsError(Exception):
    pass


def has_test_config(project_config: ProjectConfig) -> bool:
    """Return True if any test phase is configured."""
    return any(
        [
            project_config.test_unit,
            project_config.test_integration,
            project_config.test_component,
        ]
    )


type UpdateKind = Literal["vuln", "update"]

FailureStrategy = Literal["continue", "stop"]


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


@dataclass(slots=True)
class UpdateResult:
    """Tracks the outcome of a single update attempt."""

    pkg_name: str
    kind: UpdateKind
    passed: bool
    failed_phase: str | None = None
    blocked_reason: str | None = None


@dataclass(frozen=True, slots=True)
class _WorkflowConfig:
    """Parameters for a single maintenance workflow (vuln or update)."""

    kind: UpdateKind
    label: str
    commit_fmt: str


_VULN_STACK = _WorkflowConfig(
    kind="vuln",
    label="[bold red]VULN[/]",
    commit_fmt="fix: upgrade {pkg} {old} -> {new} for {detail}",
)

_UPDATE_STACK = _WorkflowConfig(
    kind="update",
    label="[bold cyan]UPDATE[/]",
    commit_fmt="chore: bump {pkg} {old} -> {new} ({detail})",
)

_RISK_ORDER = {
    SemverTier.PATCH: 0,
    SemverTier.MINOR: 1,
    SemverTier.MAJOR: 2,
    SemverTier.UNKNOWN: 3,
}

_WORKFLOW_BOOKMARKS = {
    Workflow.UPDATE: "mm/update-dependencies",
    Workflow.RESOLVE: "mm/resolve-dependencies",
}


def highest_fix_version(vulns: list[VulnFinding]) -> str:
    """Return the highest ``fixed_version`` from *vulns*.

    Uses :class:`packaging.version.Version` for comparison. Unparsable
    version strings are ignored; if *none* can be parsed the last item
    in the list is returned as a fallback.
    """

    def _sort_key(v: VulnFinding) -> Version:
        try:
            return Version(v.fixed_version or "0")
        except InvalidVersion:
            return Version("0")

    best = max(vulns, key=_sort_key)
    return best.fixed_version or vulns[-1].fixed_version or ""


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


def process_vulns(
    vulns: list[VulnFinding],
    project_config: ProjectConfig,
    *,
    flow: Workflow,
    minimum_age_days: int = 7,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process vuln fixes in the single-bookmark update flow."""
    actionable = [v for v in vulns if v.actionable]
    consolidated = consolidate_vulns(actionable)
    return process_findings(
        consolidated,
        project_config,
        _VULN_STACK,
        flow=flow,
        minimum_age_days=minimum_age_days,
        scan_result=scan_result,
        project_name=project_name,
        results_dir=results_dir,
    )


def process_updates(
    updates: list[UpdateFinding],
    project_config: ProjectConfig,
    *,
    flow: Workflow,
    minimum_age_days: int = 7,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process updates in the single-bookmark update flow, risk-ascending."""
    sorted_updates = sort_updates_by_risk(updates)
    return process_findings(
        sorted_updates,
        project_config,
        _UPDATE_STACK,
        flow=flow,
        minimum_age_days=minimum_age_days,
        scan_result=scan_result,
        project_name=project_name,
        results_dir=results_dir,
    )


def load_scan_results(project_name: str, results_dir: Path) -> ScanResult:
    """Load scan results JSON for a project. Raises NoScanResultsError if missing."""
    results_file = _results_path(project_name, results_dir)
    try:
        data = json.loads(results_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise NoScanResultsError(
            f"No scan results found for '{project_name}'. "
            f"Run 'mm scan {project_name}' first."
        ) from None
    return ScanResult.model_validate(data)


def save_scan_results(
    project_name: str, results_dir: Path, scan_result: ScanResult
) -> None:
    """Write scan results (with update statuses) back to disk."""
    results_file = _results_path(project_name, results_dir)
    results_file.write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")


def sort_updates_by_risk(updates: list[UpdateFinding]) -> list[UpdateFinding]:
    """Sort updates risk-ascending: PATCH < MINOR < MAJOR < UNKNOWN."""
    return sorted(updates, key=lambda u: _RISK_ORDER[u.semver_tier])


def _keep_incomplete[F: Finding](findings: list[F]) -> list[F]:
    return [f for f in findings if f.update_status != UpdateStatus.COMPLETED]


def remove_completed_findings(scan_result: ScanResult) -> None:
    """Remove findings with COMPLETED status from the scan result in place."""
    scan_result.vulnerabilities = _keep_incomplete(scan_result.vulnerabilities)
    scan_result.updates = _keep_incomplete(scan_result.updates)


def get_update_commands(
    package_manager: str,
    pkg_name: str,
    version: str,
    project_path: Path,
) -> list[list[str]]:
    """Return the shell command or commands to update a package."""
    match package_manager:
        case "bun":
            if not (project_path / "package.json").is_file():
                raise ValueError(
                    "package.json is missing from the update workspace; "
                    "check that the project exists on main and rescan"
                )
            return [["bun", "add", f"{pkg_name}@{version}"]]
        case "uv":
            locations = get_uv_dependency_locations(project_path, pkg_name)
            return [
                _get_uv_update_command(pkg_name, version, location)
                for location in locations
            ]
        case "mvn":
            return [
                [
                    "mvn",
                    "versions:use-dep-version",
                    f"-Dincludes={pkg_name}",
                    f"-DdepVersion={version}",
                ]
            ]
        case "gradle":
            raise ValueError(
                "Gradle updates are applied through the Gradle adapter, not a "
                "package-manager command"
            )
        case _:
            raise ValueError(f"Unsupported package manager: {package_manager}")


def _get_uv_update_command(
    pkg_name: str, version: str, location: UvDependencyLocation
) -> list[str]:
    if location.kind == "transitive":
        return ["uv", "lock", "--upgrade-package", pkg_name]
    command = ["uv", "add"]
    if location.kind == "group":
        if location.group is None:
            raise UvDependencyError("UV group dependency location missing group name")
        command.extend(["--group", location.group])
    command.append(f"{pkg_name}=={version}")
    return command


# TODO: extract as part of test command feature
def run_test_phases(
    project_config: ProjectConfig, project_path: Path
) -> tuple[bool, str | None]:
    """Run configured test phases sequentially. Returns (passed, failed_phase).

    Stops on first failure. Returns (True, None) if all phases pass.
    """
    env = _project_env()
    phases = [
        ("unit", project_config.test_unit),
        ("integration", project_config.test_integration),
        ("component", project_config.test_component),
    ]
    for phase_name, command in phases:
        if command is None:
            continue
        rprint(f"  [dim]$ {command}[/]")
        try:
            completed = subprocess.run(
                shlex.split(command),
                cwd=project_path,
                timeout=600,
                text=True,
                env=env,
            )
        except subprocess.TimeoutExpired:
            rprint(f"  [bold red]FAIL[/] {phase_name} timed out after 600s")
            return False, phase_name
        if completed.returncode != 0:
            return False, phase_name
    return True, None


@dataclass
class GradleFinding:
    """Proxy for one Gradle catalogue target across both finding lists.

    Satisfies the :class:`Finding` protocol.  ``kind`` replaces concrete-type
    checks when choosing labels and commit messages, and lifecycle writes fan
    out to every original so serialisation stays consistent.
    """

    pkg_name: str
    installed_version: str
    target: GradleUpdateTarget
    kind: UpdateKind
    _detail: str
    _originals: list[VulnFinding | UpdateFinding] = field(repr=False)
    _update_status: UpdateStatus | None = None
    _failed_phase: str | None = None
    _flow: Workflow | None = None

    def __post_init__(self) -> None:
        self.update_status = self._update_status
        self.failed_phase = self._failed_phase
        self.flow = self._flow

    @property
    def target_version(self) -> str:
        return self.target.target_version

    @property
    def detail(self) -> str:
        return self._detail

    def set_block(self, block: GradleBlock) -> None:
        """Record current policy state on every original. Not a failure."""
        for original in self._originals:
            original.blocked_reason = block.reason
            original.gradle_block_kind = block.kind

    @property
    def update_status(self) -> UpdateStatus | None:
        return self._update_status

    @update_status.setter
    def update_status(self, value: UpdateStatus | None) -> None:
        self._update_status = value
        for original in self._originals:
            original.update_status = value

    @property
    def failed_phase(self) -> str | None:
        return self._failed_phase

    @failed_phase.setter
    def failed_phase(self, value: str | None) -> None:
        self._failed_phase = value
        for original in self._originals:
            original.failed_phase = value

    @property
    def flow(self) -> Workflow | None:
        return self._flow

    @flow.setter
    def flow(self, value: Workflow | None) -> None:
        self._flow = value
        for original in self._originals:
            original.flow = value


@dataclass(slots=True)
class _GradleGroup:
    target: GradleUpdateTarget
    originals: list[VulnFinding | UpdateFinding] = field(default_factory=list)
    versions: set[str] = field(default_factory=set)
    vuln_details: list[str] = field(default_factory=list)
    update_details: list[str] = field(default_factory=list)
    has_vuln: bool = False


def prepare_gradle_findings(
    scan_result: ScanResult, project: ProjectConfig, minimum_age_days: int
) -> list[GradleFinding]:
    """Group both finding lists by catalogue target, before any selection.

    Returns eligible proxies and persists mapping, conflict, age and stale
    blocks on every affected original.  Grouping is by catalogue version
    reference or inline alias, never by package name.
    """
    groups: dict[str, _GradleGroup] = {}
    order: list[str] = []

    for vuln in scan_result.vulnerabilities:
        if vuln.update_status == UpdateStatus.COMPLETED:
            continue
        recorded = vuln.gradle_target
        if vuln.gradle_block_kind in {"mapping", "conflict"} and recorded is None:
            _apply_block(
                vuln,
                GradleBlock(
                    kind=vuln.gradle_block_kind,
                    reason=vuln.blocked_reason
                    or "structural Gradle block; run 'mm scan' again",
                ),
            )
            continue
        if recorded is None:
            _apply_block(
                vuln,
                GradleBlock(
                    kind="stale",
                    reason="no Gradle target recorded; run 'mm scan' again",
                ),
            )
            continue
        if vuln.gradle_block_kind in {"mapping", "conflict"}:
            _add_to_group(groups, order, recorded, vuln, vuln.vuln_id, is_vuln=True)
            continue
        block = validate_gradle_target_shape(recorded)
        if block is None and not vuln.actionable:
            outcome = resolve_gradle_vulnerability_target(project, vuln)
            if isinstance(outcome, GradleBlock):
                block = outcome
        if block is None and vuln.update_status != UpdateStatus.READY:
            block = validate_gradle_target(project, recorded)
            if block is None:
                outcome = resolve_gradle_vulnerability_target(project, vuln)
                if isinstance(outcome, GradleBlock):
                    block = outcome
                elif _target_identity(outcome) != _target_identity(recorded):
                    block = GradleBlock(
                        kind="stale",
                        reason=(
                            "advisory mapping no longer matches recorded Gradle "
                            "target; run 'mm scan' again"
                        ),
                    )
        if block is None and (
            recorded.target_version != vuln.fixed_version
            or not any(
                m.kind == "library"
                and m.coordinate == vuln.pkg_name
                and m.installed_version == vuln.installed_version
                for m in recorded.members
            )
        ):
            block = GradleBlock(
                kind="stale",
                reason=(
                    "advisory no longer matches recorded Gradle target; "
                    "run 'mm scan' again"
                ),
            )
        if block is not None:
            _apply_block(vuln, block)
            _add_to_group(groups, order, recorded, vuln, vuln.vuln_id, is_vuln=True)
            continue
        _add_to_group(groups, order, recorded, vuln, vuln.vuln_id, is_vuln=True)

    for update in scan_result.updates:
        if update.update_status == UpdateStatus.COMPLETED:
            continue
        if (
            update.gradle_block_kind in {"mapping", "conflict"}
            and update.gradle_target is None
        ):
            _apply_block(
                update,
                GradleBlock(
                    kind=update.gradle_block_kind,
                    reason=update.blocked_reason
                    or "structural Gradle block; run 'mm scan' again",
                ),
            )
            continue  # no known target to join; fresh scan required
        if update.gradle_target is None:
            _apply_block(
                update,
                GradleBlock(
                    kind="stale",
                    reason=(
                        "no Gradle target recorded for this finding; run "
                        "'mm scan' again before updating"
                    ),
                ),
            )
            continue
        _add_to_group(
            groups,
            order,
            update.gradle_target,
            update,
            update.semver_tier.value,
            is_vuln=False,
        )

    prepared: list[GradleFinding] = []
    for key in order:
        group = groups[key]
        block = _group_consistency_block(group)
        if block is not None:
            for original in group.originals:
                _apply_block(original, block)
            continue

        status, failed_phase, flow = _consolidated_lifecycle_state(group.originals)
        if status in (UpdateStatus.READY, UpdateStatus.COMPLETED):
            # Already applied, and never reapplied.  The lifecycle skip must come
            # before revalidation: validate_gradle_target compares the *current*
            # catalogue against the recorded pre-update versions, so running it
            # on an applied group would brand a successful upgrade "stale" and
            # then block submission of work that actually succeeded.
            continue

        block = validate_gradle_target(
            project, group.target
        ) or check_gradle_update_age(group.target, minimum_age_days)
        if block is not None:
            for original in group.originals:
                _apply_block(original, block)
            continue

        for original in group.originals:
            original.blocked_reason = None
            original.gradle_block_kind = None

        prepared.append(
            GradleFinding(
                pkg_name=group.target.display_name,
                installed_version=group.target.members[0].installed_version,
                target=group.target,
                kind="vuln" if group.has_vuln else "update",
                _detail=_group_detail(group),
                _originals=group.originals,
                _update_status=status,
                _failed_phase=failed_phase,
                _flow=flow,
            )
        )
    return prepared


def gradle_groups_from_targets(
    findings: Sequence[VulnFinding | UpdateFinding],
) -> list[GradleFinding]:
    """Order recorded groups without live catalogue or publication checks.

    Validate historical group consistency before constructing lifecycle proxies.
    Invalid originals remain available to the caller as raw blockers.
    """
    groups: dict[str, _GradleGroup] = {}
    order: list[str] = []
    for finding in findings:
        if finding.gradle_target is None:
            _apply_block(
                finding,
                GradleBlock(
                    kind="stale",
                    reason="no Gradle target recorded; run 'mm scan' again",
                ),
            )
            continue
        _add_to_group(
            groups,
            order,
            finding.gradle_target,
            finding,
            finding.detail,
            is_vuln=isinstance(finding, VulnFinding),
        )
    proxies: list[GradleFinding] = []
    for key in order:
        group = groups[key]
        block = _group_consistency_block(group)
        if block is not None:
            for original in group.originals:
                _apply_block(original, block)
            continue
        status, phase, flow = _consolidated_lifecycle_state(group.originals)
        proxies.append(
            GradleFinding(
                pkg_name=group.target.display_name,
                installed_version=group.target.members[0].installed_version,
                target=group.target,
                kind="vuln" if group.has_vuln else "update",
                _detail=_group_detail(group),
                _originals=group.originals,
                _update_status=status,
                _failed_phase=phase,
                _flow=flow,
            )
        )
    return proxies


def _target_identity(target: GradleUpdateTarget):
    return (
        normalise_alias(target.version_ref) if target.version_ref is not None else None,
        frozenset(
            (m.kind, normalise_alias(m.alias), m.coordinate, m.installed_version)
            for m in target.members
        ),
        target.target_version,
    )


def _add_to_group(
    groups: dict[str, _GradleGroup],
    order: list[str],
    target: GradleUpdateTarget,
    finding: VulnFinding | UpdateFinding,
    detail: str,
    *,
    is_vuln: bool,
) -> None:
    block = validate_gradle_target_shape(target)
    if block is not None:
        _apply_block(finding, block)
    if target.version_ref is not None:
        keys = [f"ref:{normalise_alias(target.version_ref)}"]
    else:
        identities: set[tuple[str, str]] = set()
        for member in target.members:
            try:
                alias = assert_safe_text(member.alias, "catalogue alias")
            except GradleError:
                continue
            identities.add((member.kind, normalise_alias(alias)))
        # Malformed metadata joins every known identity solely as a blocker.
        # Empty or unsafe aliases never invent linkage from package names.
        keys = [f"{kind}:{alias}" for kind, alias in sorted(identities)]
    for key in keys:
        group = groups.get(key)
        if group is None:
            group = _GradleGroup(target=target)
            groups[key] = group
            order.append(key)
        group.originals.append(finding)
        group.versions.add(target.target_version)
        if is_vuln:
            group.vuln_details.append(detail)
            group.has_vuln = True
            group.target = target
        else:
            group.update_details.append(detail)


def _group_detail(group: _GradleGroup) -> str:
    """Label a group by what it is.

    A cross-kind group takes vulnerability priority and a vulnerability-labelled
    commit, so its detail is the advisory ids alone — mixing in the ordinary
    update's semver tier would produce commit subjects like
    "fix: upgrade room 2.8.4 -> 2.8.5 for CVE-2026-6666, patch".
    """
    details = group.vuln_details if group.has_vuln else group.update_details
    return ", ".join(dict.fromkeys(details))


def _group_consistency_block(group: _GradleGroup) -> GradleBlock | None:
    for original in group.originals:
        if original.gradle_block_kind in {"mapping", "conflict"}:
            return GradleBlock(
                kind=original.gradle_block_kind,
                reason=original.blocked_reason
                or "structural Gradle block; run 'mm scan' again",
            )
    for original in group.originals:
        if original.gradle_target is not None:
            block = validate_gradle_target_shape(original.gradle_target)
            if block is not None:
                return block
    if len(group.versions) > 1:
        return GradleBlock(
            kind="conflict",
            reason=(
                f"conflicting target versions for "
                f"'{group.target.display_name}': "
                f"{', '.join(sorted(group.versions))}"
            ),
        )
    identity = _target_identity(group.target)[:2]
    if any(
        original.gradle_target is None
        or _target_identity(original.gradle_target)[:2] != identity
        for original in group.originals
    ):
        return GradleBlock(
            kind="stale",
            reason="inconsistent historical Gradle target members; run 'mm scan' again",
        )
    for original in group.originals:
        target = original.gradle_target
        if target is None:
            continue
        if isinstance(original, VulnFinding) and original.fixed_version is None:
            return GradleBlock(
                kind="mapping", reason=f"{original.vuln_id} names no fix version"
            )
        finding_version = (
            original.fixed_version
            if isinstance(original, VulnFinding)
            else original.latest_version
        )
        if finding_version != target.target_version:
            return GradleBlock(
                kind="stale",
                reason=(
                    "finding version no longer matches recorded Gradle target; "
                    "run 'mm scan' again"
                ),
            )
        if isinstance(original, UpdateFinding) and any(
            member.installed_version != original.installed_version
            for member in target.members
        ):
            return GradleBlock(
                kind="stale",
                reason=(
                    "update installed version no longer matches recorded Gradle "
                    "members; run 'mm scan' again"
                ),
            )
        if isinstance(original, VulnFinding) and not any(
            m.kind == "library"
            and m.coordinate == original.pkg_name
            and m.installed_version == original.installed_version
            for m in target.members
        ):
            return GradleBlock(
                kind="stale",
                reason=(
                    "advisory no longer matches recorded Gradle members; "
                    "run 'mm scan' again"
                ),
            )
    if (
        len(
            {
                (original.update_status, original.flow, original.failed_phase)
                for original in group.originals
            }
        )
        > 1
    ):
        return GradleBlock(
            kind="stale",
            reason=(
                f"inconsistent update state within "
                f"'{group.target.display_name}'; rescan required"
            ),
        )
    return None


def _apply_block(finding: VulnFinding | UpdateFinding, block: GradleBlock) -> None:
    if finding.gradle_block_kind in {"mapping", "conflict"}:
        block = GradleBlock(
            kind=finding.gradle_block_kind,
            reason=finding.blocked_reason
            or "structural Gradle block; run 'mm scan' again",
        )
    finding.blocked_reason = block.reason
    finding.gradle_block_kind = block.kind


def process_findings(
    findings: Sequence[Finding],
    project_config: ProjectConfig,
    cfg: _WorkflowConfig | None = None,
    *,
    flow: Workflow,
    minimum_age_days: int = 7,
    on_failure: FailureStrategy = "continue",
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
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
    has_tests = has_test_config(project_config)

    for f in findings:
        flow_cfg = _workflow_config(f, cfg)
        rprint(
            f"\n  {flow_cfg.label} {f.pkg_name} {f.installed_version} "
            f"-> {f.target_version} ({f.detail})"
        )

        if isinstance(f, GradleFinding):
            outcome = _apply_gradle_finding(f, project_config, minimum_age_days)
            if isinstance(outcome, GradleBlock):
                rprint(f"  [bold yellow]BLOCKED[/] {f.pkg_name} — {outcome.reason}")
                f.set_block(outcome)
                _persist_status(scan_result, project_name, results_dir)
                results.append(
                    UpdateResult(
                        pkg_name=f.pkg_name,
                        kind=flow_cfg.kind,
                        passed=False,
                        blocked_reason=outcome.reason,
                    )
                )
                continue
            applied = outcome
        else:
            applied = _apply_update(
                project_config.package_manager,
                f.pkg_name,
                f.target_version,
                project_path,
            )

        if not applied:
            results.append(
                _record_failure(
                    f,
                    flow_cfg.kind,
                    "apply",
                    project_path,
                    scan_result,
                    flow,
                    project_name,
                    results_dir,
                    discard=on_failure == "continue",
                )
            )
            if on_failure == "stop":
                break
            continue

        passed, failed_phase = True, None
        if has_tests:
            passed, failed_phase = run_test_phases(project_config, project_path)

        if passed:
            if not current_change_has_changes(project_path):
                rprint(f"  [bold green]PASS[/] {f.pkg_name} [dim](already applied)[/]")
                f.update_status = UpdateStatus.READY
                f.failed_phase = None
                f.flow = flow
            else:
                msg = flow_cfg.commit_fmt.format(
                    pkg=f.pkg_name,
                    old=f.installed_version,
                    new=f.target_version,
                    detail=f.detail,
                )
                if not commit_current_change(project_path, msg):
                    results.append(
                        _record_failure(
                            f,
                            flow_cfg.kind,
                            "commit",
                            project_path,
                            scan_result,
                            flow,
                            project_name,
                            results_dir,
                            discard=on_failure == "continue",
                        )
                    )
                    if on_failure == "stop":
                        break
                    continue
                if not create_or_reset_bookmark(
                    _WORKFLOW_BOOKMARKS[flow], project_path, "@-"
                ):
                    results.append(
                        _record_failure(
                            f,
                            flow_cfg.kind,
                            "commit",
                            project_path,
                            scan_result,
                            flow,
                            project_name,
                            results_dir,
                            discard=False,
                        )
                    )
                    break
                rprint(f"  [bold green]PASS[/] {f.pkg_name}")
                f.update_status = UpdateStatus.READY
                f.failed_phase = None
                f.flow = flow
        else:
            rprint(f"  [bold red]FAIL[/] {f.pkg_name} — {failed_phase} failed")
            if on_failure == "continue":
                discard_current_change(project_path)
            f.update_status = UpdateStatus.FAILED
            f.failed_phase = failed_phase
            f.flow = flow

        _persist_status(scan_result, project_name, results_dir)
        results.append(
            UpdateResult(
                pkg_name=f.pkg_name,
                kind=flow_cfg.kind,
                passed=passed,
                failed_phase=failed_phase,
            )
        )

        if not passed and on_failure == "stop":
            break

    return results


def _workflow_config(
    finding: Finding,
    cfg: _WorkflowConfig | None,
) -> _WorkflowConfig:
    """Return flow config for a finding, inferring it when omitted."""
    if cfg is not None:
        return cfg
    if isinstance(finding, GradleFinding):
        return _VULN_STACK if finding.kind == "vuln" else _UPDATE_STACK
    vuln_types = (VulnFinding, _ConsolidatedVuln)
    return _VULN_STACK if isinstance(finding, vuln_types) else _UPDATE_STACK


def _record_failure(
    finding: Finding,
    kind: UpdateKind,
    phase: str,
    project_path: Path,
    scan_result: ScanResult | None,
    flow: Workflow,
    project_name: str,
    results_dir: Path | None,
    *,
    discard: bool = True,
) -> UpdateResult:
    """Mark finding as failed, optionally discard changes, persist and return."""
    if discard:
        discard_current_change(project_path)
    finding.update_status = UpdateStatus.FAILED
    finding.failed_phase = phase
    finding.flow = flow
    _persist_status(scan_result, project_name, results_dir)
    return UpdateResult(
        pkg_name=finding.pkg_name,
        kind=kind,
        passed=False,
        failed_phase=phase,
    )


def _results_path(project_name: str, results_dir: Path) -> Path:
    """Return the path to a project's scan results file."""
    return results_dir / f"{sanitise_project_name(project_name)}.json"


def _project_env() -> dict[str, str]:
    """Return a copy of os.environ with venv isolation.

    Delegates to :func:`maintenance_man.env.project_env`.
    """
    return project_env()


def _persist_status(
    scan_result: ScanResult | None,
    project_name: str,
    results_dir: Path | None,
) -> None:
    """Save scan results if tracking args are provided."""
    if scan_result is not None and results_dir is not None:
        save_scan_results(project_name, results_dir, scan_result)


def _apply_gradle_finding(
    finding: GradleFinding, project_config: ProjectConfig, minimum_age_days: int
) -> GradleBlock | bool:
    """Revalidate, then apply one Gradle group.

    Returns a block when policy withholds the change, True after a verified
    apply, and False when the adapter raised — which means mutation may have
    begun and the existing discard/preserve policy must run.
    """
    block = validate_gradle_target(project_config, finding.target)
    if block is None:
        block = check_gradle_update_age(finding.target, minimum_age_days)
    if block is not None:
        return block
    try:
        late = apply_gradle_update(project_config, finding.target)
    except GradleError as e:
        rprint(f"  [bold red]FAIL[/] {e}")
        return False
    return late if late is not None else True


def _apply_update(
    package_manager: str, pkg_name: str, version: str, project_path: Path
) -> bool:
    """Apply a single package update. Returns True on success."""
    env = _project_env()
    try:
        commands = get_update_commands(package_manager, pkg_name, version, project_path)
    except (UvDependencyError, ValueError) as e:
        rprint(f"  [bold red]FAIL[/] {e}")
        return False

    for cmd in commands:
        completed = subprocess.run(
            cmd,
            cwd=project_path,
            timeout=300,
            capture_output=True,
            text=True,
            env=env,
        )
        if completed.returncode != 0:
            rprint(
                f"  [bold red]FAIL[/] Package manager command failed: "
                f"{' '.join(cmd)}\n  {completed.stderr.strip()}"
            )
            return False

    # Maven needs a second command to finalise
    if package_manager == "mvn":
        commit = subprocess.run(
            ["mvn", "versions:commit"],
            cwd=project_path,
            timeout=120,
            capture_output=True,
            text=True,
            env=env,
        )
        if commit.returncode != 0:
            rprint(
                f"  [bold red]FAIL[/] mvn versions:commit failed: "
                f"{commit.stderr.strip()}"
            )
            return False
    return True


def gradle_run_path(project: str) -> Path:
    root = _config.MM_HOME / "gradle-runs"
    target = root / f"{sanitise_project_name(project)}.json"
    if target.parent.resolve() != root.resolve():
        raise GradleError("Invalid Gradle run path")
    return target


def save_gradle_run(path: Path, run: GradleRun) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise GradleError("Refusing symlinked Gradle run ledger")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".gradle-run-",
            delete=False,
        ) as stream:
            temporary = stream.name
            stream.write(run.model_dump_json(indent=2))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise GradleError(f"Cannot persist Gradle run: {exc}") from exc
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def load_gradle_run(path: Path) -> GradleRun | None:
    if path.is_symlink():
        raise GradleError("Refusing symlinked Gradle run ledger")
    try:
        return GradleRun.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise GradleError(f"Invalid Gradle run ledger: {exc}") from exc


def retire_gradle_context(context: ComparisonContext) -> None:
    """Clean up retired evidence without invalidating an already saved transition."""
    try:
        release_comparison_context(context)
    except (OSError, GradleError) as exc:
        logging.getLogger(__name__).warning(
            "Could not release retired Gradle cache %s: %s",
            context.private_cache_path,
            exc,
        )


def discard_unpersisted_gradle_context(
    project_name: str, context: ComparisonContext
) -> None:
    # A failed fsync may follow a successful replace. Never delete the database
    # that the durable ledger now references, even when its save raised.
    try:
        durable = load_gradle_run(gradle_run_path(project_name))
    except GradleError:
        return
    if (
        durable is None
        or durable.context.private_cache_path != context.private_cache_path
    ):
        retire_gradle_context(context)


def _replace_gradle_attempt(run: GradleRun, attempt: AttemptState) -> GradleRun:
    attempts = tuple(
        attempt
        if old.candidate.target.group_key == attempt.candidate.target.group_key
        else old
        for old in run.attempts
    )
    if not any(
        old.candidate.target.group_key == attempt.candidate.target.group_key
        for old in run.attempts
    ):
        attempts += (attempt,)
    return GradleRun.model_validate(
        run.model_copy(update={"attempts": attempts}).model_dump(mode="json")
    )


def gradle_check_commands(project: ProjectConfig) -> tuple[str, ...]:
    tests = tuple(
        command
        for command in (
            project.test_unit,
            project.test_integration,
            project.test_component,
        )
        if command
    )
    if not project.build_command or not tests:
        raise GradleError(
            "Setup prerequisite: configure build_command and at least one test phase"
        )
    return (project.build_command, *tests)


def run_gradle_checks(project: ProjectConfig, project_name: str) -> CheckEvidence:
    commands = gradle_check_commands(project)
    checks_started = time.monotonic()
    try:
        run_build(project_name, commands[0], project.path)
    except BuildError as exc:
        raise GradleError(
            f"Build prerequisite/failure: {exc}; "
            "SDK and wrapper repairs require manual preparation"
        ) from exc
    logging.getLogger(__name__).info(
        "Gradle baseline/update build %.3fs", time.monotonic() - checks_started
    )
    tests_started = time.monotonic()
    passed, phase = run_test_phases(project, project.path)
    logging.getLogger(__name__).info(
        "Gradle configured tests %.3fs", time.monotonic() - tests_started
    )
    if not passed:
        raise GradleError(f"Gradle test phase failed: {phase}")
    return CheckEvidence(
        commands=commands,
        command_digests=tuple(
            hashlib.sha256(command.encode()).hexdigest() for command in commands
        ),
        success=True,
        checked_at=datetime.now(timezone.utc),
    )


def capture_checked_gradle_snapshot(
    project: ProjectConfig,
    project_name: str,
    context: ComparisonContext,
    *,
    expected_tree: str | None = None,
    target: GradleUpdateTarget | None = None,
) -> tuple[CheckEvidence, GradleSnapshot]:
    """Bind build, tests and security evidence to one unchanged source tree."""
    tree = expected_tree or revision_tree_id(project.path)
    if revision_tree_id(project.path) != tree:
        raise GradleError("Working tree differs from the verification revision")
    if target is not None:
        block = validate_gradle_recovery(project, target)
        if block is not None:
            raise GradleError(block.reason)
    checks = run_gradle_checks(project, project_name)
    if revision_tree_id(project.path) != tree:
        raise GradleError("Source tree changed during build or tests")
    snapshot = capture_gradle_snapshot(project, context)
    if isinstance(snapshot, IncompleteResolution):
        raise GradleError("Coverage incomplete: " + "; ".join(snapshot.reasons))
    if snapshot.tree_id != tree or revision_tree_id(project.path) != tree:
        raise GradleError("Source tree changed during security capture")
    return checks, snapshot


def start_gradle_run(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    base_commit_id: str,
    context: ComparisonContext,
    candidates: tuple[GradleCandidate, ...],
) -> GradleRun:
    _, baseline = capture_checked_gradle_snapshot(
        project,
        project_name,
        context,
        expected_tree=revision_tree_id(project.path, base_commit_id),
    )
    bookmark = _WORKFLOW_BOOKMARKS[flow]
    run = GradleRun(
        project=project_name,
        flow=flow,
        base_commit_id=base_commit_id,
        managed_bookmark=bookmark,
        managed_tip_id=base_commit_id,
        context=context,
        initial_snapshot=baseline,
        accepted_snapshot=baseline,
        attempts=tuple(PlannedAttempt(candidate=candidate) for candidate in candidates),
    )
    save_gradle_run(gradle_run_path(project_name), run)
    return run


def verify_applied_gradle_attempt(
    run: GradleRun,
    candidate: GradleCandidate,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    committed_revision: str | None = None,
) -> GradleRun:
    path = gradle_run_path(run.project)
    routing = gradle_routing_prerequisite(project)
    if routing is not None:
        raise GradleError(routing.reason)
    checks, after = capture_checked_gradle_snapshot(
        project,
        run.project,
        run.context,
        target=candidate.target,
        expected_tree=(
            revision_tree_id(project.path, committed_revision)
            if committed_revision is not None
            else None
        ),
    )
    # Persist the rejected snapshot too: it is diagnostic evidence, not READY.
    observed = ApplyingAttempt(
        candidate=candidate, baseline=run.accepted_snapshot, checks=checks, after=after
    )
    run = _replace_gradle_attempt(run, observed)
    save_gradle_run(path, run)
    comparison = compare_gradle_snapshots(run.accepted_snapshot, after, candidate)
    if not isinstance(comparison, VerifiedComparison):
        raise GradleError(
            "Security verification failed: " + "; ".join(comparison.reasons)
        )
    block = evaluate_gradle_candidate_age(
        candidate, minimum_age_days, publication, datetime.now(timezone.utc)
    )
    if block is not None:
        raise GradleError(block.reason)
    checked_tree = revision_tree_id(project.path)
    if checked_tree != after.tree_id:
        raise GradleError("Tree changed after security verification")
    prepared = ApplyingAttempt(
        candidate=candidate,
        baseline=run.accepted_snapshot,
        checks=checks,
        after=after,
        checked_tree_id=checked_tree,
    )
    run = _replace_gradle_attempt(run, prepared)
    save_gradle_run(path, run)
    if committed_revision is None:
        if not current_change_has_changes(project.path):
            raise GradleError("Candidate made no tracked source change")
        target = candidate.target
        if not commit_current_change(
            project.path,
            f"chore: bump {target.display_name} to {target.target_version}",
        ):
            raise GradleError("Could not commit verified Gradle update")
        commit_id = exact_commit_id(project.path, "@-")
    else:
        commit_id = exact_commit_id(project.path, committed_revision)
    if revision_tree_id(project.path, commit_id) != checked_tree:
        raise GradleError("Accepted commit tree differs from checked tree")
    prepared = prepared.model_copy(update={"accepted_commit_id": commit_id})
    run = _replace_gradle_attempt(run, prepared)
    save_gradle_run(path, run)
    if not create_or_reset_bookmark(run.managed_bookmark, project.path, commit_id):
        raise GradleError("Could not bind managed bookmark to accepted commit")
    receipt = VerificationReceipt(
        checked_tree_id=checked_tree,
        accepted_commit_id=commit_id,
        baseline_snapshot_id=run.accepted_snapshot.snapshot_id,
        after_snapshot_id=after.snapshot_id,
        context_identity=run.context.identity,
        checks=checks,
        publications=publication.evidence_for(candidate),
        verified_fixes=comparison.removed,
        residual_keys=comparison.residual,
    )
    accepted = ReadyAttempt(
        candidate=candidate,
        baseline=run.accepted_snapshot,
        after=after,
        receipt=receipt,
    )
    run = _replace_gradle_attempt(run, accepted).model_copy(
        update={"managed_tip_id": commit_id, "accepted_snapshot": after}
    )
    run = GradleRun.model_validate(run.model_dump(mode="json"))
    save_gradle_run(path, run)
    return run


def process_gradle_run(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> GradleRun:
    for planned in tuple(run.attempts):
        if not isinstance(planned, PlannedAttempt):
            continue
        candidate = planned.candidate
        block = validate_gradle_target(project, candidate.target)
        age = gradle_routing_prerequisite(project) or evaluate_gradle_candidate_age(
            candidate, minimum_age_days, publication, datetime.now(timezone.utc)
        )
        reason = block.reason if block else age.reason if age else None
        if reason:
            run = _replace_gradle_attempt(
                run, WithheldAttempt(candidate=candidate, reason=reason)
            )
            save_gradle_run(gradle_run_path(run.project), run)
            continue
        if not context_inputs_valid(run.context, project, datetime.now(timezone.utc)):
            raise GradleError(
                "Comparison context expired or changed; "
                "rebuild evidence before continuing"
            )
        run = _replace_gradle_attempt(
            run, ApplyingAttempt(candidate=candidate, baseline=run.accepted_snapshot)
        )
        save_gradle_run(gradle_run_path(run.project), run)
        try:
            block = apply_gradle_update(project, candidate.target)
            if block is not None:
                raise GradleError(block.reason)
            run = verify_applied_gradle_attempt(
                run, candidate, project, publication, minimum_age_days
            )
        except (GradleError, TrivyScanError) as exc:
            # Read latest pre-effect intent to retain commit-crash evidence.
            latest = load_gradle_run(gradle_run_path(run.project))
            if latest is not None:
                run = latest
            state = next(
                item
                for item in run.attempts
                if item.candidate.target.group_key == candidate.target.group_key
            )
            if isinstance(state, ApplyingAttempt) and state.checked_tree_id is not None:
                # A checked commit may already exist. Recovery must reconcile it;
                # never discard or synthesize a failure after that irreversible effect.
                raise
            failed = FailedAttempt(
                candidate=candidate,
                baseline=run.accepted_snapshot,
                reason=str(exc),
                after=state.after if isinstance(state, ApplyingAttempt) else None,
            )
            run = _replace_gradle_attempt(run, failed)
            save_gradle_run(gradle_run_path(run.project), run)
            if run.flow == Workflow.UPDATE:
                if (
                    not discard_current_change(project.path)
                    or revision_tree_id(project.path) != run.accepted_snapshot.tree_id
                ):
                    raise GradleError(
                        "Could not restore the latest accepted Gradle baseline"
                    ) from exc
            else:
                return run
    return run


def gradle_run_finalization_check(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> None:
    routing = gradle_routing_prerequisite(project)
    if routing is not None:
        raise GradleError(routing.reason)
    if any(
        isinstance(attempt, (ApplyingAttempt, FailedAttempt, PlannedAttempt))
        for attempt in run.attempts
    ):
        raise GradleError("Unfinished or failed Gradle attempt prevents finalization")
    accepted = [
        attempt
        for attempt in run.attempts
        if isinstance(attempt, (ReadyAttempt, CompletedAttempt))
    ]
    if not accepted:
        raise GradleError("No verified Gradle update to finalize")
    if not context_inputs_valid(run.context, project, datetime.now(timezone.utc)):
        raise GradleError("Final comparison context is stale")
    if (
        exact_commit_id(project.path, run.managed_bookmark) != run.managed_tip_id
        or revision_tree_id(project.path, run.managed_tip_id)
        != run.accepted_snapshot.tree_id
    ):
        raise GradleError("Managed tip differs from the verified snapshot")
    if tuple(gradle_check_commands(project)) != accepted[-1].receipt.checks.commands:
        raise GradleError("Configured verification commands changed")
    probe = accepted[-1].candidate.model_copy(
        update={"origins": frozenset({"ordinary"})}
    )
    comparison = compare_gradle_snapshots(
        run.initial_snapshot, run.accepted_snapshot, probe
    )
    if not isinstance(comparison, VerifiedComparison):
        raise GradleError("Final snapshot regressed against original run baseline")
    credited = frozenset(
        key for attempt in accepted for key in attempt.receipt.verified_fixes
    )
    if credited & frozenset(item.key for item in run.accepted_snapshot.findings):
        raise GradleError("An earlier credited fix was reintroduced")
    for attempt in accepted:
        block = evaluate_gradle_candidate_age(
            attempt.candidate, minimum_age_days, publication, datetime.now(timezone.utc)
        )
        if block is not None:
            raise GradleError(block.reason)


@contextmanager
def _gradle_evidence_workspace(
    project: ProjectConfig, revision: str
) -> Iterator[ProjectConfig]:
    resolved = exact_commit_id(project.path, revision)
    container = Path(tempfile.mkdtemp(prefix="mm-gradle-proof-"))
    token = uuid.uuid4().hex
    marker = container / ".mm-proof-owner"
    marker.write_text(token, encoding="utf-8")
    name = f"mm-proof-{token}"
    root = container / "workspace"
    registered = False
    try:
        result = _run(
            ["jj", "workspace", "add", "--name", name, "-r", resolved, str(root)],
            project.path,
        )
        if result.returncode != 0:
            raise GradleError("Cannot create recorded-baseline proof workspace")
        registered = True
        if not edit_new_change(root, resolved):
            raise GradleError("Cannot create empty proof change")
        yield project.model_copy(update={"path": root})
    finally:
        if registered:
            _run(["jj", "workspace", "forget", name], project.path)
        if (
            not container.is_symlink()
            and marker.is_file()
            and marker.read_text(encoding="utf-8") == token
        ):
            shutil.rmtree(container)


def rebuild_gradle_run_evidence(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    persist: bool = True,
) -> GradleRun:
    routing = gradle_routing_prerequisite(project)
    if routing is not None:
        raise GradleError(routing.reason)
    if any(isinstance(item, ApplyingAttempt) for item in run.attempts):
        raise GradleError("Reconcile interrupted attempt before rebuilding context")
    accepted = [
        item
        for item in run.attempts
        if isinstance(item, (ReadyAttempt, CompletedAttempt))
    ]
    with _gradle_evidence_workspace(project, run.base_commit_id) as base_project:
        catalogue = parse_catalogue(base_project.path / GRADLE_CATALOGUE_RELPATH)
        resolution = collect_gradle_resolution(base_project, catalogue)
        if isinstance(resolution, IncompleteResolution):
            raise GradleError("Recorded baseline cannot produce complete coverage")
        context = initialize_comparison_context(
            base_project, resolution, _config.MM_HOME / "gradle-contexts"
        )
        try:
            _, initial = capture_checked_gradle_snapshot(
                base_project,
                run.project,
                context,
                expected_tree=revision_tree_id(base_project.path, run.base_commit_id),
            )
        except BaseException:
            discard_unpersisted_gradle_context(run.project, context)
            raise
    rebuilt_attempts: dict[str, ReadyAttempt | CompletedAttempt] = {}
    baseline = initial
    try:
        for old in accepted:
            with _gradle_evidence_workspace(
                project, old.receipt.accepted_commit_id
            ) as checked_project:
                checks, after = capture_checked_gradle_snapshot(
                    checked_project,
                    run.project,
                    context,
                    expected_tree=revision_tree_id(
                        checked_project.path, old.receipt.accepted_commit_id
                    ),
                    target=old.candidate.target,
                )
                comparison = compare_gradle_snapshots(baseline, after, old.candidate)
                if not isinstance(comparison, VerifiedComparison):
                    raise GradleError("Recorded accepted change fails fresh comparison")
                block = evaluate_gradle_candidate_age(
                    old.candidate,
                    minimum_age_days,
                    publication,
                    datetime.now(timezone.utc),
                )
                if block is not None:
                    raise GradleError(block.reason)
                if not old.receipt.verified_fixes <= comparison.removed:
                    raise GradleError(
                        "Fresh context cannot prove every credited historical fix"
                    )
                receipt = VerificationReceipt(
                    checked_tree_id=after.tree_id,
                    accepted_commit_id=old.receipt.accepted_commit_id,
                    baseline_snapshot_id=baseline.snapshot_id,
                    after_snapshot_id=after.snapshot_id,
                    context_identity=context.identity,
                    checks=checks,
                    publications=publication.evidence_for(old.candidate),
                    verified_fixes=comparison.removed,
                    residual_keys=comparison.residual,
                )
                updates = {"baseline": baseline, "after": after, "receipt": receipt}
                rebuilt_attempts[old.candidate.target.group_key] = type(
                    old
                ).model_validate(old.model_copy(update=updates).model_dump(mode="json"))
                baseline = after
        attempts = tuple(
            rebuilt_attempts.get(item.candidate.target.group_key, item)
            for item in run.attempts
        )
        # A failed repair is compared against the newly proven accepted tip.
        attempts = tuple(
            item.model_copy(update={"baseline": baseline})
            if isinstance(item, FailedAttempt)
            else item
            for item in attempts
        )
        rebuilt = GradleRun.model_validate(
            run.model_copy(
                update={
                    "context": context,
                    "initial_snapshot": initial,
                    "accepted_snapshot": baseline,
                    "attempts": attempts,
                }
            ).model_dump(mode="json")
        )
        if persist:
            save_gradle_run(gradle_run_path(run.project), rebuilt)
            if run.context.private_cache_path != context.private_cache_path:
                retire_gradle_context(run.context)
        return rebuilt
    except BaseException:
        discard_unpersisted_gradle_context(run.project, context)
        raise


def rollback_failed_gradle_update(run: GradleRun, project: ProjectConfig) -> None:
    if run.flow != Workflow.UPDATE or any(
        isinstance(item, ApplyingAttempt) for item in run.attempts
    ):
        raise GradleError("Rollback requires a failed update ledger")
    if not any(isinstance(item, FailedAttempt) for item in run.attempts):
        raise GradleError("Rollback requires a failed update ledger")
    reclaim_gradle_outputs(project.path)
    if (
        exact_commit_id(project.path, run.managed_bookmark) != run.managed_tip_id
        or exact_commit_id(project.path, "@-") != run.managed_tip_id
        or revision_tree_id(project.path, run.managed_tip_id)
        != run.accepted_snapshot.tree_id
    ):
        raise GradleError("Failed update is not a child of its recorded accepted tip")
    changed = _run(["jj", "diff", "--name-only", "-r", "@"], project.path)
    if changed.returncode != 0 or set(changed.stdout.splitlines()) - {
        str(GRADLE_CATALOGUE_RELPATH)
    }:
        raise GradleError("Failed update contains changes outside the owned catalogue")
    if current_change_has_changes(project.path) and not discard_current_change(
        project.path
    ):
        raise GradleError("Could not restore the latest accepted Gradle baseline")
    if (
        current_change_has_changes(project.path)
        or revision_tree_id(project.path) != run.accepted_snapshot.tree_id
    ):
        raise GradleError("Failed update rollback did not restore the accepted tree")


def reconcile_gradle_applying(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> GradleRun:
    routing = gradle_routing_prerequisite(project)
    if routing is not None:
        raise GradleError(routing.reason)
    pending = [item for item in run.attempts if isinstance(item, ApplyingAttempt)]
    if len(pending) != 1:
        raise GradleError("Expected one interrupted Gradle attempt")
    state = pending[0]
    complete = (
        state.after is not None
        and state.checks is not None
        and state.checked_tree_id is not None
    )
    commit = state.accepted_commit_id
    parent = exact_commit_id(project.path, "@-")
    if not complete or (commit is None and parent == run.managed_tip_id):
        # Includes intent-only, mutation/check interruption and checked intent
        # saved before commit. None is evidence of an accepted commit.
        failed = FailedAttempt(
            candidate=state.candidate,
            baseline=state.baseline,
            reason="Interrupted Gradle attempt requires rollback or committed repair",
            after=state.after,
        )
        run = _replace_gradle_attempt(run, failed)
        save_gradle_run(gradle_run_path(run.project), run)
        if run.flow == Workflow.UPDATE:
            rollback_failed_gradle_update(run, project)
        return run
    if commit is None:
        if current_change_has_changes(project.path):
            raise GradleError(
                "Interrupted working copy is not an empty committed child"
            )
        commit = parent
    ancestry = is_ancestor(project.path, run.managed_tip_id, commit)
    if not ancestry.ok or not ancestry.value or commit == run.managed_tip_id:
        raise GradleError("Interrupted checked commit has no trustworthy run ancestry")
    if (
        revision_tree_id(project.path, commit) != state.checked_tree_id
        or state.after.tree_id != state.checked_tree_id
    ):
        raise GradleError("Interrupted commit differs from checked tree")
    current_tip = exact_commit_id(project.path, run.managed_bookmark)
    if current_tip not in {run.managed_tip_id, commit}:
        raise GradleError("Managed bookmark moved outside interrupted attempt")
    block = validate_gradle_recovery(project, state.candidate.target)
    if block is not None:
        raise GradleError(block.reason)
    after, checks, checked_tree = state.after, state.checks, state.checked_tree_id
    if not context_inputs_valid(run.context, project, datetime.now(timezone.utc)):
        # Keep the on-disk intent until BOTH historical accepted work and the
        # checked interrupted commit have been proven under one fresh context.
        previous_context = run.context
        prefix = run.model_copy(
            update={
                "attempts": tuple(item for item in run.attempts if item is not state)
            }
        )
        prefix = rebuild_gradle_run_evidence(
            prefix, project, publication, minimum_age_days, persist=False
        )
        try:
            with _gradle_evidence_workspace(project, commit) as checked_project:
                checks, after = capture_checked_gradle_snapshot(
                    checked_project,
                    run.project,
                    prefix.context,
                    expected_tree=state.checked_tree_id,
                    target=state.candidate.target,
                )
                state = state.model_copy(
                    update={
                        "baseline": prefix.accepted_snapshot,
                        "after": after,
                        "checks": checks,
                        "accepted_commit_id": commit,
                    }
                )
                run = _replace_gradle_attempt(prefix, state)
                save_gradle_run(gradle_run_path(run.project), run)
                if (
                    previous_context.private_cache_path
                    != prefix.context.private_cache_path
                ):
                    retire_gradle_context(previous_context)
        except BaseException:
            discard_unpersisted_gradle_context(run.project, prefix.context)
            raise
    comparison = compare_gradle_snapshots(state.baseline, after, state.candidate)
    if not isinstance(comparison, VerifiedComparison):
        raise GradleError("Interrupted comparison does not prove acceptance")
    block = evaluate_gradle_candidate_age(
        state.candidate, minimum_age_days, publication, datetime.now(timezone.utc)
    )
    if block is not None:
        raise GradleError(block.reason)
    if not create_or_reset_bookmark(run.managed_bookmark, project.path, commit):
        raise GradleError("Cannot bind interrupted accepted bookmark")
    receipt = VerificationReceipt(
        checked_tree_id=checked_tree,
        accepted_commit_id=commit,
        baseline_snapshot_id=state.baseline.snapshot_id,
        after_snapshot_id=after.snapshot_id,
        context_identity=run.context.identity,
        checks=checks,
        publications=publication.evidence_for(state.candidate),
        verified_fixes=comparison.removed,
        residual_keys=comparison.residual,
    )
    accepted = ReadyAttempt(
        candidate=state.candidate,
        baseline=state.baseline,
        after=after,
        receipt=receipt,
    )
    run = _replace_gradle_attempt(run, accepted).model_copy(
        update={"managed_tip_id": commit, "accepted_snapshot": after}
    )
    run = GradleRun.model_validate(run.model_dump(mode="json"))
    save_gradle_run(gradle_run_path(run.project), run)
    return run


def continue_gradle_resolve(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> GradleRun:
    routing = gradle_routing_prerequisite(project)
    if routing is not None:
        raise GradleError(routing.reason)
    if run.flow != Workflow.RESOLVE:
        raise GradleError("Continuation requires a resolve-owned Gradle run")
    reclaim_gradle_outputs(project.path)
    if current_change_has_changes(project.path):
        raise GradleError("Commit or discard manual changes before --continue")
    repaired_commit = exact_commit_id(project.path, "@-")
    ancestry = is_ancestor(project.path, run.managed_tip_id, repaired_commit)
    if not ancestry.ok or not ancestry.value or repaired_commit == run.managed_tip_id:
        raise GradleError("Repair must be a committed descendant of the managed tip")
    failures = [item for item in run.attempts if isinstance(item, FailedAttempt)]
    if len(failures) != 1:
        raise GradleError("Expected exactly one preserved resolve blocker")
    candidate = failures[0].candidate
    block = validate_gradle_recovery(project, candidate.target)
    if block is not None:
        raise GradleError(block.reason)
    if not context_inputs_valid(run.context, project, datetime.now(timezone.utc)):
        run = rebuild_gradle_run_evidence(run, project, publication, minimum_age_days)
    try:
        return verify_applied_gradle_attempt(
            run,
            candidate,
            project,
            publication,
            minimum_age_days,
            committed_revision=repaired_commit,
        )
    except (GradleError, TrivyScanError) as exc:
        latest = load_gradle_run(gradle_run_path(run.project)) or run
        state = next(
            item
            for item in latest.attempts
            if item.candidate.target.group_key == candidate.target.group_key
        )
        if isinstance(state, ApplyingAttempt) and state.checked_tree_id is not None:
            raise
        failed = FailedAttempt(
            candidate=candidate,
            baseline=latest.accepted_snapshot,
            reason=str(exc),
            after=state.after
            if isinstance(state, (ApplyingAttempt, FailedAttempt))
            else None,
        )
        save_gradle_run(
            gradle_run_path(run.project), _replace_gradle_attempt(latest, failed)
        )
        raise
