from __future__ import annotations

import json
import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from packaging.version import InvalidVersion, Version
from rich import print as rprint

from maintenance_man import sanitise_project_name
from maintenance_man.dependency_age import check_gradle_update_age
from maintenance_man.env import project_env
from maintenance_man.gradle import (
    GradleError,
    apply_gradle_update,
    assert_safe_text,
    normalise_alias,
    resolve_gradle_vulnerability_target,
    validate_gradle_target,
    validate_gradle_target_shape,
)
from maintenance_man.models.config import ProjectConfig
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
from maintenance_man.uv_dependencies import (
    UvDependencyError,
    UvDependencyLocation,
    get_uv_dependency_locations,
)
from maintenance_man.vcs import (
    commit_current_change,
    create_or_reset_bookmark,
    current_change_has_changes,
    discard_current_change,
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
        if vuln.update_status == UpdateStatus.COMPLETED or not vuln.actionable:
            continue
        recorded = vuln.gradle_target
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
        if block is not None:
            _apply_block(vuln, block)
            continue
        _add_to_group(groups, order, recorded, vuln, vuln.vuln_id, is_vuln=True)

    for update in scan_result.updates:
        if update.update_status == UpdateStatus.COMPLETED:
            continue
        if (
            update.gradle_block_kind in {"mapping", "conflict"}
            and update.gradle_target is None
        ):
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
        return
    key = (
        f"ref:{normalise_alias(target.version_ref)}"
        if target.version_ref is not None
        else f"{target.members[0].kind}:{normalise_alias(target.members[0].alias)}"
    )
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
    if len({original.update_status for original in group.originals}) > 1:
        return GradleBlock(
            kind="stale",
            reason=(
                f"inconsistent update state within "
                f"'{group.target.display_name}'; rescan required"
            ),
        )
    return None


def _apply_block(finding: VulnFinding | UpdateFinding, block: GradleBlock) -> None:
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
