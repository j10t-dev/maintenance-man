from __future__ import annotations

import json
import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from packaging.version import InvalidVersion, Version

from maintenance_man import gradle, output, sanitise_project_name
from maintenance_man.env import project_env
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    GradleUpdateTarget,
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    Workflow,
)
from maintenance_man.process import run_logged
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
    gradle_target: GradleUpdateTarget | None

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
    commit_fmt: str


_VULN_STACK = _WorkflowConfig(
    kind="vuln",
    commit_fmt="fix: upgrade {pkg} {old} -> {new} for {detail}",
)

_UPDATE_STACK = _WorkflowConfig(
    kind="update",
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
    """Proxy for saved rows applied and tested as one dependency target.

    Satisfies the :class:`Finding` protocol so it can be used in the update
    processing flows.  Writes to :attr:`update_status`, :attr:`failed_phase`
    and :attr:`flow` are fanned out to every original :class:`VulnFinding` so
    that serialisation (which works on the originals) stays consistent.
    """

    pkg_name: str
    installed_version: str
    _target_version: str
    _detail: str
    _originals: Sequence[VulnFinding | UpdateFinding] = field(repr=False)
    gradle_target: GradleUpdateTarget | None = None
    kind: UpdateKind = "vuln"
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


def group_findings(
    project: ProjectConfig, findings: Sequence[VulnFinding | UpdateFinding]
) -> list[Finding]:
    """Group saved rows into one application/test unit per dependency target."""
    eligible = [
        f
        for f in findings
        if not f.blocked_reason
        and (
            not isinstance(f, VulnFinding)
            or f.actionable
            or f.gradle_target is not None
        )
    ]
    if project.package_manager != "gradle":
        return [
            *consolidate_vulns([f for f in eligible if isinstance(f, VulnFinding)]),
            *sort_updates_by_risk(
                [f for f in eligible if isinstance(f, UpdateFinding)]
            ),
        ]
    groups: dict[str, list[VulnFinding | UpdateFinding]] = {}
    for f in eligible:
        if f.gradle_target is None:
            f.blocked_reason = "Saved scan has no catalogue target; run mm scan first"
            f.gradle_block_kind = "mapping"
            continue
        target = f.gradle_target
        shape = gradle.validate_gradle_target_shape(target)
        if shape is not None:
            f.blocked_reason = shape.reason
            f.gradle_block_kind = shape.kind
            continue
        key = json.dumps(target.model_dump(mode="json"), sort_keys=True)
        groups.setdefault(key, []).append(f)
    result: list[Finding] = []
    for originals in groups.values():
        target = originals[0].gradle_target
        assert target is not None
        status, phase, flow = _consolidated_lifecycle_state(originals)
        result.append(
            _ConsolidatedVuln(
                pkg_name=target.display_name,
                installed_version=target.members[0].installed_version,
                _target_version=target.target_version,
                _detail=", ".join(dict.fromkeys(f.detail for f in originals)),
                _originals=originals,
                gradle_target=target,
                kind="vuln"
                if any(isinstance(f, VulnFinding) for f in originals)
                else "update",
                _update_status=status,
                _failed_phase=phase,
                _flow=flow,
            )
        )
    return result


@dataclass(frozen=True)
class Applied:
    pass


@dataclass(frozen=True)
class Blocked:
    reason: str


@dataclass(frozen=True)
class ApplyFailed:
    reason: str


type ApplyOutcome = Applied | Blocked | ApplyFailed


def apply_finding(project: ProjectConfig, finding: Finding) -> ApplyOutcome:
    try:
        if project.package_manager == "gradle":
            target = finding.gradle_target
            if target is None:
                return Blocked("Saved scan has no catalogue target; run mm scan first")
            # Retry after a status-write interruption may encounter the saved
            # target already applied. Validate it, then run the common tests.
            if gradle.validate_gradle_recovery(project, target) is None:
                return Applied()
            block = gradle.apply_gradle_update(project, target)
            return Blocked(block.reason) if block else Applied()
        if _apply_update(
            project.package_manager,
            finding.pkg_name,
            finding.target_version,
            Path(project.path),
        ):
            return Applied()
        return ApplyFailed("package manager failed")
    except (gradle.GradleError, OSError, subprocess.TimeoutExpired) as exc:
        return ApplyFailed(str(exc))


def process_vulns(
    vulns: list[VulnFinding],
    project_config: ProjectConfig,
    *,
    flow: Workflow,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process vuln fixes in the single-bookmark update flow."""
    actionable: list[VulnFinding | UpdateFinding] = [
        v for v in vulns if v.actionable or v.gradle_target is not None
    ]
    if scan_result is not None:
        targets = [f.gradle_target for f in actionable if f.gradle_target is not None]
        actionable.extend(
            u
            for u in scan_result.updates
            if u.gradle_target is not None and u.gradle_target in targets
        )
    consolidated = group_findings(project_config, actionable)
    return process_findings(
        consolidated,
        project_config,
        _VULN_STACK,
        flow=flow,
        scan_result=scan_result,
        project_name=project_name,
        results_dir=results_dir,
    )


def process_updates(
    updates: list[UpdateFinding],
    project_config: ProjectConfig,
    *,
    flow: Workflow,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process updates in the single-bookmark update flow, risk-ascending."""
    sorted_updates = group_findings(project_config, updates)
    return process_findings(
        sorted_updates,
        project_config,
        _UPDATE_STACK,
        flow=flow,
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
    temporary = results_file.with_suffix(".json.tmp")
    temporary.write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(results_file)


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
        if output.is_verbose():
            output.notice(f"$ {command}")
        try:
            completed = run_logged(
                shlex.split(command),
                cwd=project_path,
                timeout=600,
                env=env,
            )
        except subprocess.TimeoutExpired:
            output.diagnostic("error", f"{phase_name} timed out after 600s")
            return False, phase_name
        if completed.returncode != 0:
            return False, phase_name
    return True, None


def process_findings(
    findings: Sequence[Finding],
    project_config: ProjectConfig,
    cfg: _WorkflowConfig | None = None,
    *,
    flow: Workflow,
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

    def report(finding: Finding, result: UpdateResult, detail: str = "") -> None:
        results.append(result)
        status = (
            "blocked"
            if result.blocked_reason
            else "passed"
            if result.passed
            else "failed"
        )
        reason = result.blocked_reason or " · ".join(
            filter(
                None,
                [
                    f"{result.failed_phase} failed" if result.failed_phase else "",
                    detail,
                ],
            )
        )
        output.outcome(
            project_name or project_path.name,
            flow.value,
            status,
            finding.pkg_name,
            installed=finding.installed_version,
            target=finding.target_version,
            reason=reason,
        )

    for f in findings:
        if f.update_status in (UpdateStatus.READY, UpdateStatus.COMPLETED):
            continue
        flow_cfg = _workflow_config(f, cfg)

        if not has_tests:
            report(f, UpdateResult(f.pkg_name, flow_cfg.kind, False, "configuration"))
            continue
        outcome = apply_finding(project_config, f)
        if isinstance(outcome, Blocked):
            originals = f._originals if isinstance(f, _ConsolidatedVuln) else [f]
            for original in originals:
                if isinstance(original, (VulnFinding, UpdateFinding)):
                    original.blocked_reason = outcome.reason
                    original.gradle_block_kind = "stale"
                    original.update_status = None
                    original.failed_phase = None
                    original.flow = None
            _persist_status(scan_result, project_name, results_dir)
            report(
                f,
                UpdateResult(
                    f.pkg_name, flow_cfg.kind, False, blocked_reason=outcome.reason
                ),
            )
            continue
        if isinstance(outcome, ApplyFailed):
            report(
                f,
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
                ),
                outcome.reason,
            )
            if on_failure == "stop" or results[-1].failed_phase == "rollback":
                break
            continue

        passed, failed_phase = True, None
        if has_tests:
            passed, failed_phase = run_test_phases(project_config, project_path)

        if passed:
            if not current_change_has_changes(project_path):
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
                    report(
                        f,
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
                        ),
                    )
                    if on_failure == "stop" or results[-1].failed_phase == "rollback":
                        break
                    continue
                if not create_or_reset_bookmark(
                    _WORKFLOW_BOOKMARKS[flow], project_path, "@-"
                ):
                    report(
                        f,
                        _record_failure(
                            f,
                            flow_cfg.kind,
                            "bookmark",
                            project_path,
                            scan_result,
                            flow,
                            project_name,
                            results_dir,
                            discard=False,
                        ),
                    )
                    break
                f.update_status = UpdateStatus.READY
                f.failed_phase = None
                f.flow = flow
        else:
            if on_failure == "continue" and not discard_current_change(project_path):
                failed_phase = "rollback"
            f.update_status = UpdateStatus.FAILED
            f.failed_phase = failed_phase
            f.flow = flow

        _persist_status(scan_result, project_name, results_dir)
        report(
            f,
            UpdateResult(
                pkg_name=f.pkg_name,
                kind=flow_cfg.kind,
                passed=passed,
                failed_phase=failed_phase,
            ),
        )

        if not passed and (on_failure == "stop" or failed_phase == "rollback"):
            break

    return results


def _workflow_config(
    finding: Finding,
    cfg: _WorkflowConfig | None,
) -> _WorkflowConfig:
    """Return flow config for a finding, inferring it when omitted."""
    if cfg is not None:
        return cfg
    if isinstance(finding, _ConsolidatedVuln):
        return _VULN_STACK if finding.kind == "vuln" else _UPDATE_STACK
    vuln_types = (VulnFinding,)
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
    if discard and not discard_current_change(project_path):
        phase = "rollback"
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


def _apply_update(
    package_manager: str, pkg_name: str, version: str, project_path: Path
) -> bool:
    """Apply a single package update. Returns True on success."""
    env = _project_env()
    try:
        commands = get_update_commands(package_manager, pkg_name, version, project_path)
    except (UvDependencyError, ValueError) as e:
        output.diagnostic("error", f"{e}")
        return False

    for cmd in commands:
        completed = run_logged(
            cmd,
            cwd=project_path,
            timeout=300,
            env=env,
        )
        if completed.returncode != 0:
            output.diagnostic(
                "error",
                f"Package manager command failed: {' '.join(cmd)} "
                f"(exit {completed.returncode})",
            )
            return False

    # Maven needs a second command to finalise
    if package_manager == "mvn":
        commit = run_logged(
            ["mvn", "versions:commit"],
            cwd=project_path,
            timeout=120,
            env=env,
        )
        if commit.returncode != 0:
            output.diagnostic(
                "error", f"mvn versions:commit failed: exit {commit.returncode}"
            )
            return False
    return True
