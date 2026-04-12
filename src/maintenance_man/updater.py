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
from maintenance_man.env import project_env
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    MaintenanceFlow,
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
)
from maintenance_man.vcs import (
    discard_changes,
    git_commit_all,
    git_has_changes,
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
    flow: MaintenanceFlow | None

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


@dataclass(frozen=True, slots=True)
class _FindingFlowConfig:
    """Varying parameters for a finding processing run."""

    kind: UpdateKind
    label: str
    commit_fmt: str


_VULN_STACK = _FindingFlowConfig(
    kind="vuln",
    label="[bold red]VULN[/]",
    commit_fmt="fix: upgrade {pkg} {old} -> {new} for {detail}",
)

_UPDATE_STACK = _FindingFlowConfig(
    kind="update",
    label="[bold cyan]UPDATE[/]",
    commit_fmt="update: {pkg} {old} -> {new} ({detail})",
)

_RISK_ORDER = {
    SemverTier.PATCH: 0,
    SemverTier.MINOR: 1,
    SemverTier.MAJOR: 2,
    SemverTier.UNKNOWN: 3,
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


def _first_non_none(values: Sequence[str | MaintenanceFlow | None]):
    return next((value for value in values if value is not None), None)


def _consolidated_lifecycle_state(
    group: list[VulnFinding],
) -> tuple[UpdateStatus | None, str | None, MaintenanceFlow | None]:
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
    processing flows.  Writes to :attr:`update_status` are fanned out to
    every original :class:`VulnFinding` so that serialisation (which works on
    the originals) stays consistent.
    """

    pkg_name: str
    installed_version: str
    _target_version: str
    _detail: str
    _originals: list[VulnFinding] = field(repr=False)
    _update_status: UpdateStatus | None = None
    _failed_phase: str | None = None
    _flow: MaintenanceFlow | None = None

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
    def flow(self) -> MaintenanceFlow | None:
        return self._flow

    @flow.setter
    def flow(self, value: MaintenanceFlow | None) -> None:
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


def process_vulns_local(
    vulns: list[VulnFinding],
    project_config: ProjectConfig,
    *,
    flow: MaintenanceFlow,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process vuln fixes in the single-branch update flow."""
    actionable = [v for v in vulns if v.actionable]
    consolidated = consolidate_vulns(actionable)
    return process_findings(
        consolidated,
        project_config,
        _VULN_STACK,
        flow=flow,
        scan_result=scan_result,
        project_name=project_name,
        results_dir=results_dir,
    )


def process_updates_local(
    updates: list[UpdateFinding],
    project_config: ProjectConfig,
    *,
    flow: MaintenanceFlow,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process updates in the single-branch update flow, risk-ascending."""
    sorted_updates = sort_updates_by_risk(updates)
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
    results_file.write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")


def sort_updates_by_risk(updates: list[UpdateFinding]) -> list[UpdateFinding]:
    """Sort updates risk-ascending: PATCH < MINOR < MAJOR < UNKNOWN."""
    return sorted(updates, key=lambda u: _RISK_ORDER[u.semver_tier])


def remove_completed_findings(scan_result: ScanResult) -> None:
    """Remove findings with COMPLETED status from the scan result in place."""
    scan_result.vulnerabilities = [
        v
        for v in scan_result.vulnerabilities
        if v.update_status != UpdateStatus.COMPLETED
    ]
    scan_result.updates = [
        u for u in scan_result.updates if u.update_status != UpdateStatus.COMPLETED
    ]


def get_update_command(package_manager: str, pkg_name: str, version: str) -> list[str]:
    """Return the shell command to update a package to a specific version."""
    match package_manager:
        case "bun":
            return ["bun", "add", f"{pkg_name}@{version}"]
        case "uv":
            return ["uv", "add", f"{pkg_name}=={version}"]
        case "mvn":
            return [
                "mvn",
                "versions:use-dep-version",
                f"-Dincludes={pkg_name}",
                f"-DdepVersion={version}",
            ]
        case _:
            raise ValueError(f"Unsupported package manager: {package_manager}")


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
        completed = subprocess.run(
            shlex.split(command),
            cwd=project_path,
            timeout=600,
            text=True,
            env=env,
        )
        if completed.returncode != 0:
            return False, phase_name
    return True, None


def process_findings(
    findings: Sequence[Finding],
    project_config: ProjectConfig,
    cfg: _FindingFlowConfig | None = None,
    *,
    flow: MaintenanceFlow,
    on_failure: FailureStrategy = "continue",
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process findings on the current branch using plain git.

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
        flow_cfg = _finding_flow_config(f, cfg)
        rprint(
            f"\n  {flow_cfg.label} {f.pkg_name} {f.installed_version} "
            f"-> {f.target_version} ({f.detail})"
        )

        if not apply_update(
            project_config.package_manager,
            f.pkg_name,
            f.target_version,
            project_path,
        ):
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
            if not git_has_changes(project_path):
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
                if not git_commit_all(msg, project_path):
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
                rprint(f"  [bold green]PASS[/] {f.pkg_name}")
                f.update_status = UpdateStatus.READY
                f.failed_phase = None
                f.flow = flow
        else:
            rprint(f"  [bold red]FAIL[/] {f.pkg_name} — {failed_phase} failed")
            if on_failure == "continue":
                discard_changes(project_path)
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


def _finding_flow_config(
    finding: Finding,
    cfg: _FindingFlowConfig | None,
) -> _FindingFlowConfig:
    """Return flow config for a finding, inferring it when omitted."""
    if cfg is not None:
        return cfg
    vuln_types = (VulnFinding, _ConsolidatedVuln)
    return _VULN_STACK if isinstance(finding, vuln_types) else _UPDATE_STACK


def _record_failure(
    finding: Finding,
    kind: UpdateKind,
    phase: str,
    project_path: Path,
    scan_result: ScanResult | None,
    flow: MaintenanceFlow,
    project_name: str,
    results_dir: Path | None,
    *,
    discard: bool = True,
) -> UpdateResult:
    """Mark finding as failed, optionally discard changes, persist and return."""
    if discard:
        discard_changes(project_path)
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


def apply_update(
    package_manager: str, pkg_name: str, version: str, project_path: Path
) -> bool:
    """Apply a single package update. Returns True on success."""
    env = _project_env()
    cmd = get_update_command(package_manager, pkg_name, version)
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
