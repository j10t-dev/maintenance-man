import json
import os
import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from rich import print as rprint

from maintenance_man.models.config import PhaseTestConfig, ProjectConfig
from maintenance_man.models.scan import (
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
)
from maintenance_man.vcs import (
    branch_slug,
    discard_changes,
    gt_checkout,
    gt_create,
    gt_delete,
    submit_stack,
)


class NoScanResultsError(Exception):
    pass


class NoPhaseTestConfigError(Exception):
    pass


type UpdateKind = Literal["vuln", "update"]


class Finding(Protocol):
    """Common interface for VulnFinding and UpdateFinding during stack processing."""

    pkg_name: str
    installed_version: str
    update_status: UpdateStatus | None

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
class _StackConfig:
    """Varying parameters for a stack processing run."""

    branch_prefix: str
    kind: UpdateKind
    label: str
    submit_label: str
    commit_fmt: str


_VULN_STACK = _StackConfig(
    branch_prefix="fix/",
    kind="vuln",
    label="[bold red]VULN[/]",
    submit_label="Fix stack",
    commit_fmt="fix: upgrade {pkg} {old} -> {new} for {detail}",
)

_UPDATE_STACK = _StackConfig(
    branch_prefix="bump/",
    kind="update",
    label="[bold cyan]UPDATE[/]",
    submit_label="Update stack",
    commit_fmt="update: {pkg} {old} -> {new} ({detail})",
)


# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------


def process_vulns(
    vulns: list[VulnFinding],
    project_config: ProjectConfig,
    *,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process vuln fixes as a Graphite stack off main.

    Each vuln gets its own stacked branch. Failures are removed from the
    stack and processing continues.  The fix stack is submitted before
    returning to main.
    """
    actionable = [v for v in vulns if v.actionable]
    return _process_stack(
        actionable,
        project_config,
        _VULN_STACK,
        scan_result=scan_result,
        project_name=project_name,
        results_dir=results_dir,
    )


def process_updates(
    updates: list[UpdateFinding],
    project_config: ProjectConfig,
    *,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process updates as a Graphite stack, risk-ascending.

    Failures are deleted from the stack and processing continues.
    """
    sorted_updates = sort_updates_by_risk(updates)
    return _process_stack(
        sorted_updates,
        project_config,
        _UPDATE_STACK,
        scan_result=scan_result,
        project_name=project_name,
        results_dir=results_dir,
    )


def _process_stack(
    findings: Sequence[Finding],
    project_config: ProjectConfig,
    cfg: _StackConfig,
    *,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process a list of findings as a Graphite stack.

    Each finding gets its own stacked branch. Failures are removed from
    the stack and processing continues. The stack is submitted before
    returning to main.
    """
    if project_config.test is None:
        raise NoPhaseTestConfigError(
            f"No test configuration for project at {project_config.path}"
        )

    results: list[UpdateResult] = []
    project_path = Path(project_config.path)
    test_config = project_config.test

    for f in findings:
        rprint(
            f"\n  {cfg.label} {f.pkg_name} {f.installed_version} "
            f"-> {f.target_version} ({f.detail})"
        )

        f.update_status = UpdateStatus.STARTED
        _persist_status(scan_result, project_name, results_dir)

        msg = cfg.commit_fmt.format(
            pkg=f.pkg_name,
            old=f.installed_version,
            new=f.target_version,
            detail=f.detail,
        )
        branch = f"{cfg.branch_prefix}{branch_slug(f.pkg_name)}"

        if not _apply_update(
            project_config.package_manager,
            f.pkg_name,
            f.target_version,
            project_path,
        ):
            discard_changes(project_path)
            f.update_status = UpdateStatus.FAILED
            _persist_status(scan_result, project_name, results_dir)
            results.append(
                UpdateResult(
                    pkg_name=f.pkg_name,
                    kind=cfg.kind,
                    passed=False,
                    failed_phase="apply",
                )
            )
            continue

        if not gt_create(msg, branch, project_path):
            discard_changes(project_path)
            f.update_status = UpdateStatus.FAILED
            _persist_status(scan_result, project_name, results_dir)
            results.append(
                UpdateResult(
                    pkg_name=f.pkg_name,
                    kind=cfg.kind,
                    passed=False,
                    failed_phase="gt-create",
                )
            )
            continue

        passed, failed_phase = run_test_phases(test_config, project_path)
        if passed:
            rprint(f"  [bold green]PASS[/] {f.pkg_name}")
            f.update_status = UpdateStatus.COMPLETED
        else:
            rprint(f"  [bold red]FAIL[/] {f.pkg_name} — {failed_phase} failed")
            gt_delete(branch, project_path)
            f.update_status = UpdateStatus.FAILED

        _persist_status(scan_result, project_name, results_dir)
        results.append(
            UpdateResult(
                pkg_name=f.pkg_name,
                kind=cfg.kind,
                passed=passed,
                failed_phase=failed_phase,
            )
        )

    # Submit stack from the tip (last passing branch)
    passing = [r for r in results if r.passed]
    if passing:
        tip = f"{cfg.branch_prefix}{branch_slug(passing[-1].pkg_name)}"
        gt_checkout(tip, project_path)
        ok, output = submit_stack(project_path)
        if ok:
            rprint(f"  [bold green]{cfg.submit_label} submitted.[/]")
        else:
            rprint(f"  [bold red]{cfg.submit_label} submit failed.[/]")
            for r in results:
                if r.passed:
                    r.passed = False
                    r.failed_phase = "submit"
            for f in findings:
                if f.update_status == UpdateStatus.COMPLETED:
                    f.update_status = UpdateStatus.FAILED
            _persist_status(scan_result, project_name, results_dir)
        if output:
            rprint(f"  [dim]{output}[/]")

    # Return to main after processing
    gt_checkout("main", project_path)
    return results


# ---------------------------------------------------------------------------
# Scan result persistence
# ---------------------------------------------------------------------------


def _results_path(project_name: str, results_dir: Path) -> Path:
    """Return the path to a project's scan results file."""
    safe = project_name.replace("/", "_").replace("\\", "_").replace("..", "_")
    return results_dir / f"{safe}.json"


def load_scan_results(project_name: str, results_dir: Path) -> ScanResult:
    """Load scan results JSON for a project. Raises NoScanResultsError if missing."""
    results_file = _results_path(project_name, results_dir)
    if not results_file.exists():
        raise NoScanResultsError(
            f"No scan results found for '{project_name}'. "
            f"Run 'mm scan {project_name}' first."
        )
    data = json.loads(results_file.read_text(encoding="utf-8"))
    return ScanResult.model_validate(data)


def save_scan_results(
    project_name: str, results_dir: Path, scan_result: ScanResult
) -> None:
    """Write scan results (with update statuses) back to disk."""
    results_file = _results_path(project_name, results_dir)
    results_file.write_text(
        scan_result.model_dump_json(indent=2), encoding="utf-8"
    )


def sort_updates_by_risk(updates: list[UpdateFinding]) -> list[UpdateFinding]:
    """Sort updates risk-ascending: PATCH < MINOR < MAJOR < UNKNOWN."""
    order = {
        SemverTier.PATCH: 0,
        SemverTier.MINOR: 1,
        SemverTier.MAJOR: 2,
        SemverTier.UNKNOWN: 3,
    }
    return sorted(updates, key=lambda u: order.get(u.semver_tier, 99))


def get_update_command(
    package_manager: str, pkg_name: str, version: str
) -> list[str]:
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


def run_test_phases(
    test_config: PhaseTestConfig, project_path: Path
) -> tuple[bool, str | None]:
    """Run configured test phases sequentially. Returns (passed, failed_phase).

    Stops on first failure. Returns (True, None) if all phases pass.
    """
    env = _project_env()
    phases = [
        ("unit", test_config.unit),
        ("integration", test_config.integration),
        ("component", test_config.component),
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


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _project_env() -> dict[str, str]:
    """Return a copy of os.environ without VIRTUAL_ENV.

    Prevents the host venv leaking into subprocess calls that run inside
    a target project directory (e.g. ``uv run``, ``uv add``).
    """
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)
    return env


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
