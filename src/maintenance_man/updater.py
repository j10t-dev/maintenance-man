import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from rich import print as rprint

from maintenance_man.models.config import PhaseTestConfig, ProjectConfig
from maintenance_man.models.scan import (
    BumpFinding,
    ScanResult,
    SemverTier,
    VulnFinding,
)


class GraphiteNotFoundError(Exception):
    pass


class RepoDirtyError(Exception):
    pass


class NoScanResultsError(Exception):
    pass


class NoPhaseTestConfigError(Exception):
    pass


@dataclass
class UpdateResult:
    """Tracks the outcome of a single update attempt."""

    pkg_name: str
    kind: str  # "vuln" or "bump"
    passed: bool
    failed_phase: str | None = None
    skipped: bool = False


def check_graphite_available() -> None:
    """Raise GraphiteNotFoundError if gt is not on PATH."""
    if shutil.which("gt") is None:
        raise GraphiteNotFoundError(
            "Graphite CLI (gt) is not installed or not on PATH. "
            "Install it from https://graphite.dev/docs/installing-the-cli"
        )


def check_repo_clean(project_path: Path) -> None:
    """Raise RepoDirtyError if the git repo has uncommitted changes."""
    completed = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        cwd=project_path,
        timeout=30,
    )
    if completed.stdout.strip():
        raise RepoDirtyError(
            f"Repository has uncommitted changes:\n{completed.stdout.strip()}"
        )


def load_scan_results(project_name: str, results_dir: Path) -> ScanResult:
    """Load scan results JSON for a project. Raises NoScanResultsError if missing."""
    safe_name = project_name.replace("/", "_").replace("\\", "_").replace("..", "_")
    results_file = results_dir / f"{safe_name}.json"
    if not results_file.exists():
        raise NoScanResultsError(
            f"No scan results found for '{project_name}'. "
            f"Run 'mm scan {project_name}' first."
        )
    data = json.loads(results_file.read_text(encoding="utf-8"))
    return ScanResult.model_validate(data)


def get_update_command(
    package_manager: str, pkg_name: str, version: str
) -> list[str]:
    """Return the shell command to update a package to a specific version."""
    if package_manager == "bun":
        return ["bun", "add", f"{pkg_name}@{version}"]
    elif package_manager == "uv":
        return ["uv", "add", f"{pkg_name}=={version}"]
    elif package_manager == "mvn":
        return [
            "mvn",
            "versions:use-dep-version",
            f"-Dincludes={pkg_name}",
            f"-DdepVersion={version}",
        ]
    else:
        raise ValueError(f"Unsupported package manager: {package_manager}")


def run_test_phases(
    test_config: PhaseTestConfig, project_path: Path
) -> tuple[bool, str | None]:
    """Run configured test phases sequentially. Returns (passed, failed_phase).

    Stops on first failure. Returns (True, None) if all phases pass.
    """
    phases = [
        ("unit", test_config.unit),
        ("integration", test_config.integration),
        ("component", test_config.component),
    ]
    for phase_name, command in phases:
        if command is None:
            continue
        completed = subprocess.run(
            shlex.split(command),
            cwd=project_path,
            timeout=600,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            return False, phase_name
    return True, None


def _apply_update(
    package_manager: str, pkg_name: str, version: str, project_path: Path
) -> bool:
    """Apply a single package update. Returns True on success."""
    cmd = get_update_command(package_manager, pkg_name, version)
    completed = subprocess.run(
        cmd,
        cwd=project_path,
        timeout=300,
        capture_output=True,
        text=True,
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
        )
        if commit.returncode != 0:
            rprint(
                f"  [bold red]FAIL[/] mvn versions:commit failed: "
                f"{commit.stderr.strip()}"
            )
            return False
    return True


def _gt_create(message: str, project_path: Path) -> bool:
    """Create a Graphite branch. Returns True on success."""
    completed = subprocess.run(
        ["gt", "create", "-a", "-m", message],
        cwd=project_path,
        timeout=60,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        rprint(
            f"  [bold red]FAIL[/] gt create failed: {completed.stderr.strip()}"
        )
        return False
    return True


def _gt_checkout_main(project_path: Path) -> None:
    """Return to main branch."""
    completed = subprocess.run(
        ["gt", "checkout", "main"],
        cwd=project_path,
        timeout=30,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] gt checkout main failed: "
            f"{completed.stderr.strip()}"
        )


def sort_bumps_by_risk(bumps: list[BumpFinding]) -> list[BumpFinding]:
    """Sort bumps risk-ascending: PATCH < MINOR < MAJOR < UNKNOWN."""
    order = {
        SemverTier.PATCH: 0,
        SemverTier.MINOR: 1,
        SemverTier.MAJOR: 2,
        SemverTier.UNKNOWN: 3,
    }
    return sorted(bumps, key=lambda b: order.get(b.semver_tier, 99))


def process_vulns(
    vulns: list[VulnFinding],
    project_config: ProjectConfig,
) -> list[UpdateResult]:
    """Process vuln fixes as independent branches off main.

    Each vuln gets its own branch. Failures don't block other vulns.
    """
    if project_config.test is None:
        raise NoPhaseTestConfigError(
            f"No test configuration for project at {project_config.path}"
        )

    results: list[UpdateResult] = []
    project_path = Path(project_config.path)
    test_config = project_config.test

    for v in vulns:
        if not v.actionable:
            continue

        rprint(
            f"\n  [bold red]VULN[/] {v.pkg_name} {v.installed_version} "
            f"-> {v.fixed_version} ({v.vuln_id})"
        )

        # Return to main before each vuln (independent branches)
        _gt_checkout_main(project_path)

        msg = (
            f"fix: upgrade {v.pkg_name} "
            f"{v.installed_version} -> {v.fixed_version} "
            f"for {v.vuln_id}"
        )

        if not _apply_update(
            project_config.package_manager,
            v.pkg_name,
            v.fixed_version,
            project_path,
        ):
            results.append(
                UpdateResult(
                    pkg_name=v.pkg_name,
                    kind="vuln",
                    passed=False,
                    failed_phase="apply",
                )
            )
            continue

        if not _gt_create(msg, project_path):
            results.append(
                UpdateResult(
                    pkg_name=v.pkg_name,
                    kind="vuln",
                    passed=False,
                    failed_phase="gt-create",
                )
            )
            continue

        passed, failed_phase = run_test_phases(test_config, project_path)
        if passed:
            rprint(f"  [bold green]PASS[/] {v.pkg_name}")
        else:
            rprint(f"  [bold red]FAIL[/] {v.pkg_name} — {failed_phase} failed")

        results.append(
            UpdateResult(
                pkg_name=v.pkg_name,
                kind="vuln",
                passed=passed,
                failed_phase=failed_phase,
            )
        )

    # Return to main after all vulns
    _gt_checkout_main(project_path)
    return results


def process_bumps(
    bumps: list[BumpFinding],
    project_config: ProjectConfig,
) -> list[UpdateResult]:
    """Process bumps as a Graphite stack, risk-ascending.

    Stops on first failure. Remaining bumps are marked as skipped.
    """
    if project_config.test is None:
        raise NoPhaseTestConfigError(
            f"No test configuration for project at {project_config.path}"
        )

    results: list[UpdateResult] = []
    project_path = Path(project_config.path)
    test_config = project_config.test
    sorted_bumps = sort_bumps_by_risk(bumps)
    failed = False

    for b in sorted_bumps:
        if failed:
            results.append(
                UpdateResult(
                    pkg_name=b.pkg_name, kind="bump", passed=False, skipped=True
                )
            )
            continue

        rprint(
            f"\n  [bold cyan]BUMP[/] {b.pkg_name} {b.installed_version} "
            f"-> {b.latest_version} ({b.semver_tier.value})"
        )

        if not _apply_update(
            project_config.package_manager,
            b.pkg_name,
            b.latest_version,
            project_path,
        ):
            results.append(
                UpdateResult(
                    pkg_name=b.pkg_name,
                    kind="bump",
                    passed=False,
                    failed_phase="apply",
                )
            )
            failed = True
            continue

        msg = (
            f"bump: {b.pkg_name} "
            f"{b.installed_version} -> {b.latest_version} "
            f"({b.semver_tier.value})"
        )
        if not _gt_create(msg, project_path):
            results.append(
                UpdateResult(
                    pkg_name=b.pkg_name,
                    kind="bump",
                    passed=False,
                    failed_phase="gt-create",
                )
            )
            failed = True
            continue

        passed, failed_phase = run_test_phases(test_config, project_path)
        if passed:
            rprint(f"  [bold green]PASS[/] {b.pkg_name}")
        else:
            rprint(
                f"  [bold red]FAIL[/] {b.pkg_name} — {failed_phase} failed"
            )
            failed = True

        results.append(
            UpdateResult(
                pkg_name=b.pkg_name,
                kind="bump",
                passed=passed,
                failed_phase=failed_phase,
            )
        )

    return results


def submit_stack(project_path: Path) -> bool:
    """Run gt submit --stack. Returns True on success."""
    completed = subprocess.run(
        ["gt", "submit", "--stack"],
        cwd=project_path,
        timeout=120,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0
