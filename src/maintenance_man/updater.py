import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from rich import print as rprint

from maintenance_man.models.config import PhaseTestConfig, ProjectConfig
from maintenance_man.models.scan import (
    UpdateFinding,
    ScanResult,
    SemverTier,
    UpdateStatus,
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
    kind: str  # "vuln" or "update"
    passed: bool
    failed_phase: str | None = None


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

        v.update_status = UpdateStatus.STARTED
        _persist_status(scan_result, project_name, results_dir)

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
            _discard_changes(project_path)
            v.update_status = UpdateStatus.FAILED
            _persist_status(scan_result, project_name, results_dir)
            results.append(
                UpdateResult(
                    pkg_name=v.pkg_name,
                    kind="vuln",
                    passed=False,
                    failed_phase="apply",
                )
            )
            continue

        if not _gt_create(msg, f"fix/{_branch_slug(v.pkg_name)}", project_path):
            _discard_changes(project_path)
            v.update_status = UpdateStatus.FAILED
            _persist_status(scan_result, project_name, results_dir)
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
            v.update_status = UpdateStatus.COMPLETED
        else:
            rprint(f"  [bold red]FAIL[/] {v.pkg_name} — {failed_phase} failed")
            _gt_delete(f"fix/{_branch_slug(v.pkg_name)}", project_path)
            v.update_status = UpdateStatus.FAILED

        _persist_status(scan_result, project_name, results_dir)
        results.append(
            UpdateResult(
                pkg_name=v.pkg_name,
                kind="vuln",
                passed=passed,
                failed_phase=failed_phase,
            )
        )

    # Submit fix stack from the tip (last passing branch)
    passing = [r for r in results if r.passed]
    if passing:
        tip = f"fix/{_branch_slug(passing[-1].pkg_name)}"
        _gt_checkout(tip, project_path)
        ok, output = submit_stack(project_path)
        if ok:
            rprint("  [bold green]Fix stack submitted.[/]")
            if output:
                rprint(f"  [dim]{output}[/]")
        else:
            rprint("  [bold red]Fix stack submit failed.[/]")
            if output:
                rprint(f"  [dim]{output}[/]")
            for r in results:
                if r.passed:
                    r.passed = False
                    r.failed_phase = "submit"
            for v in vulns:
                if v.update_status == UpdateStatus.COMPLETED:
                    v.update_status = UpdateStatus.FAILED
            _persist_status(scan_result, project_name, results_dir)

    # Return to main after all vulns
    _gt_checkout("main", project_path)
    return results


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
    if project_config.test is None:
        raise NoPhaseTestConfigError(
            f"No test configuration for project at {project_config.path}"
        )

    results: list[UpdateResult] = []
    project_path = Path(project_config.path)
    test_config = project_config.test
    sorted_updates = sort_updates_by_risk(updates)

    for u in sorted_updates:
        rprint(
            f"\n  [bold cyan]UPDATE[/] {u.pkg_name} {u.installed_version} "
            f"-> {u.latest_version} ({u.semver_tier.value})"
        )

        u.update_status = UpdateStatus.STARTED
        _persist_status(scan_result, project_name, results_dir)

        if not _apply_update(
            project_config.package_manager,
            u.pkg_name,
            u.latest_version,
            project_path,
        ):
            _discard_changes(project_path)
            u.update_status = UpdateStatus.FAILED
            _persist_status(scan_result, project_name, results_dir)
            results.append(
                UpdateResult(
                    pkg_name=u.pkg_name,
                    kind="update",
                    passed=False,
                    failed_phase="apply",
                )
            )
            continue

        msg = (
            f"update: {u.pkg_name} "
            f"{u.installed_version} -> {u.latest_version} "
            f"({u.semver_tier.value})"
        )
        if not _gt_create(msg, f"bump/{_branch_slug(u.pkg_name)}", project_path):
            _discard_changes(project_path)
            u.update_status = UpdateStatus.FAILED
            _persist_status(scan_result, project_name, results_dir)
            results.append(
                UpdateResult(
                    pkg_name=u.pkg_name,
                    kind="update",
                    passed=False,
                    failed_phase="gt-create",
                )
            )
            continue

        passed, failed_phase = run_test_phases(test_config, project_path)
        if passed:
            rprint(f"  [bold green]PASS[/] {u.pkg_name}")
            u.update_status = UpdateStatus.COMPLETED
        else:
            rprint(
                f"  [bold red]FAIL[/] {u.pkg_name} — {failed_phase} failed"
            )
            _gt_delete(f"bump/{_branch_slug(u.pkg_name)}", project_path)
            u.update_status = UpdateStatus.FAILED

        _persist_status(scan_result, project_name, results_dir)
        results.append(
            UpdateResult(
                pkg_name=u.pkg_name,
                kind="update",
                passed=passed,
                failed_phase=failed_phase,
            )
        )

    # Submit update stack from the tip (last passing branch)
    passing = [r for r in results if r.passed]
    if passing:
        tip = f"bump/{_branch_slug(passing[-1].pkg_name)}"
        _gt_checkout(tip, project_path)
        ok, output = submit_stack(project_path)
        if ok:
            rprint("  [bold green]Update stack submitted.[/]")
            if output:
                rprint(f"  [dim]{output}[/]")
        else:
            rprint("  [bold red]Update stack submit failed.[/]")
            if output:
                rprint(f"  [dim]{output}[/]")
            for r in results:
                if r.passed:
                    r.passed = False
                    r.failed_phase = "submit"
            for u in sorted_updates:
                if u.update_status == UpdateStatus.COMPLETED:
                    u.update_status = UpdateStatus.FAILED
            _persist_status(scan_result, project_name, results_dir)

    # Return to main after all updates
    _gt_checkout("main", project_path)
    return results


def sync_graphite(project_path: Path) -> bool:
    """Sync with remote and delete local branches whose PRs are merged/closed.

    Runs ``gt sync`` to fetch and update trunk, then explicitly deletes any
    tracked ``bump/`` or ``fix/`` branches whose GitHub PRs have been merged
    or closed.  This avoids stale branches blocking future stack submissions.
    """
    _run(["gt", "sync", "--no-interactive"], project_path, timeout=120)

    prefixes = ("bump/", "fix/")
    stale_branches = _gh_list_pr_branches("merged", prefixes, project_path)
    stale_branches |= _gh_list_pr_branches("closed", prefixes, project_path)

    local = _run(
        ["git", "branch", "--format=%(refname:short)"], project_path, timeout=10
    )
    if local.returncode != 0:
        return True

    local_branches = {b.strip() for b in local.stdout.splitlines()}

    # Delete stale branches — gt delete handles metadata + restacks children;
    # fall back to git branch -D for branches Graphite doesn't track.
    for branch in sorted(local_branches & stale_branches):
        if not _gt_delete(branch, project_path):
            _run(["git", "branch", "-D", branch], project_path, timeout=10)

    return True


# ---------------------------------------------------------------------------
# Scan result persistence
# ---------------------------------------------------------------------------


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


def save_scan_results(
    project_name: str, results_dir: Path, scan_result: ScanResult
) -> None:
    """Write scan results (with update statuses) back to disk."""
    safe_name = project_name.replace("/", "_").replace("\\", "_").replace("..", "_")
    results_file = results_dir / f"{safe_name}.json"
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


def check_graphite_available() -> None:
    """Raise GraphiteNotFoundError if gt is not on PATH."""
    if shutil.which("gt") is None:
        raise GraphiteNotFoundError(
            "Graphite CLI (gt) is not installed or not on PATH. "
            "Install it from https://graphite.dev/docs/installing-the-cli"
        )


def check_repo_clean(project_path: Path) -> None:
    """Raise RepoDirtyError if the git repo has uncommitted changes."""
    completed = _run(["git", "status", "--porcelain"], project_path)
    if completed.stdout.strip():
        raise RepoDirtyError(
            f"Repository has uncommitted changes:\n{completed.stdout.strip()}"
        )


def get_current_branch(project_path: Path) -> str:
    """Return the current git branch name."""
    return _run(["git", "branch", "--show-current"], project_path).stdout.strip()


def reset_to_main(project_path: Path) -> None:
    """Discard all changes and check out main."""
    _run(["git", "checkout", "main", "--", "."], project_path)
    _run(["git", "clean", "-fd"], project_path)
    _gt_checkout("main", project_path)


def submit_stack(project_path: Path) -> tuple[bool, str]:
    """Run gt submit --stack. Returns (success, output)."""
    completed = _run(["gt", "submit", "--stack"], project_path, timeout=120)
    output = (
        completed.stdout.strip()
        if completed.returncode == 0
        else completed.stderr.strip()
    )
    return completed.returncode == 0, output


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _run(
    cmd: list[str],
    cwd: Path,
    *,
    timeout: int = 30,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with standard capture settings."""
    return subprocess.run(
        cmd,
        cwd=cwd,
        timeout=timeout,
        capture_output=True,
        text=True,
        env=env,
    )


def _project_env() -> dict[str, str]:
    """Return a copy of os.environ without VIRTUAL_ENV.

    Prevents the host venv leaking into subprocess calls that run inside
    a target project directory (e.g. ``uv run``, ``uv add``).
    """
    return {k: v for k, v in os.environ.items() if k != "VIRTUAL_ENV"}


def _persist_status(
    scan_result: ScanResult | None,
    project_name: str,
    results_dir: Path | None,
) -> None:
    """Save scan results if tracking args are provided."""
    if scan_result is not None and results_dir is not None:
        save_scan_results(project_name, results_dir, scan_result)


def _branch_slug(pkg_name: str) -> str:
    """Normalise a package name into a branch-safe slug."""
    return pkg_name.lstrip("@").replace("/", "-")


def _discard_changes(project_path: Path) -> None:
    """Discard all uncommitted changes in the working tree."""
    _run(["git", "checkout", "--", "."], project_path)
    _run(["git", "clean", "-fd"], project_path)


def _apply_update(
    package_manager: str, pkg_name: str, version: str, project_path: Path
) -> bool:
    """Apply a single package update. Returns True on success."""
    env = _project_env()
    cmd = get_update_command(package_manager, pkg_name, version)
    completed = _run(cmd, project_path, timeout=300, env=env)
    if completed.returncode != 0:
        rprint(
            f"  [bold red]FAIL[/] Package manager command failed: "
            f"{' '.join(cmd)}\n  {completed.stderr.strip()}"
        )
        return False

    # Maven needs a second command to finalise
    if package_manager == "mvn":
        commit = _run(["mvn", "versions:commit"], project_path, timeout=120, env=env)
        if commit.returncode != 0:
            rprint(
                f"  [bold red]FAIL[/] mvn versions:commit failed: "
                f"{commit.stderr.strip()}"
            )
            return False
    return True


def _gt_create(message: str, branch_name: str, project_path: Path) -> bool:
    """Create a Graphite branch, deleting any stale branch with the same name first."""
    cmd = ["gt", "create", branch_name, "-a", "-m", message]
    created = _run(cmd, project_path, timeout=60)
    if created.returncode == 0:
        return True

    if "already exists" not in created.stderr:
        rprint(
            f"  [bold red]FAIL[/] gt create failed: {created.stderr.strip()}"
        )
        return False

    # Stale branch — delete and recreate
    _gt_delete(branch_name, project_path)
    retry = _run(cmd, project_path, timeout=60)
    if retry.returncode != 0:
        rprint(
            f"  [bold red]FAIL[/] gt create (retry) failed: "
            f"{retry.stderr.strip()}"
        )
        return False

    return True


def _gt_delete(branch_name: str, project_path: Path) -> bool:
    """Delete a Graphite branch. Returns True on success."""
    completed = _run(["gt", "delete", "-f", branch_name], project_path)
    if completed.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] gt delete {branch_name} failed: "
            f"{completed.stderr.strip()}"
        )
        return False
    return True


def _gt_checkout(branch: str, project_path: Path) -> bool:
    """Check out a Graphite branch. Returns True on success."""
    completed = _run(["gt", "checkout", branch], project_path)
    if completed.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] gt checkout {branch} failed: "
            f"{completed.stderr.strip()}"
        )
        return False
    return True


def _gh_list_pr_branches(
    state: str, prefixes: tuple[str, ...], project_path: Path
) -> set[str]:
    """Return branch names for PRs in the given state matching any prefix."""
    completed = _run(
        [
            "gh", "pr", "list",
            "--state", state,
            "--json", "headRefName",
            "--jq", ".[].headRefName",
        ],
        project_path,
    )
    if completed.returncode != 0:
        return set()
    return {
        b.strip()
        for b in completed.stdout.splitlines()
        if b.strip().startswith(prefixes)
    }
