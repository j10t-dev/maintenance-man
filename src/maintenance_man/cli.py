import subprocess
import sys
import time
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Annotated, NoReturn

import cyclopts
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from maintenance_man import __version__
from maintenance_man import config as _config
from maintenance_man.config import (
    ConfigError,
    ProjectNotFoundError,
    load_config,
    resolve_project,
)
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.scan import (
    ScanResult,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    sort_vulns_by_severity,
)
from maintenance_man.scanner import (
    TrivyNotFoundError,
    TrivyScanError,
    check_trivy_available,
    scan_project,
)
from maintenance_man.updater import (
    NoScanResultsError,
    _highest_fix_version,
    load_scan_results,
    process_updates,
    process_vulns,
    run_test_phases,
    save_scan_results,
)
from maintenance_man.vcs import (
    GraphiteNotFoundError,
    RepoDirtyError,
    branch_slug,
    check_graphite_available,
    check_repo_clean,
    get_current_branch,
    reset_to_main,
    submit_stack,
    sync_graphite,
)


class ExitCode(IntEnum):
    OK = 0
    ERROR = 1
    VULNS_FOUND = 2
    UPDATES_FOUND = 3
    UPDATE_FAILED = 4
    TEST_FAILED = 5


console = Console()

_TABLE_STYLE = dict(show_edge=False, pad_edge=False, box=None)

app = cyclopts.App(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    version=__version__,
    version_flags=["--version", "-v"],
)


def main() -> None:
    app()


@app.command
def scan(
    project: str | None = None,
    *,
    config: Path | None = None,
) -> None:
    """Scan projects for vulnerabilities and available updates.

    Parameters
    ----------
    project: str | None
        Project name to scan. Scans all if omitted.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)

    try:
        check_trivy_available()
    except TrivyNotFoundError as e:
        _fatal(str(e))

    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    if project:
        proj_config = _resolve_proj(cfg, project)
        try:
            result = _scan_one(project, proj_config, cfg.defaults.min_version_age_days)
        except TrivyScanError as e:
            _fatal(str(e))

        sys.exit(_scan_exit_code(result.has_actionable_vulns, result.has_updates))

    # Scan all projects
    has_vulns = False
    has_updates = False
    for name, proj_config in cfg.projects.items():
        if not proj_config.path.exists():
            console.print(
                f"[bold yellow]Warning:[/] {name} — "
                f"path does not exist: {proj_config.path}"
            )
            continue
        try:
            result = _scan_one(name, proj_config, cfg.defaults.min_version_age_days)
        except TrivyScanError as e:
            console.print(f"[bold red]Error:[/] {name} — {e}")
            continue

        has_vulns |= result.has_actionable_vulns
        has_updates |= result.has_updates

    sys.exit(_scan_exit_code(has_vulns, has_updates))


@app.command
def update(
    project: str,
    *,
    continue_: Annotated[bool, cyclopts.Parameter(name="--continue")] = False,
    config: Path | None = None,
) -> None:
    """Apply updates from scan results to a project.

    Parameters
    ----------
    project: str
        Project name to update.
    continue_: bool
        Re-test a manually fixed failed finding on the current branch.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)

    try:
        check_graphite_available()
    except GraphiteNotFoundError as e:
        _fatal(str(e))

    if not continue_:
        try:
            check_repo_clean(proj_config.path)
        except RepoDirtyError as e:
            console.print(f"[bold yellow]Warning:[/] {e}")
            if Confirm.ask("  Discard changes and reset to main?", default=False):
                reset_to_main(proj_config.path)
            else:
                sys.exit(ExitCode.ERROR)

        if not sync_graphite(proj_config.path):
            _fatal("Failed to sync trunk. Check network and gt auth.")

    results_dir = _config.MM_HOME / "scan-results"
    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError as e:
        _fatal(str(e))

    _require_test_config(project, proj_config)

    if continue_:
        _handle_continue(project, proj_config, scan_result, results_dir)

    # Collect actionable findings
    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates

    if not actionable_vulns and not updates:
        console.print(f"[bold green]{project}[/] — nothing to update.")
        sys.exit(ExitCode.OK)

    _print_scan_result(scan_result)

    numbered = _print_numbered_findings(actionable_vulns, updates)

    # Interactive selection
    parts = ["all"]
    if actionable_vulns:
        parts.append("vulns")
    if updates:
        parts.append("updates")
    parts.extend(["1,2,...", "none"])
    choices = "/".join(parts)

    while True:
        selection = Prompt.ask(
            f"\n  Select updates [{choices}]",
            default="all",
        )
        result = _parse_selection(
            selection,
            numbered,
            actionable_vulns,
            updates,
        )
        if result is not None:
            selected_vulns, selected_updates = result
            break
        console.print(f"[bold red]Invalid selection:[/] '{selection}'. Try again.")

    if not selected_vulns and not selected_updates:
        sys.exit(ExitCode.OK)

    # Process vulns (independent branches)
    vuln_results = []
    if selected_vulns:
        console.print(f"\n[bold]Processing {len(selected_vulns)} vuln fix(es)...[/]")
        vuln_results = process_vulns(
            selected_vulns,
            proj_config,
            scan_result=scan_result,
            project_name=project,
            results_dir=results_dir,
        )

    # Process updates (stacked, risk-ascending)
    update_results = []
    if selected_updates:
        console.print(f"\n[bold]Processing {len(selected_updates)} update(s)...[/]")
        update_results = process_updates(
            selected_updates,
            proj_config,
            scan_result=scan_result,
            project_name=project,
            results_dir=results_dir,
        )

    # Summary
    all_results = vuln_results + update_results
    passed = [r for r in all_results if r.passed]
    failed = [r for r in all_results if not r.passed]

    console.print("\n" + "─" * 40)
    console.print("[bold]Summary:[/]")
    if passed:
        console.print(f"  [green]{len(passed)} passed[/]")
    if failed:
        phase_labels = {
            "apply": "install failed",
            "gt-create": "branch creation failed",
        }
        for r in failed:
            label = phase_labels.get(r.failed_phase, r.failed_phase or "unknown")
            console.print(f"  [red]FAIL[/] {r.pkg_name} — {label}")
    console.print("─" * 40)

    sys.exit(ExitCode.UPDATE_FAILED if failed else ExitCode.OK)


@app.command
def deploy(
    project: str,
) -> None:
    """Deploy a project.

    Parameters
    ----------
    project: str
        Project name to deploy.
    """
    console.print("Not implemented.")
    sys.exit(ExitCode.ERROR)


@app.command
def test(
    project: str,
    *,
    config: Path | None = None,
) -> None:
    """Run a project's test suite.

    Runs configured test phases (unit → integration → component) in order,
    stopping on first failure.

    Parameters
    ----------
    project: str
        Project name to test.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)
    _require_test_config(project, proj_config)

    console.print(f"[bold]Testing {project}[/]\n")

    passed, failed_phase = run_test_phases(proj_config.test, proj_config.path)

    if passed:
        console.print("\n[bold green]All test phases passed.[/]")
        sys.exit(ExitCode.OK)
    else:
        console.print(f"\n[bold red]Failed:[/] {failed_phase} tests")
        sys.exit(ExitCode.TEST_FAILED)


_NO_DATA = "[dim]—[/]"


@app.command(name="list")
def list_projects(
    *,
    detail: Annotated[bool, cyclopts.Parameter(name=("--detail", "-d"))] = False,
    config: Path | None = None,
) -> None:
    """List all configured projects with scan findings summary.

    Parameters
    ----------
    detail: bool
        Show full findings detail for each project.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)

    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    results_dir = _config.MM_HOME / "scan-results"
    scan_results: dict[str, ScanResult] = {}
    for name in cfg.projects:
        try:
            scan_results[name] = load_scan_results(name, results_dir)
        except NoScanResultsError:
            pass
        except Exception:
            console.print(
                f"[yellow]Warning:[/] corrupt scan results for '{name}' — skipping"
            )

    table = Table(title="Configured Projects")
    for col, kw in [
        ("Name", {"style": "bold"}),
        ("Path", {}),
        ("Pkg Mgr", {}),
        ("Vulns", {"justify": "right"}),
        ("Updates", {"justify": "right"}),
        ("Secrets", {"justify": "right"}),
        ("Scanned", {}),
    ]:
        table.add_column(col, **kw)

    for name, project in sorted(cfg.projects.items()):
        sr = scan_results.get(name)
        if sr:
            counts = (
                str(sum(v.actionable for v in sr.vulnerabilities)),
                str(len(sr.updates)),
                str(len(sr.secrets)),
                _relative_time(sr.scanned_at),
            )
        else:
            counts = (_NO_DATA, _NO_DATA, _NO_DATA, "[dim]never[/]")

        table.add_row(
            name,
            str(project.path),
            project.package_manager,
            *counts,
        )

    console.print(table)

    if detail:
        for name in sorted(scan_results):
            _print_scan_result(scan_results[name])


# -- Helpers ------------------------------------------------------------------


def _fatal(msg: str, code: int = ExitCode.ERROR) -> NoReturn:
    console.print(f"[bold red]Error:[/] {msg}")
    sys.exit(code)


def _load_cfg(config: Path | None) -> MmConfig:
    try:
        return load_config(config_path=config)
    except ConfigError as e:
        _fatal(str(e))


def _resolve_proj(cfg: MmConfig, project: str) -> ProjectConfig:
    try:
        return resolve_project(cfg, project)
    except ProjectNotFoundError as e:
        _fatal(str(e))


def _require_test_config(project: str, proj_config: ProjectConfig) -> None:
    if proj_config.test is None:
        _fatal(
            f"No test configuration for [bold]{project}[/]. "
            f"Add a [projects.{project}.test] section to ~/.mm/config.toml."
        )


def _scan_exit_code(has_vulns: bool, has_updates: bool) -> ExitCode:
    match (has_vulns, has_updates):
        case (True, _):
            return ExitCode.VULNS_FOUND
        case (_, True):
            return ExitCode.UPDATES_FOUND
        case _:
            return ExitCode.OK


def _pluralise(n: int, singular: str, plural: str) -> str:
    return f"{n} {singular if n == 1 else plural}"


def _relative_time(dt: datetime, now: datetime | None = None) -> str:
    """Format a datetime as a human-readable relative time string."""
    now = now or datetime.now(timezone.utc)
    total_seconds = int((now - dt).total_seconds())
    match total_seconds:
        case s if s < 60:
            return "just now"
        case s if s < 3600:
            return f"{s // 60}m ago"
        case s if s < 86400:
            return f"{s // 3600}h ago"
        case s:
            return f"{s // 86400}d ago"


def _scan_one(name: str, proj_config: ProjectConfig, min_age_days: int) -> ScanResult:
    """Scan a single project with timing output."""
    try:
        sync_graphite(proj_config.path)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        console.print(
            f"[bold yellow]Warning:[/] {name} — failed to graphite sync: {exc}"
        )

    t0 = time.monotonic()
    result = scan_project(name, proj_config, min_age_days)
    elapsed = time.monotonic() - t0
    _print_scan_result(result, elapsed_s=elapsed)
    return result


def _print_scan_result(result: ScanResult, elapsed_s: float | None = None) -> None:
    """Print a Rich-formatted summary of scan results for one project."""
    actionable = sort_vulns_by_severity(
        [v for v in result.vulnerabilities if v.actionable]
    )
    advisories = sort_vulns_by_severity(
        [v for v in result.vulnerabilities if not v.actionable]
    )
    secrets = result.secrets
    updates = result.updates

    total = len(actionable) + len(advisories) + len(secrets) + len(updates)
    timing = f" [dim]({elapsed_s:.1f}s)[/]" if elapsed_s is not None else ""

    if total == 0:
        console.print(f"[bold green]{result.project}[/] — clean{timing}")
        return

    categories = [
        (actionable, "vulnerability", "vulnerabilities"),
        (advisories, "advisory", "advisories"),
        (secrets, "secret", "secrets"),
        (updates, "update", "updates"),
    ]
    parts = [_pluralise(len(items), s, p) for items, s, p in categories if items]

    console.print(f"\n[bold]{result.project}[/] — {', '.join(parts)}{timing}")

    if actionable:
        # Determine the winning fix version per package for the marker.
        win_versions: dict[str, str] = {}
        pkg_counts: dict[str, int] = {}
        for v in actionable:
            pkg_counts[v.pkg_name] = pkg_counts.get(v.pkg_name, 0) + 1
        for pkg in pkg_counts:
            if pkg_counts[pkg] > 1:
                group = [v for v in actionable if v.pkg_name == pkg]
                win_versions[pkg] = _highest_fix_version(group)

        table = Table(show_header=True, **_TABLE_STYLE)
        table.add_column("", style="bold red", width=4)
        table.add_column("Package")
        table.add_column("Installed")
        table.add_column("Fix")
        table.add_column("Severity")
        table.add_column("CVE")
        for v in actionable:
            fix_col = v.fixed_version or ""
            if (
                v.pkg_name in win_versions
                and v.fixed_version == win_versions[v.pkg_name]
            ):
                fix_col += " ← fix"
            table.add_row(
                "VULN",
                v.pkg_name,
                v.installed_version,
                fix_col,
                v.severity.value,
                v.vuln_id,
            )
        console.print(table)

    if advisories:
        table = Table(show_header=False, **_TABLE_STYLE)
        table.add_column("", style="bold yellow", width=4)
        table.add_column("Package")
        table.add_column("Installed")
        table.add_column("Status")
        table.add_column("Severity")
        table.add_column("CVE")
        for v in advisories:
            table.add_row(
                "ADV",
                v.pkg_name,
                v.installed_version,
                v.status,
                v.severity.value,
                v.vuln_id,
            )
        console.print(table)

    if secrets:
        for s in secrets:
            console.print(f"  [bold magenta]SECRET[/]  {s.file} — {s.title}")

    if updates:
        table = Table(show_header=True, **_TABLE_STYLE)
        table.add_column("", style="bold cyan", width=4)
        table.add_column("Package")
        table.add_column("Installed")
        table.add_column("Latest")
        table.add_column("Tier")
        table.add_column("Age")
        for u in updates:
            age = ""
            if u.published_date:
                days = (datetime.now(timezone.utc) - u.published_date).days
                age = f"({days} days old)"
            table.add_row(
                "UPDATE",
                u.pkg_name,
                u.installed_version,
                u.latest_version,
                u.semver_tier.value,
                age,
            )
        console.print(table)


def _print_numbered_findings(
    vulns: list[VulnFinding], updates: list[UpdateFinding]
) -> list[VulnFinding | UpdateFinding]:
    """Print numbered list of findings. Returns ordered list of findings."""
    vulns = sort_vulns_by_severity(vulns)
    numbered: list[VulnFinding | UpdateFinding] = []
    for idx, v in enumerate(vulns, 1):
        console.print(
            f"  [dim]{idx:>3}.[/] [bold red]VULN[/] {v.pkg_name} "
            f"{v.installed_version} -> {v.fixed_version} ({v.vuln_id})"
        )
        numbered.append(v)
    for idx, u in enumerate(updates, len(vulns) + 1):
        console.print(
            f"  [dim]{idx:>3}.[/] [bold cyan]UPDATE[/] {u.pkg_name} "
            f"{u.installed_version} -> {u.latest_version} "
            f"({u.semver_tier.value})"
        )
        numbered.append(u)
    return numbered


def _parse_selection(
    selection: str,
    numbered: list[VulnFinding | UpdateFinding],
    actionable_vulns: list[VulnFinding],
    updates: list[UpdateFinding],
) -> tuple[list[VulnFinding], list[UpdateFinding]] | None:
    """Parse user selection string into vuln and update lists.

    Returns None if the selection string is invalid.
    """
    match selection:
        case "none":
            return [], []
        case "all":
            return actionable_vulns, updates
        case "vulns":
            return actionable_vulns, []
        case "updates":
            return [], updates

    selected_vulns: list[VulnFinding] = []
    selected_updates: list[UpdateFinding] = []
    try:
        indices = [int(s.strip()) for s in selection.split(",")]
    except ValueError:
        return None

    for i in indices:
        if 1 <= i <= len(numbered):
            finding = numbered[i - 1]
            match finding:
                case VulnFinding():
                    selected_vulns.append(finding)
                case UpdateFinding():
                    selected_updates.append(finding)

    return selected_vulns, selected_updates


def _handle_continue(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
) -> NoReturn:
    """Handle --continue: re-test a manually fixed failed finding."""
    failed_vulns = [
        v for v in scan_result.vulnerabilities if v.update_status == UpdateStatus.FAILED
    ]
    failed_updates = [
        u for u in scan_result.updates if u.update_status == UpdateStatus.FAILED
    ]
    if not failed_vulns and not failed_updates:
        _fatal("No failed findings to continue.")

    branch = get_current_branch(proj_config.path)
    finding = next(
        (v for v in failed_vulns if branch == f"fix/{branch_slug(v.pkg_name)}"),
        None,
    ) or next(
        (u for u in failed_updates if branch == f"bump/{branch_slug(u.pkg_name)}"),
        None,
    )
    if finding is None:
        _fatal(f"Current branch '{branch}' does not match any failed finding.")

    console.print(f"\n[bold]Re-testing {finding.pkg_name} on {branch}...[/]")
    passed, failed_phase = run_test_phases(proj_config.test, proj_config.path)

    if not passed:
        console.print(f"  [bold red]FAIL[/] {finding.pkg_name} — {failed_phase} failed")
        sys.exit(ExitCode.UPDATE_FAILED)

    finding.update_status = UpdateStatus.COMPLETED
    save_scan_results(project, results_dir, scan_result)
    console.print(f"  [bold green]PASS[/] {finding.pkg_name}")

    remaining = [
        f
        for f in [*scan_result.vulnerabilities, *scan_result.updates]
        if f.update_status == UpdateStatus.FAILED
    ]
    if remaining:
        pkg_names = [f.pkg_name for f in remaining]
        console.print(f"\n  [dim]Still failed: {', '.join(pkg_names)}[/]")
        sys.exit(ExitCode.UPDATE_FAILED)

    ok, output = submit_stack(proj_config.path)
    if ok:
        console.print("  [bold green]Stack submitted.[/]")
    else:
        console.print("  [bold red]Submit failed.[/]")
    if output:
        console.print(f"  [dim]{output}[/]")
    sys.exit(ExitCode.OK)
