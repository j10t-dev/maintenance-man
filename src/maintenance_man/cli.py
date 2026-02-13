import sys
import time
from datetime import datetime, timezone
from typing import Annotated

import cyclopts
from rich import print as rprint
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from maintenance_man import __version__
from maintenance_man.config import MM_HOME, load_config, resolve_project
from maintenance_man.models.scan import (
    UpdateFinding,
    ScanResult,
    UpdateStatus,
    VulnFinding,
)
from maintenance_man.scanner import (
    TrivyNotFoundError,
    TrivyScanError,
    check_trivy_available,
    scan_project,
)
from maintenance_man.updater import (
    NoScanResultsError,
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


def _pluralise(n: int, singular: str, plural: str) -> str:
    return f"{n} {singular if n == 1 else plural}"


_TABLE_STYLE = dict(show_edge=False, pad_edge=False, box=None)


app = cyclopts.App(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    version=__version__,
    version_flags=["--version", "-v"],
)


def _print_scan_result(result: ScanResult, elapsed_s: float | None = None) -> None:
    """Print a Rich-formatted summary of scan results for one project."""
    console = Console()

    actionable = [v for v in result.vulnerabilities if v.actionable]
    advisories = [v for v in result.vulnerabilities if not v.actionable]
    secrets = result.secrets
    updates = result.updates

    total = len(actionable) + len(advisories) + len(secrets) + len(updates)
    timing = f" [dim]({elapsed_s:.1f}s)[/]" if elapsed_s is not None else ""

    if total == 0:
        rprint(f"[bold green]{result.project}[/] — clean{timing}")
        return

    parts = []
    if actionable:
        parts.append(_pluralise(len(actionable), "vulnerability", "vulnerabilities"))
    if advisories:
        parts.append(_pluralise(len(advisories), "advisory", "advisories"))
    if secrets:
        parts.append(_pluralise(len(secrets), "secret", "secrets"))
    if updates:
        parts.append(_pluralise(len(updates), "update", "updates"))

    rprint(f"\n[bold]{result.project}[/] — {', '.join(parts)}{timing}")

    if actionable:
        table = Table(show_header=True, **_TABLE_STYLE)
        table.add_column("", style="bold red", width=4)
        table.add_column("Package")
        table.add_column("Installed")
        table.add_column("Fix")
        table.add_column("Severity")
        table.add_column("CVE")
        for v in actionable:
            table.add_row(
                "VULN",
                v.pkg_name,
                v.installed_version,
                v.fixed_version or "",
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
            rprint(f"  [bold magenta]SECRET[/]  {s.file} — {s.title}")

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


@app.command
def scan(
    project: str | None = None,
) -> None:
    """Scan projects for vulnerabilities and available updates.

    Parameters
    ----------
    project: str | None
        Project name to scan. Scans all if omitted.
    """
    config = load_config()

    try:
        check_trivy_available()
    except TrivyNotFoundError as e:
        rprint(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    if not config.projects:
        print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    if project:
        # Single project scan
        proj_config = resolve_project(config, project)
        try:
            t0 = time.monotonic()
            result = scan_project(
                project, proj_config, config.defaults.min_version_age_days
            )
            elapsed = time.monotonic() - t0
        except TrivyScanError as e:
            rprint(f"[bold red]Error:[/] {e}")
            sys.exit(1)

        _print_scan_result(result, elapsed_s=elapsed)
        if result.has_actionable_vulns:
            sys.exit(2)
        elif result.has_updates:
            sys.exit(3)
        else:
            sys.exit(0)

    # Scan all projects
    has_vulns = False
    has_updates = False
    for name, proj_config in config.projects.items():
        if not proj_config.path.exists():
            rprint(
                f"[bold yellow]Warning:[/] {name} — "
                f"path does not exist: {proj_config.path}"
            )
            continue
        try:
            t0 = time.monotonic()
            result = scan_project(
                name, proj_config, config.defaults.min_version_age_days
            )
            elapsed = time.monotonic() - t0
        except TrivyScanError as e:
            rprint(f"[bold red]Error:[/] {name} — {e}")
            continue

        _print_scan_result(result, elapsed_s=elapsed)
        if result.has_actionable_vulns:
            has_vulns = True
        if result.has_updates:
            has_updates = True

    if has_vulns:
        sys.exit(2)
    elif has_updates:
        sys.exit(3)
    else:
        sys.exit(0)


def _print_numbered_findings(
    vulns: list[VulnFinding], updates: list[UpdateFinding]
) -> list[tuple[str, VulnFinding | UpdateFinding]]:
    """Print numbered list of findings. Returns ordered list of (kind, finding)."""
    numbered: list[tuple[str, VulnFinding | UpdateFinding]] = []
    idx = 1
    for v in vulns:
        rprint(
            f"  [dim]{idx:>3}.[/] [bold red]VULN[/] {v.pkg_name} "
            f"{v.installed_version} -> {v.fixed_version} ({v.vuln_id})"
        )
        numbered.append(("vuln", v))
        idx += 1
    for u in updates:
        rprint(
            f"  [dim]{idx:>3}.[/] [bold cyan]UPDATE[/] {u.pkg_name} "
            f"{u.installed_version} -> {u.latest_version} "
            f"({u.semver_tier.value})"
        )
        numbered.append(("update", u))
        idx += 1
    return numbered


def _parse_selection(
    selection: str,
    numbered: list[tuple[str, VulnFinding | UpdateFinding]],
    actionable_vulns: list[VulnFinding],
    updates: list[UpdateFinding],
) -> tuple[list[VulnFinding], list[UpdateFinding]]:
    """Parse user selection string into vuln and update lists."""
    if selection == "none":
        return [], []
    if selection == "all":
        return actionable_vulns, updates
    if selection == "vulns":
        return actionable_vulns, []
    if selection == "updates":
        return [], updates

    # Try comma-separated numbers
    selected_vulns: list[VulnFinding] = []
    selected_updates: list[UpdateFinding] = []
    try:
        indices = [int(s.strip()) for s in selection.split(",")]
    except ValueError:
        return actionable_vulns, updates  # fallback to all

    for i in indices:
        if 1 <= i <= len(numbered):
            kind, finding = numbered[i - 1]
            if kind == "vuln":
                selected_vulns.append(finding)
            else:
                selected_updates.append(finding)

    return selected_vulns, selected_updates


@app.command
def update(
    project: str,
    *,
    continue_: Annotated[bool, cyclopts.Parameter(name="--continue")] = False,
) -> None:
    """Apply updates from scan results to a project.

    Parameters
    ----------
    project: str
        Project name to update.
    continue_: bool
        Re-test a manually fixed failed finding on the current branch.
    """
    config = load_config()
    proj_config = resolve_project(config, project)

    # Pre-checks
    try:
        check_graphite_available()
    except GraphiteNotFoundError as e:
        rprint(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    if not continue_:
        try:
            check_repo_clean(proj_config.path)
        except RepoDirtyError as e:
            rprint(f"[bold yellow]Warning:[/] {e}")
            if Confirm.ask(
                "  Discard changes and reset to main?", default=False
            ):
                reset_to_main(proj_config.path)
            else:
                sys.exit(1)

        # Sync trunk and clean up branches whose PRs have been merged/closed
        if not sync_graphite(proj_config.path):
            rprint("[bold red]Error:[/] Failed to sync trunk. Check network and gt auth.")
            sys.exit(1)

    results_dir = MM_HOME / "scan-results"
    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError as e:
        rprint(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    if proj_config.test is None:
        rprint(
            f"[bold red]Error:[/] No test configuration for [bold]{project}[/]. "
            f"Add a [projects.{project}.test] section to ~/.mm/config.toml."
        )
        sys.exit(1)

    if continue_:
        # Find failed findings
        failed_vulns = [
            v for v in scan_result.vulnerabilities
            if v.update_status == UpdateStatus.FAILED
        ]
        failed_updates = [
            u for u in scan_result.updates
            if u.update_status == UpdateStatus.FAILED
        ]
        if not failed_vulns and not failed_updates:
            rprint("[bold red]Error:[/] No failed findings to continue.")
            sys.exit(1)

        # Match current branch to a failed finding
        branch = get_current_branch(proj_config.path)
        finding = None
        for v in failed_vulns:
            if branch == f"fix/{branch_slug(v.pkg_name)}":
                finding = v
                break
        if finding is None:
            for u in failed_updates:
                if branch == f"bump/{branch_slug(u.pkg_name)}":
                    finding = u
                    break
        if finding is None:
            rprint(
                f"[bold red]Error:[/] Current branch '{branch}' does not "
                f"match any failed finding."
            )
            sys.exit(1)

        # Re-test
        rprint(f"\n[bold]Re-testing {finding.pkg_name} on {branch}...[/]")
        passed, failed_phase = run_test_phases(proj_config.test, proj_config.path)

        if passed:
            finding.update_status = UpdateStatus.COMPLETED
            save_scan_results(project, results_dir, scan_result)
            rprint(f"  [bold green]PASS[/] {finding.pkg_name}")

            # Check remaining failures
            remaining = [
                v for v in scan_result.vulnerabilities
                if v.update_status == UpdateStatus.FAILED
            ] + [
                u for u in scan_result.updates
                if u.update_status == UpdateStatus.FAILED
            ]
            if not remaining:
                ok, output = submit_stack(proj_config.path)
                if ok:
                    rprint("  [bold green]Stack submitted.[/]")
                    if output:
                        rprint(f"  [dim]{output}[/]")
                else:
                    rprint("  [bold red]Submit failed.[/]")
                    if output:
                        rprint(f"  [dim]{output}[/]")
                sys.exit(0)
            else:
                pkg_names = [f.pkg_name for f in remaining]
                rprint(f"\n  [dim]Still failed: {', '.join(pkg_names)}[/]")
                sys.exit(4)
        else:
            rprint(
                f"  [bold red]FAIL[/] {finding.pkg_name} — {failed_phase} failed"
            )
            sys.exit(4)

    # Collect actionable findings
    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates

    if not actionable_vulns and not updates:
        rprint(f"[bold green]{project}[/] — nothing to update.")
        sys.exit(0)

    # Display findings
    _print_scan_result(scan_result)

    # Numbered listing
    numbered = _print_numbered_findings(actionable_vulns, updates)

    # Interactive selection
    choices = "all"
    if actionable_vulns and updates:
        choices = "all/vulns/updates/1,2,.../none"
    elif actionable_vulns:
        choices = "all/vulns/1,2,.../none"
    elif updates:
        choices = "all/updates/1,2,.../none"

    selection = Prompt.ask(
        f"\n  Select updates [{choices}]",
        default="all",
    )

    selected_vulns, selected_updates = _parse_selection(
        selection, numbered, actionable_vulns, updates,
    )

    if not selected_vulns and not selected_updates:
        sys.exit(0)

    # Process vulns (independent branches)
    vuln_results = []
    if selected_vulns:
        rprint(f"\n[bold]Processing {len(selected_vulns)} vuln fix(es)...[/]")
        vuln_results = process_vulns(
            selected_vulns, proj_config,
            scan_result=scan_result, project_name=project,
            results_dir=results_dir,
        )

    # Process updates (stacked, risk-ascending)
    update_results = []
    if selected_updates:
        rprint(f"\n[bold]Processing {len(selected_updates)} update(s)...[/]")
        update_results = process_updates(
            selected_updates, proj_config,
            scan_result=scan_result, project_name=project,
            results_dir=results_dir,
        )

    # Summary
    all_results = vuln_results + update_results
    passed = [r for r in all_results if r.passed]
    failed = [r for r in all_results if not r.passed]

    rprint("\n" + "─" * 40)
    rprint("[bold]Summary:[/]")
    if passed:
        rprint(f"  [green]{len(passed)} passed[/]")
    if failed:
        phase_labels = {
            "apply": "install failed",
            "gt-create": "branch creation failed",
        }
        for r in failed:
            label = phase_labels.get(r.failed_phase, r.failed_phase or "unknown")
            rprint(f"  [red]FAIL[/] {r.pkg_name} — {label}")
    rprint("─" * 40)

    has_failures = any(not r.passed for r in all_results)
    sys.exit(4 if has_failures else 0)


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
    print("Not implemented.")
    sys.exit(1)


@app.command(name="list")
def list_projects() -> None:
    """List all configured projects."""
    config = load_config()

    if not config.projects:
        print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    console = Console()
    table = Table(title="Configured Projects")
    table.add_column("Name", style="bold")
    table.add_column("Path")
    table.add_column("Package Manager")

    for name, project in sorted(config.projects.items()):
        table.add_row(name, str(project.path), project.package_manager)

    console.print(table)


def main() -> None:
    app()
