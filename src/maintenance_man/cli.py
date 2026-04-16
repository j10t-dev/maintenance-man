import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Annotated, Literal, NoReturn

import cyclopts
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from maintenance_man import __version__
from maintenance_man import config as _config
from maintenance_man.config import (
    MM_HOME,
    ConfigError,
    ProjectNotFoundError,
    ensure_mm_home,
    load_config,
    resolve_project,
)
from maintenance_man.deployer import (
    BuildError,
    DeployError,
    check_health,
    run_build,
    run_deploy,
)
from maintenance_man.models.activity import (
    ActivityEvent,
    load_activity,
    record_activity,
)
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.scan import (
    Workflow,
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
    UpdateResult,
    has_test_config,
    highest_fix_version,
    load_scan_results,
    process_updates,
    process_vulns,
    remove_completed_findings,
    run_test_phases,
    save_scan_results,
)
from maintenance_man.vcs import (
    GitHubCLINotFoundError,
    check_gh_available,
    create_worktree,
    ensure_on_main,
    get_current_branch,
    git_branch_exists,
    git_create_branch,
    git_delete_branch,
    git_merge_fast_forward,
    remove_worktree,
    sync_remote,
)


class ExitCode(IntEnum):
    OK = 0
    ERROR = 1
    VULNS_FOUND = 2
    UPDATES_FOUND = 3
    UPDATE_FAILED = 4
    TEST_FAILED = 5
    BUILD_FAILED = 6
    DEPLOY_FAILED = 7


@dataclass
class DeployResult:
    project: str
    build_status: Literal["pass", "fail", "skip"]
    deploy_status: Literal["pass", "fail", "skip"]


console = Console()

_TABLE_STYLE = dict(show_edge=False, pad_edge=False, box=None)

_UPDATE_BRANCH = "mm/update-dependencies"

app = cyclopts.App(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    version=__version__,
    version_flags=["--version", "-v"],
)


def main() -> None:
    app()


@app.command
def init() -> None:
    """Initialise the ~/.mm directory and skeleton config."""
    ensure_mm_home()
    console.print(f"Initialised {MM_HOME}")
    console.print(f"Edit {MM_HOME / 'config.toml'} to add projects.")


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


def _dedupe_preserve_order(names: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def _validate_project_names(cfg: MmConfig, names: list[str]) -> None:
    known = set(cfg.projects)
    for name in names:
        if name not in known:
            _fatal(
                f"Unknown project '{name}'. "
                f"Known projects: {', '.join(cfg.projects) or '(none)'}"
            )


def _sorted_project_names(cfg: MmConfig) -> list[str]:
    return sorted(cfg.projects)


def _exit_if_no_update_targets(cfg: MmConfig, target_names: list[str]) -> None:
    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        sys.exit(ExitCode.OK)

    if not target_names:
        console.print("No target projects.")
        sys.exit(ExitCode.OK)


def _resolve_update_targets(
    cfg: MmConfig,
    projects: list[str],
    *,
    negate: bool,
) -> tuple[Literal["single", "batch"], list[str]]:
    ordered = _dedupe_preserve_order(projects)
    _validate_project_names(cfg, ordered)

    if negate:
        excluded = set(ordered)
        targets = [name for name in _sorted_project_names(cfg) if name not in excluded]
        return "batch", targets

    if not ordered:
        return "batch", _sorted_project_names(cfg)

    if len(ordered) == 1:
        return "single", ordered

    return "batch", ordered


@app.command
def update(
    *projects: str,
    negate: Annotated[bool, cyclopts.Parameter(name=("--negate", "-n"))] = False,
    config: Path | None = None,
) -> None:
    """Apply updates from scan results to one, many, or all projects.

    Parameters
    ----------
    projects: str
        Project names to update. No names batch-updates all configured projects.
        With -n/--negate, names are exclusions. One name keeps the interactive
        single-project flow.
    negate: bool
        Treat all positional project names as exclusions.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)
    mode, targets = _resolve_update_targets(cfg, list(projects), negate=negate)

    _exit_if_no_update_targets(cfg, targets)

    try:
        check_gh_available()
    except GitHubCLINotFoundError as e:
        _fatal(str(e))

    if mode == "single":
        _update_interactive(cfg, targets[0])

    _update_batch_targets(cfg, target_names=targets)


def _update_interactive(cfg: MmConfig, project: str) -> NoReturn:
    """Update a single project with interactive selection."""
    proj_config = _resolve_proj(cfg, project)
    results_dir = _config.MM_HOME / "scan-results"

    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError:
        console.print(f"[bold green]{project}[/] — no scan results; nothing to do.")
        sys.exit(ExitCode.OK)

    _assert_supported_in_progress_state(scan_result)
    _assert_no_conflicting_flow(scan_result, Workflow.UPDATE)

    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates
    if not actionable_vulns and not updates:
        console.print(f"[bold green]{project}[/] — nothing to update.")
        sys.exit(ExitCode.OK)

    _warn_missing_test_config(project, proj_config)

    exit_code = _run_update_flow(
        project,
        proj_config,
        scan_result,
        results_dir,
        actionable_vulns,
        updates,
        interactive=True,
    )
    sys.exit(exit_code)


def _update_batch(
    project: str,
    proj_config: ProjectConfig,
    results_dir: Path,
) -> tuple[list[UpdateResult], bool] | None:
    """Process all actionable findings for a single project (batch mode).

    Returns ``(results, merge_failed)``. ``merge_failed`` is ``True`` only when
    the post-batch merge-to-main step was attempted and failed; when merge was
    skipped (per-finding failures) or succeeded it is ``False``. Returns
    ``None`` if the project was skipped due to an error.
    """
    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError:
        return ([], False)

    _assert_supported_in_progress_state(scan_result)
    _assert_no_conflicting_flow(scan_result, Workflow.UPDATE)

    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates
    if not actionable_vulns and not updates:
        console.print(f"  [dim]{project} — nothing to update[/]")
        return ([], False)

    _warn_missing_test_config(project, proj_config)

    try:
        wt_path = _enter_update_worktree(project, proj_config, scan_result)
    except _UpdateSetupError as e:
        console.print(f"  [bold red]Error:[/] {project} — {e}")
        return None

    work_config = proj_config.model_copy(update={"path": wt_path})

    finalised = False
    merge_attempted = False
    try:
        _print_scan_result(scan_result)

        selectable_vulns = _selectable_vulns(actionable_vulns)
        selectable_updates = _selectable_updates(updates)

        vuln_results = _process_selected_vulns(
            selectable_vulns, work_config, scan_result, project, results_dir
        )
        update_results = _process_selected_updates(
            selectable_updates, work_config, scan_result, project, results_dir
        )
        all_results = vuln_results + update_results

        any_failed_result = any(not r.passed for r in all_results)
        any_failed_finding = _has_update_failures(scan_result)

        if not (any_failed_result or any_failed_finding):
            merge_attempted = True
            finalised = _finalise_local_update(
                proj_config.path, scan_result, project, results_dir
            )
    finally:
        remove_worktree(proj_config.path, wt_path)

    if finalised:
        git_delete_branch(_UPDATE_BRANCH, proj_config.path)
    return (all_results, merge_attempted and not finalised)


def _update_batch_targets(
    cfg: MmConfig,
    *,
    target_names: list[str],
) -> NoReturn:
    """Update an explicit ordered set of projects, auto-selecting all findings."""
    _exit_if_no_update_targets(cfg, target_names)

    results_dir = _config.MM_HOME / "scan-results"
    all_project_results: list[tuple[str, list[UpdateResult]]] = []
    had_errors = False

    for name in target_names:
        proj_config = cfg.projects[name]
        if not proj_config.path.exists():
            console.print(
                f"[bold yellow]Warning:[/] {name} — "
                f"path does not exist: {proj_config.path}"
            )
            had_errors = True
            continue

        console.print(f"\n{'═' * 40}")
        console.print(f"[bold]{name}[/]")
        console.print("═" * 40)

        outcome = _update_batch(name, proj_config, results_dir)
        if outcome is None:
            had_errors = True
            continue
        results, merge_failed = outcome
        if merge_failed:
            had_errors = True
        if results:
            all_project_results.append((name, results))

    _print_mass_update_summary(all_project_results)

    any_failed = had_errors or any(
        not r.passed for _, results in all_project_results for r in results
    )
    sys.exit(ExitCode.UPDATE_FAILED if any_failed else ExitCode.OK)


class _UpdateSetupError(Exception):
    pass


def _enter_update_worktree(
    project: str, proj_config: ProjectConfig, scan_result: ScanResult
) -> Path:
    """Create (fresh) or attach (resume) the update worktree. Returns its path."""
    wt_path = _config.MM_HOME / "worktrees" / project
    if wt_path.exists():
        remove_worktree(proj_config.path, wt_path)

    if _has_update_progress(scan_result):
        if not git_branch_exists(_UPDATE_BRANCH, proj_config.path):
            raise _UpdateSetupError(
                f"update branch '{_UPDATE_BRANCH}' is missing but in-progress "
                f"state exists — rescan required"
            )
        if not create_worktree(
            proj_config.path, wt_path, branch=_UPDATE_BRANCH, detach=False
        ):
            raise _UpdateSetupError("could not attach worktree to update branch")
        return wt_path

    if git_branch_exists(_UPDATE_BRANCH, proj_config.path):
        git_delete_branch(_UPDATE_BRANCH, proj_config.path)
    if not sync_remote(proj_config.path):
        raise _UpdateSetupError("failed to sync trunk")
    if not create_worktree(proj_config.path, wt_path, branch="main", detach=True):
        raise _UpdateSetupError("could not create worktree")
    if not git_create_branch(_UPDATE_BRANCH, wt_path):
        remove_worktree(proj_config.path, wt_path)
        raise _UpdateSetupError("could not create update branch")
    return wt_path


def _run_update_flow(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
    actionable_vulns: list[VulnFinding],
    updates: list[UpdateFinding],
    *,
    interactive: bool,
) -> int:
    """Set up the worktree, process findings, finalise. Returns exit code."""
    try:
        wt_path = _enter_update_worktree(project, proj_config, scan_result)
    except _UpdateSetupError as e:
        _fatal(str(e))

    work_config = proj_config.model_copy(update={"path": wt_path})

    finalised = False
    try:
        _print_scan_result(scan_result)

        selectable_vulns = _selectable_vulns(actionable_vulns)
        selectable_updates = _selectable_updates(updates)

        if interactive and (selectable_vulns or selectable_updates):
            selected_vulns, selected_updates = _prompt_selection(
                selectable_vulns, selectable_updates
            )
        else:
            selected_vulns, selected_updates = selectable_vulns, selectable_updates

        vuln_results = _process_selected_vulns(
            selected_vulns, work_config, scan_result, project, results_dir
        )
        update_results = _process_selected_updates(
            selected_updates, work_config, scan_result, project, results_dir
        )
        all_results = vuln_results + update_results

        _print_update_summary(all_results)

        any_failed_result = any(not r.passed for r in all_results)
        any_failed_finding = _has_update_failures(scan_result)

        if any_failed_result or any_failed_finding:
            return ExitCode.UPDATE_FAILED

        finalised = _finalise_local_update(
            proj_config.path, scan_result, project, results_dir
        )
    finally:
        remove_worktree(proj_config.path, wt_path)

    if not finalised:
        return ExitCode.UPDATE_FAILED

    git_delete_branch(_UPDATE_BRANCH, proj_config.path)
    return ExitCode.OK


def _selectable_vulns(vulns: list[VulnFinding]) -> list[VulnFinding]:
    return [
        v
        for v in vulns
        if v.update_status is None
        or (
            v.update_status == UpdateStatus.FAILED
            and v.flow == Workflow.UPDATE
        )
    ]


def _selectable_updates(updates: list[UpdateFinding]) -> list[UpdateFinding]:
    return [
        u
        for u in updates
        if u.update_status is None
        or (
            u.update_status == UpdateStatus.FAILED
            and u.flow == Workflow.UPDATE
        )
    ]


def _prompt_selection(
    selectable_vulns: list[VulnFinding],
    selectable_updates: list[UpdateFinding],
) -> tuple[list[VulnFinding], list[UpdateFinding]]:
    numbered = _print_numbered_findings(selectable_vulns, selectable_updates)
    parts = ["all"]
    if selectable_vulns:
        parts.append("vulns")
    if selectable_updates:
        parts.append("updates")
    parts.extend(["1,2,...", "none"])
    choices = "/".join(parts)

    while True:
        selection = Prompt.ask(
            f"\n  Select updates [{choices}]", default="all"
        )
        result = _parse_selection(
            selection, numbered, selectable_vulns, selectable_updates
        )
        if result is not None:
            return result
        console.print(
            f"[bold red]Invalid selection:[/] '{selection}'. Try again."
        )


def _process_selected_vulns(
    selected: list[VulnFinding],
    work_config: ProjectConfig,
    scan_result: ScanResult,
    project: str,
    results_dir: Path,
) -> list[UpdateResult]:
    if not selected:
        return []
    console.print(f"\n[bold]Processing {len(selected)} vuln fix(es)...[/]")
    return process_vulns(
        selected,
        work_config,
        flow=Workflow.UPDATE,
        scan_result=scan_result,
        project_name=project,
        results_dir=results_dir,
    )


def _process_selected_updates(
    selected: list[UpdateFinding],
    work_config: ProjectConfig,
    scan_result: ScanResult,
    project: str,
    results_dir: Path,
) -> list[UpdateResult]:
    if not selected:
        return []
    console.print(f"\n[bold]Processing {len(selected)} update(s)...[/]")
    return process_updates(
        selected,
        work_config,
        flow=Workflow.UPDATE,
        scan_result=scan_result,
        project_name=project,
        results_dir=results_dir,
    )


def _print_update_summary(all_results: list[UpdateResult]) -> None:
    passed = [r for r in all_results if r.passed]
    failed = [r for r in all_results if not r.passed]
    console.print("\n" + "─" * 40)
    console.print("[bold]Summary:[/]")
    if passed:
        console.print(f"  [green]{len(passed)} passed[/]")
    if failed:
        phase_labels = {
            "apply": "install failed",
            "branch": "branch creation failed",
            "commit": "commit failed",
        }
        for r in failed:
            label = phase_labels.get(r.failed_phase, r.failed_phase or "unknown")
            console.print(f"  [red]FAIL[/] {r.pkg_name} — {label}")
    console.print("─" * 40)


def _has_update_progress(scan_result: ScanResult) -> bool:
    return any(
        f.update_status in (UpdateStatus.READY, UpdateStatus.FAILED)
        and f.flow == Workflow.UPDATE
        for f in (*scan_result.vulnerabilities, *scan_result.updates)
    )


def _has_update_failures(scan_result: ScanResult) -> bool:
    return any(
        f.update_status == UpdateStatus.FAILED and f.flow == Workflow.UPDATE
        for f in (*scan_result.vulnerabilities, *scan_result.updates)
    )


def _assert_supported_in_progress_state(scan_result: ScanResult) -> None:
    for f in (*scan_result.vulnerabilities, *scan_result.updates):
        if f.update_status is not None and f.flow is None:
            _fatal(
                "Scan results contain findings with in-progress status but no "
                "flow ownership — please rescan the project."
            )


def _assert_no_conflicting_flow(
    scan_result: ScanResult, required_flow: Workflow
) -> None:
    conflicts = [
        f
        for f in (*scan_result.vulnerabilities, *scan_result.updates)
        if f.update_status is not None
        and f.flow is not None
        and f.flow != required_flow
    ]
    if conflicts:
        other = conflicts[0].flow.value if conflicts[0].flow else "unknown"
        _fatal(
            f"Cannot run update: {len(conflicts)} finding(s) owned by the "
            f"'{other}' flow. Complete or abandon that flow first."
        )


def _finalise_local_update(
    orig_path: Path,
    scan_result: ScanResult,
    project_name: str,
    results_dir: Path,
) -> bool:
    """Fast-forward `_UPDATE_BRANCH` into main and promote READY findings.

    Refuses to merge when the main checkout has uncommitted changes — those
    changes would otherwise be silently mixed with automation output. Branch
    cleanup is deferred to the caller so the worktree can be removed first.
    """
    try:
        check_repo_clean(orig_path)
    except RepoDirtyError as e:
        console.print(
            f"[bold red]Merge aborted:[/] {orig_path} has uncommitted changes — "
            f"{_UPDATE_BRANCH} kept for manual recovery.\n{e}"
        )
        return False
    if not ensure_on_main(orig_path):
        console.print("[bold red]Error:[/] could not checkout main for merge")
        return False
    if not git_merge_fast_forward(_UPDATE_BRANCH, orig_path):
        console.print(
            f"[bold red]Merge failed:[/] {_UPDATE_BRANCH} could not fast-forward "
            f"into main"
        )
        return False

    for v in scan_result.vulnerabilities:
        if v.update_status == UpdateStatus.READY and v.flow == Workflow.UPDATE:
            v.update_status = UpdateStatus.COMPLETED
    for u in scan_result.updates:
        if u.update_status == UpdateStatus.READY and u.flow == Workflow.UPDATE:
            u.update_status = UpdateStatus.COMPLETED

    remove_completed_findings(scan_result)
    save_scan_results(project_name, results_dir, scan_result)
    console.print(f"[bold green]Merged {_UPDATE_BRANCH} into main.[/]")
    return True


def _warn_missing_test_config(project: str, proj_config: ProjectConfig) -> None:
    if not has_test_config(proj_config):
        console.print(
            f"  [bold yellow]Warning:[/] {project} — no test configuration "
            f"(test phases will be skipped)"
        )


def _print_mass_update_summary(
    project_results: list[tuple[str, list[UpdateResult]]],
) -> None:
    """Print a cross-project summary table."""
    if not project_results:
        console.print("\n[dim]No projects had actionable findings.[/]")
        return

    table = Table(title="Update Summary")
    table.add_column("Project", style="bold")
    table.add_column("Package")
    table.add_column("Kind")
    table.add_column("Result")

    for proj_name, results in project_results:
        for r in results:
            status = (
                "[green]PASS[/]" if r.passed else f"[red]FAIL ({r.failed_phase})[/]"
            )
            table.add_row(proj_name, r.pkg_name, r.kind, status)

    console.print()
    console.print(table)


def _deploy_one(
    name: str,
    proj_config: ProjectConfig,
    cfg: MmConfig,
    *,
    check: bool = False,
) -> DeployResult:
    """Build and deploy a single project. Returns result, never raises."""
    build_status = "skip"
    deploy_status = "skip"

    if proj_config.build_command:
        console.print("  [bold]Building...[/]")
        try:
            _run_build_step(name, proj_config)
        except BuildError as e:
            console.print(f"  [bold red]Build failed:[/] {e}")
            build_status = "fail"
            return DeployResult(
                project=name,
                build_status=build_status,
                deploy_status=deploy_status,
            )
        build_status = "pass"

    console.print("  [bold]Deploying...[/]")
    try:
        _run_deploy_step(name, proj_config)
    except DeployError as e:
        console.print(f"  [bold red]Deploy failed:[/] {e}")
        deploy_status = "fail"
        return DeployResult(
            project=name,
            build_status=build_status,
            deploy_status=deploy_status,
        )
    deploy_status = "pass"

    if check and cfg.defaults.healthcheck_url:
        _run_health_check_step(cfg.defaults.healthcheck_url, name, indent="  ")

    return DeployResult(
        project=name,
        build_status=build_status,
        deploy_status=deploy_status,
    )


def _deploy_all(cfg: MmConfig, *, check: bool = False) -> NoReturn:
    """Deploy all configured projects that have a deploy_command."""
    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        sys.exit(ExitCode.OK)

    results: list[DeployResult] = []

    for name, proj_config in sorted(cfg.projects.items()):
        if not proj_config.deployable:
            console.print(f"[dim]{name} — skipped (not deployable)[/]")
            continue

        if not proj_config.deploy_command:
            continue

        if not proj_config.path.exists():
            console.print(
                f"[bold yellow]Warning:[/] {name} — "
                f"path does not exist: {proj_config.path}"
            )
            results.append(
                DeployResult(project=name, build_status="skip", deploy_status="fail")
            )
            continue

        console.print(f"\n{'═' * 40}")
        console.print(f"[bold]{name}[/]")
        console.print("═" * 40)

        results.append(_deploy_one(name, proj_config, cfg, check=check))

    _print_deploy_summary(results)

    any_failed = any(
        r.deploy_status == "fail" or r.build_status == "fail" for r in results
    )
    sys.exit(ExitCode.DEPLOY_FAILED if any_failed else ExitCode.OK)


def _print_deploy_summary(results: list[DeployResult]) -> None:
    """Print a cross-project deploy summary table."""
    if not results:
        console.print("\n[dim]No projects have deploy_command configured.[/]")
        return

    _STATUS_DISPLAY = {
        "pass": "[green]PASS[/]",
        "fail": "[red]FAIL[/]",
        "skip": "[dim]SKIP[/]",
    }

    table = Table(title="Deploy Summary")
    table.add_column("Project", style="bold")
    table.add_column("Build")
    table.add_column("Deploy")

    for r in results:
        table.add_row(
            r.project,
            _STATUS_DISPLAY[r.build_status],
            _STATUS_DISPLAY[r.deploy_status],
        )

    console.print()
    console.print(table)


def _warn_missing_healthcheck_url() -> None:
    """Warn when --check was requested but no healthcheck_url is configured."""
    console.print("[dim]--check: no healthcheck_url configured in [defaults][/]")


def _record_deploy_activity(
    project: str,
    event_type: Literal["build", "deploy"],
    *,
    success: bool,
    project_path: Path,
) -> None:
    """Record build/deploy activity for a project."""
    activity_path = _config.MM_HOME / "activity.json"
    branch = _safe_branch(project_path)
    record_activity(activity_path, project, event_type, success=success, branch=branch)


def _run_build_step(project: str, proj_config: ProjectConfig) -> None:
    """Run build and record activity, raising BuildError on failure."""
    assert proj_config.build_command is not None
    try:
        run_build(project, proj_config.build_command, proj_config.path)
    except BuildError:
        _record_deploy_activity(
            project,
            "build",
            success=False,
            project_path=proj_config.path,
        )
        raise
    _record_deploy_activity(
        project,
        "build",
        success=True,
        project_path=proj_config.path,
    )


def _run_deploy_step(project: str, proj_config: ProjectConfig) -> None:
    """Run deploy and record activity, raising DeployError on failure."""
    assert proj_config.deploy_command is not None
    try:
        run_deploy(project, proj_config.deploy_command, proj_config.path)
    except DeployError:
        _record_deploy_activity(
            project,
            "deploy",
            success=False,
            project_path=proj_config.path,
        )
        raise
    _record_deploy_activity(
        project,
        "deploy",
        success=True,
        project_path=proj_config.path,
    )


def _run_health_check_step(
    healthcheck_url: str,
    project: str,
    *,
    indent: str = "",
) -> None:
    """Run a health check and print a consistent status message."""
    result = check_health(healthcheck_url, project)
    if result.is_up:
        console.print(f"{indent}[bold green]Healthy:[/] {project} is up")
    elif result.error:
        console.print(f"{indent}[bold yellow]Warning:[/] {result.error}")
    else:
        console.print(f"{indent}[bold yellow]Warning:[/] {project} is not healthy")


@app.command
def deploy(
    project: str | None = None,
    *,
    build: bool = False,
    check: bool = False,
    config: Path | None = None,
) -> None:
    """Deploy a project.

    Parameters
    ----------
    project: str | None
        Project name to deploy. Deploys all if omitted.
    build: bool
        Run build_command before deploying. Silently skips if no build_command
        is configured. Always enabled when deploying all projects.
    check: bool
        Verify deployment health via healthchecker after deploy.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)

    if not project:
        if check and not cfg.defaults.healthcheck_url:
            _warn_missing_healthcheck_url()
        _deploy_all(cfg, check=check)
        return  # _deploy_all calls sys.exit(); guard against refactors

    proj_config = _resolve_proj(cfg, project)

    if not proj_config.deployable:
        console.print(f"[dim]{project} — skipped (not deployable)[/]")
        sys.exit(ExitCode.OK)

    if not proj_config.deploy_command:
        _fatal(
            f"No deploy_command configured for [bold]{project}[/]. "
            f"Add deploy_command to [projects.{project}] in ~/.mm/config.toml."
        )

    if build and proj_config.build_command:
        console.print(f"[bold]Building {project}[/]\n")
        try:
            _run_build_step(project, proj_config)
        except BuildError as e:
            _fatal(str(e), code=ExitCode.BUILD_FAILED)
        console.print("\n[bold green]Build succeeded.[/]\n")

    console.print(f"[bold]Deploying {project}[/]\n")

    try:
        _run_deploy_step(project, proj_config)
    except DeployError as e:
        _fatal(str(e), code=ExitCode.DEPLOY_FAILED)

    console.print("\n[bold green]Deploy succeeded.[/]")

    if check:
        if not cfg.defaults.healthcheck_url:
            _warn_missing_healthcheck_url()
        else:
            console.print(f"\n[bold]Checking health of {project}...[/]")
            _run_health_check_step(cfg.defaults.healthcheck_url, project)

    sys.exit(ExitCode.OK)


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

    passed, failed_phase = run_test_phases(proj_config, proj_config.path)

    if passed:
        console.print("\n[bold green]All test phases passed.[/]")
        sys.exit(ExitCode.OK)
    else:
        console.print(f"\n[bold red]Failed:[/] {failed_phase} tests")
        sys.exit(ExitCode.TEST_FAILED)


@app.command
def build(
    project: str,
    *,
    config: Path | None = None,
) -> None:
    """Build a project's artefacts.

    Parameters
    ----------
    project: str
        Project name to build.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)

    if not proj_config.build_command:
        _fatal(
            f"No build_command configured for [bold]{project}[/]. "
            f"Add build_command to [projects.{project}] in ~/.mm/config.toml."
        )

    console.print(f"[bold]Building {project}[/]\n")

    activity_path = _config.MM_HOME / "activity.json"
    branch = _safe_branch(proj_config.path)
    try:
        run_build(project, proj_config.build_command, proj_config.path)
    except BuildError as e:
        record_activity(activity_path, project, "build", success=False, branch=branch)
        _fatal(str(e), code=ExitCode.BUILD_FAILED)

    record_activity(activity_path, project, "build", success=True, branch=branch)
    console.print("\n[bold green]Build succeeded.[/]")
    sys.exit(ExitCode.OK)


_NO_DATA = "[dim]—[/]"


@app.command(name=("list", "status"))
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

    activity = load_activity(_config.MM_HOME / "activity.json")

    table = Table(title="Configured Projects")
    for col, kw in [
        ("Name", {"style": "bold"}),
        ("Type", {}),
        ("Vulns", {"justify": "right"}),
        ("Updates", {"justify": "right"}),
        ("Secrets", {"justify": "right"}),
        ("Scanned", {}),
        ("Built", {}),
        ("Deployed", {}),
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

        proj_activity = activity.get(name)
        table.add_row(
            name,
            project.package_manager,
            *counts,
            _format_activity(proj_activity.last_build if proj_activity else None),
            "[dim]n/a[/]"
            if not project.deployable
            else _format_activity(proj_activity.last_deploy if proj_activity else None),
        )

    console.print(table)

    if detail:
        for name in sorted(scan_results):
            _print_scan_result(scan_results[name])


@app.command
def todo(
    project: str | None = None,
    *,
    config: Path | None = None,
) -> None:
    """Show TODO.md items for projects.

    Parameters
    ----------
    project: str | None
        Project name. Shows all projects if omitted.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)

    if project:
        proj_config = _resolve_proj(cfg, project)
        _print_project_todo(project, proj_config.path)
        return

    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    empty = []
    has_content = []
    for name in sorted(cfg.projects):
        todo_path = cfg.projects[name].path / "TODO.md"
        content = todo_path.read_text().strip() if todo_path.exists() else ""
        if content:
            has_content.append(name)
        else:
            empty.append(name)

    for name in empty:
        _print_project_todo(name, cfg.projects[name].path)
    for name in has_content:
        _print_project_todo(name, cfg.projects[name].path)


# -- Helpers ------------------------------------------------------------------


def _print_project_todo(name: str, project_path: Path) -> None:
    """Print a single project's TODO.md content with header."""
    todo_path = project_path / "TODO.md"
    if not todo_path.exists():
        console.print(Panel("[dim]no TODO.md[/]", title=name, border_style="dim"))
        return
    content = todo_path.read_text().strip()
    if not content:
        console.print(Panel("[dim]empty[/]", title=name, border_style="dim"))
        return
    console.print(Panel(Markdown(content), title=name))


def _safe_branch(project_path: Path) -> str:
    """Get current branch, returning 'unknown' on any failure."""
    try:
        return get_current_branch(project_path)
    except Exception:
        return "unknown"


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
    if not has_test_config(proj_config):
        _fatal(
            f"No test configuration for [bold]{project}[/]. "
            f"Add test_unit to [projects.{project}] in ~/.mm/config.toml."
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


def _format_activity(event: ActivityEvent | None, now: datetime | None = None) -> str:
    """Format an activity event as relative time with optional failure marker."""
    if event is None:
        return _NO_DATA
    time_str = _relative_time(event.timestamp, now)
    if not event.success:
        return f"{time_str} [red]\\[F][/]"
    return time_str


def _scan_one(name: str, proj_config: ProjectConfig, min_age_days: int) -> ScanResult:
    """Scan a single project with timing output."""
    try:
        sync_remote(proj_config.path)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        console.print(
            f"[bold yellow]Warning:[/] {name} — failed to sync remote: {exc}"
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
                win_versions[pkg] = highest_fix_version(group)

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


