import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Annotated, Literal, NoReturn

import cyclopts
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
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
    MaintenanceFlow,
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
    Finding,
    NoScanResultsError,
    UpdateResult,
    consolidate_vulns,
    has_test_config,
    highest_fix_version,
    load_scan_results,
    process_findings,
    process_updates_local,
    process_vulns_local,
    remove_completed_findings,
    run_test_phases,
    save_scan_results,
    sort_updates_by_risk,
)
from maintenance_man.vcs import (
    GraphiteNotFoundError,
    RepoDirtyError,
    check_graphite_available,
    check_repo_clean,
    create_worktree,
    ensure_on_main,
    get_current_branch,
    git_branch_exists,
    git_checkout,
    git_create_branch,
    git_delete_branch,
    git_merge_fast_forward,
    git_replace_branch,
    remove_worktree,
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
    BUILD_FAILED = 6
    DEPLOY_FAILED = 7


@dataclass
class DeployResult:
    project: str
    build_status: Literal["pass", "fail", "skip"]
    deploy_status: Literal["pass", "fail", "skip"]


@dataclass(slots=True)
class _UpdateFinalisation:
    results: list[UpdateResult]
    exit_code: int
    delete_branch: bool = False


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
    mode, targets = _resolve_update_targets(
        cfg,
        list(projects),
        negate=negate,
    )

    _exit_if_no_update_targets(cfg, targets)

    if mode == "single":
        _update_interactive(
            cfg,
            targets[0],
        )
        return  # _update_interactive calls sys.exit(); guard against refactors

    _update_batch_targets(cfg, target_names=targets)


@app.command
def resolve(
    project: str,
    continue_: Annotated[bool, cyclopts.Parameter(name="--continue")] = False,
    config: Path | None = None,
) -> None:
    """Work through failed findings for a project.

    Applies each failed finding, runs tests, and stops on failure for
    debugging. Use --continue after committing a manual fix to re-test and
    proceed. Submits a PR via Graphite when all findings are resolved.

    Parameters
    ----------
    project: str
        Project name (required).
    continue_: bool
        Re-test a manually fixed, committed failed finding on the current branch.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)
    _require_test_config(project, proj_config)
    results_dir = _config.MM_HOME / "scan-results"

    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError as e:
        _fatal(str(e))

    _assert_supported_in_progress_state(scan_result, project)
    _assert_no_conflicting_flow(scan_result, MaintenanceFlow.RESOLVE, project)

    failed_findings = _ordered_failed_findings(scan_result)
    resolve_candidates = _ordered_resolve_candidates(scan_result)
    if not failed_findings and not resolve_candidates and not _ordered_ready_findings(
        scan_result,
        flow=MaintenanceFlow.RESOLVE,
    ):
        console.print("Nothing to resolve.")
        sys.exit(ExitCode.OK)

    if continue_:
        _handle_resolve_continue(project, proj_config, scan_result, results_dir)

    try:
        check_graphite_available()
    except GraphiteNotFoundError as e:
        _fatal(str(e))

    try:
        check_repo_clean(proj_config.path)
    except RepoDirtyError as e:
        console.print(f"[bold yellow]Warning:[/] {e}")
        if Confirm.ask("  Discard changes and reset to main?", default=False):
            reset_to_main(proj_config.path)
        else:
            sys.exit(ExitCode.ERROR)

    if not ensure_on_main(proj_config.path):
        _fatal(f"Could not checkout main for [bold]{project}[/].")
    if not sync_graphite(proj_config.path):
        _fatal("Failed to sync trunk. Check network and gt auth.")
    if not _prepare_branch(_RESOLVE_BRANCH, project, proj_config.path):
        _fatal(f"Aborted resolve for [bold]{project}[/].")

    sys.exit(
        _run_resolve_findings(
            project,
            proj_config,
            scan_result,
            results_dir,
            resolve_candidates,
        )
    )


@contextmanager
def _worktree_context(
    proj_config: ProjectConfig,
    project: str,
    *,
    branch: str = "main",
    detach: bool = True,
):
    """Create a temporary worktree, yield a config pointing at it, then clean up."""
    wt_path = _config.MM_HOME / "worktrees" / project
    if wt_path.exists():
        remove_worktree(proj_config.path, wt_path)
    if not create_worktree(
        proj_config.path,
        wt_path,
        branch=branch,
        detach=detach,
    ):
        yield None
        return
    try:
        yield proj_config.model_copy(update={"path": wt_path})
    finally:
        remove_worktree(proj_config.path, wt_path)


_UPDATE_BRANCH = "mm/update-dependencies"
_RESOLVE_BRANCH = "mm/resolve-dependencies"


def _lifecycle_findings(scan_result: ScanResult) -> list[Finding]:
    return [
        *[v for v in scan_result.vulnerabilities if v.actionable],
        *scan_result.updates,
    ]


def _findings_for_flow(scan_result: ScanResult, flow: MaintenanceFlow) -> list[Finding]:
    return [f for f in _lifecycle_findings(scan_result) if f.flow == flow]


def _findings_with_status(
    scan_result: ScanResult,
    status: UpdateStatus,
    *,
    flow: MaintenanceFlow | None = None,
) -> list[Finding]:
    findings = [
        f for f in _lifecycle_findings(scan_result) if f.update_status == status
    ]
    if flow is not None:
        findings = [f for f in findings if f.flow == flow]
    return findings


def _in_progress_findings(
    scan_result: ScanResult,
    flow: MaintenanceFlow,
) -> list[Finding]:
    return [
        f
        for f in _findings_for_flow(scan_result, flow)
        if f.update_status in {UpdateStatus.FAILED, UpdateStatus.READY}
    ]


def _ordered_ready_findings(
    scan_result: ScanResult,
    flow: MaintenanceFlow,
) -> list[Finding]:
    ready = _findings_with_status(scan_result, UpdateStatus.READY, flow=flow)
    ready_vulns = [f for f in ready if isinstance(f, VulnFinding)]
    ready_updates = [f for f in ready if isinstance(f, UpdateFinding)]
    return [*consolidate_vulns(ready_vulns), *sort_updates_by_risk(ready_updates)]


def _ordered_failed_findings(
    scan_result: ScanResult,
) -> list[Finding]:
    """Return remaining resolve-owned failed findings in resolve order."""
    failed = _findings_with_status(
        scan_result,
        UpdateStatus.FAILED,
        flow=MaintenanceFlow.RESOLVE,
    )
    failed_vulns = [f for f in failed if isinstance(f, VulnFinding)]
    failed_updates = [f for f in failed if isinstance(f, UpdateFinding)]
    return [*consolidate_vulns(failed_vulns), *sort_updates_by_risk(failed_updates)]


def _ordered_resolve_candidates(scan_result: ScanResult) -> list[Finding]:
    candidates = [
        f
        for f in _lifecycle_findings(scan_result)
        if (
            f.flow is None
            and f.update_status is None
        )
        or (
            f.flow == MaintenanceFlow.RESOLVE
            and f.update_status == UpdateStatus.FAILED
        )
    ]
    candidate_vulns = [f for f in candidates if isinstance(f, VulnFinding)]
    candidate_updates = [f for f in candidates if isinstance(f, UpdateFinding)]
    return [
        *consolidate_vulns(candidate_vulns),
        *sort_updates_by_risk(candidate_updates),
    ]


def _assert_supported_in_progress_state(scan_result: ScanResult, project: str) -> None:
    unsupported = [
        f
        for f in _lifecycle_findings(scan_result)
        if f.update_status in {UpdateStatus.FAILED, UpdateStatus.READY}
        and f.flow is None
    ]
    if unsupported:
        _fatal(
            f"Unsupported in-progress scan state for [bold]{project}[/]. "
            "Discard the old scan results and rescan."
        )


def _assert_no_conflicting_flow(
    scan_result: ScanResult,
    active_flow: MaintenanceFlow,
    project: str,
) -> None:
    conflicting = [
        f
        for f in _lifecycle_findings(scan_result)
        if f.update_status in {UpdateStatus.FAILED, UpdateStatus.READY}
        and f.flow is not None
        and f.flow != active_flow
    ]
    if conflicting:
        other_flow = conflicting[0].flow
        assert other_flow is not None
        _fatal(
            f"{project} already has in-progress {other_flow} findings. "
            f"Finish or discard that {other_flow} flow before running {active_flow}."
        )


def _prepare_branch(branch: str, project: str, working_path: Path) -> bool:
    """Create or replace a named branch, prompting on collision."""
    if not git_branch_exists(branch, working_path):
        return git_create_branch(branch, working_path)

    choice = Prompt.ask(
        f"Branch {branch} already exists for {project}. [m]erge/[d]iscard/[a]bort",
        choices=["m", "d", "a"],
        default="a",
    )
    if choice == "m":
        return git_checkout(branch, working_path)
    if choice == "d":
        return git_replace_branch(branch, "main", working_path)
    return False


def _warn_missing_update_test_config(project: str, proj_config: ProjectConfig) -> None:
    if not has_test_config(proj_config):
        console.print(
            f"  [bold yellow]Warning:[/] {project} — "
            "no test configuration. Continuing without tests."
        )


def _merge_failure_result() -> UpdateResult:
    return UpdateResult(
        pkg_name="(merge)",
        kind="update",
        passed=False,
        failed_phase="merge",
    )


def _finalise_local_update(
    project: str,
    repo_path: Path,
    results_dir: Path,
    scan_result: ScanResult,
    all_results: list[UpdateResult],
    *,
    merge_prompt: str,
    keep_message: str,
    all_failed_message: str,
) -> _UpdateFinalisation:
    """Handle merge, persistence, and deferred branch cleanup for updates."""
    ready_findings = _ordered_ready_findings(
        scan_result,
        flow=MaintenanceFlow.UPDATE,
    )
    failed_findings = _findings_with_status(
        scan_result,
        UpdateStatus.FAILED,
        flow=MaintenanceFlow.UPDATE,
    )

    if failed_findings:
        if not ready_findings:
            console.print(all_failed_message)
        return _UpdateFinalisation(
            results=all_results,
            exit_code=ExitCode.UPDATE_FAILED,
        )

    if not ready_findings:
        return _UpdateFinalisation(results=all_results, exit_code=ExitCode.OK)

    if not Confirm.ask(merge_prompt, default=True):
        console.print(keep_message)
        return _UpdateFinalisation(results=all_results, exit_code=ExitCode.OK)

    if not git_checkout("main", repo_path):
        console.print(f"  [bold red]Error:[/] {project} — could not checkout main")
        return _UpdateFinalisation(
            results=all_results + [_merge_failure_result()],
            exit_code=ExitCode.UPDATE_FAILED,
        )

    if not git_merge_fast_forward(_UPDATE_BRANCH, repo_path):
        console.print(
            "  [bold yellow]Merge failed.[/] Keeping "
            f"{_UPDATE_BRANCH} for manual recovery."
        )
        return _UpdateFinalisation(
            results=all_results + [_merge_failure_result()],
            exit_code=ExitCode.UPDATE_FAILED,
        )

    for finding in ready_findings:
        finding.update_status = UpdateStatus.COMPLETED
        finding.failed_phase = None
        finding.flow = None
    remove_completed_findings(scan_result)
    save_scan_results(project, results_dir, scan_result)
    return _UpdateFinalisation(
        results=all_results,
        exit_code=ExitCode.OK,
        delete_branch=True,
    )


def _summarise_update_results(all_results: list[UpdateResult]) -> None:
    """Print a concise summary for an update run."""
    passed = [r for r in all_results if r.passed]
    failed = [r for r in all_results if not r.passed]

    console.print("\n" + "─" * 40)
    console.print("[bold]Summary:[/]")
    if passed:
        console.print(f"  [green]{len(passed)} passed[/]")
    if failed:
        phase_labels = {
            "apply": "install failed",
            "commit": "commit failed",
            "merge": "merge failed",
        }
        for r in failed:
            label = phase_labels.get(r.failed_phase, r.failed_phase or "unknown")
            console.print(f"  [red]FAIL[/] {r.pkg_name} — {label}")
    console.print("─" * 40)

def _submit_resolve_branch(
    project: str,
    project_path: Path,
    results_dir: Path,
    scan_result: ScanResult,
    ready_findings: list[Finding],
) -> int:
    """Submit the resolve branch and persist scan cleanup on success."""
    try:
        check_graphite_available()
    except GraphiteNotFoundError as e:
        _fatal(str(e))

    ok, output = submit_stack(project_path)
    if output:
        console.print(f"  [dim]{output}[/]")
    if not ok:
        save_scan_results(project, results_dir, scan_result)
        console.print(
            "  [bold yellow]Submit failed.[/] Keeping "
            f"{_RESOLVE_BRANCH} for manual recovery."
        )
        return ExitCode.UPDATE_FAILED

    for f in ready_findings:
        f.update_status = UpdateStatus.COMPLETED
        f.failed_phase = None
        f.flow = None
    remove_completed_findings(scan_result)
    save_scan_results(project, results_dir, scan_result)
    return ExitCode.OK


def _run_resolve_findings(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
    findings: list[VulnFinding | UpdateFinding],
) -> int:
    """Process remaining resolve findings, pausing or submitting as needed."""
    results = process_findings(
        findings,
        proj_config,
        flow=MaintenanceFlow.RESOLVE,
        scan_result=scan_result,
        project_name=project,
        results_dir=results_dir,
        on_failure="stop",
    )
    if any(not r.passed for r in results):
        console.print(
            "  [bold yellow]Resolve paused.[/] Continue with "
            f"[bold]mm resolve {project} --continue[/]."
        )
        return ExitCode.UPDATE_FAILED

    remaining_failed = _ordered_failed_findings(scan_result)
    if remaining_failed:
        console.print(
            "  [bold yellow]Resolve paused.[/] Continue with "
            f"[bold]mm resolve {project} --continue[/]."
        )
        return ExitCode.UPDATE_FAILED

    ready_findings = _ordered_ready_findings(
        scan_result,
        flow=MaintenanceFlow.RESOLVE,
    )
    if not ready_findings:
        return ExitCode.OK
    return _submit_resolve_branch(
        project, proj_config.path, results_dir, scan_result, ready_findings
    )


def _handle_resolve_continue(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
) -> NoReturn:
    """Resume the paused resolve blocker after a committed manual fix."""
    if get_current_branch(proj_config.path) != _RESOLVE_BRANCH:
        _fatal(f"--continue requires being on {_RESOLVE_BRANCH}.")
    try:
        check_repo_clean(proj_config.path)
    except RepoDirtyError:
        _fatal(
            "--continue requires a clean working tree. "
            "Commit or discard manual changes first."
        )

    remaining = _ordered_failed_findings(scan_result)
    if not remaining:
        console.print("Nothing to resolve.")
        sys.exit(ExitCode.OK)

    current = remaining[0]
    if current.failed_phase == "apply":
        retry_results = process_findings(
            [current],
            proj_config,
            flow=MaintenanceFlow.RESOLVE,
            scan_result=scan_result,
            project_name=project,
            results_dir=results_dir,
            on_failure="stop",
        )
        if any(not r.passed for r in retry_results):
            sys.exit(ExitCode.UPDATE_FAILED)
    else:
        passed, failed_phase = run_test_phases(proj_config, proj_config.path)
        if not passed:
            current.update_status = UpdateStatus.FAILED
            current.failed_phase = failed_phase
            current.flow = MaintenanceFlow.RESOLVE
            save_scan_results(project, results_dir, scan_result)
            console.print(
                f"  [bold red]FAIL[/] {current.pkg_name} — {failed_phase} failed"
            )
            sys.exit(ExitCode.UPDATE_FAILED)

        current.update_status = UpdateStatus.READY
        current.failed_phase = None
        current.flow = MaintenanceFlow.RESOLVE
        save_scan_results(project, results_dir, scan_result)

    sys.exit(
        _run_resolve_findings(
            project,
            proj_config,
            scan_result,
            results_dir,
            _ordered_resolve_candidates(scan_result),
        )
    )


@dataclass(slots=True)
class _UpdateRunState:
    scan_result: ScanResult
    actionable_vulns: list[VulnFinding]
    updates: list[UpdateFinding]
    failed_vulns: list[VulnFinding]
    failed_updates: list[UpdateFinding]
    ready_findings: list[Finding]
    resume: bool

    @property
    def has_findings(self) -> bool:
        return bool(self.actionable_vulns or self.updates)

    @property
    def available_vulns(self) -> list[VulnFinding]:
        return self.failed_vulns if self.resume else self.actionable_vulns

    @property
    def available_updates(self) -> list[UpdateFinding]:
        return self.failed_updates if self.resume else self.updates

    @property
    def merge_only(self) -> bool:
        return (
            self.resume
            and not self.available_vulns
            and not self.available_updates
            and bool(self.ready_findings)
        )


@dataclass(frozen=True, slots=True)
class _UpdateSelection:
    vulns: list[VulnFinding]
    updates: list[UpdateFinding]

    @property
    def empty(self) -> bool:
        return not self.vulns and not self.updates



def _load_update_run_state(project: str, results_dir: Path) -> _UpdateRunState:
    scan_result = load_scan_results(project, results_dir)
    update_flow = MaintenanceFlow.UPDATE
    _assert_supported_in_progress_state(scan_result, project)
    _assert_no_conflicting_flow(scan_result, update_flow, project)

    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates
    failed_vulns = [
        v
        for v in actionable_vulns
        if v.update_status == UpdateStatus.FAILED and v.flow == update_flow
    ]
    failed_updates = [
        u
        for u in updates
        if u.update_status == UpdateStatus.FAILED and u.flow == update_flow
    ]

    return _UpdateRunState(
        scan_result=scan_result,
        actionable_vulns=actionable_vulns,
        updates=updates,
        failed_vulns=failed_vulns,
        failed_updates=failed_updates,
        ready_findings=_ordered_ready_findings(scan_result, flow=update_flow),
        resume=bool(_in_progress_findings(scan_result, update_flow)),
    )



def _prepare_update_workspace(
    stack: ExitStack,
    project: str,
    proj_config: ProjectConfig,
    *,
    resume: bool,
) -> tuple[ProjectConfig | None, str | None]:
    repo_path = proj_config.path
    worktree_branch = _UPDATE_BRANCH if resume else "main"

    if resume:
        if not git_branch_exists(_UPDATE_BRANCH, repo_path):
            return None, (
                f"Missing {_UPDATE_BRANCH} for in-progress update flow on "
                f"[bold]{project}[/]."
            )
    else:
        try:
            check_graphite_available()
        except GraphiteNotFoundError as e:
            return None, str(e)
        if not sync_graphite(repo_path):
            return None, "Failed to sync trunk. Check network and gt auth."

    wt_config = stack.enter_context(
        _worktree_context(
            proj_config,
            project,
            branch=worktree_branch,
            detach=not resume,
        )
    )
    if wt_config is None:
        return None, "Could not create worktree."

    if not resume and not _prepare_branch(_UPDATE_BRANCH, project, wt_config.path):
        return None, f"Aborted update for [bold]{project}[/]."

    return wt_config, None



def _prompt_for_update_selection(state: _UpdateRunState) -> _UpdateSelection | None:
    if state.merge_only:
        return _UpdateSelection(vulns=[], updates=[])

    _print_scan_result(state.scan_result)
    numbered = _print_numbered_findings(state.available_vulns, state.available_updates)

    parts = ["all"]
    if state.available_vulns:
        parts.append("vulns")
    if state.available_updates:
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
            state.available_vulns,
            state.available_updates,
        )
        if result is not None:
            return _UpdateSelection(*result)
        console.print(f"[bold red]Invalid selection:[/] '{selection}'. Try again.")



def _process_update_selection(
    project: str,
    work_config: ProjectConfig,
    state: _UpdateRunState,
    results_dir: Path,
    selection: _UpdateSelection,
) -> list[UpdateResult]:
    results: list[UpdateResult] = []
    update_flow = MaintenanceFlow.UPDATE

    if selection.vulns:
        console.print(f"\n[bold]Processing {len(selection.vulns)} vuln fix(es)...[/]")
        results.extend(
            process_vulns_local(
                selection.vulns,
                work_config,
                flow=update_flow,
                scan_result=state.scan_result,
                project_name=project,
                results_dir=results_dir,
            )
        )

    if selection.updates:
        console.print(f"\n[bold]Processing {len(selection.updates)} update(s)...[/]")
        results.extend(
            process_updates_local(
                selection.updates,
                work_config,
                flow=update_flow,
                scan_result=state.scan_result,
                project_name=project,
                results_dir=results_dir,
            )
        )

    return results



def _cleanup_update_branch(repo_path: Path, finalisation: _UpdateFinalisation) -> None:
    if finalisation.delete_branch:
        git_checkout("main", repo_path)
        git_delete_branch(_UPDATE_BRANCH, repo_path)



def _update_interactive(
    cfg: MmConfig,
    project: str,
) -> NoReturn:
    """Update a single project with the local single-branch flow."""
    proj_config = _resolve_proj(cfg, project)
    repo_path = proj_config.path
    results_dir = _config.MM_HOME / "scan-results"

    try:
        state = _load_update_run_state(project, results_dir)
    except NoScanResultsError as e:
        _fatal(str(e))

    if not state.has_findings:
        console.print(f"[bold green]{project}[/] — nothing to update.")
        sys.exit(ExitCode.OK)

    try:
        check_repo_clean(repo_path)
    except RepoDirtyError as e:
        _fatal(str(e))

    _warn_missing_update_test_config(project, proj_config)

    with ExitStack() as stack:
        work_config, error = _prepare_update_workspace(
            stack,
            project,
            proj_config,
            resume=state.resume,
        )
        if error is not None:
            _fatal(error)
        assert work_config is not None

        selection = _prompt_for_update_selection(state)
        assert selection is not None
        if selection.empty and not state.merge_only:
            sys.exit(ExitCode.OK)

        finalisation = _finalise_local_update(
            project,
            repo_path,
            results_dir,
            state.scan_result,
            []
            if state.merge_only
            else _process_update_selection(
                project,
                work_config,
                state,
                results_dir,
                selection,
            ),
            merge_prompt="Merge ready changes into main?",
            keep_message=f"  [dim]Keeping {_UPDATE_BRANCH} for later review.[/]",
            all_failed_message=(
                f"  [bold yellow]Update paused with failed findings.[/] "
                f"Keeping {_UPDATE_BRANCH} for retry."
            ),
        )
        _summarise_update_results(finalisation.results)

    _cleanup_update_branch(repo_path, finalisation)
    sys.exit(finalisation.exit_code)



def _update_batch(
    project: str,
    proj_config: ProjectConfig,
    results_dir: Path,
) -> list[UpdateResult] | None:
    """Process all actionable findings for a single project (batch mode)."""
    try:
        state = _load_update_run_state(project, results_dir)
    except NoScanResultsError:
        return []

    if not state.has_findings:
        console.print(f"  [dim]{project} — nothing to update[/]")
        return []

    repo_path = proj_config.path
    try:
        check_repo_clean(repo_path)
    except RepoDirtyError as e:
        console.print(f"  [bold red]Error:[/] {project} — {e}")
        return None

    _warn_missing_update_test_config(project, proj_config)

    with ExitStack() as stack:
        work_config, error = _prepare_update_workspace(
            stack,
            project,
            proj_config,
            resume=state.resume,
        )
        if error is not None:
            console.print(f"  [bold red]Error:[/] {project} — {error}")
            return None
        assert work_config is not None

        _print_scan_result(state.scan_result)
        selection = _UpdateSelection(
            vulns=[] if state.merge_only else state.available_vulns,
            updates=[] if state.merge_only else state.available_updates,
        )
        finalisation = _finalise_local_update(
            project,
            repo_path,
            results_dir,
            state.scan_result,
            []
            if state.merge_only
            else _process_update_selection(
                project,
                work_config,
                state,
                results_dir,
                selection,
            ),
            merge_prompt=f"Merge ready changes for {project} into main?",
            keep_message=f"  [dim]Keeping {_UPDATE_BRANCH} for {project}.[/]",
            all_failed_message=(
                f"  [bold yellow]Update paused with failed findings for {project}.[/] "
                f"Keeping {_UPDATE_BRANCH}."
            ),
        )

    _cleanup_update_branch(repo_path, finalisation)
    _summarise_update_results(finalisation.results)
    return finalisation.results



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

        results = _update_batch(
            name,
            proj_config,
            results_dir,
        )
        if results is None:
            had_errors = True
        elif results:
            all_project_results.append((name, results))

    _print_mass_update_summary(all_project_results)

    any_failed = had_errors or any(
        not r.passed for _, results in all_project_results for r in results
    )
    sys.exit(ExitCode.UPDATE_FAILED if any_failed else ExitCode.OK)


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
    if not ensure_on_main(proj_config.path):
        console.print(
            f"[bold yellow]Warning:[/] {name} — could not checkout main, "
            "scanning current branch state"
        )

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
