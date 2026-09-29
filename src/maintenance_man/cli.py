import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, NoReturn

import cyclopts
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from maintenance_man import __version__, gradle_workflow, paths, vcs_workflow
from maintenance_man.config import (
    ConfigError,
    ProjectNotFoundError,
    ensure_mm_home,
    load_config,
    resolve_project,
)
from maintenance_man.deployer import BuildError
from maintenance_man.exit_codes import ExitCode
from maintenance_man.github import CodeHostError
from maintenance_man.models.activity import ActivityEvent
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.events import (
    DeployStep,
    DeployStepFailed,
    DeployStepStarted,
    DeployStepSucceeded,
    Emit,
    Event,
    FindingFailed,
    FindingPassed,
    FindingsProcessed,
    FindingStarted,
    FindingStepFailed,
    FindingStepKind,
    GradleFlowFailed,
    GradleRunArchived,
    GradleRunReported,
    GradleWithheld,
    HealthChecked,
    HealthcheckUnconfigured,
    MissingTestConfig,
    NoEligibleGradleChanges,
    Operation,
    OperationFailed,
    Outcome,
    ProcessingStarted,
    ProjectSkipped,
    ProjectStarted,
    Promoted,
    PullRequestOutput,
    ScanReported,
    SkipReason,
    SyncCompleted,
    TestCommandStarted,
)
from maintenance_man.models.gradle import (
    FailedAttempt,
    GradleCandidate,
    GradleRun,
    WithheldAttempt,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    ScanResult,
    SecretFinding,
    UpdateFinding,
    UpdateResult,
    UpdateStatus,
    VulnFinding,
    Workflow,
    highest_fix_version,
    sort_vulns_by_severity,
)
from maintenance_man.process import ToolNotFoundError
from maintenance_man.services import WorkflowError, flows
from maintenance_man.services import deploy as deploy_service
from maintenance_man.services import scan as scan_service
from maintenance_man.services import update as update_service
from maintenance_man.services.scan import ScanSummary
from maintenance_man.storage import (
    NoScanResultsError,
    load_activity,
    load_scan_results,
    save_scan_results,
)
from maintenance_man.updater import (
    Finding,
    consolidate_vulns,
    process_findings,
    remove_completed_findings,
    run_test_phases,
    sort_updates_by_risk,
)
from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import (
    VcsServices,
    ensure_main_bookmark,
    make_vcs_services,
    push_bookmark_and_create_pr,
)
from maintenance_man.vcs_workflow import (
    prune_stale_bookmarks as prune_repository_bookmarks,
)

console = Console()

_TABLE_STYLE: dict[str, Any] = {"show_edge": False, "pad_edge": False, "box": None}

type _Render = Callable[[Any, bool], None]
_RENDERERS: dict[type, _Render] = {}


def _renders(kind: type) -> Callable[[_Render], _Render]:
    def register(render: _Render) -> _Render:
        _RENDERERS[kind] = render
        return render

    return register


@dataclass(frozen=True, slots=True)
class _Renderer:
    batch: bool

    def __call__(self, event: Event) -> None:
        _RENDERERS[type(event)](event, self.batch)


_SKIP_TEXT: dict[SkipReason, tuple[str | None, str | None]] = {
    SkipReason.PATH_MISSING: (
        "[bold yellow]Warning:[/] {name} — path does not exist: {detail}",
        "[bold yellow]Warning:[/] {name} — path does not exist: {detail}",
    ),
    SkipReason.NO_SCAN_RESULTS: (
        "[bold green]{name}[/] — no scan results; nothing to do.",
        None,
    ),
    SkipReason.NOTHING_TO_DO: (
        "[bold green]{name}[/] — nothing to {detail}.",
        "[dim]  {name} — nothing to update[/]",
    ),
    SkipReason.FLOW_CONFLICT: (
        "  [bold yellow]Skipped:[/] {name} — {detail}",
        "  [bold yellow]Skipped:[/] {name} — {detail}",
    ),
    SkipReason.NOT_DEPLOYABLE: (
        "[dim]{name} — skipped (not deployable)[/]",
        "[dim]{name} — skipped (not deployable)[/]",
    ),
    SkipReason.UNCHANGED: (
        "[bold yellow]{name}[/] unchanged since last deploy (use --force to redeploy).",
        "[dim]{name} — unchanged since last deploy[/]",
    ),
    SkipReason.BLOCKED: (
        "[bold yellow]Warning:[/] {name} — could not resolve main revision; "
        "skipping (use --force to deploy anyway)",
        "[bold yellow]Warning:[/] {name} — could not resolve main revision; "
        "skipping (use --force to deploy anyway)",
    ),
}

_OPERATION_TEXT: dict[Operation, tuple[str, str]] = {
    Operation.UPDATE_SETUP: (
        "  [bold red]Error:[/] {name} — {error}",
        "  [bold red]Error:[/] {name} — {error}",
    ),
    Operation.PROMOTE: (
        "[bold red]Promotion failed:[/] {error}",
        "[bold red]Promotion failed:[/] {error}",
    ),
    Operation.REFRESH: (
        "[bold red]Workspace refresh failed:[/] {name}: {error}",
        "[bold red]Workspace refresh failed:[/] {name}: {error}",
    ),
    Operation.WORKSPACE_CLEANUP: (
        "[bold red]Workspace cleanup failed:[/] {error}",
        "  [bold red]Workspace cleanup failed:[/] {error}",
    ),
    Operation.BOOKMARK_CLEANUP: (
        "[bold red]Bookmark cleanup failed:[/] {error}",
        "  [bold red]Bookmark cleanup failed:[/] {name} — {error}",
    ),
    Operation.RESOLVE_SETUP: (
        "  [bold red]Resolve setup failed:[/] {error}",
        "  [bold red]Resolve setup failed:[/] {error}",
    ),
    Operation.SUBMIT: (
        "  [dim]{error}[/]\n  [bold yellow]Submit failed.[/] Keeping {bookmark} "
        "for manual recovery.",
        "  [dim]{error}[/]\n  [bold yellow]Submit failed.[/] Keeping {bookmark} "
        "for manual recovery.",
    ),
    Operation.REMOTE_SYNC: (
        "[bold yellow]Warning:[/] {name} — failed to sync remote: {error}",
        "[bold yellow]Warning:[/] {name} — failed to sync remote: {error}",
    ),
    Operation.SCAN: (
        "[bold red]Error:[/] {name} — {error}",
        "[bold red]Error:[/] {name} — {error}",
    ),
    Operation.SYNC: (
        "[bold red]  {name} — {error}[/]",
        "[bold red]  {name} — {error}[/]",
    ),
}


@_renders(ProjectSkipped)
def _render_project_skipped(event: ProjectSkipped, batch: bool) -> None:
    template = _SKIP_TEXT[event.reason][int(batch)]
    if template is None:
        return
    console.print(
        template.format(name=escape(event.project), detail=escape(event.detail or ""))
    )


@_renders(OperationFailed)
def _render_operation_failed(event: OperationFailed, batch: bool) -> None:
    template = _OPERATION_TEXT[event.operation][int(batch)]
    console.print(
        template.format(
            name=escape(event.project),
            error=escape(event.error),
            bookmark=escape(WORKFLOW_BOOKMARKS[Workflow.RESOLVE]),
        )
    )


@_renders(ScanReported)
def _render_scan_reported(event: ScanReported, batch: bool) -> None:
    del batch
    _print_scan_result(event.result, elapsed_s=event.elapsed_s)


@_renders(MissingTestConfig)
def _render_missing_test_config(event: MissingTestConfig, batch: bool) -> None:
    del batch
    console.print(
        f"  [bold yellow]Warning:[/] {escape(event.project)} — no test "
        "configuration (test phases will be skipped)"
    )


@_renders(ProcessingStarted)
def _render_processing_started(event: ProcessingStarted, batch: bool) -> None:
    del batch
    if event.vulns:
        console.print(f"\n[bold]Processing {event.vulns} vuln fix(es)...[/]")
    if event.updates:
        console.print(f"\n[bold]Processing {event.updates} update(s)...[/]")


@_renders(FindingsProcessed)
def _render_findings_processed(event: FindingsProcessed, batch: bool) -> None:
    if not batch:
        _print_update_summary(list(event.results))


@_renders(Promoted)
def _render_promoted(event: Promoted, batch: bool) -> None:
    del batch
    console.print(f"[bold green]Promoted {escape(event.bookmark)} to main.[/]")


@_renders(SyncCompleted)
def _render_sync_completed(event: SyncCompleted, batch: bool) -> None:
    del batch
    console.print(f"  {escape(event.project)} — {escape(event.action)}")


@_renders(ProjectStarted)
def _render_project_started(event: ProjectStarted, batch: bool) -> None:
    if not batch:
        return
    console.print(f"\n{'═' * 40}")
    console.print(f"[bold]{escape(event.project)}[/]")
    console.print("═" * 40)


@_renders(FindingStarted)
def _render_finding_started(event: FindingStarted, batch: bool) -> None:
    del batch
    label = "[bold red]VULN[/]" if event.kind == "vuln" else "[bold cyan]UPDATE[/]"
    console.print(
        f"\n  {label} {escape(event.pkg)} {escape(event.installed)} -> "
        f"{escape(event.target)} ({escape(event.detail)})"
    )


@_renders(TestCommandStarted)
def _render_test_command_started(event: TestCommandStarted, batch: bool) -> None:
    del batch
    console.print(f"  [dim]$ {escape(event.command)}[/]")


@_renders(FindingStepFailed)
def _render_finding_step_failed(event: FindingStepFailed, batch: bool) -> None:
    del batch
    error = escape(event.error)
    if event.step is FindingStepKind.PACKAGE_COMMAND:
        console.print(f"  [bold red]FAIL[/] Package manager command failed: {error}")
    else:
        console.print(f"  [bold red]FAIL[/] {error}")


@_renders(FindingPassed)
def _render_finding_passed(event: FindingPassed, batch: bool) -> None:
    del batch
    suffix = " [dim](already applied)[/]" if event.already_applied else ""
    console.print(f"  [bold green]PASS[/] {escape(event.pkg)}{suffix}")


@_renders(FindingFailed)
def _render_finding_failed(event: FindingFailed, batch: bool) -> None:
    del batch
    console.print(
        f"  [bold red]FAIL[/] {escape(event.pkg)} — {escape(event.phase)} failed"
    )


@_renders(DeployStepStarted)
def _render_deploy_step_started(event: DeployStepStarted, batch: bool) -> None:
    if batch:
        if event.step is DeployStep.BUILD:
            console.print("  [bold]Building...[/]")
        elif event.step is DeployStep.DEPLOY:
            console.print("  [bold]Deploying...[/]")
        return

    if event.step is DeployStep.BUILD:
        console.print(f"[bold]Building {escape(event.project)}[/]\n")
    elif event.step is DeployStep.DEPLOY:
        console.print(f"[bold]Deploying {escape(event.project)}[/]\n")
    else:
        console.print(f"\n[bold]Checking health of {escape(event.project)}...[/]")


@_renders(DeployStepSucceeded)
def _render_deploy_step_succeeded(event: DeployStepSucceeded, batch: bool) -> None:
    if batch:
        return
    if event.step is DeployStep.BUILD:
        console.print("\n[bold green]Build succeeded.[/]\n")
    elif event.step is DeployStep.DEPLOY:
        console.print("\n[bold green]Deploy succeeded.[/]")


@_renders(DeployStepFailed)
def _render_deploy_step_failed(event: DeployStepFailed, batch: bool) -> None:
    error = escape(event.error)
    if not batch:
        console.print(f"[bold red]Error:[/] {error}")
    elif event.step is DeployStep.BUILD:
        console.print(f"  [bold red]Build failed:[/] {error}")
    elif event.step is DeployStep.DEPLOY:
        console.print(f"  [bold red]Deploy failed:[/] {error}")


@_renders(HealthChecked)
def _render_health_checked(event: HealthChecked, batch: bool) -> None:
    indent = "  " if batch else ""
    if event.is_up:
        console.print(f"{indent}[bold green]Healthy:[/] {escape(event.project)} is up")
    elif event.error:
        console.print(f"{indent}[bold yellow]Warning:[/] {escape(event.error)}")
    else:
        console.print(
            f"{indent}[bold yellow]Warning:[/] {escape(event.project)} is not healthy"
        )


@_renders(HealthcheckUnconfigured)
def _render_healthcheck_unconfigured(
    event: HealthcheckUnconfigured, batch: bool
) -> None:
    del event, batch
    console.print("[dim]--check: no healthcheck_url configured in \\[defaults][/]")


@_renders(PullRequestOutput)
def _render_pull_request_output(event: PullRequestOutput, batch: bool) -> None:
    del batch
    console.print(f"[dim]  {escape(event.text)}[/]")


@_renders(GradleWithheld)
def _render_gradle_withheld(event: GradleWithheld, batch: bool) -> None:
    del batch
    console.print(f"Withheld {escape(event.label)}: {escape(event.reason)}")


@_renders(NoEligibleGradleChanges)
def _render_no_eligible_gradle_changes(
    event: NoEligibleGradleChanges, batch: bool
) -> None:
    del event, batch
    console.print("No eligible Gradle changes")


@_renders(GradleRunArchived)
def _render_gradle_run_archived(event: GradleRunArchived, batch: bool) -> None:
    del batch
    console.print(
        f"Archived failed Gradle run to {escape(str(event.path))}; "
        "rebuilding candidates from main"
    )


@_renders(GradleFlowFailed)
def _render_gradle_flow_failed(event: GradleFlowFailed, batch: bool) -> None:
    del batch
    console.print(
        f"Cannot complete Gradle {escape(event.flow.value)}: {escape(event.error)}"
    )


@_renders(GradleRunReported)
def _render_gradle_run_reported(event: GradleRunReported, batch: bool) -> None:
    del batch
    _print_scan_result(event.scan)
    _print_gradle_run_summary(event.run)


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
    console.print(f"Initialised {escape(str(paths.mm_home()))}")
    console.print(f"Edit {escape(str(paths.config_path()))} to add projects.")


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

    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    vcs = make_vcs_services()

    if project:
        proj_config = _resolve_proj(cfg, project)
        try:
            result = scan_service.scan_one(
                project,
                proj_config,
                minimum_age_days=cfg.defaults.min_version_age_days,
                vcs=vcs,
                emit=_Renderer(batch=False),
            )
        except scan_service.SCAN_ERRORS as e:
            _fatal(str(e))
        sys.exit(_scan_exit_code(ScanSummary.of(result)))

    summary = scan_service.scan_all(cfg, vcs=vcs, emit=_Renderer(batch=True))
    sys.exit(_scan_exit_code(summary))


def _exit_if_no_update_targets(cfg: MmConfig, target_names: list[str]) -> None:
    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        sys.exit(ExitCode.OK)

    if not target_names:
        console.print("No target projects.")
        sys.exit(ExitCode.OK)


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
    try:
        mode, targets = update_service.resolve_update_targets(
            cfg, projects, negate=negate
        )
    except ProjectNotFoundError as exc:
        _fatal(str(exc))

    _exit_if_no_update_targets(cfg, targets)

    try:
        vcs_workflow.require_vcs_tools()
    except ToolNotFoundError as e:
        _fatal(str(e))

    vcs = make_vcs_services()
    if mode == "single":
        name = targets[0]
        proj_config = _resolve_proj(cfg, name)
        try:
            result = update_service.update_project(
                name,
                proj_config,
                minimum_age_days=cfg.defaults.min_version_age_days,
                choose=_choose_findings,
                choose_gradle=_choose_gradle_candidates,
                vcs=vcs,
                emit=_Renderer(batch=False),
            )
        except WorkflowError as exc:
            _fatal(str(exc))
        sys.exit(
            ExitCode.OK
            if result.outcome is Outcome.SUCCEEDED
            else ExitCode.UPDATE_FAILED
        )

    batch = update_service.update_projects(
        cfg, targets, vcs=vcs, emit=_Renderer(batch=True)
    )
    summary = [
        (project.project, list(project.results))
        for project in batch.projects
        if project.results
    ]
    if summary or not any(
        project.route is update_service.UpdateRoute.GRADLE for project in batch.projects
    ):
        _print_mass_update_summary(summary)
    sys.exit(ExitCode.UPDATE_FAILED if batch.outcome is Outcome.FAILED else ExitCode.OK)


@app.command
def sync(
    *projects: str,
    config: Path | None = None,
) -> None:
    """Sync local main with remote for one, many, or all configured projects.

    Parameters
    ----------
    projects: str
        Project names to sync. No names syncs all configured projects.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)

    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        sys.exit(ExitCode.OK)

    vcs_services = make_vcs_services()
    try:
        outcome = scan_service.sync_projects(
            cfg,
            projects,
            vcs=vcs_services,
            emit=_Renderer(batch=True),
        )
    except ProjectNotFoundError as exc:
        _fatal(str(exc))
    sys.exit(ExitCode.SYNC_FAILED if outcome is Outcome.FAILED else ExitCode.OK)


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
            "branch": "bookmark creation failed",
            "commit": "commit failed",
        }
        for r in failed:
            phase = r.failed_phase or "unknown"
            label = phase_labels.get(phase, phase)
            console.print(f"  [red]FAIL[/] {escape(r.pkg_name)} — {escape(label)}")
    console.print("─" * 40)


# -- Resolve command ---------------------------------------------------------


def _ordered_resolve_candidates(
    scan_result: ScanResult,
) -> list[Finding]:
    """Return fresh + resolve-owned failed findings, ordered for processing."""
    candidate_vulns = [
        v
        for v in scan_result.vulnerabilities
        if v.actionable
        and (
            (v.flow is None and v.update_status is None)
            or (v.flow == Workflow.RESOLVE and v.update_status == UpdateStatus.FAILED)
            or flows.is_resolve_claimable_failure(v, Workflow.RESOLVE)
        )
    ]
    candidate_updates = [
        u
        for u in scan_result.updates
        if (u.flow is None and u.update_status is None)
        or (u.flow == Workflow.RESOLVE and u.update_status == UpdateStatus.FAILED)
        or flows.is_resolve_claimable_failure(u, Workflow.RESOLVE)
    ]
    return [
        *consolidate_vulns(candidate_vulns),
        *sort_updates_by_risk(candidate_updates),
    ]


def _ordered_failed_findings(
    scan_result: ScanResult,
) -> list[Finding]:
    """Return resolve-owned FAILED findings in processing order."""
    failed_vulns = [
        v
        for v in scan_result.vulnerabilities
        if v.update_status == UpdateStatus.FAILED and v.flow == Workflow.RESOLVE
    ]
    failed_updates = [
        u
        for u in scan_result.updates
        if u.update_status == UpdateStatus.FAILED and u.flow == Workflow.RESOLVE
    ]
    return [
        *consolidate_vulns(failed_vulns),
        *sort_updates_by_risk(failed_updates),
    ]


def _ordered_ready_findings(
    scan_result: ScanResult,
    *,
    flow: Workflow,
) -> list[Finding]:
    """Return READY findings owned by *flow*, ordered for submission."""
    ready_vulns = [
        v
        for v in scan_result.vulnerabilities
        if v.update_status == UpdateStatus.READY and v.flow == flow
    ]
    ready_updates = [
        u
        for u in scan_result.updates
        if u.update_status == UpdateStatus.READY and u.flow == flow
    ]
    return [
        *consolidate_vulns(ready_vulns),
        *sort_updates_by_risk(ready_updates),
    ]


def _has_ready_resolve_progress(scan_result: ScanResult) -> bool:
    return any(
        f.update_status == UpdateStatus.READY and f.flow == Workflow.RESOLVE
        for f in scan_result.findings
    )


def _prepare_resolve_bookmark(
    project_path: Path,
    scan_result: ScanResult,
    candidates: list[Finding],
    *,
    vcs: VcsServices,
) -> bool:
    """Create or resume the resolve bookmark without dropping committed progress."""
    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    repo = vcs.repository(project_path)
    try:
        if _has_ready_resolve_progress(scan_result):
            if not repo.bookmark_exists(bookmark=bookmark):
                _fatal(
                    f"resolve bookmark '{bookmark}' is missing but "
                    "in-progress state exists — rescan or recover the bookmark manually"
                )
            if candidates:
                repo.new_change(revision=bookmark)
            return True

        if repo.bookmark_exists(bookmark=bookmark):
            repo.delete_bookmark(bookmark=bookmark)
        repo.create_bookmark(bookmark=bookmark, revision="main")
        repo.new_change(revision=bookmark)
    except RevisionError as exc:
        console.print(f"  [bold red]Resolve setup failed:[/] {escape(str(exc))}")
        return False
    return True


def _run_resolve_findings(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    findings: list[Finding],
    *,
    vcs: VcsServices,
) -> int:
    """Process resolve candidates; stop on first failure, submit when all READY."""
    results = process_findings(
        findings,
        proj_config,
        flow=Workflow.RESOLVE,
        scan_result=scan_result,
        project_name=project,
        on_failure="stop",
        vcs=vcs,
        emit=_Renderer(batch=False),
    )
    if any(not r.passed for r in results) or _ordered_failed_findings(scan_result):
        console.print(
            f"  [bold yellow]Resolve paused.[/] Continue with "
            f"[bold]mm resolve {escape(project)} --continue[/]."
        )
        return ExitCode.UPDATE_FAILED

    ready_findings = _ordered_ready_findings(scan_result, flow=Workflow.RESOLVE)
    if scan_result.blocked_findings:
        _print_blocked_findings(scan_result)
        save_scan_results(project, scan_result)
        return ExitCode.UPDATE_FAILED
    if not ready_findings:
        return ExitCode.OK
    return _submit_resolve_bookmark(
        project,
        proj_config.path,
        scan_result,
        ready_findings,
        vcs=vcs,
    )


def _submit_resolve_bookmark(
    project: str,
    project_path: Path,
    scan_result: ScanResult,
    ready_findings: list[Finding],
    *,
    vcs: VcsServices,
) -> int:
    """Push the resolve bookmark, open a PR, and promote READY findings on success."""
    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    if scan_result.blocked_findings:
        _print_blocked_findings(scan_result)
        console.print(
            "  [bold yellow]Not submitting:[/] blocked findings remain. "
            "Rescan or resolve them manually."
        )
        save_scan_results(project, scan_result)
        return ExitCode.UPDATE_FAILED
    for f in ready_findings:
        f.failed_phase = None

    try:
        output = push_bookmark_and_create_pr(
            repo=vcs.repository(project_path),
            host=vcs.code_host(project_path),
            bookmark=bookmark,
        )
    except (RevisionError, CodeHostError) as exc:
        save_scan_results(project, scan_result)
        console.print(f"  [dim]{escape(str(exc))}[/]")
        console.print(
            f"  [bold yellow]Submit failed.[/] Keeping {bookmark} for manual recovery."
        )
        return ExitCode.UPDATE_FAILED
    if output:
        console.print(f"  [dim]{escape(output)}[/]")

    for f in ready_findings:
        f.update_status = UpdateStatus.COMPLETED
        f.failed_phase = None
        f.flow = None
    remove_completed_findings(scan_result)
    save_scan_results(project, scan_result)
    return ExitCode.OK


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
                "[green]PASS[/]"
                if r.passed
                else (f"[red]FAIL ({escape(r.failed_phase or '')})[/]")
            )
            table.add_row(escape(proj_name), escape(r.pkg_name), escape(r.kind), status)

    console.print()
    console.print(table)


def _print_deploy_summary(results: list[deploy_service.DeployResult]) -> None:
    """Print a cross-project deploy summary table."""
    if not results:
        console.print("\n[dim]No projects have deploy_command configured.[/]")
        return

    status_display = {
        "pass": "[green]PASS[/]",
        "fail": "[red]FAIL[/]",
        "skip": "[dim]SKIP[/]",
        "unchanged": "[dim]UNCHANGED[/]",
        "blocked": "[yellow]BLOCKED[/]",
    }

    table = Table(title="Deploy Summary")
    table.add_column("Project", style="bold")
    table.add_column("Build")
    table.add_column("Deploy")

    for r in results:
        table.add_row(
            escape(r.project),
            status_display[r.build_status],
            status_display[r.deploy_status],
        )

    console.print()
    console.print(table)


@app.command
def deploy(
    project: str | None = None,
    *,
    build: bool = False,
    check: bool = False,
    force: Annotated[bool, cyclopts.Parameter(name=["--force", "-f"])] = False,
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
    force: bool
        Deploy even when main is unchanged since the last successful deploy or
        could not be resolved.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)
    vcs = make_vcs_services()
    renderer = _Renderer(batch=project is None)

    if not project:
        if check and not cfg.defaults.healthcheck_url:
            renderer(HealthcheckUnconfigured())
        if not cfg.projects:
            console.print(
                "No projects configured. Edit ~/.mm/config.toml to add projects."
            )
            sys.exit(ExitCode.OK)
        results = deploy_service.deploy_all(
            cfg,
            check=check,
            force=force,
            vcs=vcs,
            emit=renderer,
        )
        _print_deploy_summary(list(results))
        any_failed = any(
            result.deploy_status == "fail" or result.build_status == "fail"
            for result in results
        )
        sys.exit(ExitCode.DEPLOY_FAILED if any_failed else ExitCode.OK)

    proj_config = _resolve_proj(cfg, project)
    try:
        result = deploy_service.deploy_project(
            project,
            proj_config,
            healthcheck_url=cfg.defaults.healthcheck_url,
            build=build,
            check=check,
            force=force,
            vcs=vcs,
            emit=renderer,
        )
    except WorkflowError as exc:
        _fatal(str(exc))
    if result.build_status == "fail":
        sys.exit(ExitCode.BUILD_FAILED)
    if result.deploy_status == "fail":
        sys.exit(ExitCode.DEPLOY_FAILED)
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

    console.print(f"[bold]Testing {escape(project)}[/]\n")

    passed, failed_phase = run_test_phases(
        proj_config, proj_config.path, emit=_Renderer(batch=False)
    )

    if passed:
        console.print("\n[bold green]All test phases passed.[/]")
        sys.exit(ExitCode.OK)
    else:
        console.print(f"\n[bold red]Failed:[/] {escape(failed_phase or '')} tests")
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
    vcs = make_vcs_services()

    if not proj_config.build_command:
        _fatal(
            f"No build_command configured for {project}. "
            f"Add build_command to [projects.{project}] in ~/.mm/config.toml."
        )

    console.print(f"[bold]Building {escape(project)}[/]\n")

    try:
        deploy_service.build_project(project, proj_config, vcs=vcs)
    except BuildError as e:
        _fatal(str(e), code=ExitCode.BUILD_FAILED)

    console.print("\n[bold green]Build succeeded.[/]")
    sys.exit(ExitCode.OK)


_NO_DATA = "[dim]—[/]"


@app.command(name=("list", "status", "st"))
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

    scan_results: dict[str, ScanResult] = {}
    for name in cfg.projects:
        try:
            scan_results[name] = load_scan_results(name)
        except NoScanResultsError:
            pass
        except Exception:
            console.print(
                f"[yellow]Warning:[/] corrupt scan results for "
                f"'{escape(name)}' — skipping"
            )

    activity = load_activity(paths.activity_path())

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
        table.add_column(col, **kw)  # type: ignore

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
            escape(name),
            escape(str(project.package_manager)),
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
        console.print(
            Panel("[dim]no TODO.md[/]", title=escape(name), border_style="dim")
        )
        return
    content = todo_path.read_text().strip()
    if not content:
        console.print(Panel("[dim]empty[/]", title=escape(name), border_style="dim"))
        return
    console.print(Panel(Markdown(content), title=escape(name)))


def _fatal(msg: str, code: int = ExitCode.ERROR) -> NoReturn:
    console.print(f"[bold red]Error:[/] {escape(msg)}")
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
    if not proj_config.test_phases:
        _fatal(
            f"No test configuration for {project}. "
            f"Add test_unit to [projects.{project}] in ~/.mm/config.toml."
        )


def _scan_exit_code(summary: ScanSummary) -> ExitCode:
    if summary.had_error:
        return ExitCode.ERROR
    match (summary.has_vulns, summary.has_updates):
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
    now = now or datetime.now(UTC)
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


def _print_numbered_findings(
    vulns: list[VulnFinding], updates: list[UpdateFinding]
) -> list[VulnFinding | UpdateFinding]:
    """Print numbered list of findings. Returns ordered list of findings."""
    vulns = sort_vulns_by_severity(vulns)
    numbered: list[VulnFinding | UpdateFinding] = []
    for idx, v in enumerate(vulns, 1):
        console.print(
            f"  [dim]{idx:>3}.[/] [bold red]VULN[/] {escape(v.pkg_name)} "
            f"{escape(v.installed_version)} -> {escape(v.fixed_version or '')} "
            f"({escape(v.vuln_id)})"
        )
        numbered.append(v)
    for idx, u in enumerate(updates, len(vulns) + 1):
        console.print(
            f"  [dim]{idx:>3}.[/] [bold cyan]UPDATE[/] {escape(u.pkg_name)} "
            f"{escape(u.installed_version)} -> {escape(u.latest_version)} "
            f"({escape(u.semver_tier.value)})"
        )
        numbered.append(u)
    return numbered


type _Selection = Literal["all", "none", "vulns", "updates"] | tuple[int, ...]


def _parse_selection(text: str, count: int) -> _Selection | None:
    choice = text.strip().lower()
    if choice == "all":
        return "all"
    if choice == "none":
        return "none"
    if choice == "vulns":
        return "vulns"
    if choice == "updates":
        return "updates"
    try:
        indices = [int(part) for part in choice.split(",")]
    except ValueError:
        return None
    if not all(1 <= index <= count for index in indices):
        return None
    return tuple(dict.fromkeys(indices))


def _choose_findings(
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
        text = Prompt.ask(f"\n  Select updates {escape(f'[{choices}]')}", default="all")
        selection = _parse_selection(text, len(numbered))
        if selection is None:
            console.print(
                f"[bold red]Invalid selection:[/] '{escape(text)}'. Try again."
            )
            continue
        if selection == "all":
            return selectable_vulns, selectable_updates
        if selection == "vulns":
            return selectable_vulns, []
        if selection == "updates":
            return [], selectable_updates
        if selection == "none":
            return [], []

        selected_vulns: list[VulnFinding] = []
        selected_updates: list[UpdateFinding] = []
        for index in selection:
            finding = numbered[index - 1]
            if isinstance(finding, VulnFinding):
                selected_vulns.append(finding)
            else:
                selected_updates.append(finding)
        return selected_vulns, selected_updates


def _choose_gradle_candidates(
    candidates: tuple[GradleCandidate, ...],
) -> tuple[GradleCandidate, ...]:
    for index, candidate in enumerate(candidates, 1):
        console.print(
            f"{index}. {escape(candidate.target.display_name)} -> "
            f"{escape(candidate.target.target_version)}"
        )
        for member in candidate.target.members:
            console.print(
                f"   {escape(member.alias)}: {escape(member.coordinate)} "
                f"{escape(member.installed_version)} -> "
                f"{escape(candidate.target.target_version)}"
            )
    while True:
        text = console.input(
            "Select all, none, vulns, updates, or comma-separated numbers: "
        )
        selection = _parse_selection(text, len(candidates))
        if selection is None:
            console.print("Invalid selection")
            continue
        if selection == "all":
            return candidates
        if selection == "none":
            return ()
        if selection in {"vulns", "updates"}:
            origin = "security" if selection == "vulns" else "ordinary"
            return tuple(item for item in candidates if origin in item.origins)
        return tuple(
            item for index, item in enumerate(candidates, 1) if index in selection
        )


@app.command
def resolve(
    project: str,
    continue_: Annotated[bool, cyclopts.Parameter(name="--continue")] = False,
    config: Path | None = None,
) -> None:
    """Work through failed findings for a project.

    Applies each failed finding on ``mm/resolve-dependencies``, runs tests, and
    stops on the first failure so the operator can debug manually. Rerun with
    ``--continue`` after committing a manual fix to re-test and advance. Submits
    a PR once all candidates reach READY.

    Parameters
    ----------
    project: str
        Project name (required).
    continue_: bool
        Re-test a paused, manually fixed finding on the resolve branch.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)
    minimum_age_days = cfg.defaults.min_version_age_days
    try:
        vcs_workflow.require_vcs_tools()
    except ToolNotFoundError as e:
        _fatal(str(e))
    vcs = make_vcs_services()
    if proj_config.package_manager == "gradle":
        sys.exit(
            _run_gradle_flow(
                project,
                proj_config,
                Workflow.RESOLVE,
                interactive=False,
                minimum_age_days=minimum_age_days,
                continue_=continue_,
                vcs=vcs,
            )
        )
    try:
        scan_result = flows.load_validated_scan(
            project,
            proj_config,
            Workflow.RESOLVE,
            emit=_Renderer(batch=False),
        )
    except flows.FlowConflictError as exc:
        _fatal(str(exc))
    if scan_result is None:
        sys.exit(ExitCode.OK)
    if continue_:
        sys.exit(_handle_resolve_continue(project, proj_config, scan_result, vcs=vcs))
    candidates = _ordered_resolve_candidates(scan_result)
    try:
        repo = vcs.repository(proj_config.path)
        prune_repository_bookmarks(repo=repo, host=vcs.code_host(proj_config.path))
        ensure_main_bookmark(repo=repo)
        if _ordered_failed_findings(scan_result):
            _fatal(f"resolve already paused for {project} — rerun with --continue")
        if not _prepare_resolve_bookmark(
            proj_config.path, scan_result, candidates, vcs=vcs
        ):
            _fatal(f"aborted resolve for {project}")
    except (RevisionError, CodeHostError) as exc:
        _fatal(str(exc))
    sys.exit(
        _run_resolve_findings(
            project,
            proj_config,
            scan_result,
            candidates,
            vcs=vcs,
        )
    )


def _handle_resolve_continue(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    *,
    vcs: VcsServices,
) -> int:
    """Retest the paused blocker on the resolve bookmark."""
    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    repo = vcs.repository(proj_config.path)
    try:
        if not repo.is_ancestor(ancestor=bookmark, descendant="@"):
            _fatal(f"--continue requires current jj change to descend from {bookmark}")
        has_changes = repo.has_changes()
    except RevisionError as exc:
        _fatal(f"Cannot inspect resolve work: {exc}")
    if has_changes:
        _fatal(
            "--continue requires an empty current jj change — commit or discard "
            "manual changes first"
        )
    failed = _ordered_failed_findings(scan_result)
    if failed:
        passed, failed_phase = run_test_phases(
            proj_config, proj_config.path, emit=_Renderer(batch=False)
        )
        for blocker in failed:
            blocker.flow = Workflow.RESOLVE
            if not passed:
                blocker.update_status = UpdateStatus.FAILED
                blocker.failed_phase = failed_phase
        if not passed:
            save_scan_results(project, scan_result)
            names = ", ".join(b.pkg_name for b in failed)
            console.print(
                f"  [bold red]FAIL[/] {escape(failed_phase or '')} — "
                f"still blocking: {escape(names)}"
            )
            return ExitCode.UPDATE_FAILED
        try:
            repo.set_bookmark(bookmark=bookmark, revision="@-")
        except RevisionError:
            save_scan_results(project, scan_result)
            _fatal(f"could not move {bookmark} to the committed manual fix")
        for blocker in failed:
            blocker.update_status = UpdateStatus.READY
            blocker.failed_phase = None
        save_scan_results(project, scan_result)
        for blocker in failed:
            console.print(f"  [bold green]PASS[/] {escape(blocker.pkg_name)}")
    return _run_resolve_findings(
        project,
        proj_config,
        scan_result,
        _ordered_resolve_candidates(scan_result),
        vcs=vcs,
    )


def _print_gradle_run_summary(run: GradleRun) -> None:
    counts = {
        state: sum(attempt.state == state for attempt in run.attempts)
        for state in ("ready", "completed", "failed", "applying")
    }
    withheld: dict[tuple[str, str, str, str], str] = {}
    for block in run.selection_blocks:
        if block.group_key is not None:
            key = ("target", block.group_key, "", block.reason)
            label = block.group_key
        else:
            key = ("package", block.coordinate, block.installed_version, block.reason)
            label = f"{block.coordinate}@{block.installed_version}"
        withheld[key] = label
    for attempt in run.attempts:
        if isinstance(attempt, WithheldAttempt):
            target = attempt.candidate.target
            key = ("target", target.group_key, "", attempt.reason)
            withheld[key] = f"{target.display_name} -> {target.target_version}"
    console.print(
        f"Verified: {counts['ready'] + counts['completed']}; "
        f"withheld: {len(withheld)}; "
        f"failed: {counts['failed'] + counts['applying']}; "
        f"residual advisories: {len(run.accepted_snapshot.findings)}"
    )
    for (kind, _identity, _version, reason), label in sorted(withheld.items()):
        prefix = "WITHHELD TARGET" if kind == "target" else "RESIDUAL PACKAGE"
        console.print(f"  {prefix} {escape(label)} — {escape(reason)}")
    for attempt in run.attempts:
        if isinstance(attempt, FailedAttempt):
            target = attempt.candidate.target
            console.print(
                f"  FAILED {escape(target.display_name)} -> "
                f"{escape(target.target_version)} "
                f"— {escape(attempt.reason)}"
            )


def _print_scan_result(
    result: ScanResult,
    elapsed_s: float | None = None,
) -> None:
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
        console.print(f"[bold green]{escape(result.project)}[/] — clean{timing}")
        return

    categories = [
        (actionable, "vulnerability", "vulnerabilities"),
        (advisories, "advisory", "advisories"),
        (secrets, "secret", "secrets"),
        (updates, "update", "updates"),
    ]
    parts = [_pluralise(len(items), s, p) for items, s, p in categories if items]

    console.print(f"\n[bold]{escape(result.project)}[/] — {', '.join(parts)}{timing}")
    _print_vuln_table(actionable)
    _print_advisory_table(advisories)
    _print_secrets(secrets)
    _print_update_table(updates)


def _print_vuln_table(vulnerabilities: list[VulnFinding]) -> None:
    if not vulnerabilities:
        return
    win_versions: dict[str, str] = {}
    for package in {item.pkg_name for item in vulnerabilities}:
        group = [item for item in vulnerabilities if item.pkg_name == package]
        if len(group) > 1:
            win_versions[package] = highest_fix_version(group)

    table = Table(show_header=True, **_TABLE_STYLE)
    table.add_column("", style="bold red", width=4)
    table.add_column("Package", overflow="fold")
    table.add_column("Installed")
    table.add_column("Fix")
    table.add_column("Severity")
    table.add_column("CVE")
    for item in vulnerabilities:
        fix = item.fixed_version or ""
        if item.pkg_name in win_versions and fix == win_versions[item.pkg_name]:
            fix += " ← fix"
        table.add_row(
            "VULN",
            escape(item.pkg_name),
            escape(item.installed_version),
            escape(fix),
            escape(item.severity.value),
            escape(item.vuln_id),
        )
    console.print(table)


def _print_advisory_table(advisories: list[VulnFinding]) -> None:
    if not advisories:
        return
    table = Table(show_header=False, **_TABLE_STYLE)
    table.add_column("", style="bold yellow", width=4)
    table.add_column("Package", overflow="fold")
    table.add_column("Installed")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("CVE")
    for item in advisories:
        table.add_row(
            "ADV",
            escape(item.pkg_name),
            escape(item.installed_version),
            escape(item.status),
            escape(item.severity.value),
            escape(item.vuln_id),
        )
    console.print(table)


def _print_secrets(secrets: list[SecretFinding]) -> None:
    for item in secrets:
        console.print(
            f"  [bold magenta]SECRET[/]  {escape(item.file)} — {escape(item.title)}"
        )


def _print_update_table(updates: list[UpdateFinding]) -> None:
    if not updates:
        return
    table = Table(show_header=True, **_TABLE_STYLE)
    table.add_column("", style="bold cyan", width=6, no_wrap=True)
    table.add_column("Package", overflow="fold")
    table.add_column("Installed")
    table.add_column("Latest")
    table.add_column("Tier")
    table.add_column("Age")
    for item in updates:
        age = ""
        if item.published_date:
            days = (datetime.now(UTC) - item.published_date).days
            age = f"({days} days old)"
        table.add_row(
            "UPDATE",
            escape(item.pkg_name),
            escape(item.installed_version),
            escape(item.latest_version),
            escape(item.semver_tier.value),
            age,
        )
    console.print(table)


def _print_blocked_findings(scan_result: ScanResult) -> None:
    """Explain why an explicit update or resolve operation cannot proceed."""
    for finding in scan_result.blocked_findings:
        console.print(
            f"  [yellow]BLOCKED[/] {escape(finding.pkg_name)} — "
            f"{escape(finding.blocked_reason or '')}"
        )


def _run_gradle_flow(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    *,
    interactive: bool,
    minimum_age_days: int,
    continue_: bool = False,
    vcs: VcsServices,
    emit: Emit | None = None,
) -> int:
    outcome = gradle_workflow.run_gradle_flow(
        project_name,
        project,
        flow,
        minimum_age_days=minimum_age_days,
        continue_=continue_,
        choose=_choose_gradle_candidates if interactive else None,
        emit=emit or _Renderer(batch=False),
        vcs=vcs,
    )
    return ExitCode.OK if outcome is Outcome.SUCCEEDED else ExitCode.UPDATE_FAILED
