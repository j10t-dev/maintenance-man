import functools
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, NoReturn

import cyclopts
from rich.console import Console
from rich.markup import escape
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from maintenance_man import __version__, output, paths, vcs_workflow
from maintenance_man.config import (
    ConfigError,
    ProjectNotFoundError,
    ensure_mm_home,
    load_config,
    resolve_project,
)
from maintenance_man.deployer import BuildError
from maintenance_man.exit_codes import ExitCode
from maintenance_man.gradle import GradleError
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.events import (
    BlockersStillFailing,
    DeployStep,
    DeployStepFailed,
    DeployStepStarted,
    DeployStepSucceeded,
    Event,
    FindingFailed,
    FindingPassed,
    FindingsBlocked,
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
    ResolvePaused,
    ScanReported,
    SkipReason,
    SubmissionBlocked,
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
    VulnFinding,
    Workflow,
    highest_fix_version,
    sort_vulns_by_severity,
)
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.process import ToolNotFoundError
from maintenance_man.scanner import ScanError
from maintenance_man.services import WorkflowError
from maintenance_man.services import deploy as deploy_service
from maintenance_man.services import resolve as resolve_service
from maintenance_man.services import scan as scan_service
from maintenance_man.services import update as update_service
from maintenance_man.services.scan import ScanSummary
from maintenance_man.storage import (
    NoScanResultsError,
    load_activity,
    load_scan_results,
)
from maintenance_man.updater import run_test_phases
from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import make_vcs_services

console = Console()


_EXIT_FOR: dict[type[Exception], ExitCode] = {
    WorkflowError: ExitCode.ERROR,
    ConfigError: ExitCode.ERROR,
    ProjectNotFoundError: ExitCode.ERROR,
    ToolNotFoundError: ExitCode.ERROR,
    BuildError: ExitCode.BUILD_FAILED,
    ScanError: ExitCode.ERROR,
    GradleError: ExitCode.ERROR,
    RevisionError: ExitCode.ERROR,
    OutdatedCheckError: ExitCode.ERROR,
}


_OVERVIEW_HEADERS = (
    "project",
    "type",
    "vulns",
    "updates",
    "secrets",
    "scanned",
    "built",
    "deployed",
)
_NARROW_DROP_ORDER = (
    "scanned",
    "built",
    "deployed",
    "type",
    "secrets",
    "updates",
    "vulns",
)


def _command[**P](function: Callable[P, None]) -> Callable[P, None]:
    @functools.wraps(function)
    def mapped_command(*args: P.args, **kwargs: P.kwargs) -> None:
        try:
            function(*args, **kwargs)
        except tuple(_EXIT_FOR) as exc:
            code = next(
                code for kind, code in _EXIT_FOR.items() if isinstance(exc, kind)
            )
            _fatal(str(exc), code=code)

    return mapped_command


@functools.singledispatch
def _render(event: Event, *, batch: bool, project: str, flow: str) -> None:
    raise NotImplementedError(type(event))


@dataclass(slots=True)
class _Renderer:
    batch: bool
    project: str = ""
    flow: str = "update"

    def __call__(self, event: Event) -> None:
        if isinstance(event, ProjectStarted):
            self.project = event.project
        _render(event, batch=self.batch, project=self.project, flow=self.flow)


_SKIP_TEXT: dict[SkipReason, str] = {
    SkipReason.PATH_MISSING: (
        "[bold yellow]Warning:[/] {name} — path does not exist: {detail}"
    ),
    SkipReason.NO_SCAN_RESULTS: (
        "[bold green]{name}[/] — no scan results; nothing to do."
    ),
    SkipReason.NOTHING_TO_DO: "[bold green]{name}[/] — nothing to {detail}.",
    SkipReason.FLOW_CONFLICT: "  [bold yellow]Skipped:[/] {name} — {detail}",
    SkipReason.NOT_DEPLOYABLE: "[dim]{name} — skipped (not deployable)[/]",
    SkipReason.UNCHANGED: (
        "[bold yellow]{name}[/] unchanged since last deploy (use --force to redeploy)."
    ),
    SkipReason.BLOCKED: (
        "[bold yellow]Warning:[/] {name} — could not resolve main revision; "
        "skipping (use --force to deploy anyway)"
    ),
}

_SKIP_BATCH_OVERRIDES: dict[SkipReason, str | None] = {
    SkipReason.NO_SCAN_RESULTS: None,
    SkipReason.NOTHING_TO_DO: "[dim]  {name} — nothing to update[/]",
    SkipReason.UNCHANGED: "[dim]{name} — unchanged since last deploy[/]",
}

_OPERATION_TEXT: dict[Operation, str] = {
    Operation.UPDATE_SETUP: "  [bold red]Error:[/] {name} — {error}",
    Operation.PROMOTE: "[bold red]Promotion failed:[/] {error}",
    Operation.REFRESH: "[bold red]Workspace refresh failed:[/] {name}: {error}",
    Operation.WORKSPACE_CLEANUP: "[bold red]Workspace cleanup failed:[/] {error}",
    Operation.BOOKMARK_CLEANUP: "[bold red]Bookmark cleanup failed:[/] {error}",
    Operation.RESOLVE_SETUP: "  [bold red]Resolve setup failed:[/] {error}",
    Operation.SUBMIT: (
        "  [dim]{error}[/]\n  [bold yellow]Submit failed.[/] Keeping {bookmark} "
        "for manual recovery."
    ),
    Operation.REMOTE_SYNC: (
        "[bold yellow]Warning:[/] {name} — failed to sync remote: {error}"
    ),
    Operation.SCAN: "[bold red]Error:[/] {name} — {error}",
    Operation.SYNC: "[bold red]  {name} — {error}[/]",
}

_OPERATION_BATCH_OVERRIDES: dict[Operation, str] = {
    Operation.WORKSPACE_CLEANUP: "  [bold red]Workspace cleanup failed:[/] {error}",
    Operation.BOOKMARK_CLEANUP: (
        "  [bold red]Bookmark cleanup failed:[/] {name} — {error}"
    ),
}


@_render.register
def _render_project_skipped(
    event: ProjectSkipped, *, batch: bool, project: str, flow: str
) -> None:
    template = (
        _SKIP_BATCH_OVERRIDES.get(event.reason, _SKIP_TEXT[event.reason])
        if batch
        else _SKIP_TEXT[event.reason]
    )
    if template is None:
        return
    console.print(
        template.format(name=escape(event.project), detail=escape(event.detail or ""))
    )


@_render.register
def _render_operation_failed(
    event: OperationFailed, *, batch: bool, project: str, flow: str
) -> None:
    template = (
        _OPERATION_BATCH_OVERRIDES.get(
            event.operation, _OPERATION_TEXT[event.operation]
        )
        if batch
        else _OPERATION_TEXT[event.operation]
    )
    console.print(
        template.format(
            name=escape(event.project),
            error=escape(event.error),
            bookmark=escape(WORKFLOW_BOOKMARKS[Workflow.RESOLVE]),
        )
    )


@_render.register
def _render_scan_reported(
    event: ScanReported, *, batch: bool, project: str, flow: str
) -> None:
    result = event.result
    if flow == "scan" or output.terminal():
        _print_scan_result(result, elapsed_s=event.elapsed_s)
    else:
        _print_blocked_findings(result, flow)
    if result.has_findings or batch:
        return
    if event.elapsed_s is None:
        output.notice(f"No findings in {result.project}")
    else:
        output.notice(
            f"No findings in {result.project} · scanned in {event.elapsed_s:.1f}s"
        )


@_render.register
def _render_missing_test_config(
    event: MissingTestConfig, *, batch: bool, project: str, flow: str
) -> None:
    console.print(
        f"  [bold yellow]Warning:[/] {escape(event.project)} — no test "
        "configuration (test phases will be skipped)"
    )


@_render.register
def _render_processing_started(
    event: ProcessingStarted, *, batch: bool, project: str, flow: str
) -> None:
    if event.vulns:
        console.print(f"\n[bold]Processing {event.vulns} vuln fix(es)...[/]")
    if event.updates:
        console.print(f"\n[bold]Processing {event.updates} update(s)...[/]")


@_render.register
def _render_findings_processed(
    event: FindingsProcessed, *, batch: bool, project: str, flow: str
) -> None:
    if not batch:
        _print_update_summary(list(event.results))


@_render.register
def _render_promoted(event: Promoted, *, batch: bool, project: str, flow: str) -> None:
    console.print(f"[bold green]Promoted {escape(event.bookmark)} to main.[/]")


@_render.register
def _render_resolve_paused(
    event: ResolvePaused, *, batch: bool, project: str, flow: str
) -> None:
    console.print(
        f"  [bold yellow]Resolve paused.[/] Continue with "
        f"[bold]mm resolve {escape(event.project)} --continue[/]."
    )


@_render.register
def _render_findings_blocked(
    event: FindingsBlocked, *, batch: bool, project: str, flow: str
) -> None:
    for package, reason in event.findings:
        console.print(f"  [yellow]BLOCKED[/] {escape(package)} — {escape(reason)}")


@_render.register
def _render_submission_blocked(
    event: SubmissionBlocked, *, batch: bool, project: str, flow: str
) -> None:
    console.print(
        "  [bold yellow]Not submitting:[/] blocked findings remain. "
        "Rescan or resolve them manually."
    )


@_render.register
def _render_blockers_still_failing(
    event: BlockersStillFailing, *, batch: bool, project: str, flow: str
) -> None:
    console.print(
        f"  [bold red]FAIL[/] {escape(event.phase)} — still blocking: "
        f"{escape(', '.join(event.pkgs))}"
    )


@_render.register
def _render_sync_completed(
    event: SyncCompleted, *, batch: bool, project: str, flow: str
) -> None:
    console.print(f"  {escape(event.project)} — {escape(event.action)}")


@_render.register
def _render_project_started(
    event: ProjectStarted, *, batch: bool, project: str, flow: str
) -> None:
    if not batch:
        return
    console.print(f"\n{'═' * 40}")
    console.print(f"[bold]{escape(event.project)}[/]")
    console.print("═" * 40)


@_render.register
def _render_finding_started(
    event: FindingStarted, *, batch: bool, project: str, flow: str
) -> None:
    label = "[bold red]VULN[/]" if event.kind == "vuln" else "[bold cyan]UPDATE[/]"
    console.print(
        f"\n  {label} {escape(event.pkg)} {escape(event.installed)} -> "
        f"{escape(event.target)} ({escape(event.detail)})"
    )


@_render.register
def _render_test_command_started(
    event: TestCommandStarted, *, batch: bool, project: str, flow: str
) -> None:
    console.print(f"  [dim]$ {escape(event.command)}[/]")


@_render.register
def _render_finding_step_failed(
    event: FindingStepFailed, *, batch: bool, project: str, flow: str
) -> None:
    error = escape(event.error)
    if event.step is FindingStepKind.PACKAGE_COMMAND:
        console.print(f"  [bold red]FAIL[/] Package manager command failed: {error}")
    else:
        console.print(f"  [bold red]FAIL[/] {error}")


@_render.register
def _render_finding_passed(
    event: FindingPassed, *, batch: bool, project: str, flow: str
) -> None:
    suffix = " [dim](already applied)[/]" if event.already_applied else ""
    console.print(f"  [bold green]PASS[/] {escape(event.pkg)}{suffix}")


@_render.register
def _render_finding_failed(
    event: FindingFailed, *, batch: bool, project: str, flow: str
) -> None:
    console.print(
        f"  [bold red]FAIL[/] {escape(event.pkg)} — {escape(event.phase)} failed"
    )


@_render.register
def _render_deploy_step_started(
    event: DeployStepStarted, *, batch: bool, project: str, flow: str
) -> None:
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


@_render.register
def _render_deploy_step_succeeded(
    event: DeployStepSucceeded, *, batch: bool, project: str, flow: str
) -> None:
    if batch:
        return
    if event.step is DeployStep.BUILD:
        console.print("\n[bold green]Build succeeded.[/]\n")
    elif event.step is DeployStep.DEPLOY:
        console.print("\n[bold green]Deploy succeeded.[/]")


@_render.register
def _render_deploy_step_failed(
    event: DeployStepFailed, *, batch: bool, project: str, flow: str
) -> None:
    error = escape(event.error)
    if not batch:
        console.print(f"[bold red]Error:[/] {error}")
    elif event.step is DeployStep.BUILD:
        console.print(f"  [bold red]Build failed:[/] {error}")
    elif event.step is DeployStep.DEPLOY:
        console.print(f"  [bold red]Deploy failed:[/] {error}")


@_render.register
def _render_health_checked(
    event: HealthChecked, *, batch: bool, project: str, flow: str
) -> None:
    indent = "  " if batch else ""
    if event.is_up:
        console.print(f"{indent}[bold green]Healthy:[/] {escape(event.project)} is up")
    elif event.error:
        console.print(f"{indent}[bold yellow]Warning:[/] {escape(event.error)}")
    else:
        console.print(
            f"{indent}[bold yellow]Warning:[/] {escape(event.project)} is not healthy"
        )


@_render.register
def _render_healthcheck_unconfigured(
    event: HealthcheckUnconfigured, *, batch: bool, project: str, flow: str
) -> None:
    console.print("[dim]--check: no healthcheck_url configured in \\[defaults][/]")


@_render.register
def _render_pull_request_output(
    event: PullRequestOutput, *, batch: bool, project: str, flow: str
) -> None:
    console.print(f"[dim]  {escape(event.text)}[/]")


@_render.register
def _render_gradle_withheld(
    event: GradleWithheld, *, batch: bool, project: str, flow: str
) -> None:
    console.print(f"Withheld {escape(event.label)}: {escape(event.reason)}")


@_render.register
def _render_no_eligible_gradle_changes(
    event: NoEligibleGradleChanges, *, batch: bool, project: str, flow: str
) -> None:
    console.print("No eligible Gradle changes")


@_render.register
def _render_gradle_run_archived(
    event: GradleRunArchived, *, batch: bool, project: str, flow: str
) -> None:
    console.print(
        f"Archived failed Gradle run to {escape(str(event.path))}; "
        "rebuilding candidates from main"
    )


@_render.register
def _render_gradle_flow_failed(
    event: GradleFlowFailed, *, batch: bool, project: str, flow: str
) -> None:
    console.print(
        f"Cannot complete Gradle {escape(event.flow.value)}: {escape(event.error)}"
    )


@_render.register
def _render_gradle_run_reported(
    event: GradleRunReported, *, batch: bool, project: str, flow: str
) -> None:
    _print_scan_result(event.scan)
    _print_gradle_run_summary(event.run)


app = cyclopts.App(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    version=__version__,
    version_flags=["--version", "-v"],
)


def main(argv: Sequence[str] | None = None) -> None:
    """Usage errors exit with ExitCode.ERROR; cyclopts would exit 2 on its own."""
    try:
        app(argv, exit_on_error=False)
    except cyclopts.CycloptsError:
        sys.exit(ExitCode.ERROR)


@app.command
@_command
def init() -> None:
    """Initialise the ~/.mm directory and skeleton config."""
    ensure_mm_home()
    console.print(f"Initialised {escape(str(paths.mm_home()))}")
    console.print(f"Edit {escape(str(paths.config_path()))} to add projects.")


@app.command
@_command
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
        _notice_no_projects()
        return

    vcs = make_vcs_services()

    if project:
        proj_config = _resolve_proj(cfg, project)
        result = scan_service.scan_one(
            project,
            proj_config,
            minimum_age_days=cfg.defaults.min_version_age_days,
            vcs=vcs,
            emit=_Renderer(batch=False, project=project, flow="scan"),
        )
        sys.exit(_scan_exit_code(ScanSummary.of(result)))

    started = time.monotonic()
    summary = scan_service.scan_all(
        cfg, vcs=vcs, emit=_Renderer(batch=True, flow="scan")
    )
    if summary.clean:
        elapsed = time.monotonic() - started
        output.notice(
            f"{len(summary.clean)} projects have no findings: "
            f"{', '.join(summary.clean)} · scanned in {elapsed:.1f}s"
        )
    sys.exit(_scan_exit_code(summary))


def _exit_if_no_update_targets(cfg: MmConfig, target_names: list[str]) -> None:
    if not cfg.projects:
        _notice_no_projects()
        sys.exit(ExitCode.OK)

    if not target_names:
        console.print("No target projects.")
        sys.exit(ExitCode.OK)


@app.command
@_command
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
    mode, targets = update_service.resolve_update_targets(cfg, projects, negate=negate)

    _exit_if_no_update_targets(cfg, targets)

    vcs_workflow.require_vcs_tools()

    vcs = make_vcs_services()
    if mode == "single":
        name = targets[0]
        proj_config = _resolve_proj(cfg, name)
        result = update_service.update_project(
            name,
            proj_config,
            minimum_age_days=cfg.defaults.min_version_age_days,
            choose=_choose_findings,
            choose_gradle=_choose_gradle_candidates,
            vcs=vcs,
            emit=_Renderer(batch=False),
        )
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
@_command
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
        _notice_no_projects()
        sys.exit(ExitCode.OK)

    vcs_services = make_vcs_services()
    outcome = scan_service.sync_projects(
        cfg,
        projects,
        vcs=vcs_services,
        emit=_Renderer(batch=True),
    )
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
            "commit": "commit failed",
        }
        for r in failed:
            phase = r.failed_phase or "unknown"
            label = phase_labels.get(phase, phase)
            console.print(f"  [red]FAIL[/] {escape(r.pkg_name)} — {escape(label)}")
    console.print("─" * 40)


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
@_command
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
    batch = not project
    renderer = _Renderer(batch=batch)

    if batch:
        if check and not cfg.defaults.healthcheck_url:
            renderer(HealthcheckUnconfigured())
        if not cfg.projects:
            _notice_no_projects()
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

    assert project is not None
    proj_config = _resolve_proj(cfg, project)
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
    if result.build_status == "fail":
        sys.exit(ExitCode.BUILD_FAILED)
    if result.deploy_status == "fail":
        sys.exit(ExitCode.DEPLOY_FAILED)
    sys.exit(ExitCode.OK)


@app.command
@_command
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

    failed_phase = run_test_phases(
        proj_config, proj_config.path, emit=_Renderer(batch=False)
    )

    if failed_phase is None:
        console.print("\n[bold green]All test phases passed.[/]")
        sys.exit(ExitCode.OK)
    else:
        console.print(f"\n[bold red]Failed:[/] {escape(failed_phase or '')} tests")
        sys.exit(ExitCode.TEST_FAILED)


@app.command
@_command
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

    deploy_service.build_project(project, proj_config, vcs=vcs)

    console.print("\n[bold green]Build succeeded.[/]")
    sys.exit(ExitCode.OK)


@app.command(name=("list", "status", "st"))
@_command
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
        _notice_no_projects()
        return

    scan_results: dict[str, ScanResult] = {}
    for name in cfg.projects:
        try:
            scan_results[name] = load_scan_results(name)
        except NoScanResultsError:
            pass
        except Exception:
            output.diagnostic("warning", f"corrupt scan results for {name}; skipped")

    if detail:
        _print_project_detail(cfg, scan_results)
    else:
        activity = load_activity(paths.activity_path())
        _print_project_overview(cfg, scan_results, activity)


def _print_project_detail(cfg: MmConfig, scan_results: dict[str, ScanResult]) -> None:
    clean = []
    unscanned = []
    for name in sorted(cfg.projects):
        result = scan_results.get(name)
        if result is None:
            unscanned.append(name)
        elif result.has_findings:
            _print_scan_result(result)
        else:
            clean.append(name)
    if clean:
        output.notice(f"{len(clean)} projects have no findings: {', '.join(clean)}")
    if unscanned:
        output.notice(
            f"{len(unscanned)} projects have no saved scan: {', '.join(unscanned)}"
        )


def _print_project_overview(
    cfg: MmConfig,
    scan_results: dict[str, ScanResult],
    activity: dict[str, ProjectActivity],
) -> None:
    rows: list[list[str]] = []
    pipe_rows: list[list[str]] = []
    for name, project in sorted(cfg.projects.items()):
        row, pipe_row = _project_row(
            name, project, scan_results.get(name), activity.get(name)
        )
        rows.append(row)
        pipe_rows.append(pipe_row)

    visible, footer_parts = _hidden_columns(_OVERVIEW_HEADERS, rows)
    visible, narrow = _fit_columns(_OVERVIEW_HEADERS, rows, visible)
    if narrow:
        footer_parts.append("hidden: " + ", ".join(narrow))
    output.heading("projects", f"{len(rows)} configured")
    output.project_records(
        [_OVERVIEW_HEADERS[index] for index in visible],
        [
            [
                output.literal(row[index], "bold" if index == 0 else "")
                for index in visible
            ]
            for row in rows
        ],
        pipe_rows,
        footer=" · ".join(footer_parts),
    )


def _project_row(
    name: str,
    project: ProjectConfig,
    result: ScanResult | None,
    events: ProjectActivity | None,
) -> tuple[list[str], list[str]]:
    """The terminal row and the complete pipe row for one project."""
    counts = (
        [
            str(sum(v.actionable for v in result.vulnerabilities)),
            str(len(result.updates)),
            str(len(result.secrets)),
        ]
        if result
        else ["-"] * 3
    )
    built = events.last_build if events else None
    deployed = events.last_deploy if events else None
    deploy_status = (
        _activity_status(deployed) if project.deployable else "not deployable"
    )
    row = [
        name,
        project.package_manager,
        *counts,
        output.timestamp(result.scanned_at) if result else "never",
        _activity_cell(built),
        _activity_cell(deployed) if project.deployable else deploy_status,
    ]
    pipe_row = [
        name,
        project.package_manager,
        *counts,
        result.scanned_at.isoformat() if result else "never",
        built.timestamp.isoformat() if built else "-",
        _activity_status(built),
        deployed.timestamp.isoformat() if deployed else "-",
        deploy_status,
    ]
    return row, pipe_row


def _activity_status(event: ActivityEvent | None) -> str:
    if event is None:
        return "-"
    return "passed" if event.success else "failed"


def _activity_cell(event: ActivityEvent | None) -> str:
    text = output.timestamp(event.timestamp if event else None)
    return f"failed {text}" if event and not event.success else text


def _hidden_columns(
    headers: Sequence[str], rows: Sequence[Sequence[str]]
) -> tuple[list[int], list[str]]:
    """Visible column indexes, plus footer fragments for columns that never vary."""
    visible = [0]
    footer_parts = []
    for index, title in enumerate(headers[1:], 1):
        values = {row[index] for row in rows}
        if len(rows) < 2 or len(values) > 1:
            visible.append(index)
        elif values == {"-"}:
            footer_parts.append(f"{title} -")
        elif values == {"0"}:
            footer_parts.append(f"0 {title}")
        else:
            footer_parts.append(f"{title} {next(iter(values))}")
    return visible, footer_parts


def _fit_columns(
    headers: Sequence[str], rows: Sequence[Sequence[str]], visible: Sequence[int]
) -> tuple[list[int], list[str]]:
    """Visible column indexes that fit the terminal, plus the names dropped."""
    fitting = list(visible)
    if not output.terminal():
        return fitting, []
    width = output.console().width
    dropped = []
    for name in _NARROW_DROP_ORDER:
        required = sum(
            max(len(headers[column]), min(24, max(len(row[column]) for row in rows)))
            + 2
            for column in fitting
        )
        if required <= width:
            break
        index = headers.index(name)
        if index in fitting:
            fitting.remove(index)
            dropped.append(name)
    return fitting, dropped


@app.command
@_command
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
        _notice_no_projects()
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

    if empty:
        output.notice(f"{len(empty)} projects have no TODO items: {', '.join(empty)}")
    for name in has_content:
        _print_project_todo(name, cfg.projects[name].path)


# -- Helpers ------------------------------------------------------------------


def _print_project_todo(name: str, project_path: Path) -> None:
    todo_path = project_path / "TODO.md"
    content = todo_path.read_text() if todo_path.exists() else ""
    if not content.strip():
        output.notice(f"No TODO items in {name}")
        return
    lines = content.splitlines()
    output.heading(name, "TODO.md")
    output.records(
        name,
        (),
        [[line] for line in lines],
        pipe_rows=[[str(index), line] for index, line in enumerate(lines, 1)],
    )


def _notice_no_projects() -> None:
    output.notice("No projects configured")
    output.diagnostic("hint", "add projects to ~/.mm/config.toml")


def _fatal(msg: str, code: int = ExitCode.ERROR) -> NoReturn:
    console.print(f"[bold red]Error:[/] {escape(msg)}")
    sys.exit(code)


def _load_cfg(config: Path | None) -> MmConfig:
    return load_config(config)


def _resolve_proj(cfg: MmConfig, project: str) -> ProjectConfig:
    return resolve_project(cfg, project)


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


type _KeywordSelection = Literal["all", "none", "vulns", "updates"]
type _Selection = _KeywordSelection | tuple[int, ...]

_KEYWORD_SELECTIONS: dict[str, _KeywordSelection] = {
    "all": "all",
    "none": "none",
    "vulns": "vulns",
    "updates": "updates",
}


def _parse_selection(text: str, count: int) -> _Selection | None:
    choice = text.strip().lower()
    if selection := _KEYWORD_SELECTIONS.get(choice):
        return selection
    try:
        indices = [int(part) for part in choice.split(",")]
    except ValueError:
        return None
    if not all(1 <= index <= count for index in indices):
        return None
    return tuple(dict.fromkeys(indices))


def _selected_findings(
    selection: _Selection,
    numbered: list[VulnFinding | UpdateFinding],
    selectable_vulns: list[VulnFinding],
    selectable_updates: list[UpdateFinding],
) -> tuple[list[VulnFinding], list[UpdateFinding]]:
    if selection == "all":
        return selectable_vulns, selectable_updates
    if selection == "vulns":
        return selectable_vulns, []
    if selection == "updates":
        return [], selectable_updates
    if selection == "none":
        return [], []
    selected = [numbered[index - 1] for index in selection]
    return (
        [finding for finding in selected if isinstance(finding, VulnFinding)],
        [finding for finding in selected if isinstance(finding, UpdateFinding)],
    )


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
        return _selected_findings(
            selection, numbered, selectable_vulns, selectable_updates
        )


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
@_command
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
    vcs_workflow.require_vcs_tools()
    vcs = make_vcs_services()
    outcome = resolve_service.resolve_project(
        project,
        proj_config,
        minimum_age_days=minimum_age_days,
        continue_=continue_,
        vcs=vcs,
        emit=_Renderer(batch=False),
    )
    sys.exit(ExitCode.OK if outcome is Outcome.SUCCEEDED else ExitCode.UPDATE_FAILED)


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


type _FindingRows = tuple[list[list[str | Text]], list[list[str]]]


def _print_scan_result(result: ScanResult, elapsed_s: float | None = None) -> None:
    wins = _selected_fix_versions(result.vulnerabilities)
    rows, pipe_rows = _vulnerability_rows(result.vulnerabilities, wins)
    for found_rows, found_pipe_rows in (
        _secret_rows(result.secrets),
        _update_rows(result.updates),
    ):
        rows += found_rows
        pipe_rows += found_pipe_rows
    if not rows:
        return
    output.heading(result.project, f"{len(rows)} findings")
    headers = ["kind", "severity", "versions", "package / detail"]
    visible = [0, 1, 2, 3] if output.console().width >= 70 else [0, 3]
    output.records(
        result.project,
        [headers[index] for index in visible],
        [[row[index] for index in visible] for row in rows],
        pipe_rows=pipe_rows,
        footer="hidden: severity, versions · pipe for full records"
        if len(visible) < len(headers)
        else "",
    )
    if elapsed_s is not None:
        output.notice(f"Scanned {result.project} in {elapsed_s:.1f}s")


def _selected_fix_versions(vulnerabilities: list[VulnFinding]) -> dict[str, str]:
    """For packages with several actionable fixes, the one version that fixes all."""
    wins = {}
    for package in {v.pkg_name for v in vulnerabilities if v.actionable}:
        group = [v for v in vulnerabilities if v.pkg_name == package and v.actionable]
        if len(group) > 1:
            wins[package] = highest_fix_version(group)
    return wins


def _vulnerability_rows(
    vulnerabilities: list[VulnFinding], wins: dict[str, str]
) -> _FindingRows:
    rows: list[list[str | Text]] = []
    pipe_rows: list[list[str]] = []
    for vuln in sort_vulns_by_severity(vulnerabilities):
        kind = "vuln" if vuln.actionable else "advisory"
        reason = vuln.blocked_reason or ""
        if vuln.fixed_version and wins.get(vuln.pkg_name) == vuln.fixed_version:
            reason = " · ".join(filter(None, ["selected fix", reason]))
        versions = (
            f"{vuln.installed_version} → {vuln.fixed_version}"
            if vuln.fixed_version
            else "no fix"
        )
        rows.append(
            [
                output.literal(
                    "! blocked" if vuln.blocked_reason else f"! {kind}",
                    "yellow" if kind == "advisory" or vuln.blocked_reason else "red",
                ),
                vuln.severity.value.lower(),
                versions,
                " · ".join(filter(None, [vuln.pkg_name, vuln.vuln_id, reason])),
            ]
        )
        pipe_rows.append(
            [
                kind,
                vuln.pkg_name,
                vuln.installed_version,
                vuln.fixed_version or "-",
                vuln.severity.value,
                vuln.vuln_id,
                vuln.published_date.isoformat() if vuln.published_date else "-",
                "blocked" if vuln.blocked_reason else vuln.status,
                reason or "-",
            ]
        )
    return rows, pipe_rows


def _secret_rows(secrets: list[SecretFinding]) -> _FindingRows:
    rows: list[list[str | Text]] = [
        [
            output.literal("! secret", "yellow"),
            secret.severity.value.lower(),
            "-",
            f"{secret.file} · {secret.title}",
        ]
        for secret in secrets
    ]
    pipe_rows = [
        [
            "secret",
            secret.file,
            "-",
            "-",
            secret.severity.value,
            secret.rule_id,
            "-",
            "found",
            secret.title,
        ]
        for secret in secrets
    ]
    return rows, pipe_rows


def _update_rows(updates: list[UpdateFinding]) -> _FindingRows:
    rows: list[list[str | Text]] = []
    pipe_rows: list[list[str]] = []
    for update in updates:
        reason = update.blocked_reason or ""
        age = (
            f"{(datetime.now(UTC) - update.published_date).days}d old"
            if update.published_date
            else ""
        )
        rows.append(
            [
                output.literal(
                    "! blocked" if reason else "~ update", "yellow" if reason else ""
                ),
                update.semver_tier.value,
                f"{update.installed_version} → {update.latest_version}",
                " · ".join(filter(None, [update.pkg_name, age, reason])),
            ]
        )
        pipe_rows.append(
            [
                "update",
                update.pkg_name,
                update.installed_version,
                update.latest_version,
                update.semver_tier.value,
                "-",
                update.published_date.isoformat() if update.published_date else "-",
                "blocked" if reason else "available",
                reason or "-",
            ]
        )
    return rows, pipe_rows


def _print_blocked_findings(result: ScanResult, flow: str) -> None:
    """Piped update and resolve runs record each blocked package once."""
    for finding in result.blocked_findings:
        target = (
            finding.latest_version
            if isinstance(finding, UpdateFinding)
            else finding.fixed_version or "-"
        )
        output.outcome(
            result.project,
            flow,
            "blocked",
            finding.pkg_name,
            installed=finding.installed_version,
            target=target,
            reason=finding.blocked_reason or "",
        )
