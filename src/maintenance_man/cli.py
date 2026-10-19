import functools
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Annotated, Literal, NoReturn, get_args

import cyclopts
from rich.text import Text

from maintenance_man import __version__, output, paths, vcs_workflow
from maintenance_man.clock import utc_now
from maintenance_man.config import (
    ConfigError,
    ProjectNotFoundError,
    UnknownProjectError,
    ensure_mm_home,
    load_config,
    resolve_project,
)
from maintenance_man.deployer import BuildError
from maintenance_man.gradle import GradleError
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.events import (
    BlockersStillFailing,
    DeployStep,
    DeployStepFinished,
    Event,
    FindingFailed,
    FindingPassed,
    FindingsBlocked,
    FindingStarted,
    FindingStepFailed,
    HealthChecked,
    MissingTestConfig,
    OperationFailed,
    Outcome,
    ProcessingStarted,
    ProjectSkipped,
    ProjectStarted,
    Promoted,
    PromotionFailed,
    ResolvePaused,
    ScanReported,
    SkipReason,
    Status,
    SyncCompleted,
    TestCommandStarted,
)
from maintenance_man.models.scan import (
    GradleBlock,
    ScanResult,
    SecretFinding,
    UpdateFinding,
    UpdateResult,
    VulnFinding,
    highest_fix_version,
    sort_vulns_by_severity,
)
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.process import ToolNotFoundError, require_tool
from maintenance_man.scanner import ScanError
from maintenance_man.services import WorkflowError
from maintenance_man.services import deploy as deploy_service
from maintenance_man.services import resolve as resolve_service
from maintenance_man.services import scan as scan_service
from maintenance_man.services import update as update_service
from maintenance_man.services.scan import ScanSummary
from maintenance_man.storage import (
    CorruptScanResultsError,
    NoScanResultsError,
    load_activity,
    load_scan_results,
)
from maintenance_man.updater import run_test_phases
from maintenance_man.vcs import JJ_INSTALL_HINT, RevisionError


class ExitCode(IntEnum):
    OK = 0
    ERROR = 1
    VULNS_FOUND = 2
    UPDATES_FOUND = 3
    UPDATE_FAILED = 4
    TEST_FAILED = 5
    BUILD_FAILED = 6
    DEPLOY_FAILED = 7
    SYNC_FAILED = 8


_HANDLED_ERRORS = (
    WorkflowError,
    CorruptScanResultsError,
    EOFError,
    ProjectNotFoundError,
    ToolNotFoundError,
    ScanError,
    GradleError,
    RevisionError,
    OutdatedCheckError,
)


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
_NARROW_OVERVIEW = ("project", "vulns", "updates", "secrets")
_NARROW_TERMINAL_WIDTH = 70


type _Flow = Literal["scan", "update", "resolve", "deploy"]


@dataclass(slots=True)
class _Renderer:
    batch: bool
    project: str = ""
    flow: _Flow = "update"

    @functools.singledispatchmethod
    def __call__(self, event: Event) -> None:
        raise NotImplementedError(type(event))

    @__call__.register
    def _render_project_skipped(self, event: ProjectSkipped) -> None:
        if event.reason in _DEPLOY_SKIPS:
            status, reason = _DEPLOY_SKIPS[event.reason]
            output.outcome(event.project, "deploy", status, "deploy", reason=reason)
            return
        match event.reason:
            case SkipReason.PATH_MISSING if self.flow == "deploy":
                output.outcome(
                    event.project,
                    "deploy",
                    "failed",
                    "deploy",
                    reason=f"path does not exist: {event.detail}",
                )
            case SkipReason.PATH_MISSING:
                output.diagnostic(
                    "warning", f"{event.project} · path does not exist: {event.detail}"
                )
            case SkipReason.FLOW_CONFLICT:
                output.diagnostic("warning", f"{event.project} · {event.detail}")
            case SkipReason.NO_SCAN_RESULTS if not self.batch:
                output.notice(f"No scan results for {event.project}")
            case SkipReason.NOTHING_TO_DO:
                output.notice(f"Nothing to {event.detail} in {event.project}")
            case SkipReason.CORRUPT_SCAN_RESULTS:
                output.diagnostic(
                    "warning",
                    f"{event.project} · corrupt scan results; "
                    f"run mm scan {event.project}",
                )

    @__call__.register
    def _render_operation_failed(self, event: OperationFailed) -> None:
        output.diagnostic(
            "error", f"{event.project} · {event.operation} · {event.error}"
        )

    @__call__.register
    def _render_promotion(self, event: Promoted | PromotionFailed) -> None:
        match event:
            case PromotionFailed(project=project, error=error):
                output.outcome(
                    project, "promotion", "failed", _LOCAL_MAIN, reason=error
                )
            case Promoted():
                output.outcome(self.project, "promotion", "passed", _LOCAL_MAIN)

    @__call__.register
    def _render_scan_reported(self, event: ScanReported) -> None:
        result = event.result
        if self.flow == "scan" or output.terminal():
            _print_scan_result(result, elapsed_s=event.elapsed_s)
        else:
            _print_blocked_findings(result, self.flow)
        if result.has_findings or self.batch:
            return
        if event.elapsed_s is None:
            output.notice(f"No findings in {result.project}")
        else:
            output.notice(
                f"No findings in {result.project} · scanned in {event.elapsed_s:.1f}s"
            )

    @__call__.register
    def _render_missing_test_config(self, event: MissingTestConfig) -> None:
        output.diagnostic(
            "error",
            f"{event.project} · no test configuration · automatic updates need "
            "test_unit, test_integration or test_component",
        )

    @__call__.register
    def _render_processing_started(self, event: ProcessingStarted) -> None:
        output.heading(
            self.project, f"{event.vulns} vulnerabilities · {event.updates} updates"
        )

    @__call__.register
    def _render_resolve_paused(self, event: ResolvePaused) -> None:
        output.notice("Resolve paused")
        output.diagnostic("hint", f"mm resolve {event.project} --continue")

    @__call__.register
    def _render_findings_blocked(self, event: FindingsBlocked) -> None:
        for package, reason in event.findings:
            output.outcome(self.project, self.flow, "blocked", package, reason=reason)

    @__call__.register
    def _render_blockers_still_failing(self, event: BlockersStillFailing) -> None:
        output.diagnostic(
            "error", f"{event.phase} · still blocking: {', '.join(event.pkgs)}"
        )

    @__call__.register
    def _render_sync_completed(self, event: SyncCompleted) -> None:
        if event.action == vcs_workflow.SyncAction.UNCHANGED:
            output.outcome(event.project, "sync", "unchanged", "main")
        else:
            output.outcome(event.project, "sync", "passed", "main", reason=event.action)

    @__call__.register
    def _render_project_started(self, event: ProjectStarted) -> None:
        self.project = event.project
        if self.flow == "deploy":
            output.heading(event.project)

    @__call__.register
    def _render_finding_started(self, event: FindingStarted) -> None:
        if output.stderr_terminal():
            output.notice(f"Updating {event.pkg} {event.installed} → {event.target}")

    @__call__.register
    def _render_test_command_started(self, event: TestCommandStarted) -> None:
        if output.is_verbose():
            output.notice(f"$ {event.command}")

    @__call__.register
    def _render_finding_step_failed(self, event: FindingStepFailed) -> None:
        prefix = f"{self.project} · " if self.project else ""
        output.diagnostic("error", f"{prefix}{event.step} · {event.error}")

    @__call__.register
    def _render_finding_outcome(self, event: FindingPassed | FindingFailed) -> None:
        match event:
            case FindingFailed(phase=phase):
                status, reason = "failed", f"{phase} failed"
            case FindingPassed(already_applied=applied):
                status, reason = "passed", "already applied" if applied else ""
        output.outcome(
            self.project,
            self.flow,
            status,
            event.pkg,
            installed=event.installed,
            target=event.target,
            reason=reason,
        )

    @__call__.register
    def _render_deploy_step_finished(self, event: DeployStepFinished) -> None:
        word = event.step.value
        if event.error is None:
            output.outcome(event.project, word, "passed", word)
            return
        output.outcome(event.project, word, "failed", word, reason=event.error)
        if event.step is DeployStep.BUILD:
            output.outcome(
                event.project, "deploy", "skipped", "deploy", reason="build failed"
            )

    @__call__.register
    def _render_health_checked(self, event: HealthChecked) -> None:
        if event.is_up:
            output.outcome(event.project, "health", "passed", "healthcheck")
        else:
            output.outcome(
                event.project,
                "health",
                "failed",
                "healthcheck",
                reason=event.error or "not healthy",
            )


_DEPLOY_SKIPS: dict[SkipReason, tuple[Status, str]] = {
    SkipReason.NOT_DEPLOYABLE: ("skipped", "not deployable"),
    SkipReason.UNCHANGED: (
        "unchanged",
        "unchanged since last deploy · use --force to redeploy",
    ),
    SkipReason.BLOCKED: (
        "blocked",
        "could not resolve main revision · use --force to deploy anyway",
    ),
}
_STATUS_ORDER: tuple[Status, ...] = get_args(Status.__value__)
_LOCAL_MAIN = "local main"
_HEALTHCHECK_UNCONFIGURED = "--check: no healthcheck_url configured in [defaults]"


app = cyclopts.App(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    version=__version__,
    version_flags=["--version", "-v"],
    help_formatter=output.HelpFormatter(),
    error_formatter=lambda error: output.literal(f"error: {error}"),
)


def main(argv: Sequence[str] | None = None) -> None:
    """Usage errors and handled service errors exit with ExitCode.ERROR.

    Cyclopts would exit 2 on its own for usage errors.
    """
    try:
        app(argv, exit_on_error=False)
    except cyclopts.CycloptsError:
        sys.exit(ExitCode.ERROR)
    except ConfigError as exc:
        for message in exc.messages:
            output.diagnostic("error", message)
        sys.exit(ExitCode.ERROR)
    except _HANDLED_ERRORS as exc:
        _fatal(str(exc), hint=_hint_for(exc))


def _hint_for(exc: Exception) -> str | None:
    match exc:
        case UnknownProjectError():
            return "mm list"
        case CorruptScanResultsError(project=project):
            return f"mm scan {project}"
        case _:
            return None


type ConfigOption = Annotated[
    Path | None,
    cyclopts.Parameter(help="Path to config file. Uses ~/.mm/config.toml if omitted."),
]
type VerboseOption = Annotated[
    bool,
    cyclopts.Parameter(
        help="Stream subprocess logs to stderr, including successful commands."
    ),
]


def _reset_output_and_load_config(
    config: Path | None, *, verbose: bool = False, require_projects: bool = False
) -> MmConfig:
    output.reset_invocation_output(verbose=verbose)
    cfg = load_config(config)
    if require_projects and not cfg.projects:
        _exit_without_projects(config)
    return cfg


@app.command
def init() -> None:
    """Initialise the ~/.mm directory and skeleton config."""
    output.reset_invocation_output(verbose=False)
    ensure_mm_home()
    output.notice(f"Initialised {paths.mm_home()}")
    output.notice(f"Add projects to {paths.config_path()}")


@app.command
def scan(
    project: str | None = None,
    *,
    config: ConfigOption = None,
) -> None:
    """Scan projects for vulnerabilities and available updates.

    Parameters
    ----------
    project: str | None
        Project name to scan. Scans all if omitted.
    """
    cfg = _reset_output_and_load_config(config, require_projects=True)

    if project:
        proj_config = resolve_project(cfg, project)
        result = scan_service.scan_one(
            project,
            proj_config,
            minimum_age_days=cfg.defaults.min_version_age_days,
            emit=_Renderer(batch=False, project=project, flow="scan"),
        )
        sys.exit(
            _scan_exit_code(
                ScanSummary(
                    has_vulns=result.has_actionable_vulns,
                    has_updates=bool(result.updates),
                )
            )
        )

    started = time.monotonic()
    summary = scan_service.scan_all(cfg, emit=_Renderer(batch=True, flow="scan"))
    _notice_projects(
        summary.clean,
        "findings",
        suffix=f" · scanned in {time.monotonic() - started:.1f}s",
    )
    sys.exit(_scan_exit_code(summary))


@app.command
def update(
    *projects: str,
    negate: Annotated[bool, cyclopts.Parameter(name=("--negate", "-n"))] = False,
    config: ConfigOption = None,
    verbose: VerboseOption = False,
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
    """
    cfg = _reset_output_and_load_config(config, verbose=verbose, require_projects=True)
    mode, targets = update_service.resolve_update_targets(cfg, projects, negate=negate)

    if not targets:
        output.notice("No target projects")
        sys.exit(ExitCode.OK)

    require_tool("jj", JJ_INSTALL_HINT)

    if mode == "single":
        name = targets[0]
        proj_config = resolve_project(cfg, name)
        result = update_service.update_project(
            name,
            proj_config,
            choose=_choose_findings,
            emit=_Renderer(batch=False, project=name),
        )
        _print_result_totals(result.results, result.blocked)
        sys.exit(
            ExitCode.OK
            if result.outcome is Outcome.SUCCEEDED
            else ExitCode.UPDATE_FAILED
        )

    batch = update_service.update_projects(cfg, targets, emit=_Renderer(batch=True))
    results = [result for project in batch.projects for result in project.results]
    blocked = sum(project.blocked for project in batch.projects)
    if results or blocked:
        _print_result_totals(results, blocked)
    else:
        output.notice("No projects had actionable findings")
    sys.exit(ExitCode.UPDATE_FAILED if batch.outcome is Outcome.FAILED else ExitCode.OK)


@app.command
def sync(
    *projects: str,
    config: ConfigOption = None,
) -> None:
    """Sync local main with remote for one, many, or all configured projects.

    Parameters
    ----------
    projects: str
        Project names to sync. No names syncs all configured projects.
    """
    cfg = _reset_output_and_load_config(config, require_projects=True)
    outcome = scan_service.sync_projects(cfg, projects, emit=_Renderer(batch=True))
    sys.exit(ExitCode.SYNC_FAILED if outcome is Outcome.FAILED else ExitCode.OK)


def _print_result_totals(results: Sequence[UpdateResult], blocked: int) -> None:
    passed = sum(result.passed for result in results)
    counts = {"passed": passed, "failed": len(results) - passed, "blocked": blocked}
    if results or blocked:
        output.summary({state: count for state, count in counts.items() if count})


def _print_deploy_summary(results: Sequence[deploy_service.DeployResult]) -> None:
    if not results:
        output.notice("No projects have deploy_command configured")
        return
    counts = Counter(
        "failed" if "failed" in (r.build_status, r.deploy_status) else r.deploy_status
        for r in results
    )
    output.summary(
        {status: counts[status] for status in _STATUS_ORDER if counts[status]}
    )


@app.command
def deploy(
    project: str | None = None,
    *,
    build: bool = False,
    check: bool = False,
    force: Annotated[bool, cyclopts.Parameter(name=["--force", "-f"])] = False,
    config: ConfigOption = None,
    verbose: VerboseOption = False,
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
    """
    cfg = _reset_output_and_load_config(config, verbose=verbose)
    batch = not project
    renderer = _Renderer(batch=batch, flow="deploy")

    if batch:
        if check and not cfg.defaults.healthcheck_url:
            output.notice(_HEALTHCHECK_UNCONFIGURED)
        if not cfg.projects:
            _exit_without_projects(config)
        results = deploy_service.deploy_all(
            cfg,
            check=check,
            force=force,
            emit=renderer,
        )
        _print_deploy_summary(results)
        any_failed = any(
            "failed" in (result.build_status, result.deploy_status)
            for result in results
        )
        sys.exit(ExitCode.DEPLOY_FAILED if any_failed else ExitCode.OK)

    assert project is not None
    proj_config = resolve_project(cfg, project)
    result = deploy_service.deploy_project(
        project,
        proj_config,
        healthcheck_url=cfg.defaults.healthcheck_url if check else None,
        build=build,
        force=force,
        emit=renderer,
    )
    if check and not cfg.defaults.healthcheck_url and result.deploy_status == "passed":
        output.notice(_HEALTHCHECK_UNCONFIGURED)
    if result.build_status == "failed":
        sys.exit(ExitCode.BUILD_FAILED)
    if result.deploy_status == "failed":
        sys.exit(ExitCode.DEPLOY_FAILED)
    sys.exit(ExitCode.OK)


@app.command
def test(
    project: str,
    *,
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Run a project's test suite.

    Runs configured test phases (unit → integration → component) in order,
    stopping on first failure.

    Parameters
    ----------
    project: str
        Project name to test.
    """
    cfg = _reset_output_and_load_config(config, verbose=verbose)
    proj_config = resolve_project(cfg, project)
    if not proj_config.test_phases:
        _fatal(
            f"No test configuration for {project}",
            hint=f"add test_unit to [projects.{project}] in {_config_file(config)}",
        )

    output.heading(project)
    failed_phase = run_test_phases(
        proj_config, proj_config.path, emit=_Renderer(batch=False)
    )

    if failed_phase is None:
        output.outcome(project, "test", "passed", "tests")
        sys.exit(ExitCode.OK)
    output.outcome(project, "test", "failed", "tests", reason=f"{failed_phase} failed")
    sys.exit(ExitCode.TEST_FAILED)


@app.command
def build(
    project: str,
    *,
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Build a project's artefacts.

    Parameters
    ----------
    project: str
        Project name to build.
    """
    cfg = _reset_output_and_load_config(config, verbose=verbose)
    proj_config = resolve_project(cfg, project)

    if not proj_config.build_command:
        _fatal(
            f"No build_command configured for {project}",
            hint=(
                f"add build_command to [projects.{project}] in {_config_file(config)}"
            ),
        )

    output.heading(project)
    try:
        deploy_service.build_project(project, proj_config)
    except BuildError as exc:
        output.outcome(project, "build", "failed", "build", reason=str(exc))
        sys.exit(ExitCode.BUILD_FAILED)
    output.outcome(project, "build", "passed", "build")
    sys.exit(ExitCode.OK)


@app.command(name=("list", "status", "st"))
def list_projects(
    *,
    detail: Annotated[bool, cyclopts.Parameter(name=("--detail", "-d"))] = False,
    config: ConfigOption = None,
) -> None:
    """List all configured projects with scan findings summary.

    Parameters
    ----------
    detail: bool
        Show full findings detail for each project.
    """
    cfg = _reset_output_and_load_config(config, require_projects=True)

    scan_results: dict[str, ScanResult] = {}
    for name in cfg.projects:
        try:
            scan_results[name] = load_scan_results(name)
        except NoScanResultsError:
            pass
        except CorruptScanResultsError:
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
    _notice_projects(clean, "findings")
    _notice_projects(unscanned, "saved scan")


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
    if output.terminal() and output.console().width < _NARROW_TERMINAL_WIDTH:
        hidden = [
            _OVERVIEW_HEADERS[i]
            for i in visible
            if _OVERVIEW_HEADERS[i] not in _NARROW_OVERVIEW
        ]
        visible = [i for i in visible if _OVERVIEW_HEADERS[i] in _NARROW_OVERVIEW]
        if hidden:
            footer_parts.append("hidden: " + ", ".join(hidden))
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


@app.command
def todo(
    project: str | None = None,
    *,
    config: ConfigOption = None,
) -> None:
    """Show TODO.md items for projects.

    Parameters
    ----------
    project: str | None
        Project name. Shows all projects if omitted.
    """
    cfg = _reset_output_and_load_config(config)

    if project:
        proj_config = resolve_project(cfg, project)
        _print_project_todo(project, _read_todo(proj_config.path))
        return

    if not cfg.projects:
        _exit_without_projects(config)

    todos = {name: _read_todo(cfg.projects[name].path) for name in sorted(cfg.projects)}
    empty = [name for name, content in todos.items() if not content.strip()]
    _notice_projects(empty, "TODO items")
    for name, content in todos.items():
        if content.strip():
            _print_project_todo(name, content)


def _read_todo(project_path: Path) -> str:
    """The raw TODO.md text, or '' when the file is absent."""
    todo_path = project_path / "TODO.md"
    return todo_path.read_text() if todo_path.exists() else ""


def _print_project_todo(name: str, content: str) -> None:
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


def _exit_without_projects(config: Path | None) -> NoReturn:
    output.notice("No projects configured")
    output.diagnostic("hint", f"add projects to {_config_file(config)}")
    sys.exit(ExitCode.OK)


def _notice_projects(names: Sequence[str], what: str, suffix: str = "") -> None:
    if names:
        output.notice(
            f"{len(names)} projects have no {what}: {', '.join(names)}{suffix}"
        )


def _config_file(config: Path | None) -> Path:
    """The file `load_config` reads for this `--config` value."""
    return config or paths.config_path()


def _fatal(
    msg: str, code: int = ExitCode.ERROR, *, hint: str | None = None
) -> NoReturn:
    output.diagnostic("error", msg)
    if hint:
        output.diagnostic("hint", hint)
    sys.exit(code)


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
    numbered: list[VulnFinding | UpdateFinding] = [
        *sort_vulns_by_severity(vulns),
        *updates,
    ]
    rows = []
    for finding in numbered:
        owner = ""
        if isinstance(finding, VulnFinding):
            kind = "! vuln"
            risk = f"{finding.severity.value.lower()} · {finding.vuln_id}"
            if finding.gradle_target is not None:
                target = finding.gradle_target
                owner = (
                    f" via {target.display_name} "
                    f"{target.members[0].installed_version} → {target.target_version}"
                )
        else:
            kind = "~ update"
            risk = finding.semver_tier.value
        rows.append(
            (
                kind,
                risk,
                f"{finding.installed_version} → {finding.target_version}",
                finding.pkg_name + owner,
            )
        )
    output.choices(rows)
    return numbered


def _parse_selection(
    text: str,
    numbered: list[VulnFinding | UpdateFinding],
    vulns: list[VulnFinding],
    updates: list[UpdateFinding],
) -> tuple[list[VulnFinding], list[UpdateFinding]] | None:
    """The chosen findings for a keyword or comma-separated numbers, else None."""
    choice = text.strip().lower()
    keywords = {
        "all": (vulns, updates),
        "none": ([], []),
        "vulns": (vulns, []),
        "updates": ([], updates),
    }
    if choice in keywords:
        return keywords[choice]
    try:
        indices = [int(part) for part in choice.split(",")]
    except ValueError:
        return None
    if not all(1 <= index <= len(numbered) for index in indices):
        return None
    selected = [numbered[index - 1] for index in dict.fromkeys(indices)]
    return (
        [finding for finding in selected if isinstance(finding, VulnFinding)],
        [finding for finding in selected if isinstance(finding, UpdateFinding)],
    )


def _choose_findings(
    selectable_vulns: list[VulnFinding],
    selectable_updates: list[UpdateFinding],
) -> tuple[list[VulnFinding], list[UpdateFinding]]:
    numbered = _print_numbered_findings(selectable_vulns, selectable_updates)
    parts = [
        "all",
        *(["vulns"] if selectable_vulns else []),
        *(["updates"] if selectable_updates else []),
        "1,2,...",
        "none",
    ]
    message = f"Select updates [{'/'.join(parts)}]"
    while True:
        text = output.prompt(message, default="all")
        selection = _parse_selection(
            text, numbered, selectable_vulns, selectable_updates
        )
        if selection is not None:
            return selection
        output.diagnostic("error", f"Invalid selection: {text}")


@app.command
def resolve(
    project: str,
    continue_: Annotated[bool, cyclopts.Parameter(name="--continue")] = False,
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Work through failed findings for a project.

    Applies each failed finding on ``mm/resolve-dependencies``, runs tests, and
    stops on the first failure so the operator can debug manually. Rerun with
    ``--continue`` after committing a manual fix to re-test and advance. Promotes
    the resolve bookmark to local main once every candidate is Ready. Takes
    over pending update work when it exists.

    Parameters
    ----------
    project: str
        Project name (required).
    continue_: bool
        Re-test a paused, manually fixed finding on the resolve branch.
    """
    cfg = _reset_output_and_load_config(config, verbose=verbose)
    proj_config = resolve_project(cfg, project)
    require_tool("jj", JJ_INSTALL_HINT)
    outcome = resolve_service.resolve_project(
        project,
        proj_config,
        continue_=continue_,
        emit=_Renderer(batch=False, project=project, flow="resolve"),
    )
    sys.exit(ExitCode.OK if outcome is Outcome.SUCCEEDED else ExitCode.UPDATE_FAILED)


def _print_scan_result(result: ScanResult, elapsed_s: float | None = None) -> None:
    wins = _selected_fix_versions(result.vulnerabilities)
    found = [
        *(
            _vulnerability_row(vuln, wins)
            for vuln in sort_vulns_by_severity(result.vulnerabilities)
        ),
        *map(_secret_row, result.secrets),
        *map(_update_row, result.updates),
    ]
    if not found:
        return
    rows, pipe_rows = zip(*found, strict=True)
    output.heading(result.project, f"{len(rows)} findings")
    headers = ["kind", "severity", "versions", "package / detail"]
    visible = (
        [0, 1, 2, 3] if output.console().width >= _NARROW_TERMINAL_WIDTH else [0, 3]
    )
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
    groups = defaultdict(list)
    for vuln in vulnerabilities:
        if vuln.actionable:
            groups[vuln.pkg_name].append(vuln)
    return {
        package: highest_fix_version(group)
        for package, group in groups.items()
        if len(group) > 1
    }


type _FindingRow = tuple[list[str | Text], list[str]]


def _vulnerability_row(vuln: VulnFinding, wins: dict[str, str]) -> _FindingRow:
    kind = "vuln" if vuln.actionable else "advisory"
    blocked = isinstance(vuln.state, GradleBlock)
    reason = vuln.state.reason if blocked else ""
    if vuln.fixed_version and wins.get(vuln.pkg_name) == vuln.fixed_version:
        reason = " · ".join(filter(None, ["selected fix", reason]))
    versions = (
        f"{vuln.installed_version} → {vuln.fixed_version}"
        if vuln.fixed_version
        else "no fix"
    )
    row = [
        output.literal(
            "! blocked" if blocked else f"! {kind}",
            "yellow" if kind == "advisory" or blocked else "red",
        ),
        vuln.severity.value.lower(),
        versions,
        " · ".join(filter(None, [vuln.pkg_name, vuln.vuln_id, reason])),
    ]
    pipe_row = [
        kind,
        vuln.pkg_name,
        vuln.installed_version,
        vuln.fixed_version or "-",
        vuln.severity.value,
        vuln.vuln_id,
        vuln.published_date.isoformat() if vuln.published_date else "-",
        "blocked" if blocked else vuln.status,
        reason or "-",
    ]
    return row, pipe_row


def _secret_row(secret: SecretFinding) -> _FindingRow:
    row = [
        output.literal("! secret", "yellow"),
        secret.severity.value.lower(),
        "-",
        f"{secret.file} · {secret.title}",
    ]
    pipe_row = [
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
    return row, pipe_row


def _update_row(update: UpdateFinding) -> _FindingRow:
    blocked = isinstance(update.state, GradleBlock)
    reason = update.state.reason if blocked else ""
    age = (
        f"{(utc_now() - update.published_date).days}d old"
        if update.published_date
        else ""
    )
    row = [
        output.literal(
            "! blocked" if blocked else "~ update", "yellow" if blocked else ""
        ),
        update.semver_tier.value,
        f"{update.installed_version} → {update.latest_version}",
        " · ".join(filter(None, [update.pkg_name, age, reason])),
    ]
    pipe_row = [
        "update",
        update.pkg_name,
        update.installed_version,
        update.latest_version,
        update.semver_tier.value,
        "-",
        update.published_date.isoformat() if update.published_date else "-",
        "blocked" if blocked else "available",
        reason or "-",
    ]
    return row, pipe_row


def _print_blocked_findings(result: ScanResult, flow: str) -> None:
    """Piped update and resolve runs record each blocked package once."""
    for finding in result.blocked_findings:
        if not isinstance(finding.state, GradleBlock):
            continue
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
            reason=finding.state.reason,
        )
