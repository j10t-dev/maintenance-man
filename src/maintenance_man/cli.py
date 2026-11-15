import sys
import time
from collections import Counter
from collections.abc import Sequence
from enum import IntEnum
from pathlib import Path
from typing import Annotated, NoReturn, get_args

import cyclopts

from maintenance_man import __version__, output, paths
from maintenance_man.config import (
    ConfigError,
    ProjectNotFoundError,
    UnknownProjectError,
    ensure_mm_home,
    load_config,
    resolve_project,
)
from maintenance_man.deployer import BuildError
from maintenance_man.event_renderer import EventRenderer
from maintenance_man.finding_selection import choose_findings
from maintenance_man.gradle import GradleError
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.events import Outcome, Status
from maintenance_man.models.scan import ScanResult, UpdateResult
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.process import ToolNotFoundError, require_tool
from maintenance_man.scan_table import print_scan_result
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
_STATUS_ORDER: tuple[Status, ...] = get_args(Status.__value__)
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
        case CorruptScanResultsError(project_name=project_name):
            return f"mm scan {project_name}"
        case _:
            return None


type ConfigOption = Annotated[
    Path | None,
    cyclopts.Parameter(
        help=(
            "Path to config file. Uses config.toml in MM_HOME "
            "(default ~/.mm) if omitted."
        )
    ),
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
    """Initialise MM_HOME (default ~/.mm) and its skeleton config."""
    output.reset_invocation_output(verbose=False)
    ensure_mm_home()
    output.notice(f"Initialised {paths.mm_home()}")
    output.notice(f"Add projects to {paths.config_path()}")


@app.command
def scan(
    project_name: Annotated[str | None, cyclopts.Parameter(name="project")] = None,
    *,
    config: ConfigOption = None,
) -> None:
    """Scan projects for vulnerabilities and available updates.

    Parameters
    ----------
    project_name: str | None
        Project name to scan. Scans all if omitted.
    """
    cfg = _reset_output_and_load_config(config, require_projects=True)

    if project_name:
        project = resolve_project(cfg, project_name)
        result = scan_service.scan_one(
            project_name,
            project,
            minimum_age_days=cfg.defaults.min_version_age_days,
            emit=EventRenderer(batch=False, project_name=project_name, flow="scan"),
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
    summary = scan_service.scan_all(cfg, emit=EventRenderer(batch=True, flow="scan"))
    _notice_projects(
        summary.clean,
        "findings",
        suffix=f" · scanned in {time.monotonic() - started:.1f}s",
    )
    sys.exit(_scan_exit_code(summary))


@app.command
def update(
    *project_names: Annotated[str, cyclopts.Parameter(name="projects")],
    negate: Annotated[bool, cyclopts.Parameter(name=("--negate", "-n"))] = False,
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Apply updates from scan results to one, many, or all projects.

    Parameters
    ----------
    project_names: str
        Project names to update. No names batch-updates all configured projects.
        With -n/--negate, names are exclusions. One name keeps the interactive
        single-project flow.
    negate: bool
        Treat all positional project names as exclusions.
    """
    cfg = _reset_output_and_load_config(config, verbose=verbose, require_projects=True)
    mode, targets = update_service.resolve_update_targets(
        cfg, project_names, negate=negate
    )

    if not targets:
        output.notice("No target projects")
        sys.exit(ExitCode.OK)

    require_tool("jj", JJ_INSTALL_HINT)

    if mode == "single":
        project_name = targets[0]
        project = resolve_project(cfg, project_name)
        result = update_service.update_project(
            project_name,
            project,
            choose=choose_findings,
            emit=EventRenderer(batch=False, project_name=project_name),
        )
        _print_result_totals(result.results, result.blocked)
        sys.exit(
            ExitCode.OK
            if result.outcome is Outcome.SUCCEEDED
            else ExitCode.UPDATE_FAILED
        )

    batch = update_service.update_projects(cfg, targets, emit=EventRenderer(batch=True))
    results = [
        result for project_update in batch.projects for result in project_update.results
    ]
    blocked = sum(project_update.blocked for project_update in batch.projects)
    if results or blocked:
        _print_result_totals(results, blocked)
    else:
        output.notice("No projects had actionable findings")
    sys.exit(ExitCode.UPDATE_FAILED if batch.outcome is Outcome.FAILED else ExitCode.OK)


@app.command
def sync(
    *project_names: Annotated[str, cyclopts.Parameter(name="projects")],
    config: ConfigOption = None,
) -> None:
    """Sync local main with remote for one, many, or all configured projects.

    Parameters
    ----------
    project_names: str
        Project names to sync. No names syncs all configured projects.
    """
    cfg = _reset_output_and_load_config(config, require_projects=True)
    outcome = scan_service.sync_projects(
        cfg, project_names, emit=EventRenderer(batch=True)
    )
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
    counts = Counter("failed" if r.failed else r.deploy_status for r in results)
    output.summary(
        {status: counts[status] for status in _STATUS_ORDER if counts[status]}
    )


@app.command
def deploy(
    project_name: Annotated[str | None, cyclopts.Parameter(name="project")] = None,
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
    project_name: str | None
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
    batch = not project_name
    renderer = EventRenderer(batch=batch, flow="deploy")

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
        any_failed = any(result.failed for result in results)
        sys.exit(ExitCode.DEPLOY_FAILED if any_failed else ExitCode.OK)

    assert project_name is not None
    project = resolve_project(cfg, project_name)
    result = deploy_service.deploy_project(
        project_name,
        project,
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
    project_name: Annotated[str, cyclopts.Parameter(name="project")],
    *,
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Run a project's test suite.

    Runs configured test phases (unit → integration → component) in order,
    stopping on first failure.

    Parameters
    ----------
    project_name: str
        Project name to test.
    """
    cfg = _reset_output_and_load_config(config, verbose=verbose)
    project = resolve_project(cfg, project_name)
    if not project.test_phases:
        _fatal(
            f"No test configuration for {project_name}",
            hint=(
                f"add test_unit to [projects.{project_name}] in {_config_file(config)}"
            ),
        )

    output.heading(project_name)
    failed_phase = run_test_phases(
        project, project.path, emit=EventRenderer(batch=False)
    )

    if failed_phase is None:
        output.outcome(project_name, "test", "passed", "tests")
        sys.exit(ExitCode.OK)
    output.outcome(
        project_name, "test", "failed", "tests", reason=f"{failed_phase} failed"
    )
    sys.exit(ExitCode.TEST_FAILED)


@app.command
def build(
    project_name: Annotated[str, cyclopts.Parameter(name="project")],
    *,
    config: ConfigOption = None,
    verbose: VerboseOption = False,
) -> None:
    """Build a project's artefacts.

    Parameters
    ----------
    project_name: str
        Project name to build.
    """
    cfg = _reset_output_and_load_config(config, verbose=verbose)
    project = resolve_project(cfg, project_name)

    if not project.build_command:
        _fatal(
            f"No build_command configured for {project_name}",
            hint=(
                f"add build_command to [projects.{project_name}] "
                f"in {_config_file(config)}"
            ),
        )

    output.heading(project_name)
    try:
        deploy_service.build_project(project_name, project)
    except BuildError as exc:
        output.outcome(project_name, "build", "failed", "build", reason=str(exc))
        sys.exit(ExitCode.BUILD_FAILED)
    output.outcome(project_name, "build", "passed", "build")
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
    for project_name in cfg.projects:
        try:
            scan_results[project_name] = load_scan_results(project_name)
        except NoScanResultsError:
            pass
        except CorruptScanResultsError:
            output.diagnostic(
                "warning", f"corrupt scan results for {project_name}; skipped"
            )

    if detail:
        _print_project_detail(cfg, scan_results)
    else:
        activity = load_activity(paths.activity_path())
        _print_project_overview(cfg, scan_results, activity)


def _print_project_detail(cfg: MmConfig, scan_results: dict[str, ScanResult]) -> None:
    clean = []
    unscanned = []
    for project_name in sorted(cfg.projects):
        result = scan_results.get(project_name)
        if result is None:
            unscanned.append(project_name)
        elif result.has_findings:
            print_scan_result(result)
        else:
            clean.append(project_name)
    _notice_projects(clean, "findings")
    _notice_projects(unscanned, "saved scan")


def _print_project_overview(
    cfg: MmConfig,
    scan_results: dict[str, ScanResult],
    activity: dict[str, ProjectActivity],
) -> None:
    rows: list[list[str]] = []
    pipe_rows: list[list[str]] = []
    for project_name, project in sorted(cfg.projects.items()):
        row, pipe_row = _project_row(
            project_name,
            project,
            scan_results.get(project_name),
            activity.get(project_name),
        )
        rows.append(row)
        pipe_rows.append(pipe_row)

    visible, footer_parts = _hidden_columns(_OVERVIEW_HEADERS, rows)
    if output.terminal() and output.console().width < output.NARROW_TERMINAL_WIDTH:
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
    project_name: str,
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
        project_name,
        project.package_manager,
        *counts,
        output.timestamp(result.scanned_at) if result else "never",
        _activity_cell(built),
        _activity_cell(deployed) if project.deployable else deploy_status,
    ]
    pipe_row = [
        project_name,
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
    project_name: Annotated[str | None, cyclopts.Parameter(name="project")] = None,
    *,
    config: ConfigOption = None,
) -> None:
    """Show TODO.md items for projects.

    Parameters
    ----------
    project_name: str | None
        Project name. Shows all projects if omitted.
    """
    cfg = _reset_output_and_load_config(config)

    if project_name:
        project = resolve_project(cfg, project_name)
        _print_project_todo(project_name, _read_todo(project.path))
        return

    if not cfg.projects:
        _exit_without_projects(config)

    todos = {
        project_name: _read_todo(cfg.projects[project_name].path)
        for project_name in sorted(cfg.projects)
    }
    empty = [
        project_name for project_name, content in todos.items() if not content.strip()
    ]
    _notice_projects(empty, "TODO items")
    for project_name, content in todos.items():
        if content.strip():
            _print_project_todo(project_name, content)


def _read_todo(project_path: Path) -> str:
    """The raw TODO.md text, or '' when the file is absent."""
    todo_path = project_path / "TODO.md"
    return todo_path.read_text() if todo_path.exists() else ""


def _print_project_todo(project_name: str, content: str) -> None:
    if not content.strip():
        output.notice(f"No TODO items in {project_name}")
        return
    lines = content.splitlines()
    output.heading(project_name, "TODO.md")
    output.records(
        project_name,
        (),
        [[line] for line in lines],
        pipe_rows=[[str(index), line] for index, line in enumerate(lines, 1)],
    )


def _exit_without_projects(config: Path | None) -> NoReturn:
    output.notice("No projects configured")
    output.diagnostic("hint", f"add projects to {_config_file(config)}")
    sys.exit(ExitCode.OK)


def _notice_projects(project_names: Sequence[str], what: str, suffix: str = "") -> None:
    if project_names:
        output.notice(
            f"{len(project_names)} projects have no {what}: "
            f"{', '.join(project_names)}{suffix}"
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


@app.command
def resolve(
    project_name: Annotated[str, cyclopts.Parameter(name="project")],
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
    project_name: str
        Project name (required).
    continue_: bool
        Re-test a paused, manually fixed finding on the resolve branch.
    """
    cfg = _reset_output_and_load_config(config, verbose=verbose)
    project = resolve_project(cfg, project_name)
    require_tool("jj", JJ_INSTALL_HINT)
    outcome = resolve_service.resolve_project(
        project_name,
        project,
        continue_=continue_,
        emit=EventRenderer(batch=False, project_name=project_name, flow="resolve"),
    )
    sys.exit(ExitCode.OK if outcome is Outcome.SUCCEEDED else ExitCode.UPDATE_FAILED)
