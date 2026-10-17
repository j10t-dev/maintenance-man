import functools
import sys
import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, NoReturn, get_args

import cyclopts
from rich.cells import cell_len
from rich.text import Text

from maintenance_man import __version__, output, paths, vcs_workflow
from maintenance_man.config import (
    ConfigError,
    ProjectNotFoundError,
    UnknownProjectError,
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

_EXIT_FOR: dict[type[Exception], ExitCode] = {
    WorkflowError: ExitCode.ERROR,
    ConfigError: ExitCode.ERROR,
    ProjectNotFoundError: ExitCode.ERROR,
    ToolNotFoundError: ExitCode.ERROR,
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
            hint = "mm list" if isinstance(exc, UnknownProjectError) else None
            _fatal(str(exc), code=code, hint=hint)

    return mapped_command


type _Flow = Literal["scan", "update", "resolve", "deploy"]


@functools.singledispatch
def _render(event: Event, *, batch: bool, project: str, flow: _Flow) -> None:
    raise NotImplementedError(type(event))


@dataclass(slots=True)
class _Renderer:
    batch: bool
    project: str = ""
    flow: _Flow = "update"

    def __call__(self, event: Event) -> None:
        if isinstance(event, ProjectStarted):
            self.project = event.project
        _render(event, batch=self.batch, project=self.project, flow=self.flow)


_DEPLOY_SKIPS: dict[SkipReason, tuple[output.Status, str]] = {
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
_STATUS_ORDER: tuple[output.Status, ...] = get_args(output.Status.__value__)
_DEPLOY_STATUS_WORDS: dict[str, output.Status] = {
    "pass": "passed",
    "skip": "skipped",
    "unchanged": "unchanged",
    "blocked": "blocked",
}
_DEPLOY_STEP_WORDS: dict[DeployStep, str] = {
    DeployStep.BUILD: "build",
    DeployStep.DEPLOY: "deploy",
}
_OPERATION_WORDS: dict[Operation, str] = {
    Operation.UPDATE_SETUP: "update setup",
    Operation.REFRESH: "workspace refresh",
    Operation.WORKSPACE_CLEANUP: "workspace cleanup",
    Operation.BOOKMARK_CLEANUP: "bookmark cleanup",
    Operation.RESOLVE_SETUP: "resolve setup",
    Operation.SUBMIT: "submit failed",
    Operation.REMOTE_SYNC: "failed to sync remote",
    Operation.SCAN: "scan",
    Operation.SYNC: "sync",
}
_WARNING_OPERATIONS = {Operation.SUBMIT, Operation.REMOTE_SYNC}
_LOCAL_MAIN = "local main"


def _project_outcome(
    project: str, operation: str, status: output.Status, subject: str, reason: str = ""
) -> None:
    """Print an outcome under the project's heading, which prints once."""
    output.heading(project)
    output.outcome(project, operation, status, subject, reason=reason)


@_render.register
def _render_project_skipped(
    event: ProjectSkipped, *, batch: bool, project: str, flow: _Flow
) -> None:
    if event.reason in _DEPLOY_SKIPS:
        status, reason = _DEPLOY_SKIPS[event.reason]
        _project_outcome(event.project, "deploy", status, "deploy", reason)
        return
    match event.reason:
        case SkipReason.PATH_MISSING if flow == "deploy":
            _project_outcome(
                event.project,
                "deploy",
                "failed",
                "deploy",
                f"path does not exist: {event.detail}",
            )
        case SkipReason.PATH_MISSING:
            output.diagnostic(
                "warning", f"{event.project} · path does not exist: {event.detail}"
            )
        case SkipReason.FLOW_CONFLICT:
            output.diagnostic("warning", f"{event.project} · {event.detail}")
        case SkipReason.NO_SCAN_RESULTS if not batch:
            output.notice(f"No scan results for {event.project}")
        case SkipReason.NOTHING_TO_DO:
            output.notice(f"Nothing to {event.detail} in {event.project}")


@_render.register
def _render_operation_failed(
    event: OperationFailed, *, batch: bool, project: str, flow: _Flow
) -> None:
    if event.operation is Operation.PROMOTE:
        output.outcome(
            event.project, "promotion", "failed", _LOCAL_MAIN, reason=event.error
        )
        return
    words = _OPERATION_WORDS[event.operation]
    if event.operation is Operation.SUBMIT:
        bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
        words = f"{words} · keeping {bookmark} for manual recovery"
    kind = "warning" if event.operation in _WARNING_OPERATIONS else "error"
    output.diagnostic(kind, f"{event.project} · {words} · {event.error}")


@_render.register
def _render_scan_reported(
    event: ScanReported, *, batch: bool, project: str, flow: _Flow
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
    event: MissingTestConfig, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.diagnostic(
        "warning", f"{event.project} · no test configuration · test phases skipped"
    )


@_render.register
def _render_processing_started(
    event: ProcessingStarted, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.heading(project, f"{event.vulns} vulnerabilities · {event.updates} updates")


@_render.register
def _render_findings_processed(
    event: FindingsProcessed, *, batch: bool, project: str, flow: _Flow
) -> None:
    if not batch:
        _print_result_totals(event.results, event.blocked)


@_render.register
def _render_promoted(
    event: Promoted, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.outcome(project, "promotion", "passed", _LOCAL_MAIN)


@_render.register
def _render_resolve_paused(
    event: ResolvePaused, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.notice("Resolve paused")
    output.diagnostic("hint", f"mm resolve {event.project} --continue")


@_render.register
def _render_findings_blocked(
    event: FindingsBlocked, *, batch: bool, project: str, flow: _Flow
) -> None:
    if project:
        output.heading(project)
    for package, reason in event.findings:
        output.outcome(project, "resolve", "blocked", package, reason=reason)


@_render.register
def _render_submission_blocked(
    event: SubmissionBlocked, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.diagnostic(
        "warning",
        f"{event.project} · blocked findings remain · rescan or resolve them manually",
    )


@_render.register
def _render_blockers_still_failing(
    event: BlockersStillFailing, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.diagnostic(
        "error", f"{event.phase} · still blocking: {', '.join(event.pkgs)}"
    )


@_render.register
def _render_sync_completed(
    event: SyncCompleted, *, batch: bool, project: str, flow: _Flow
) -> None:
    if event.action == vcs_workflow.SyncAction.UNCHANGED:
        _project_outcome(event.project, "sync", "unchanged", "main")
    else:
        _project_outcome(event.project, "sync", "passed", "main", event.action)


@_render.register
def _render_project_started(
    event: ProjectStarted, *, batch: bool, project: str, flow: _Flow
) -> None:
    """The renderer records the project; its heading prints with the counts."""


@_render.register
def _render_finding_started(
    event: FindingStarted, *, batch: bool, project: str, flow: _Flow
) -> None:
    if output.stderr_terminal():
        output.notice(f"Updating {event.pkg} {event.installed} → {event.target}")


@_render.register
def _render_test_command_started(
    event: TestCommandStarted, *, batch: bool, project: str, flow: _Flow
) -> None:
    if output.is_verbose():
        output.notice(f"$ {event.command}")


@_render.register
def _render_finding_step_failed(
    event: FindingStepFailed, *, batch: bool, project: str, flow: _Flow
) -> None:
    words = event.step.value.replace("_", " ")
    prefix = f"{project} · " if project else ""
    output.diagnostic("error", f"{prefix}{words} · {event.error}")


@_render.register
def _render_finding_passed(
    event: FindingPassed, *, batch: bool, project: str, flow: _Flow
) -> None:
    if project:
        output.heading(project)
    output.outcome(
        project,
        flow,
        "passed",
        event.pkg,
        installed=event.installed,
        target=event.target,
        reason="already applied" if event.already_applied else "",
    )


@_render.register
def _render_finding_failed(
    event: FindingFailed, *, batch: bool, project: str, flow: _Flow
) -> None:
    if project:
        output.heading(project)
    output.outcome(
        project,
        flow,
        "failed",
        event.pkg,
        installed=event.installed,
        target=event.target,
        reason=f"{event.phase} failed",
    )


@_render.register
def _render_deploy_step_started(
    event: DeployStepStarted, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.heading(event.project)


@_render.register
def _render_deploy_step_succeeded(
    event: DeployStepSucceeded, *, batch: bool, project: str, flow: _Flow
) -> None:
    word = _DEPLOY_STEP_WORDS.get(event.step)
    if word is None:
        return
    _project_outcome(event.project, word, "passed", word)


@_render.register
def _render_deploy_step_failed(
    event: DeployStepFailed, *, batch: bool, project: str, flow: _Flow
) -> None:
    word = _DEPLOY_STEP_WORDS.get(event.step)
    if word is None:
        return
    _project_outcome(event.project, word, "failed", word, event.error)
    if event.step is DeployStep.BUILD:
        _project_outcome(event.project, "deploy", "skipped", "deploy", "build failed")


@_render.register
def _render_health_checked(
    event: HealthChecked, *, batch: bool, project: str, flow: _Flow
) -> None:
    if event.is_up:
        _project_outcome(event.project, "health", "passed", "healthcheck")
    else:
        _project_outcome(
            event.project,
            "health",
            "failed",
            "healthcheck",
            event.error or "not healthy",
        )


@_render.register
def _render_healthcheck_unconfigured(
    event: HealthcheckUnconfigured, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.notice("--check: no healthcheck_url configured in [defaults]")


@_render.register
def _render_pull_request_output(
    event: PullRequestOutput, *, batch: bool, project: str, flow: _Flow
) -> None:
    if project:
        output.heading(project)
    output.outcome(project, "resolve", "passed", "pull request", reason=event.text)


@_render.register
def _render_gradle_withheld(
    event: GradleWithheld, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.outcome(project, flow, "blocked", event.label, reason=event.reason)


@_render.register
def _render_no_eligible_gradle_changes(
    event: NoEligibleGradleChanges, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.notice(f"No eligible Gradle changes in {project}")


@_render.register
def _render_gradle_run_archived(
    event: GradleRunArchived, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.diagnostic(
        "warning",
        f"archived failed Gradle run to {event.path} · rebuilding candidates from main",
    )


@_render.register
def _render_gradle_flow_failed(
    event: GradleFlowFailed, *, batch: bool, project: str, flow: _Flow
) -> None:
    output.diagnostic(
        "error", f"cannot complete Gradle {event.flow.value} · {event.error}"
    )


@_render.register
def _render_gradle_run_reported(
    event: GradleRunReported, *, batch: bool, project: str, flow: _Flow
) -> None:
    _print_scan_result(event.scan)
    _print_gradle_run_summary(event.run)


app = cyclopts.App(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    version=__version__,
    version_flags=["--version", "-v"],
    help_formatter=output.HelpFormatter(),
    error_formatter=lambda error: output.literal(f"error: {error}"),
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
    output.set_verbose(False)
    ensure_mm_home()
    output.notice(f"Initialised {paths.mm_home()}")
    output.notice(f"Add projects to {paths.config_path()}")


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
    output.set_verbose(False)
    cfg = _load_cfg(config)

    if not cfg.projects:
        _notice_no_projects(config)
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


def _exit_if_no_update_targets(
    cfg: MmConfig, target_names: list[str], config: Path | None
) -> None:
    if not cfg.projects:
        _notice_no_projects(config)
        sys.exit(ExitCode.OK)

    if not target_names:
        output.notice("No target projects")
        sys.exit(ExitCode.OK)


@app.command
@_command
def update(
    *projects: str,
    negate: Annotated[bool, cyclopts.Parameter(name=("--negate", "-n"))] = False,
    config: Path | None = None,
    verbose: bool = False,
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
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
    """
    output.set_verbose(verbose)
    cfg = _load_cfg(config)
    mode, targets = update_service.resolve_update_targets(cfg, projects, negate=negate)

    _exit_if_no_update_targets(cfg, targets, config)

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
            emit=_Renderer(batch=False, project=name),
        )
        sys.exit(
            ExitCode.OK
            if result.outcome is Outcome.SUCCEEDED
            else ExitCode.UPDATE_FAILED
        )

    batch = update_service.update_projects(
        cfg, targets, vcs=vcs, emit=_Renderer(batch=True)
    )
    results = [result for project in batch.projects for result in project.results]
    blocked = sum(project.blocked for project in batch.projects)
    if results or blocked:
        _print_result_totals(results, blocked)
    elif not any(
        project.route is update_service.UpdateRoute.GRADLE for project in batch.projects
    ):
        output.notice("No projects had actionable findings")
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
    output.set_verbose(False)
    cfg = _load_cfg(config)

    if not cfg.projects:
        _notice_no_projects(config)
        sys.exit(ExitCode.OK)

    vcs_services = make_vcs_services()
    outcome = scan_service.sync_projects(
        cfg,
        projects,
        vcs=vcs_services,
        emit=_Renderer(batch=True),
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
    counts = Counter(_deploy_status(result) for result in results)
    output.summary(
        {status: counts[status] for status in _STATUS_ORDER if counts[status]}
    )


def _deploy_status(result: deploy_service.DeployResult) -> output.Status:
    if "fail" in (result.build_status, result.deploy_status):
        return "failed"
    return _DEPLOY_STATUS_WORDS[result.deploy_status]


@app.command
@_command
def deploy(
    project: str | None = None,
    *,
    build: bool = False,
    check: bool = False,
    force: Annotated[bool, cyclopts.Parameter(name=["--force", "-f"])] = False,
    config: Path | None = None,
    verbose: bool = False,
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
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
    """
    output.set_verbose(verbose)
    cfg = _load_cfg(config)
    vcs = make_vcs_services()
    batch = not project
    renderer = _Renderer(batch=batch, flow="deploy")

    if batch:
        if check and not cfg.defaults.healthcheck_url:
            renderer(HealthcheckUnconfigured())
        if not cfg.projects:
            _notice_no_projects(config)
            sys.exit(ExitCode.OK)
        results = deploy_service.deploy_all(
            cfg,
            check=check,
            force=force,
            vcs=vcs,
            emit=renderer,
        )
        _print_deploy_summary(results)
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
    verbose: bool = False,
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
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
    """
    output.set_verbose(verbose)
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)
    _require_test_config(project, proj_config, config)

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
@_command
def build(
    project: str,
    *,
    config: Path | None = None,
    verbose: bool = False,
) -> None:
    """Build a project's artefacts.

    Parameters
    ----------
    project: str
        Project name to build.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
    """
    output.set_verbose(verbose)
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)
    vcs = make_vcs_services()

    if not proj_config.build_command:
        _fatal(
            f"No build_command configured for {project}",
            hint=(
                f"add build_command to [projects.{project}] in {_config_file(config)}"
            ),
        )

    output.heading(project)
    try:
        deploy_service.build_project(project, proj_config, vcs=vcs)
    except BuildError as exc:
        output.outcome(project, "build", "failed", "build", reason=str(exc))
        sys.exit(ExitCode.BUILD_FAILED)
    output.outcome(project, "build", "passed", "build")
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
    output.set_verbose(False)
    cfg = _load_cfg(config)

    if not cfg.projects:
        _notice_no_projects(config)
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
        widths = []
        for column in fitting:
            longest = max(cell_len(row[column]) for row in rows)
            shown = longest if column == fitting[-1] else min(24, longest)
            widths.append(max(cell_len(headers[column]), shown))
        required = 2 + sum(widths) + 2 * (len(widths) - 1)
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
    output.set_verbose(False)
    cfg = _load_cfg(config)

    if project:
        proj_config = _resolve_proj(cfg, project)
        _print_project_todo(project, proj_config.path)
        return

    if not cfg.projects:
        _notice_no_projects(config)
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


def _notice_no_projects(config: Path | None) -> None:
    output.notice("No projects configured")
    output.diagnostic("hint", f"add projects to {_config_file(config)}")


def _config_file(config: Path | None) -> Path:
    """The file `_load_cfg` reads for this `--config` value."""
    return config or paths.config_path()


def _fatal(
    msg: str, code: int = ExitCode.ERROR, *, hint: str | None = None
) -> NoReturn:
    output.diagnostic("error", msg)
    if hint:
        output.diagnostic("hint", hint)
    sys.exit(code)


def _load_cfg(config: Path | None) -> MmConfig:
    return load_config(config)


def _resolve_proj(cfg: MmConfig, project: str) -> ProjectConfig:
    return resolve_project(cfg, project)


def _require_test_config(
    project: str, proj_config: ProjectConfig, config: Path | None
) -> None:
    if not proj_config.test_phases:
        _fatal(
            f"No test configuration for {project}",
            hint=(f"add test_unit to [projects.{project}] in {_config_file(config)}"),
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
    numbered: list[VulnFinding | UpdateFinding] = [
        *sort_vulns_by_severity(vulns),
        *updates,
    ]
    rows = []
    for finding in numbered:
        if isinstance(finding, VulnFinding):
            kind = "! vuln"
            risk = f"{finding.severity.value.lower()} · {finding.vuln_id}"
        else:
            kind = "~ update"
            risk = finding.semver_tier.value
        rows.append(
            (
                kind,
                risk,
                f"{finding.installed_version} → {finding.target_version}",
                finding.pkg_name,
            )
        )
    output.choices(rows)
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


def _prompt_selection(message: str, count: int) -> _Selection:
    while True:
        text = output.prompt(message, default="all")
        selection = _parse_selection(text, count)
        if selection is not None:
            return selection
        output.diagnostic("error", f"Invalid selection: {text}")


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

    selection = _prompt_selection(f"Select updates [{choices}]", len(numbered))
    return _selected_findings(selection, numbered, selectable_vulns, selectable_updates)


def _choose_gradle_candidates(
    candidates: tuple[GradleCandidate, ...],
) -> tuple[GradleCandidate, ...]:
    output.choices(
        [
            (
                f"{candidate.target.display_name} → {candidate.target.target_version}",
                " · ".join(
                    f"{member.alias}: {member.coordinate} "
                    f"{member.installed_version} → {candidate.target.target_version}"
                    for member in candidate.target.members
                ),
            )
            for candidate in candidates
        ]
    )
    selection = _prompt_selection(
        "Select all, none, vulns, updates, or comma-separated numbers",
        len(candidates),
    )
    if selection == "all":
        return candidates
    if selection == "none":
        return ()
    if selection in {"vulns", "updates"}:
        origin = "security" if selection == "vulns" else "ordinary"
        return tuple(item for item in candidates if origin in item.origins)
    return tuple(item for index, item in enumerate(candidates, 1) if index in selection)


@app.command
@_command
def resolve(
    project: str,
    continue_: Annotated[bool, cyclopts.Parameter(name="--continue")] = False,
    config: Path | None = None,
    verbose: bool = False,
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
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
    """
    output.set_verbose(verbose)
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
        emit=_Renderer(batch=False, project=project, flow="resolve"),
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
    for (_kind, _identity, _version, reason), label in sorted(withheld.items()):
        output.outcome(run.project, run.flow.value, "blocked", label, reason=reason)
    for attempt in run.attempts:
        if isinstance(attempt, FailedAttempt):
            target = attempt.candidate.target
            output.outcome(
                run.project,
                run.flow.value,
                "failed",
                f"{target.display_name} -> {target.target_version}",
                reason=attempt.reason,
            )
    output.summary(
        {
            "verified": counts["ready"] + counts["completed"],
            "withheld": len(withheld),
            "failed": counts["failed"] + counts["applying"],
            "residual advisories": len(run.accepted_snapshot.findings),
        }
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
