import contextlib
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
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
from maintenance_man import config as config_module
from maintenance_man.config import (
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
from maintenance_man.exit_codes import ExitCode
from maintenance_man.exit_codes import UpdateSetupError as _UpdateSetupError
from maintenance_man.github import CodeHostError
from maintenance_man.gradle import workspace_environment_reason
from maintenance_man.gradle_verification import snapshot_vulnerabilities
from maintenance_man.models.activity import (
    ActivityEvent,
    ProjectActivity,
)
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.events import (
    Event,
    Operation,
    OperationFailed,
    Outcome,
    ProjectSkipped,
    ScanReported,
    SkipReason,
    SyncCompleted,
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
    UpdateStatus,
    VulnFinding,
    Workflow,
    highest_fix_version,
    sort_vulns_by_severity,
)
from maintenance_man.process import ToolNotFoundError
from maintenance_man.services import scan as scan_service
from maintenance_man.services.scan import ScanSummary
from maintenance_man.storage import (
    NoScanResultsError,
    load_activity,
    load_scan_results,
    record_activity,
    save_scan_results,
)
from maintenance_man.updater import (
    Finding,
    UpdateResult,
    consolidate_vulns,
    process_findings,
    process_updates,
    process_vulns,
    remove_completed_findings,
    run_test_phases,
    sort_updates_by_risk,
)
from maintenance_man.vcs import (
    RevisionError,
    workspace_path_for_project,
)
from maintenance_man.vcs_workflow import (
    VcsServices,
    create_workspace,
    ensure_main_bookmark,
    make_vcs_services,
    push_bookmark_and_create_pr,
    refresh_working_copy_from_main,
    remove_workspace,
)
from maintenance_man.vcs_workflow import (
    current_label as repository_current_label,
)
from maintenance_man.vcs_workflow import (
    prune_stale_bookmarks as prune_repository_bookmarks,
)


class GateDecision(StrEnum):
    DEPLOY = "deploy"
    SKIP_UNCHANGED = "unchanged"
    SKIP_BLOCKED = "blocked"


@dataclass
class DeployResult:
    project: str
    build_status: Literal["pass", "fail", "skip"]
    deploy_status: Literal["pass", "fail", "skip", "unchanged", "blocked"]


def should_deploy(
    name: str,
    project_path: Path,
    activity: dict[str, ProjectActivity],
    *,
    force: bool,
    vcs: VcsServices,
) -> tuple[GateDecision, str | None]:
    """Decide whether a project needs deploying.

    Returns the decision and the main commit_id it gated on (None when
    unresolvable). The caller records this id rather than re-resolving, so the
    recorded identity matches what was gated even if main moves concurrently.
    """
    try:
        current_id = vcs.repository(project_path).resolve_revision(revision="main")
    except RevisionError:
        current_id = None

    if force:
        return GateDecision.DEPLOY, current_id
    if current_id is None:
        return GateDecision.SKIP_BLOCKED, None

    proj = activity.get(name)
    last = proj.last_deploy if proj else None
    if last is not None and last.success and last.commit_id == current_id:
        return GateDecision.SKIP_UNCHANGED, current_id
    return GateDecision.DEPLOY, current_id


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


@_renders(SyncCompleted)
def _render_sync_completed(event: SyncCompleted, batch: bool) -> None:
    del batch
    console.print(f"  {escape(event.project)} — {escape(event.action)}")


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


def _resolve_update_targets(
    cfg: MmConfig,
    projects: list[str],
    *,
    negate: bool,
) -> tuple[Literal["single", "batch"], list[str]]:
    try:
        ordered = config_module.validate_project_names(cfg, projects)
    except ProjectNotFoundError as exc:
        _fatal(str(exc))

    if negate:
        excluded = set(ordered)
        targets = [name for name in sorted(cfg.projects) if name not in excluded]
        return "batch", targets

    if not ordered:
        return "batch", sorted(cfg.projects)

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
        vcs_workflow.require_vcs_tools()
    except ToolNotFoundError as e:
        _fatal(str(e))

    vcs = make_vcs_services()
    if mode == "single":
        _update_interactive(cfg, targets[0], vcs=vcs)

    _update_batch_targets(cfg, target_names=targets, vcs=vcs)


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


def _update_batch_targets(
    cfg: MmConfig,
    *,
    target_names: list[str],
    vcs: VcsServices,
) -> NoReturn:
    """Update an explicit ordered set of projects, auto-selecting all findings."""
    _exit_if_no_update_targets(cfg, target_names)

    all_project_results: list[tuple[str, list[UpdateResult]]] = []
    had_errors = False
    gradle_reported = False

    for name in target_names:
        proj_config = cfg.projects[name]
        if not proj_config.path.exists():
            console.print(
                f"[bold yellow]Warning:[/] {escape(name)} — "
                f"path does not exist: {escape(str(proj_config.path))}"
            )
            had_errors = True
            continue

        console.print(f"\n{'═' * 40}")
        console.print(f"[bold]{escape(name)}[/]")
        console.print("═" * 40)

        outcome = _update_batch(
            name,
            proj_config,
            cfg.defaults.min_version_age_days,
            vcs=vcs,
        )
        if outcome is None:
            had_errors = True
            continue
        results, promotion_failed = outcome
        if proj_config.package_manager == "gradle":
            gradle_reported = True
        if promotion_failed:
            had_errors = True
        if results:
            all_project_results.append((name, results))

    if all_project_results or not gradle_reported:
        _print_mass_update_summary(all_project_results)

    any_failed = had_errors or any(
        not r.passed for _, results in all_project_results for r in results
    )
    sys.exit(ExitCode.UPDATE_FAILED if any_failed else ExitCode.OK)


def _gradle_workspace_revision(
    project: str,
    proj_config: ProjectConfig,
    revision: str,
    *,
    vcs: VcsServices,
) -> str:
    """Verify SDK file availability and pin the revision inspected."""
    reason = workspace_environment_reason(
        proj_config.path, workspace_path_for_project(project)
    )
    if reason is None:
        return revision
    try:
        inspection = vcs.repository(proj_config.path).revision_file(
            revision=revision, filename="local.properties"
        )
    except RevisionError as exc:
        raise _UpdateSetupError(
            f"Cannot inspect local.properties in {revision}: {exc}"
        ) from exc
    if not inspection.is_regular:
        raise _UpdateSetupError(reason)
    return inspection.commit_id


def _enter_update_workspace(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    *,
    vcs: VcsServices,
) -> Path:
    """Create a fresh or resumed update jj workspace. Returns its path."""
    bookmark = WORKFLOW_BOOKMARKS[Workflow.UPDATE]
    repo = vcs.repository(proj_config.path)
    remove_workspace(repo=repo, project=project)

    if _has_update_progress(scan_result):
        if not repo.bookmark_exists(bookmark=bookmark):
            raise _UpdateSetupError(
                f"update bookmark '{bookmark}' is missing but in-progress "
                f"state exists — rescan required"
            )
        workspace_path = create_workspace(repo=repo, project=project, revision=bookmark)
        vcs.repository(workspace_path).new_change(revision=bookmark)
        return workspace_path

    prune_repository_bookmarks(repo=repo, host=vcs.code_host(proj_config.path))
    ensure_main_bookmark(repo=repo)
    if repo.bookmark_exists(bookmark=bookmark):
        repo.delete_bookmark(bookmark=bookmark)
    repo.create_bookmark(bookmark=bookmark, revision="main")
    workspace_path = create_workspace(repo=repo, project=project, revision="main")
    try:
        vcs.repository(workspace_path).new_change(revision=bookmark)
    except RevisionError:
        remove_workspace(repo=repo, project=project)
        raise
    return workspace_path


def _selectable_vulns(vulns: list[VulnFinding]) -> list[VulnFinding]:
    return [
        vuln
        for vuln in vulns
        if vuln.update_status is None
        or (vuln.update_status == UpdateStatus.FAILED and vuln.flow == Workflow.UPDATE)
    ]


def _selectable_updates(updates: list[UpdateFinding]) -> list[UpdateFinding]:
    return [
        u
        for u in updates
        if u.update_status is None
        or (u.update_status == UpdateStatus.FAILED and u.flow == Workflow.UPDATE)
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
            f"\n  Select updates {escape(f'[{choices}]')}", default="all"
        )
        result = _parse_selection(
            selection, numbered, selectable_vulns, selectable_updates
        )
        if result is not None:
            return result
        console.print(
            f"[bold red]Invalid selection:[/] '{escape(selection)}'. Try again."
        )


def _process_selected_vulns(
    selected: list[VulnFinding],
    work_config: ProjectConfig,
    scan_result: ScanResult,
    project: str,
    *,
    vcs: VcsServices,
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
        vcs=vcs,
    )


def _process_selected_updates(
    selected: list[UpdateFinding],
    work_config: ProjectConfig,
    scan_result: ScanResult,
    project: str,
    *,
    vcs: VcsServices,
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
        vcs=vcs,
    )


def _process_selected_findings(
    selected_vulns: list[VulnFinding],
    selected_updates: list[UpdateFinding],
    work_config: ProjectConfig,
    scan_result: ScanResult,
    project: str,
    *,
    vcs: VcsServices,
) -> list[UpdateResult]:
    """Process both update categories in one failure-policy sequence."""
    if selected_vulns:
        console.print(f"\n[bold]Processing {len(selected_vulns)} vuln fix(es)...[/]")
    if selected_updates:
        console.print(f"\n[bold]Processing {len(selected_updates)} update(s)...[/]")
    findings: list[Finding] = [
        *consolidate_vulns(selected_vulns),
        *sort_updates_by_risk(selected_updates),
    ]
    if not findings:
        return []
    return process_findings(
        findings,
        work_config,
        cfg=None,
        flow=Workflow.UPDATE,
        scan_result=scan_result,
        project_name=project,
        vcs=vcs,
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
            "branch": "bookmark creation failed",
            "commit": "commit failed",
        }
        for r in failed:
            phase = r.failed_phase or "unknown"
            label = phase_labels.get(phase, phase)
            console.print(f"  [red]FAIL[/] {escape(r.pkg_name)} — {escape(label)}")
    console.print("─" * 40)


def _has_update_progress(scan_result: ScanResult) -> bool:
    return any(
        f.update_status in (UpdateStatus.READY, UpdateStatus.FAILED)
        and f.flow == Workflow.UPDATE
        for f in scan_result.findings
    )


def _has_update_failures(scan_result: ScanResult) -> bool:
    return any(
        f.update_status == UpdateStatus.FAILED and f.flow == Workflow.UPDATE
        for f in scan_result.findings
    )


class _FlowConflictError(Exception):
    """Raised when scan-result flow state is incompatible with the active flow."""


def _assert_supported_in_progress_state(scan_result: ScanResult, project: str) -> None:
    for f in scan_result.findings:
        if f.update_status is not None and f.flow is None:
            raise _FlowConflictError(
                f"{project} has in-progress findings without flow ownership — "
                f"please rescan the project."
            )


_RESOLVE_CLAIMABLE_TEST_PHASES = {"unit", "integration", "component"}


def _is_resolve_claimable_failure(f: Finding, active_flow: Workflow) -> bool:
    return (
        active_flow == Workflow.RESOLVE
        and f.flow == Workflow.UPDATE
        and f.update_status == UpdateStatus.FAILED
        and f.failed_phase in _RESOLVE_CLAIMABLE_TEST_PHASES
    )


def _assert_no_conflicting_flow(
    scan_result: ScanResult,
    active_flow: Workflow,
    project: str,
) -> None:
    conflicts = [
        f
        for f in scan_result.findings
        if f.update_status is not None
        and f.flow is not None
        and f.flow != active_flow
        and not _is_resolve_claimable_failure(f, active_flow)
    ]
    if conflicts:
        assert conflicts[0].flow is not None
        other = conflicts[0].flow.value
        raise _FlowConflictError(
            f"Cannot run {active_flow.value} on {project}: {len(conflicts)} "
            f"finding(s) owned by the '{other}' flow. Complete or abandon "
            f"that flow first."
        )


def _finalise_local_update(
    orig_path: Path,
    scan_result: ScanResult,
    project_name: str,
    *,
    vcs: VcsServices,
) -> bool:
    """Promote the update bookmark to main and promote READY findings.

    Dirty-tree checks are unnecessary here because update work runs in an
    isolated jj workspace, then only the managed bookmark is promoted.
    """
    bookmark = WORKFLOW_BOOKMARKS[Workflow.UPDATE]
    repo = vcs.repository(orig_path)
    try:
        repo.promote_bookmark_to_main(bookmark=bookmark)
    except RevisionError as exc:
        console.print(f"[bold red]Promotion failed:[/] {escape(str(exc))}")
        return False

    try:
        refresh_working_copy_from_main(repo=repo)
    except RevisionError as exc:
        console.print(
            f"[bold red]Workspace refresh failed:[/] {escape(project_name)}: "
            f"{escape(str(exc))}"
        )
        return False

    for v in scan_result.vulnerabilities:
        if v.update_status == UpdateStatus.READY and v.flow == Workflow.UPDATE:
            v.update_status = UpdateStatus.COMPLETED
    for u in scan_result.updates:
        if u.update_status == UpdateStatus.READY and u.flow == Workflow.UPDATE:
            u.update_status = UpdateStatus.COMPLETED

    remove_completed_findings(scan_result)
    save_scan_results(project_name, scan_result)
    console.print(f"[bold green]Promoted {escape(bookmark)} to main.[/]")
    return True


def _warn_missing_test_config(project: str, proj_config: ProjectConfig) -> None:
    if not proj_config.test_phases:
        console.print(
            f"  [bold yellow]Warning:[/] {escape(project)} — no test configuration "
            f"(test phases will be skipped)"
        )


def _load_validated_scan(
    project: str,
    proj_config: ProjectConfig,
    workflow: Workflow,
) -> tuple[ScanResult, list[VulnFinding], list[UpdateFinding]]:
    try:
        scan_result = load_scan_results(project)
    except NoScanResultsError:
        console.print(
            f"[bold green]{escape(project)}[/] — no scan results; nothing to do."
        )
        sys.exit(ExitCode.OK)
    try:
        _assert_supported_in_progress_state(scan_result, project)
        _assert_no_conflicting_flow(scan_result, workflow, project)
    except _FlowConflictError as e:
        _fatal(str(e))
    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates
    if not actionable_vulns and not updates:
        console.print(
            f"[bold green]{escape(project)}[/] — nothing to {escape(workflow)}."
        )
        sys.exit(ExitCode.OK)
    _warn_missing_test_config(project, proj_config)
    return scan_result, actionable_vulns, updates


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
            or _is_resolve_claimable_failure(v, Workflow.RESOLVE)
        )
    ]
    candidate_updates = [
        u
        for u in scan_result.updates
        if (u.flow is None and u.update_status is None)
        or (u.flow == Workflow.RESOLVE and u.update_status == UpdateStatus.FAILED)
        or _is_resolve_claimable_failure(u, Workflow.RESOLVE)
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


def _deploy_one(
    name: str,
    proj_config: ProjectConfig,
    cfg: MmConfig,
    commit_id: str | None,
    *,
    check: bool = False,
    vcs: VcsServices,
) -> DeployResult:
    """Build and deploy a single project. Returns result, never raises."""
    build_status = "skip"
    deploy_status = "skip"

    if proj_config.build_command:
        console.print("  [bold]Building...[/]")
        try:
            _run_build_step(name, proj_config, vcs=vcs)
        except BuildError as e:
            console.print(f"  [bold red]Build failed:[/] {escape(str(e))}")
            build_status = "fail"
            return DeployResult(
                project=name,
                build_status=build_status,
                deploy_status=deploy_status,
            )
        build_status = "pass"

    console.print("  [bold]Deploying...[/]")
    try:
        _run_deploy_step(name, proj_config, commit_id, vcs=vcs)
    except DeployError as e:
        console.print(f"  [bold red]Deploy failed:[/] {escape(str(e))}")
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


def _deploy_all(
    cfg: MmConfig,
    *,
    check: bool = False,
    force: bool = False,
    vcs: VcsServices,
) -> NoReturn:
    """Deploy all configured projects that have a deploy_command."""
    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        sys.exit(ExitCode.OK)

    activity = load_activity(paths.activity_path())
    results: list[DeployResult] = []

    for name, proj_config in sorted(cfg.projects.items()):
        if not proj_config.deployable:
            console.print(f"[dim]{escape(name)} — skipped (not deployable)[/]")
            continue

        if not proj_config.deploy_command:
            continue

        if not proj_config.path.exists():
            console.print(
                f"[bold yellow]Warning:[/] {escape(name)} — "
                f"path does not exist: {escape(str(proj_config.path))}"
            )
            results.append(
                DeployResult(project=name, build_status="skip", deploy_status="fail")
            )
            continue

        decision, current_id = should_deploy(
            name, proj_config.path, activity, force=force, vcs=vcs
        )
        if decision is GateDecision.SKIP_UNCHANGED:
            console.print(f"[dim]{escape(name)} — unchanged since last deploy[/]")
            results.append(
                DeployResult(
                    project=name, build_status="skip", deploy_status="unchanged"
                )
            )
            continue
        if decision is GateDecision.SKIP_BLOCKED:
            console.print(
                f"[bold yellow]Warning:[/] {escape(name)} — could not resolve main "
                f"revision; skipping (use --force to deploy anyway)"
            )
            results.append(
                DeployResult(project=name, build_status="skip", deploy_status="blocked")
            )
            continue

        console.print(f"\n{'═' * 40}")
        console.print(f"[bold]{escape(name)}[/]")
        console.print("═" * 40)

        results.append(
            _deploy_one(name, proj_config, cfg, current_id, check=check, vcs=vcs)
        )

    _print_deploy_summary(results)

    # Only "fail" counts; "unchanged"/"blocked" are deliberate skips, not failures.
    any_failed = any(
        r.deploy_status == "fail" or r.build_status == "fail" for r in results
    )
    sys.exit(ExitCode.DEPLOY_FAILED if any_failed else ExitCode.OK)


def _print_deploy_summary(results: list[DeployResult]) -> None:
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


def _warn_missing_healthcheck_url() -> None:
    """Warn when --check was requested but no healthcheck_url is configured."""
    console.print("[dim]--check: no healthcheck_url configured in \\[defaults][/]")


def _record_deploy_activity(
    project: str,
    event_type: Literal["build", "deploy"],
    *,
    success: bool,
    project_path: Path,
    commit_id: str | None = None,
    vcs: VcsServices,
) -> None:
    """Record build/deploy activity for a project."""
    activity_path = paths.activity_path()
    branch = repository_current_label(repo=vcs.repository(project_path))
    record_activity(
        activity_path,
        project,
        event_type,
        success=success,
        branch=branch,
        commit_id=commit_id,
    )


def _run_build_step(
    project: str, proj_config: ProjectConfig, *, vcs: VcsServices
) -> None:
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
            vcs=vcs,
        )
        raise
    _record_deploy_activity(
        project,
        "build",
        success=True,
        project_path=proj_config.path,
        vcs=vcs,
    )


def _run_deploy_step(
    project: str,
    proj_config: ProjectConfig,
    commit_id: str | None,
    *,
    vcs: VcsServices,
) -> None:
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
            commit_id=None,
            vcs=vcs,
        )
        raise
    _record_deploy_activity(
        project,
        "deploy",
        success=True,
        project_path=proj_config.path,
        commit_id=commit_id,
        vcs=vcs,
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
        console.print(f"{indent}[bold green]Healthy:[/] {escape(project)} is up")
    elif result.error:
        console.print(f"{indent}[bold yellow]Warning:[/] {escape(result.error)}")
    else:
        console.print(
            f"{indent}[bold yellow]Warning:[/] {escape(project)} is not healthy"
        )


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

    if not project:
        if check and not cfg.defaults.healthcheck_url:
            _warn_missing_healthcheck_url()
        _deploy_all(cfg, check=check, force=force, vcs=vcs)
        return  # _deploy_all calls sys.exit(); guard against refactors

    proj_config = _resolve_proj(cfg, project)

    if not proj_config.deployable:
        console.print(f"[dim]{escape(project)} — skipped (not deployable)[/]")
        sys.exit(ExitCode.OK)

    if not proj_config.deploy_command:
        _fatal(
            f"No deploy_command configured for {project}. "
            f"Add deploy_command to [projects.{project}] in ~/.mm/config.toml."
        )

    activity = load_activity(paths.activity_path())
    decision, current_id = should_deploy(
        project, proj_config.path, activity, force=force, vcs=vcs
    )
    if decision is GateDecision.SKIP_UNCHANGED:
        console.print(
            f"[bold yellow]{escape(project)}[/] unchanged since last deploy "
            f"(use --force to redeploy)."
        )
        sys.exit(ExitCode.OK)
    if decision is GateDecision.SKIP_BLOCKED:
        _fatal(
            f"Could not resolve main revision for {project}; refusing "
            f"to deploy unverified state (use --force to override).",
            code=ExitCode.ERROR,
        )

    if build and proj_config.build_command:
        console.print(f"[bold]Building {escape(project)}[/]\n")
        try:
            _run_build_step(project, proj_config, vcs=vcs)
        except BuildError as e:
            _fatal(str(e), code=ExitCode.BUILD_FAILED)
        console.print("\n[bold green]Build succeeded.[/]\n")

    console.print(f"[bold]Deploying {escape(project)}[/]\n")

    try:
        _run_deploy_step(project, proj_config, current_id, vcs=vcs)
    except DeployError as e:
        _fatal(str(e), code=ExitCode.DEPLOY_FAILED)

    console.print("\n[bold green]Deploy succeeded.[/]")

    if check:
        if not cfg.defaults.healthcheck_url:
            _warn_missing_healthcheck_url()
        else:
            console.print(f"\n[bold]Checking health of {escape(project)}...[/]")
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

    console.print(f"[bold]Testing {escape(project)}[/]\n")

    passed, failed_phase = run_test_phases(proj_config, proj_config.path)

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
        _run_build_step(project, proj_config, vcs=vcs)
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
        selection = (
            console.input(
                "Select all, none, vulns, updates, or comma-separated numbers: "
            )
            .strip()
            .lower()
        )
        if selection == "all":
            return candidates
        if selection == "none":
            return ()
        if selection in {"vulns", "updates"}:
            origin = "security" if selection == "vulns" else "ordinary"
            return tuple(item for item in candidates if origin in item.origins)
        try:
            indices = {int(value.strip()) for value in selection.split(",")}
        except ValueError:
            console.print("Invalid selection")
            continue
        if indices and min(indices) >= 1 and max(indices) <= len(candidates):
            return tuple(
                item for index, item in enumerate(candidates, 1) if index in indices
            )
        console.print("Invalid selection")


def _run_update_flow(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    actionable_vulns: list[VulnFinding],
    updates: list[UpdateFinding],
    *,
    interactive: bool,
    vcs: VcsServices,
) -> int:
    """Set up the workspace, process findings, finalise. Returns exit code."""
    try:
        wt_path = _enter_update_workspace(project, proj_config, scan_result, vcs=vcs)
    except (_UpdateSetupError, RevisionError, CodeHostError) as e:
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
            selected_vulns, selected_updates = (selectable_vulns, selectable_updates)
        all_results = _process_selected_findings(
            selected_vulns,
            selected_updates,
            work_config,
            scan_result,
            project,
            vcs=vcs,
        )
        _print_update_summary(all_results)
        if (
            any(not r.passed for r in all_results)
            or _has_update_failures(scan_result)
            or scan_result.blocked_findings
        ):
            return ExitCode.UPDATE_FAILED
        finalised = _finalise_local_update(
            proj_config.path, scan_result, project, vcs=vcs
        )
    finally:
        try:
            remove_workspace(repo=vcs.repository(proj_config.path), project=project)
        except RevisionError as exc:
            console.print(f"[bold red]Workspace cleanup failed:[/] {escape(str(exc))}")
            finalised = False
    if not finalised:
        return ExitCode.UPDATE_FAILED
    try:
        vcs.repository(proj_config.path).delete_bookmark(
            bookmark=WORKFLOW_BOOKMARKS[Workflow.UPDATE]
        )
    except RevisionError as exc:
        console.print(f"[bold red]Bookmark cleanup failed:[/] {escape(str(exc))}")
        return ExitCode.UPDATE_FAILED
    return ExitCode.OK


def _update_batch(
    project: str,
    proj_config: ProjectConfig,
    minimum_age_days: int,
    *,
    vcs: VcsServices,
) -> tuple[list[UpdateResult], bool] | None:
    """Process all actionable findings for a single project (batch mode).

    Returns ``(results, promotion_failed)``. ``promotion_failed`` is ``True``
    when outstanding blocks remain or bookmark promotion was attempted and
    failed. Per-finding failures are reported in ``results``. Returns ``None``
    if the project was skipped due to an error.
    """
    if proj_config.package_manager == "gradle":
        code = _run_gradle_flow(
            project,
            proj_config,
            Workflow.UPDATE,
            interactive=False,
            minimum_age_days=minimum_age_days,
            vcs=vcs,
        )
        return ([], code != ExitCode.OK)
    try:
        scan_result = load_scan_results(project)
    except NoScanResultsError:
        return ([], False)
    try:
        _assert_supported_in_progress_state(scan_result, project)
        _assert_no_conflicting_flow(scan_result, Workflow.UPDATE, project)
    except _FlowConflictError as e:
        console.print(
            f"  [bold yellow]Skipped:[/] {escape(project)} — {escape(str(e))}"
        )
        return None
    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates
    if not actionable_vulns and (not updates):
        console.print(f"  [dim]{escape(project)} — nothing to update[/]")
        return ([], False)
    _warn_missing_test_config(project, proj_config)
    try:
        wt_path = _enter_update_workspace(project, proj_config, scan_result, vcs=vcs)
    except (_UpdateSetupError, RevisionError, CodeHostError) as e:
        console.print(f"  [bold red]Error:[/] {escape(project)} — {escape(str(e))}")
        return None
    work_config = proj_config.model_copy(update={"path": wt_path})
    finalised = False
    promotion_attempted = False
    try:
        _print_scan_result(scan_result)
        all_results = _process_selected_findings(
            _selectable_vulns(actionable_vulns),
            _selectable_updates(updates),
            work_config,
            scan_result,
            project,
            vcs=vcs,
        )
        any_failed_result = any(not r.passed for r in all_results)
        any_failed_finding = _has_update_failures(scan_result)
        if not (
            any_failed_result or any_failed_finding or scan_result.blocked_findings
        ):
            promotion_attempted = True
            finalised = _finalise_local_update(
                proj_config.path, scan_result, project, vcs=vcs
            )
    finally:
        try:
            remove_workspace(repo=vcs.repository(proj_config.path), project=project)
        except RevisionError as exc:
            console.print(
                f"  [bold red]Workspace cleanup failed:[/] {escape(str(exc))}"
            )
            finalised = False
            promotion_attempted = True
    if finalised:
        try:
            vcs.repository(proj_config.path).delete_bookmark(
                bookmark=WORKFLOW_BOOKMARKS[Workflow.UPDATE]
            )
        except RevisionError as exc:
            console.print(
                f"  [bold red]Bookmark cleanup failed:[/] {escape(project)} — "
                f"{escape(str(exc))}"
            )
            finalised = False
    return (
        all_results,
        bool(scan_result.blocked_findings) or (promotion_attempted and (not finalised)),
    )


def _update_interactive(cfg: MmConfig, project: str, *, vcs: VcsServices) -> NoReturn:
    """Update a single project with interactive selection."""
    proj_config = _resolve_proj(cfg, project)
    if proj_config.package_manager == "gradle":
        sys.exit(
            _run_gradle_flow(
                project,
                proj_config,
                Workflow.UPDATE,
                interactive=True,
                minimum_age_days=cfg.defaults.min_version_age_days,
                vcs=vcs,
            )
        )
    scan_result, actionable_vulns, updates = _load_validated_scan(
        project, proj_config, Workflow.UPDATE
    )
    exit_code = _run_update_flow(
        project,
        proj_config,
        scan_result,
        actionable_vulns,
        updates,
        interactive=True,
        vcs=vcs,
    )
    sys.exit(exit_code)


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
    scan_result, _, _ = _load_validated_scan(project, proj_config, Workflow.RESOLVE)
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
        passed, failed_phase = run_test_phases(proj_config, proj_config.path)
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


def _print_gradle_run_result(run: GradleRun, project: ProjectConfig) -> None:
    result = None
    if run.refreshed:
        # A removed results file must not hide durable residual evidence.
        with contextlib.suppress(NoScanResultsError):
            result = load_scan_results(run.project)
    if result is None:
        result = ScanResult(
            project=run.project,
            scanned_at=run.context.created_at,
            trivy_target=str(project.path),
            vulnerabilities=snapshot_vulnerabilities(run.accepted_snapshot),
            gradle_resolution=run.accepted_snapshot.resolution.report.model_dump(
                mode="json"
            ),
        )
    _print_scan_result(result)
    _print_gradle_run_summary(run)


def _run_gradle_flow(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    *,
    interactive: bool,
    minimum_age_days: int,
    continue_: bool = False,
    vcs: VcsServices,
) -> int:
    return gradle_workflow.run_gradle_flow(
        project_name,
        project,
        flow,
        interactive=interactive,
        minimum_age_days=minimum_age_days,
        continue_=continue_,
        vcs=vcs,
        interaction=gradle_workflow.GradleInteraction(
            choose=_choose_gradle_candidates,
            report=_print_gradle_run_result,
            report_scan=_print_scan_result,
            workspace_revision=lambda name, config, revision: (
                _gradle_workspace_revision(name, config, revision, vcs=vcs)
            ),
        ),
    )
