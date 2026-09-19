import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, NoReturn

import cyclopts
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from maintenance_man import __version__
from maintenance_man import config as _config
from maintenance_man import updater as gradle_updater
from maintenance_man.config import (
    MM_HOME,
    ConfigError,
    ProjectNotFoundError,
    ensure_mm_home,
    load_config,
    resolve_project,
)
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    check_gradle_update_age,
    evaluate_gradle_candidate_age,
)
from maintenance_man.deployer import (
    BuildError,
    DeployError,
    check_health,
    run_build,
    run_deploy,
)
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GradleError,
    discover_gradle_updates,
    parse_catalogue,
    validate_gradle_recovery,
    validate_gradle_target,
    workspace_environment_reason,
)
from maintenance_man.gradle_resolution import (
    attach_gradle_publications,
    collect_gradle_resolution,
    gradle_routing_prerequisite,
    select_gradle_candidates,
    validate_gradle_candidates,
)
from maintenance_man.gradle_verification import (
    context_inputs_valid,
    initialize_comparison_context,
    release_comparison_context,
)
from maintenance_man.models.activity import (
    ActivityEvent,
    ProjectActivity,
    load_activity,
    record_activity,
)
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.gradle import (
    ApplyingAttempt,
    CandidateWithheld,
    CompletedAttempt,
    FailedAttempt,
    GradleCandidate,
    GradleRun,
    IncompleteResolution,
    PlannedAttempt,
    ReadyAttempt,
    WithheldAttempt,
)
from maintenance_man.models.scan import (
    ScanResult,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    Workflow,
    sort_vulns_by_severity,
)
from maintenance_man.scanner import (
    TrivyNotFoundError,
    TrivyScanError,
    _run_trivy_secret_scan,
    check_trivy_available,
    scan_project,
)
from maintenance_man.updater import (
    Finding,
    GradleFinding,
    NoScanResultsError,
    UpdateResult,
    consolidate_vulns,
    gradle_groups_from_targets,
    has_test_config,
    highest_fix_version,
    load_scan_results,
    prepare_gradle_findings,
    process_findings,
    process_updates,
    process_vulns,
    remove_completed_findings,
    run_test_phases,
    save_scan_results,
    sort_updates_by_risk,
)
from maintenance_man.vcs import (
    GitHubCLINotFoundError,
    JJCLINotFoundError,
    bookmark_exists,
    check_gh_available,
    check_jj_available,
    create_or_reset_bookmark,
    create_workspace,
    current_change_has_changes,
    current_label,
    delete_bookmark,
    edit_new_change,
    ensure_main_bookmark,
    exact_commit_id,
    main_commit_id,
    promote_bookmark_to_main,
    prune_stale_bookmarks,
    push_bookmark_and_create_pr,
    refresh_working_copy_from_main,
    remove_workspace,
    reset_verified_gradle_bookmark,
    resolve_bookmark_contains_current_change,
    revision_file,
    revision_tree_id,
    sync_main,
    workspace_path_for_project,
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
    SYNC_FAILED = 8


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
) -> tuple[GateDecision, str | None]:
    """Decide whether a project needs deploying.

    Returns the decision and the main commit_id it gated on (None when
    unresolvable). The caller records this id rather than re-resolving, so the
    recorded identity matches what was gated even if main moves concurrently.
    """
    resolved = main_commit_id(project_path)
    current_id = resolved.commit_id if resolved.ok else None

    if force:
        return GateDecision.DEPLOY, current_id
    if not resolved.ok:
        return GateDecision.SKIP_BLOCKED, None

    proj = activity.get(name)
    last = proj.last_deploy if proj else None
    if last is not None and last.success and last.commit_id == current_id:
        return GateDecision.SKIP_UNCHANGED, current_id
    return GateDecision.DEPLOY, current_id


console = Console()

_TABLE_STYLE: dict[str, Any] = dict(show_edge=False, pad_edge=False, box=None)

_UPDATE_BOOKMARK = "mm/update-dependencies"
_RESOLVE_BOOKMARK = "mm/resolve-dependencies"

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
        except (TrivyScanError, GradleError) as e:
            _fatal(str(e))

        sys.exit(
            _scan_exit_code(_scan_has_vulns(result, proj_config), result.has_updates)
        )

    # Scan all projects
    has_vulns = False
    has_updates = False
    had_gradle_error = False
    for name, proj_config in cfg.projects.items():
        if not proj_config.path.exists():
            console.print(
                f"[bold yellow]Warning:[/] {name} — "
                f"path does not exist: {proj_config.path}"
            )
            continue
        try:
            result = _scan_one(name, proj_config, cfg.defaults.min_version_age_days)
        except (TrivyScanError, GradleError) as e:
            console.print(f"[bold red]Error:[/] {name} — {e}")
            had_gradle_error |= proj_config.package_manager == "gradle"
            continue

        has_vulns |= _scan_has_vulns(result, proj_config)
        has_updates |= result.has_updates

    if had_gradle_error:
        sys.exit(ExitCode.ERROR)
    sys.exit(_scan_exit_code(has_vulns, has_updates))


def _scan_has_vulns(result: ScanResult, proj_config: ProjectConfig) -> bool:
    return result.has_actionable_vulns or (
        proj_config.package_manager == "gradle"
        and any(v.blocked_reason for v in result.vulnerabilities)
    )


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
        check_jj_available()
    except (GitHubCLINotFoundError, JJCLINotFoundError) as e:
        _fatal(str(e))

    if mode == "single":
        _update_interactive(cfg, targets[0])

    _update_batch_targets(cfg, target_names=targets)


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

    ordered = _dedupe_preserve_order(list(projects))
    _validate_project_names(cfg, ordered)
    targets = ordered if ordered else _sorted_project_names(cfg)

    had_errors = False
    for name in targets:
        proj_config = cfg.projects[name]
        if not proj_config.path.exists():
            console.print(
                f"[bold yellow]Warning:[/] {name} — "
                f"path does not exist: {proj_config.path}"
            )
            had_errors = True
            continue
        ok, msg = sync_main(proj_config.path)
        if ok:
            console.print(f"  {name} — {msg}")
        else:
            console.print(f"  [bold red]{name} — {msg}[/]")
            had_errors = True

    sys.exit(ExitCode.SYNC_FAILED if had_errors else ExitCode.OK)


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

        outcome = _update_batch(
            name, proj_config, results_dir, cfg.defaults.min_version_age_days
        )
        if outcome is None:
            had_errors = True
            continue
        results, promotion_failed = outcome
        if promotion_failed:
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


def _gradle_workspace_revision(
    project: str, proj_config: ProjectConfig, revision: str
) -> str:
    """Verify SDK file availability and pin the revision inspected."""
    reason = workspace_environment_reason(
        proj_config.path, workspace_path_for_project(project)
    )
    if reason is None:
        return revision
    inspection = revision_file(proj_config.path, revision, "local.properties")
    if not inspection.ok:
        raise _UpdateSetupError(
            f"Cannot inspect local.properties in {revision}: "
            f"{inspection.error or 'revision inspection failed'}"
        )
    if not inspection.value:
        raise _UpdateSetupError(reason)
    return inspection.commit_id


def _enter_update_workspace(
    project: str, proj_config: ProjectConfig, scan_result: ScanResult
) -> Path:
    """Create a fresh or resumed update jj workspace. Returns its path."""
    if proj_config.package_manager != "gradle":
        remove_workspace(proj_config.path, project)
    workspace_path = workspace_path_for_project(project)

    if _has_update_progress(scan_result):
        if not bookmark_exists(_UPDATE_BOOKMARK, proj_config.path):
            raise _UpdateSetupError(
                f"update bookmark '{_UPDATE_BOOKMARK}' is missing but in-progress "
                f"state exists — rescan required"
            )
        revision = _UPDATE_BOOKMARK
        if proj_config.package_manager == "gradle":
            revision = _gradle_workspace_revision(project, proj_config, revision)
            remove_workspace(proj_config.path, project)
        if not create_workspace(proj_config.path, project, revision):
            raise _UpdateSetupError("could not attach workspace to update bookmark")
        if not edit_new_change(workspace_path, revision):
            raise _UpdateSetupError("could not create clean change on update bookmark")
        return workspace_path

    if not prune_stale_bookmarks(proj_config.path):
        raise _UpdateSetupError("failed to sync trunk")
    if not ensure_main_bookmark(proj_config.path):
        raise _UpdateSetupError("main bookmark not found")
    revision = "main"
    if proj_config.package_manager == "gradle":
        revision = _gradle_workspace_revision(project, proj_config, revision)
        remove_workspace(proj_config.path, project)
    if bookmark_exists(_UPDATE_BOOKMARK, proj_config.path):
        delete_bookmark(_UPDATE_BOOKMARK, proj_config.path)
    if not create_or_reset_bookmark(_UPDATE_BOOKMARK, proj_config.path, revision):
        raise _UpdateSetupError("could not create update bookmark")
    if not create_workspace(proj_config.path, project, revision):
        raise _UpdateSetupError("could not create workspace")
    new_revision = (
        revision if proj_config.package_manager == "gradle" else _UPDATE_BOOKMARK
    )
    if not edit_new_change(workspace_path, new_revision):
        remove_workspace(proj_config.path, project)
        raise _UpdateSetupError("could not create update change")
    return workspace_path


def _finish_gradle_update_without_application(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
) -> int:
    if scan_result.blocked_findings or _has_update_failures(scan_result):
        return ExitCode.UPDATE_FAILED
    if not _has_update_progress(scan_result):
        return ExitCode.OK
    if not bookmark_exists(_UPDATE_BOOKMARK, proj_config.path):
        console.print(
            f"[bold red]Cannot update {project}:[/] update bookmark is missing"
        )
        return ExitCode.UPDATE_FAILED
    if not _finalise_local_update(proj_config.path, scan_result, project, results_dir):
        return ExitCode.UPDATE_FAILED
    delete_bookmark(_UPDATE_BOOKMARK, proj_config.path)
    return ExitCode.OK


def _prepare_gradle_update_groups(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
    minimum_age_days: int,
) -> list[GradleFinding]:
    groups = prepare_gradle_findings(scan_result, proj_config, minimum_age_days)
    save_scan_results(project, results_dir, scan_result)
    _print_blocked_findings(scan_result)
    return groups


def _process_gradle_update_groups(
    groups: list[GradleFinding],
    work_config: ProjectConfig,
    scan_result: ScanResult,
    project: str,
    results_dir: Path,
    minimum_age_days: int,
) -> list[UpdateResult]:
    console.print(f"\n[bold]Processing {len(groups)} Gradle group(s)...[/]")
    return process_findings(
        groups,
        work_config,
        flow=Workflow.UPDATE,
        scan_result=scan_result,
        project_name=project,
        results_dir=results_dir,
        minimum_age_days=minimum_age_days,
    )


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
        selection = Prompt.ask(f"\n  Select updates [{choices}]", default="all")
        result = _parse_selection(
            selection, numbered, selectable_vulns, selectable_updates
        )
        if result is not None:
            return result
        console.print(f"[bold red]Invalid selection:[/] '{selection}'. Try again.")


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


def _prompt_gradle_selection(groups: list[GradleFinding]) -> list[GradleFinding]:
    """Select whole catalogue groups; every affected alias is shown first."""
    console.print()
    for idx, group in enumerate(groups, 1):
        label = "[bold red]VULN[/]" if group.kind == "vuln" else "[bold cyan]UPDATE[/]"
        console.print(
            f"  [dim]{idx:>3}.[/] {label} {group.pkg_name} "
            f"{group.installed_version} -> {group.target_version} ({group.detail})"
        )
        aliases = ", ".join(m.alias for m in group.target.members)
        console.print(f"       [dim]affects: {aliases}[/]")

    while True:
        selection = Prompt.ask("\n  Select updates [all/1,2,.../none]", default="all")
        if selection == "none":
            return []
        if selection == "all":
            return groups
        try:
            indices = [int(s.strip()) for s in selection.split(",")]
        except ValueError:
            console.print(f"[bold red]Invalid selection:[/] '{selection}'. Try again.")
            continue
        chosen = [
            groups[i - 1] for i in dict.fromkeys(indices) if 1 <= i <= len(groups)
        ]
        if chosen:
            return chosen
        console.print(f"[bold red]Invalid selection:[/] '{selection}'. Try again.")


def _print_update_summary(all_results: list[UpdateResult]) -> None:
    blocked = [r for r in all_results if r.blocked_reason]
    passed = [r for r in all_results if r.passed and not r.blocked_reason]
    failed = [r for r in all_results if not r.passed and not r.blocked_reason]
    console.print("\n" + "─" * 40)
    console.print("[bold]Summary:[/]")
    if passed:
        console.print(f"  [green]{len(passed)} passed[/]")
    if blocked:
        console.print(f"  [yellow]{len(blocked)} blocked[/]")
        for r in blocked:
            console.print(f"  [yellow]BLOCKED[/] {r.pkg_name} — {r.blocked_reason}")
    if failed:
        phase_labels = {
            "apply": "install failed",
            "branch": "bookmark creation failed",
            "commit": "commit failed",
        }
        for r in failed:
            phase = r.failed_phase or "unknown"
            label = phase_labels.get(phase, phase)
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


class _FlowConflictError(Exception):
    """Raised when scan-result flow state is incompatible with the active flow."""


def _assert_supported_in_progress_state(scan_result: ScanResult, project: str) -> None:
    for f in (*scan_result.vulnerabilities, *scan_result.updates):
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
        for f in (*scan_result.vulnerabilities, *scan_result.updates)
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
    results_dir: Path,
) -> bool:
    """Promote `_UPDATE_BOOKMARK` to main and promote READY findings.

    Dirty-tree checks are unnecessary here because update work runs in an
    isolated jj workspace, then only the managed bookmark is promoted.
    """
    if not promote_bookmark_to_main(orig_path, _UPDATE_BOOKMARK):
        console.print(
            f"[bold red]Promotion failed:[/] {_UPDATE_BOOKMARK} could not be "
            f"promoted to main"
        )
        return False

    if not refresh_working_copy_from_main(orig_path):
        console.print(
            f"[bold red]Workspace refresh failed:[/] {project_name} could not be "
            "updated to the promoted main bookmark"
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
    console.print(f"[bold green]Promoted {_UPDATE_BOOKMARK} to main.[/]")
    return True


def _warn_missing_test_config(project: str, proj_config: ProjectConfig) -> None:
    if not has_test_config(proj_config):
        console.print(
            f"  [bold yellow]Warning:[/] {project} — no test configuration "
            f"(test phases will be skipped)"
        )


def _load_validated_scan(
    project: str,
    results_dir: Path,
    proj_config: ProjectConfig,
    workflow: Workflow,
) -> tuple[ScanResult, list[VulnFinding], list[UpdateFinding]]:
    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError:
        console.print(f"[bold green]{project}[/] — no scan results; nothing to do.")
        sys.exit(ExitCode.OK)
    if proj_config.package_manager == "gradle" and workflow == Workflow.RESOLVE:
        gradle_groups_from_targets([*scan_result.vulnerabilities, *scan_result.updates])
    try:
        _assert_supported_in_progress_state(scan_result, project)
        _assert_no_conflicting_flow(scan_result, workflow, project)
    except _FlowConflictError as e:
        if proj_config.package_manager == "gradle" and scan_result.blocked_findings:
            _print_blocked_findings(scan_result)
            save_scan_results(project, results_dir, scan_result)
            sys.exit(ExitCode.UPDATE_FAILED)
        _fatal(str(e))
    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates
    if proj_config.package_manager != "gradle" and not actionable_vulns and not updates:
        console.print(f"[bold green]{project}[/] — nothing to {workflow}.")
        sys.exit(ExitCode.OK)
    _warn_missing_test_config(project, proj_config)
    return scan_result, actionable_vulns, updates


# -- Resolve command ---------------------------------------------------------


def _ordered_resolve_candidates(
    scan_result: ScanResult,
    proj_config: ProjectConfig,
    minimum_age_days: int,
) -> list[Finding]:
    """Return fresh + resolve-owned failed findings, ordered for processing."""
    if proj_config.package_manager == "gradle":
        return [
            group
            for group in prepare_gradle_findings(
                scan_result, proj_config, minimum_age_days
            )
            if (group.flow is None and group.update_status is None)
            or (
                group.flow == Workflow.RESOLVE
                and group.update_status == UpdateStatus.FAILED
            )
            or _is_resolve_claimable_failure(group, Workflow.RESOLVE)
        ]
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
    proj_config: ProjectConfig,
    minimum_age_days: int,
) -> list[Finding]:
    """Return resolve-owned FAILED findings in processing order."""
    if proj_config.package_manager == "gradle":
        return _recorded_gradle_progress(
            scan_result, UpdateStatus.FAILED, Workflow.RESOLVE
        )
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
    proj_config: ProjectConfig,
) -> list[Finding]:
    """Return READY findings owned by *flow*, ordered for submission."""
    if proj_config.package_manager == "gradle":
        return _recorded_gradle_progress(scan_result, UpdateStatus.READY, flow)
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


def _recorded_gradle_progress(
    scan_result: ScanResult, status: UpdateStatus, flow: Workflow
) -> list[Finding]:
    originals = [f for f in (*scan_result.vulnerabilities, *scan_result.updates)]
    groups = gradle_groups_from_targets(originals)
    grouped_ids = {id(original) for group in groups for original in group._originals}
    selected: list[Finding] = [
        group
        for group in groups
        if group.update_status == status and group.flow == flow
    ]
    selected.extend(
        f
        for f in originals
        if id(f) not in grouped_ids and f.update_status == status and f.flow == flow
    )
    return selected


def _has_ready_resolve_progress(scan_result: ScanResult) -> bool:
    return any(
        f.update_status == UpdateStatus.READY and f.flow == Workflow.RESOLVE
        for f in (*scan_result.vulnerabilities, *scan_result.updates)
    )


def _prepare_resolve_bookmark(
    project_path: Path,
    scan_result: ScanResult,
    candidates: list[Finding],
) -> bool:
    """Create or resume the resolve bookmark without dropping committed progress."""
    if _has_ready_resolve_progress(scan_result):
        if not bookmark_exists(_RESOLVE_BOOKMARK, project_path):
            _fatal(
                f"resolve bookmark '{_RESOLVE_BOOKMARK}' is missing but "
                "in-progress state exists — rescan or recover the bookmark manually"
            )
        if candidates:
            return edit_new_change(project_path, _RESOLVE_BOOKMARK)
        return True

    if bookmark_exists(_RESOLVE_BOOKMARK, project_path):
        delete_bookmark(_RESOLVE_BOOKMARK, project_path)
    if not create_or_reset_bookmark(_RESOLVE_BOOKMARK, project_path, "main"):
        return False
    return edit_new_change(project_path, _RESOLVE_BOOKMARK)


def _run_resolve_findings(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
    findings: list[Finding],
    minimum_age_days: int,
) -> int:
    """Process resolve candidates; stop on first failure, submit when all READY."""
    results = process_findings(
        findings,
        proj_config,
        flow=Workflow.RESOLVE,
        scan_result=scan_result,
        project_name=project,
        results_dir=results_dir,
        on_failure="stop",
        minimum_age_days=minimum_age_days,
    )
    if any(not r.passed for r in results) or _ordered_failed_findings(
        scan_result, proj_config, minimum_age_days
    ):
        console.print(
            f"  [bold yellow]Resolve paused.[/] Continue with "
            f"[bold]mm resolve {project} --continue[/]."
        )
        return ExitCode.UPDATE_FAILED

    ready_findings = _ordered_ready_findings(
        scan_result, flow=Workflow.RESOLVE, proj_config=proj_config
    )
    if scan_result.blocked_findings:
        _print_blocked_findings(scan_result)
        save_scan_results(project, results_dir, scan_result)
        return ExitCode.UPDATE_FAILED
    if not ready_findings:
        return ExitCode.OK
    return _submit_resolve_bookmark(
        project, proj_config.path, results_dir, scan_result, ready_findings
    )


def _submit_resolve_bookmark(
    project: str,
    project_path: Path,
    results_dir: Path,
    scan_result: ScanResult,
    ready_findings: list[Finding],
) -> int:
    """Push the resolve bookmark, open a PR, and promote READY findings on success."""
    if scan_result.blocked_findings:
        _print_blocked_findings(scan_result)
        console.print(
            "  [bold yellow]Not submitting:[/] blocked findings remain. "
            "Rescan or resolve them manually."
        )
        save_scan_results(project, results_dir, scan_result)
        return ExitCode.UPDATE_FAILED
    for f in ready_findings:
        f.failed_phase = None

    ok, output = push_bookmark_and_create_pr(project_path, _RESOLVE_BOOKMARK)
    if output:
        console.print(f"  [dim]{output}[/]")
    if not ok:
        save_scan_results(project, results_dir, scan_result)
        console.print(
            f"  [bold yellow]Submit failed.[/] Keeping {_RESOLVE_BOOKMARK} "
            f"for manual recovery."
        )
        return ExitCode.UPDATE_FAILED

    for f in ready_findings:
        f.update_status = UpdateStatus.COMPLETED
        f.failed_phase = None
        f.flow = None
    remove_completed_findings(scan_result)
    save_scan_results(project, results_dir, scan_result)
    return ExitCode.OK


def _gradle_recovery_verified(
    proj_config: ProjectConfig,
    failed: list[Finding],
    scan_result: ScanResult,
    project: str,
    results_dir: Path,
    minimum_age_days: int,
) -> bool:
    """Verify the complete intended manual repair before tests or promotion."""
    if proj_config.package_manager != "gradle":
        return True
    ready = _ordered_ready_findings(
        scan_result, flow=Workflow.RESOLVE, proj_config=proj_config
    )
    if any(not isinstance(finding, GradleFinding) for finding in ready):
        _print_blocked_findings(scan_result)
        save_scan_results(project, results_dir, scan_result)
        return False
    blocked = False
    for blocker in failed:
        if not isinstance(blocker, GradleFinding):
            blocked = True
            continue
        block = validate_gradle_recovery(
            proj_config, blocker.target
        ) or check_gradle_update_age(blocker.target, minimum_age_days)
        if block is not None:
            blocker.set_block(block)
            blocked = True
        else:
            for original in blocker._originals:
                original.blocked_reason = None
                original.gradle_block_kind = None
    if blocked:
        _print_blocked_findings(scan_result)
        save_scan_results(project, results_dir, scan_result)
    return not blocked


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
                f"[yellow]BLOCKED ({r.blocked_reason})[/]"
                if r.blocked_reason
                else "[green]PASS[/]"
                if r.passed
                else f"[red]FAIL ({r.failed_phase})[/]"
            )
            table.add_row(proj_name, r.pkg_name, r.kind, status)

    console.print()
    console.print(table)


def _deploy_one(
    name: str,
    proj_config: ProjectConfig,
    cfg: MmConfig,
    commit_id: str | None,
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
        _run_deploy_step(name, proj_config, commit_id)
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


def _deploy_all(cfg: MmConfig, *, check: bool = False, force: bool = False) -> NoReturn:
    """Deploy all configured projects that have a deploy_command."""
    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        sys.exit(ExitCode.OK)

    activity = load_activity(_config.MM_HOME / "activity.json")
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

        decision, current_id = should_deploy(
            name, proj_config.path, activity, force=force
        )
        if decision is GateDecision.SKIP_UNCHANGED:
            console.print(f"[dim]{name} — unchanged since last deploy[/]")
            results.append(
                DeployResult(
                    project=name, build_status="skip", deploy_status="unchanged"
                )
            )
            continue
        if decision is GateDecision.SKIP_BLOCKED:
            console.print(
                f"[bold yellow]Warning:[/] {name} — could not resolve main "
                f"revision; skipping (use --force to deploy anyway)"
            )
            results.append(
                DeployResult(project=name, build_status="skip", deploy_status="blocked")
            )
            continue

        console.print(f"\n{'═' * 40}")
        console.print(f"[bold]{name}[/]")
        console.print("═" * 40)

        results.append(_deploy_one(name, proj_config, cfg, current_id, check=check))

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

    _STATUS_DISPLAY = {
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
    commit_id: str | None = None,
) -> None:
    """Record build/deploy activity for a project."""
    activity_path = _config.MM_HOME / "activity.json"
    branch = _current_label(project_path)
    record_activity(
        activity_path,
        project,
        event_type,
        success=success,
        branch=branch,
        commit_id=commit_id,
    )


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


def _run_deploy_step(
    project: str, proj_config: ProjectConfig, commit_id: str | None
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
        )
        raise
    _record_deploy_activity(
        project,
        "deploy",
        success=True,
        project_path=proj_config.path,
        commit_id=commit_id,
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

    if not project:
        if check and not cfg.defaults.healthcheck_url:
            _warn_missing_healthcheck_url()
        _deploy_all(cfg, check=check, force=force)
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

    activity = load_activity(_config.MM_HOME / "activity.json")
    decision, current_id = should_deploy(
        project, proj_config.path, activity, force=force
    )
    if decision is GateDecision.SKIP_UNCHANGED:
        console.print(
            f"[bold yellow]{project}[/] unchanged since last deploy "
            f"(use --force to redeploy)."
        )
        sys.exit(ExitCode.OK)
    if decision is GateDecision.SKIP_BLOCKED:
        _fatal(
            f"Could not resolve main revision for [bold]{project}[/]; refusing "
            f"to deploy unverified state (use --force to override).",
            code=ExitCode.ERROR,
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
        _run_deploy_step(project, proj_config, current_id)
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
    branch = _current_label(proj_config.path)
    try:
        run_build(project, proj_config.build_command, proj_config.path)
    except BuildError as e:
        record_activity(activity_path, project, "build", success=False, branch=branch)
        _fatal(str(e), code=ExitCode.BUILD_FAILED)

    record_activity(activity_path, project, "build", success=True, branch=branch)
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


def _current_label(project_path: Path) -> str:
    """Get current jj label, returning 'unknown' on any failure."""
    try:
        return current_label(project_path)
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
        prune_stale_bookmarks(proj_config.path)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        console.print(f"[bold yellow]Warning:[/] {name} — failed to sync remote: {exc}")

    t0 = time.monotonic()
    result = scan_project(name, proj_config, min_age_days)
    elapsed = time.monotonic() - t0
    _print_scan_result(result, elapsed_s=elapsed)
    return result


def _print_blocked_findings(scan_result: ScanResult) -> None:
    """Show current policy blocks with their count. These are not failures."""
    blocked = scan_result.blocked_findings
    if not blocked:
        return
    console.print(
        f"\n[bold yellow]{len(blocked)} blocked[/] — not applied automatically:"
    )
    for f in blocked:
        assert f.blocked_reason is not None
        console.print(f"  [yellow]BLOCKED[/] {f.pkg_name} — {escape(f.blocked_reason)}")


def _print_scan_result(
    result: ScanResult, elapsed_s: float | None = None, *, show_blocked: bool = True
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

    if show_blocked:
        _print_blocked_findings(result)


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


def _choose_gradle_candidates(
    candidates: tuple[GradleCandidate, ...],
) -> tuple[GradleCandidate, ...]:
    for index, candidate in enumerate(candidates, 1):
        console.print(
            f"{index}. {candidate.target.display_name} -> "
            f"{candidate.target.target_version}"
        )
        for member in candidate.target.members:
            console.print(
                f"   {member.alias}: {member.coordinate} "
                f"{member.installed_version} -> {candidate.target.target_version}"
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


def _prepare_gradle_run(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    base: str,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    interactive: bool,
    discovered: list[UpdateFinding] | None = None,
) -> GradleRun:
    catalogue = parse_catalogue(project.path / GRADLE_CATALOGUE_RELPATH)
    resolution = collect_gradle_resolution(project, catalogue)
    if isinstance(resolution, IncompleteResolution):
        raise GradleError(
            "Incomplete baseline resolution: " + "; ".join(resolution.reasons)
        )
    context = initialize_comparison_context(
        project, resolution, _config.MM_HOME / "gradle-contexts"
    )
    try:
        # start_gradle_run persists a checked baseline before any candidate effect.
        run = gradle_updater.start_gradle_run(
            project_name, project, flow, base, context, ()
        )
        vulnerabilities = tuple(
            row for item in run.initial_snapshot.findings for row in item.rows
        )
        plan = select_gradle_candidates(
            catalogue,
            resolution,
            vulnerabilities,
            discovered if discovered is not None else discover_gradle_updates(project),
        )
        for withheld in plan.withheld:
            console.print(f"Withheld {withheld.coordinate}: {withheld.reason}")
        candidates = (
            _choose_gradle_candidates(plan.candidates)
            if interactive
            else plan.candidates
        )
        routing_block = gradle_routing_prerequisite(project)
        attempts = []
        prepared = {}
        if routing_block is not None:
            attempts.extend(
                WithheldAttempt(candidate=candidate, reason=routing_block.reason)
                for candidate in candidates
            )
        else:
            batch = validate_gradle_candidates(project, candidates)
            for candidate in candidates:
                bound = attach_gradle_publications(candidate, resolution, batch)
                if isinstance(bound, CandidateWithheld):
                    attempts.append(
                        WithheldAttempt(candidate=candidate, reason=bound.reason)
                    )
                    continue
                prepared[candidate.target.group_key] = bound
        publication.prefetch(
            request
            for bound in prepared.values()
            for request in bound.publication_requests
        )
        for candidate in candidates:
            bound = prepared.get(candidate.target.group_key)
            if bound is None:
                continue
            block = evaluate_gradle_candidate_age(
                bound, minimum_age_days, publication, datetime.now(timezone.utc)
            )
            attempts.append(
                WithheldAttempt(candidate=bound, reason=block.reason)
                if block
                else PlannedAttempt(candidate=bound)
            )
        run = GradleRun.model_validate(
            run.model_copy(
                update={"attempts": tuple(attempts), "selection_blocks": plan.withheld}
            ).model_dump(mode="json")
        )
        gradle_updater.save_gradle_run(
            gradle_updater.gradle_run_path(project_name), run
        )
        return run
    except BaseException:
        gradle_updater.discard_unpersisted_gradle_context(project_name, context)
        raise


def _complete_gradle_attempts(run: GradleRun) -> GradleRun:
    attempts = tuple(
        CompletedAttempt(
            candidate=item.candidate,
            baseline=item.baseline,
            after=item.after,
            receipt=item.receipt,
            promoted_commit_id=run.managed_tip_id,
        )
        if isinstance(item, ReadyAttempt)
        else item
        for item in run.attempts
    )
    return GradleRun.model_validate(
        run.model_copy(update={"attempts": attempts}).model_dump(mode="json")
    )


def _publish_verified_gradle_scan(
    run: GradleRun,
    project: ProjectConfig,
    results_dir: Path,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> None:
    if revision_tree_id(project.path) != run.accepted_snapshot.tree_id:
        raise GradleError("Refreshed working tree differs from verified tree")
    discovered = discover_gradle_updates(project)
    catalogue = parse_catalogue(project.path / GRADLE_CATALOGUE_RELPATH)
    plan = select_gradle_candidates(
        catalogue, run.accepted_snapshot.resolution, (), discovered
    )
    proven = {item.candidate.target.group_key: item.candidate for item in run.attempts}
    blocks = {
        item.group_key: item.reason
        for item in plan.withheld
        if item.group_key is not None
    }
    routing_block = gradle_routing_prerequisite(project)
    for candidate in plan.candidates:
        if routing_block is not None:
            blocks[candidate.target.group_key] = routing_block.reason
            continue
        previous = proven.get(candidate.target.group_key)
        if (
            previous is None
            or previous.target != candidate.target
            or not previous.publication_requests
        ):
            blocks[candidate.target.group_key] = (
                "Fresh native metadata validation required on next invocation"
            )
            continue
        shape_block = validate_gradle_target(project, previous.target)
        age_block = evaluate_gradle_candidate_age(
            previous, minimum_age_days, publication, datetime.now(timezone.utc)
        )
        block = shape_block or age_block
        if block is not None:
            blocks[candidate.target.group_key] = block.reason
    for update in discovered:
        if (
            update.gradle_target is not None
            and update.gradle_target.group_key in blocks
        ):
            update.blocked_reason = blocks[update.gradle_target.group_key]
    # Scope expansion must not duplicate original CVE/version rows in scan JSON.
    raw = {}
    for finding in run.accepted_snapshot.findings:
        scope = finding.key.scope
        scope_text = f"{scope.project_path}/{scope.domain}/{scope.configuration}"
        for row in finding.rows:
            key = row.model_dump_json(
                exclude={"gradle_scopes", "update_status", "flow", "failed_phase"}
            )
            if key not in raw:
                raw[key] = row.model_copy(
                    update={
                        "update_status": None,
                        "flow": None,
                        "failed_phase": None,
                        "gradle_scopes": (),
                    }
                )
            raw[key] = raw[key].model_copy(
                update={
                    "gradle_scopes": tuple(
                        sorted(set(raw[key].gradle_scopes) | {scope_text})
                    )
                }
            )
    rows = list(raw.values())
    secrets = (
        _run_trivy_secret_scan(project.path, project.scan_skip_dirs)
        if project.scan_secrets
        else []
    )
    fresh = ScanResult(
        project=run.project,
        scanned_at=datetime.now(timezone.utc),
        trivy_target=str(project.path),
        vulnerabilities=rows,
        secrets=secrets,
        updates=discovered,
        gradle_resolution=run.accepted_snapshot.resolution.report.model_dump(
            mode="json"
        ),
    )
    if revision_tree_id(project.path) != run.accepted_snapshot.tree_id:
        raise GradleError("Source changed while publishing verified findings")
    results_dir.mkdir(parents=True, exist_ok=True)
    save_scan_results(run.project, results_dir, fresh)


def _require_gradle_accepted_workspace(run: GradleRun, project: ProjectConfig) -> None:
    if current_change_has_changes(project.path):
        raise GradleError(
            "Automatic Gradle processing requires an empty working change"
        )
    if exact_commit_id(project.path, "@-") != run.managed_tip_id:
        raise GradleError(
            "Working change is not an empty child of the recorded accepted tip"
        )
    if (
        exact_commit_id(project.path, run.managed_bookmark) != run.managed_tip_id
        or revision_tree_id(project.path, run.managed_tip_id)
        != run.accepted_snapshot.tree_id
        or revision_tree_id(project.path) != run.accepted_snapshot.tree_id
    ):
        raise GradleError(
            "Working revision differs from the recorded accepted snapshot"
        )


def _run_update_flow(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
    actionable_vulns: list[VulnFinding],
    updates: list[UpdateFinding],
    *,
    interactive: bool,
    minimum_age_days: int,
) -> int:
    """Set up the workspace, process findings, finalise. Returns exit code."""
    if proj_config.package_manager == "gradle":
        return _run_gradle_flow(
            project,
            proj_config,
            results_dir,
            Workflow.UPDATE,
            interactive=interactive,
            minimum_age_days=minimum_age_days,
        )
    try:
        wt_path = _enter_update_workspace(project, proj_config, scan_result)
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
            selected_vulns, selected_updates = (selectable_vulns, selectable_updates)
        all_results = _process_selected_vulns(
            selected_vulns, work_config, scan_result, project, results_dir
        ) + _process_selected_updates(
            selected_updates, work_config, scan_result, project, results_dir
        )
        _print_update_summary(all_results)
        if (
            any((not r.passed for r in all_results))
            or _has_update_failures(scan_result)
            or scan_result.blocked_findings
        ):
            return ExitCode.UPDATE_FAILED
        finalised = _finalise_local_update(
            proj_config.path, scan_result, project, results_dir
        )
    finally:
        remove_workspace(proj_config.path, project)
    if not finalised:
        return ExitCode.UPDATE_FAILED
    delete_bookmark(_UPDATE_BOOKMARK, proj_config.path)
    return ExitCode.OK


def _update_batch(
    project: str, proj_config: ProjectConfig, results_dir: Path, minimum_age_days: int
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
            results_dir,
            Workflow.UPDATE,
            interactive=False,
            minimum_age_days=minimum_age_days,
        )
        return ([], code != ExitCode.OK)
    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError:
        return ([], False)
    try:
        _assert_supported_in_progress_state(scan_result, project)
        _assert_no_conflicting_flow(scan_result, Workflow.UPDATE, project)
    except _FlowConflictError as e:
        console.print(f"  [bold yellow]Skipped:[/] {project} — {e}")
        return None
    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates
    if not actionable_vulns and (not updates):
        console.print(f"  [dim]{project} — nothing to update[/]")
        return ([], False)
    _warn_missing_test_config(project, proj_config)
    try:
        wt_path = _enter_update_workspace(project, proj_config, scan_result)
    except _UpdateSetupError as e:
        console.print(f"  [bold red]Error:[/] {project} — {e}")
        return None
    work_config = proj_config.model_copy(update={"path": wt_path})
    finalised = False
    promotion_attempted = False
    try:
        _print_scan_result(scan_result)
        all_results = _process_selected_vulns(
            _selectable_vulns(actionable_vulns),
            work_config,
            scan_result,
            project,
            results_dir,
        ) + _process_selected_updates(
            _selectable_updates(updates), work_config, scan_result, project, results_dir
        )
        any_failed_result = any((not r.passed for r in all_results))
        any_failed_finding = _has_update_failures(scan_result)
        if not (
            any_failed_result or any_failed_finding or scan_result.blocked_findings
        ):
            promotion_attempted = True
            finalised = _finalise_local_update(
                proj_config.path, scan_result, project, results_dir
            )
    finally:
        remove_workspace(proj_config.path, project)
    if finalised:
        delete_bookmark(_UPDATE_BOOKMARK, proj_config.path)
    return (
        all_results,
        bool(scan_result.blocked_findings) or (promotion_attempted and (not finalised)),
    )


def _update_interactive(cfg: MmConfig, project: str) -> NoReturn:
    """Update a single project with interactive selection."""
    proj_config = _resolve_proj(cfg, project)
    results_dir = _config.MM_HOME / "scan-results"
    if proj_config.package_manager == "gradle":
        sys.exit(
            _run_gradle_flow(
                project,
                proj_config,
                results_dir,
                Workflow.UPDATE,
                interactive=True,
                minimum_age_days=cfg.defaults.min_version_age_days,
            )
        )
    scan_result, actionable_vulns, updates = _load_validated_scan(
        project, results_dir, proj_config, Workflow.UPDATE
    )
    exit_code = _run_update_flow(
        project,
        proj_config,
        scan_result,
        results_dir,
        actionable_vulns,
        updates,
        interactive=True,
        minimum_age_days=cfg.defaults.min_version_age_days,
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
    results_dir = _config.MM_HOME / "scan-results"
    minimum_age_days = cfg.defaults.min_version_age_days
    try:
        check_gh_available()
        check_jj_available()
    except (GitHubCLINotFoundError, JJCLINotFoundError) as e:
        _fatal(str(e))
    if proj_config.package_manager == "gradle":
        sys.exit(
            _run_gradle_flow(
                project,
                proj_config,
                results_dir,
                Workflow.RESOLVE,
                interactive=False,
                minimum_age_days=minimum_age_days,
                continue_=continue_,
            )
        )
    scan_result, actionable_vulns, updates = _load_validated_scan(
        project, results_dir, proj_config, Workflow.RESOLVE
    )
    if continue_:
        sys.exit(
            _handle_resolve_continue(
                project, proj_config, scan_result, results_dir, minimum_age_days
            )
        )
    candidates = _ordered_resolve_candidates(scan_result, proj_config, minimum_age_days)
    if not prune_stale_bookmarks(proj_config.path):
        _fatal("failed to sync trunk")
    if not ensure_main_bookmark(proj_config.path):
        _fatal("main bookmark not found")
    if _ordered_failed_findings(scan_result, proj_config, minimum_age_days):
        _fatal(f"resolve already paused for [bold]{project}[/] — rerun with --continue")
    if not _prepare_resolve_bookmark(proj_config.path, scan_result, candidates):
        _fatal(f"aborted resolve for [bold]{project}[/]")
    sys.exit(
        _run_resolve_findings(
            project, proj_config, scan_result, results_dir, candidates, minimum_age_days
        )
    )


def _handle_resolve_continue(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
    minimum_age_days: int,
) -> int:
    """Retest the paused blocker on the resolve bookmark."""
    if proj_config.package_manager == "gradle":
        return _run_gradle_flow(
            project,
            proj_config,
            results_dir,
            Workflow.RESOLVE,
            interactive=False,
            minimum_age_days=minimum_age_days,
            continue_=True,
        )
    if not resolve_bookmark_contains_current_change(
        proj_config.path, _RESOLVE_BOOKMARK
    ):
        _fatal(
            f"--continue requires current jj change to descend from {_RESOLVE_BOOKMARK}"
        )
    if current_change_has_changes(proj_config.path):
        _fatal(
            "--continue requires an empty current jj change — commit or discard "
            "manual changes first"
        )
    failed = _ordered_failed_findings(scan_result, proj_config, minimum_age_days)
    if failed:
        passed, failed_phase = run_test_phases(proj_config, proj_config.path)
        for blocker in failed:
            blocker.flow = Workflow.RESOLVE
            if not passed:
                blocker.update_status = UpdateStatus.FAILED
                blocker.failed_phase = failed_phase
        if not passed:
            save_scan_results(project, results_dir, scan_result)
            names = ", ".join((b.pkg_name for b in failed))
            console.print(
                f"  [bold red]FAIL[/] {failed_phase} — still blocking: {names}"
            )
            return ExitCode.UPDATE_FAILED
        if not create_or_reset_bookmark(_RESOLVE_BOOKMARK, proj_config.path, "@-"):
            save_scan_results(project, results_dir, scan_result)
            _fatal(f"could not move {_RESOLVE_BOOKMARK} to the committed manual fix")
        for blocker in failed:
            blocker.update_status = UpdateStatus.READY
            blocker.failed_phase = None
        save_scan_results(project, results_dir, scan_result)
        for blocker in failed:
            console.print(f"  [bold green]PASS[/] {blocker.pkg_name}")
    return _run_resolve_findings(
        project,
        proj_config,
        scan_result,
        results_dir,
        _ordered_resolve_candidates(scan_result, proj_config, minimum_age_days),
        minimum_age_days,
    )


def _finish_verified_gradle_run(
    run: GradleRun,
    project: ProjectConfig,
    results_dir: Path,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> GradleRun:
    routing_block = gradle_routing_prerequisite(project)
    if routing_block is not None:
        raise GradleError(routing_block.reason)
    # Verification reads the accepted revision, not the source workspace's old tree.
    with gradle_updater._gradle_evidence_workspace(
        project, run.managed_tip_id
    ) as verified:
        if not context_inputs_valid(run.context, verified, datetime.now(timezone.utc)):
            run = gradle_updater.rebuild_gradle_run_evidence(
                run, verified, publication, minimum_age_days
            )
        gradle_updater.gradle_run_finalization_check(
            run, verified, publication, minimum_age_days
        )
    path = gradle_updater.gradle_run_path(run.project)
    if run.flow == Workflow.RESOLVE:
        if not run.submitted:
            ok, output = push_bookmark_and_create_pr(
                project.path,
                run.managed_bookmark,
                expected_base=run.base_commit_id,
                expected_tip=run.managed_tip_id,
            )
            if output:
                console.print(output)
            if not ok:
                raise GradleError(
                    "Verified Gradle submission failed; retained for retry"
                )
            run = _complete_gradle_attempts(run.model_copy(update={"submitted": True}))
            gradle_updater.save_gradle_run(path, run)
        return run
    main = exact_commit_id(project.path, "main")
    if run.promoted_commit_id is None:
        if main != run.managed_tip_id:
            if not promote_bookmark_to_main(
                project.path,
                run.managed_bookmark,
                expected_base=run.base_commit_id,
                expected_tip=run.managed_tip_id,
            ):
                raise GradleError("Main or managed tip changed; promotion refused")
        # main already equals verified tip also covers crash after promotion but
        # before this durable record. Finalization above still checks exact tip.
        run = run.model_copy(update={"promoted_commit_id": run.managed_tip_id})
        gradle_updater.save_gradle_run(path, run)
    elif run.promoted_commit_id != run.managed_tip_id or main != run.promoted_commit_id:
        raise GradleError("Main moved after recorded Gradle promotion")
    if not run.refreshed:
        if not refresh_working_copy_from_main(project.path):
            raise GradleError(
                "Promotion recorded; working-copy refresh failed, retry update"
            )
        if exact_commit_id(project.path, "main") != run.managed_tip_id:
            raise GradleError("Main moved during refresh")
        _publish_verified_gradle_scan(
            run, project, results_dir, publication, minimum_age_days
        )
        run = _complete_gradle_attempts(run.model_copy(update={"refreshed": True}))
        gradle_updater.save_gradle_run(path, run)
    return run


def _archive_rolled_back_gradle_run(run: GradleRun, project: ProjectConfig) -> None:
    if (
        run.flow != Workflow.UPDATE
        or run.promoted_commit_id is not None
        or any(isinstance(item, ApplyingAttempt) for item in run.attempts)
        or not any(isinstance(item, FailedAttempt) for item in run.attempts)
    ):
        raise GradleError("Only rolled-back failed update runs can restart")
    workspace = workspace_path_for_project(run.project)
    if not workspace.exists() or current_change_has_changes(project.path):
        raise GradleError(
            "Uncommitted or missing failed workspace requires manual review"
        )
    # Repeat guarded rollback after a crash between saving Failed and restoring.
    gradle_updater.rollback_failed_gradle_update(
        run, project.model_copy(update={"path": workspace})
    )
    if current_change_has_changes(workspace):
        raise GradleError(
            "Uncommitted or missing failed workspace requires manual review"
        )
    if (
        exact_commit_id(project.path, "main") != run.base_commit_id
        or exact_commit_id(workspace, run.managed_bookmark) != run.managed_tip_id
        or exact_commit_id(workspace, "@-") != run.managed_tip_id
        or revision_tree_id(workspace) != run.accepted_snapshot.tree_id
        or revision_tree_id(workspace, run.managed_tip_id)
        != run.accepted_snapshot.tree_id
    ):
        raise GradleError(
            "Failed update rollback cannot be proven; retained for manual review"
        )
    path = gradle_updater.gradle_run_path(run.project)
    archive = path.parent / "history" / f"{path.stem}-{uuid.uuid4().hex}.json"
    gradle_updater.save_gradle_run(archive, run)
    if not reset_verified_gradle_bookmark(
        project.path,
        run.managed_bookmark,
        expected_base=run.base_commit_id,
        expected_tip=run.managed_tip_id,
    ):
        raise GradleError("Revisions changed during restart; original ledger retained")
    path.unlink()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    gradle_updater.retire_gradle_context(run.context)
    console.print(
        f"Archived failed Gradle run to {archive}; rebuilding candidates from main"
    )


def _run_gradle_flow(
    project_name: str,
    project: ProjectConfig,
    results_dir: Path,
    flow: Workflow,
    *,
    interactive: bool,
    minimum_age_days: int,
    continue_: bool = False,
) -> int:
    try:
        path = gradle_updater.gradle_run_path(project_name)
        run = gradle_updater.load_gradle_run(path)
        if run is not None and (run.refreshed or run.submitted):
            gradle_updater.retire_gradle_context(run.context)
            if continue_:
                return ExitCode.OK
            run = None
        if (
            run is not None
            and run.flow == Workflow.UPDATE
            and not continue_
            and any(isinstance(item, FailedAttempt) for item in run.attempts)
        ):
            _archive_rolled_back_gradle_run(run, project)
            run = None
        if run is not None and (run.project != project_name or run.flow != flow):
            raise GradleError("Another Gradle workflow owns the unfinished ledger")
        if run is None:
            if continue_:
                raise GradleError("No preserved Gradle resolve attempt to continue")
            try:
                scan_result = load_scan_results(project_name, results_dir)
            except NoScanResultsError:
                scan_result = ScanResult(
                    project=project_name,
                    scanned_at=datetime.now(timezone.utc),
                    trivy_target=str(project.path),
                )
            legacy = [
                item
                for item in (*scan_result.vulnerabilities, *scan_result.updates)
                if item.update_status in {UpdateStatus.FAILED, UpdateStatus.READY}
            ]
            if legacy:
                raise GradleError(
                    "Legacy Gradle progress has no revision-bound ledger; "
                    "manual review required"
                )
            if flow == Workflow.UPDATE:
                _gradle_workspace_revision(project_name, project, "main")
            if not prune_stale_bookmarks(project.path) or not ensure_main_bookmark(
                project.path
            ):
                raise GradleError("Cannot prepare main")
            base = exact_commit_id(project.path, "main")
            bookmark = (
                _UPDATE_BOOKMARK if flow == Workflow.UPDATE else _RESOLVE_BOOKMARK
            )
            if flow == Workflow.UPDATE:
                _gradle_workspace_revision(project_name, project, base)
                remove_workspace(project.path, project_name)
                if not create_workspace(project.path, project_name, base):
                    raise GradleError("Cannot prepare Gradle workspace")
                work = project.model_copy(
                    update={"path": workspace_path_for_project(project_name)}
                )
            else:
                if current_change_has_changes(project.path):
                    raise GradleError("Commit or discard source edits before resolve")
                work = project
            if not edit_new_change(work.path, base):
                raise GradleError("Cannot prepare empty Gradle change")
            if not create_or_reset_bookmark(bookmark, work.path, base):
                raise GradleError("Cannot create managed Gradle bookmark")
        else:
            if flow == Workflow.UPDATE:
                workspace = workspace_path_for_project(project_name)
                if not workspace.exists():
                    if any(isinstance(item, ApplyingAttempt) for item in run.attempts):
                        raise GradleError(
                            "Interrupted workspace missing; manual review required"
                        )
                    if not create_workspace(
                        project.path, project_name, run.managed_tip_id
                    ):
                        raise GradleError("Cannot resume verified workspace")
                    if not edit_new_change(workspace, run.managed_tip_id):
                        raise GradleError("Cannot create resumed empty change")
                work = project.model_copy(update={"path": workspace})
            else:
                work = project
            expected_main = run.promoted_commit_id or run.base_commit_id
            main = exact_commit_id(project.path, "main")
            if main not in {expected_main, run.managed_tip_id}:
                raise GradleError("Main moved outside the recorded Gradle run")
            if not any(isinstance(item, ApplyingAttempt) for item in run.attempts):
                if (
                    exact_commit_id(work.path, run.managed_bookmark)
                    != run.managed_tip_id
                ):
                    raise GradleError("Managed Gradle bookmark changed")
        with PublicationLookupContext(
            _config.MM_HOME / "gradle-publications"
        ) as publication:
            if run is None:
                proposals = discover_gradle_updates(work)
                if not proposals and not scan_result.vulnerabilities:
                    console.print("No catalogue updates available")
                    if flow == Workflow.UPDATE:
                        remove_workspace(project.path, project_name)
                    return ExitCode.OK
                gradle_updater.gradle_check_commands(work)
                run = _prepare_gradle_run(
                    project_name,
                    work,
                    flow,
                    base,
                    publication,
                    minimum_age_days,
                    interactive,
                    discovered=proposals,
                )
            if any(isinstance(item, ApplyingAttempt) for item in run.attempts):
                run = gradle_updater.reconcile_gradle_applying(
                    run, work, publication, minimum_age_days
                )
            if continue_:
                run = gradle_updater.continue_gradle_resolve(
                    run, work, publication, minimum_age_days
                )
            elif any(isinstance(item, FailedAttempt) for item in run.attempts):
                raise GradleError(
                    "Preserved Gradle failure requires manual review "
                    "or resolve --continue"
                )
            # Committed resolve repair is separately verified above and becomes
            # the new accepted tip before automatic processing can resume.
            _require_gradle_accepted_workspace(run, work)
            if not context_inputs_valid(run.context, work, datetime.now(timezone.utc)):
                run = gradle_updater.rebuild_gradle_run_evidence(
                    run, work, publication, minimum_age_days
                )
            run = gradle_updater.process_gradle_run(
                run, work, publication, minimum_age_days
            )
            for item in run.attempts:
                console.print(f"{item.candidate.target.display_name}: {item.state}")
                if isinstance(item, (WithheldAttempt, FailedAttempt)):
                    console.print(item.reason)
            if any(
                isinstance(item, (ApplyingAttempt, FailedAttempt, PlannedAttempt))
                for item in run.attempts
            ):
                return ExitCode.UPDATE_FAILED
            if not any(
                isinstance(item, (ReadyAttempt, CompletedAttempt))
                for item in run.attempts
            ):
                console.print("No eligible Gradle changes")
                # A clean/withheld-only run has no effects requiring recovery.
                path.unlink(missing_ok=True)
                release_comparison_context(run.context)
                if flow == Workflow.UPDATE:
                    remove_workspace(project.path, project_name)
                return (
                    ExitCode.UPDATE_FAILED
                    if run.attempts
                    or run.selection_blocks
                    or run.initial_snapshot.findings
                    else ExitCode.OK
                )
            run = _finish_verified_gradle_run(
                run, project, results_dir, publication, minimum_age_days
            )
        if flow == Workflow.UPDATE and run.refreshed:
            remove_workspace(project.path, project_name)
        return ExitCode.OK
    except (GradleError, TrivyScanError, _UpdateSetupError, OSError) as exc:
        console.print(f"Cannot complete Gradle {flow}: {exc}")
        return ExitCode.UPDATE_FAILED
