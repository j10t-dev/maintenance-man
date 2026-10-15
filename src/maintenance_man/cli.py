import subprocess
import sys
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, NoReturn

import cyclopts
from rich.text import Text

from maintenance_man import __version__, output
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
from maintenance_man.exit_codes import ExitCode
from maintenance_man.exit_codes import UpdateSetupError as _UpdateSetupError
from maintenance_man.gradle import (
    GradleError,
    validate_gradle_recovery,
    workspace_environment_reason,
)
from maintenance_man.models.activity import (
    ProjectActivity,
    load_activity,
    record_activity,
)
from maintenance_man.models.config import MmConfig, ProjectConfig
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
    check_trivy_available,
    scan_project,
)
from maintenance_man.updater import (
    Finding,
    NoScanResultsError,
    UpdateResult,
    group_findings,
    has_test_config,
    highest_fix_version,
    load_scan_results,
    process_findings,
    process_updates,
    process_vulns,
    remove_completed_findings,
    run_test_phases,
    save_scan_results,
)
from maintenance_man.vcs import (
    BookmarkLookupError,
    GitHubCLINotFoundError,
    JJCLINotFoundError,
    bookmark_exists,
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
    refresh_working_copy_from_main,
    remove_workspace,
    resolve_bookmark_contains_current_change,
    revision_file,
    same_revision,
    sync_main,
    workspace_path_for_project,
)


class GateDecision(StrEnum):
    DEPLOY = "deploy"
    SKIP_UNCHANGED = "unchanged"
    SKIP_BLOCKED = "blocked"


type BuildPhaseStatus = Literal["pass", "fail", "skip"]
type DeployPhaseStatus = BuildPhaseStatus | Literal["unchanged", "blocked"]


@dataclass
class DeployResult:
    project: str
    build_status: BuildPhaseStatus
    deploy_status: DeployPhaseStatus


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


_UPDATE_BOOKMARK = "mm/update-dependencies"
_RESOLVE_BOOKMARK = "mm/resolve-dependencies"

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
def init() -> None:
    """Initialise the ~/.mm directory and skeleton config."""
    output.set_verbose(False)
    ensure_mm_home()
    output.notice(f"Initialised {MM_HOME}")
    output.notice(f"Add projects to {MM_HOME / 'config.toml'}")


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
    output.set_verbose(False)
    cfg = _load_cfg(config)

    try:
        check_trivy_available()
    except TrivyNotFoundError as e:
        _fatal(str(e))

    if not cfg.projects:
        output.notice("No projects configured · add projects to ~/.mm/config.toml")
        return

    if project:
        proj_config = _resolve_proj(cfg, project)
        try:
            result = _scan_one(
                project,
                proj_config,
                cfg.defaults.min_version_age_days,
                report_clean=True,
            )
        except (TrivyScanError, GradleError) as e:
            _fatal(str(e))

        sys.exit(
            _scan_exit_code(_scan_has_vulns(result, proj_config), result.has_updates)
        )

    # Scan all projects
    started = time.monotonic()
    has_vulns = False
    has_updates = False
    had_gradle_error = False
    clean: list[str] = []
    for name, proj_config in cfg.projects.items():
        if not proj_config.path.exists():
            output.diagnostic(
                "warning", f"{name} · path does not exist: {proj_config.path}"
            )
            continue
        try:
            result = _scan_one(name, proj_config, cfg.defaults.min_version_age_days)
        except (TrivyScanError, GradleError) as e:
            output.diagnostic("error", f"{name} · {e}")
            had_gradle_error |= proj_config.package_manager == "gradle"
            continue

        if not result.has_findings:
            clean.append(name)
        has_vulns |= _scan_has_vulns(result, proj_config)
        has_updates |= result.has_updates

    if clean:
        output.notice(
            f"{len(clean)} projects have no findings: {', '.join(clean)}"
            f" · scanned in {time.monotonic() - started:.1f}s"
        )
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
        output.notice("No projects configured · add projects to ~/.mm/config.toml")
        sys.exit(ExitCode.OK)

    if not target_names:
        output.notice("No target projects")
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
    verbose: bool = False,
    config: Path | None = None,
) -> None:
    """Apply updates from scan results to one, many, or all projects.

    Parameters
    ----------
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
    projects: str
        Project names to update. No names batch-updates all configured projects.
        With -n/--negate, names are exclusions. One name keeps the interactive
        single-project flow.
    negate: bool
        Treat all positional project names as exclusions.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    output.set_verbose(verbose)
    cfg = _load_cfg(config)
    mode, targets = _resolve_update_targets(cfg, list(projects), negate=negate)

    _exit_if_no_update_targets(cfg, targets)

    try:
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
    output.set_verbose(False)
    cfg = _load_cfg(config)

    if not cfg.projects:
        output.notice("No projects configured · add projects to ~/.mm/config.toml")
        sys.exit(ExitCode.OK)

    ordered = _dedupe_preserve_order(list(projects))
    _validate_project_names(cfg, ordered)
    targets = ordered if ordered else _sorted_project_names(cfg)

    had_errors = False
    failures: dict[str, list[str]] = {}
    for name in targets:
        proj_config = cfg.projects[name]
        if not proj_config.path.exists():
            output.diagnostic(
                "warning", f"{name} · path does not exist: {proj_config.path}"
            )
            had_errors = True
            continue
        ok, msg = sync_main(proj_config.path)
        output.heading(name)
        output.outcome(
            name,
            "sync",
            "passed" if ok else "failed",
            "main",
            reason=msg if ok or not output.terminal() else "",
        )
        if not ok:
            failures.setdefault(msg, []).append(name)
        had_errors |= not ok

    for reason, names in failures.items():
        output.diagnostic(
            "error",
            f"{len(names)} projects failed to sync: {', '.join(names)} · {reason}",
        )
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
            output.diagnostic(
                "warning", f"{name} · path does not exist: {proj_config.path}"
            )
            had_errors = True
            continue

        output.heading(name)

        outcome = _update_batch(name, proj_config, results_dir)
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
        not r.passed and not r.blocked_reason
        for _, results in all_project_results
        for r in results
    )
    sys.exit(ExitCode.UPDATE_FAILED if any_failed else ExitCode.OK)


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


def _selectable_vulns(vulns: list[VulnFinding]) -> list[VulnFinding]:
    return [
        vuln
        for vuln in vulns
        if (vuln.actionable or vuln.gradle_target is not None)
        and not vuln.blocked_reason
        and (
            vuln.update_status is None
            or (
                vuln.update_status == UpdateStatus.FAILED
                and vuln.flow == Workflow.UPDATE
            )
        )
    ]


def _selectable_updates(updates: list[UpdateFinding]) -> list[UpdateFinding]:
    return [
        u
        for u in updates
        if not u.blocked_reason
        and (
            u.update_status is None
            or (u.update_status == UpdateStatus.FAILED and u.flow == Workflow.UPDATE)
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
        selection = output.prompt(f"Select updates [{choices}]", default="all")
        result = _parse_selection(
            selection, numbered, selectable_vulns, selectable_updates
        )
        if result is not None:
            return result
        output.diagnostic("error", f"Invalid selection: {selection}")


def _process_selected_vulns(
    selected: list[VulnFinding],
    work_config: ProjectConfig,
    scan_result: ScanResult,
    project: str,
    results_dir: Path,
) -> list[UpdateResult]:
    if not selected:
        return []
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
    return process_updates(
        selected,
        work_config,
        flow=Workflow.UPDATE,
        scan_result=scan_result,
        project_name=project,
        results_dir=results_dir,
    )


def _print_update_summary(all_results: list[UpdateResult]) -> None:
    if not all_results:
        return
    counts = Counter(
        "blocked" if result.blocked_reason else "passed" if result.passed else "failed"
        for result in all_results
    )
    output.summary(
        {
            state: counts[state]
            for state in ("passed", "failed", "blocked")
            if counts[state]
        }
    )


def _has_update_progress(scan_result: ScanResult) -> bool:
    return any(
        f.update_status in (UpdateStatus.READY, UpdateStatus.FAILED)
        and f.flow == Workflow.UPDATE
        for f in (*scan_result.vulnerabilities, *scan_result.updates)
    )


def _has_update_failures(scan_result: ScanResult) -> bool:
    return any(
        f.update_status == UpdateStatus.FAILED
        and f.flow == Workflow.UPDATE
        and not f.blocked_reason
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


def _is_resolve_claimable_failure(f: Finding, active_flow: Workflow) -> bool:
    return (
        active_flow == Workflow.RESOLVE
        and f.flow == Workflow.UPDATE
        and f.update_status == UpdateStatus.FAILED
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
        and not (active_flow == Workflow.RESOLVE and f.flow == Workflow.UPDATE)
    ]
    if conflicts:
        assert conflicts[0].flow is not None
        other = conflicts[0].flow.value
        raise _FlowConflictError(
            f"Cannot run {active_flow.value} on {project}: {len(conflicts)} "
            f"finding(s) owned by the '{other}' flow. Complete or abandon "
            f"that flow first."
        )


def _finalise_local_changes(
    orig_path: Path,
    scan_result: ScanResult,
    project_name: str,
    results_dir: Path,
    flow: Workflow,
) -> bool:
    bookmark = _UPDATE_BOOKMARK if flow == Workflow.UPDATE else _RESOLVE_BOOKMARK
    if not promote_bookmark_to_main(orig_path, bookmark):
        output.outcome(
            project_name, "promotion", "failed", "local main", reason="remains pending"
        )
        return False
    if not refresh_working_copy_from_main(orig_path):
        output.outcome(
            project_name,
            "promotion",
            "failed",
            "local main",
            reason="main promoted; workspace refresh failed",
        )
        return False
    for finding in (*scan_result.vulnerabilities, *scan_result.updates):
        if finding.update_status == UpdateStatus.READY and finding.flow == flow:
            finding.update_status = UpdateStatus.COMPLETED
            finding.failed_phase = None
            finding.flow = None
    remove_completed_findings(scan_result)
    save_scan_results(project_name, results_dir, scan_result)
    output.outcome(project_name, "promotion", "passed", "local main")
    return True


def _load_validated_scan(
    project: str,
    results_dir: Path,
    proj_config: ProjectConfig,
    workflow: Workflow,
) -> tuple[ScanResult, list[VulnFinding], list[UpdateFinding]]:
    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError:
        _fatal(f"No scan results for {project}; run mm scan {project} first")
    try:
        _assert_supported_in_progress_state(scan_result, project)
        _assert_no_conflicting_flow(scan_result, workflow, project)
    except _FlowConflictError as e:
        _fatal(str(e))
    actionable_vulns = [
        v
        for v in scan_result.vulnerabilities
        if v.actionable or v.gradle_target is not None
    ]
    updates = scan_result.updates
    if not actionable_vulns and not updates:
        output.notice(f"No findings to {workflow} in {project}")
        sys.exit(ExitCode.OK)
    if group_findings(proj_config, [*actionable_vulns, *updates]):
        _require_test_config(project, proj_config)
    return scan_result, actionable_vulns, updates


# -- Resolve command ---------------------------------------------------------


def _ordered_resolve_candidates(
    scan_result: ScanResult,
    proj_config: ProjectConfig,
) -> list[Finding]:
    """Return fresh + resolve-owned failed findings, ordered for processing."""
    candidate_vulns = [
        v
        for v in scan_result.vulnerabilities
        if (v.actionable or v.gradle_target is not None)
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
    return group_findings(proj_config, [*candidate_vulns, *candidate_updates])


def _ordered_failed_findings(
    scan_result: ScanResult,
    proj_config: ProjectConfig,
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
    return group_findings(proj_config, [*failed_vulns, *failed_updates])


def _ordered_ready_findings(
    scan_result: ScanResult,
    *,
    flow: Workflow,
    proj_config: ProjectConfig,
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
    return group_findings(proj_config, [*ready_vulns, *ready_updates])


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
) -> int:
    """Process resolve candidates; stop on first failure, promote when all READY."""
    output.heading(project)
    _print_blocked_findings(scan_result, Workflow.RESOLVE)
    results = process_findings(
        findings,
        proj_config,
        flow=Workflow.RESOLVE,
        scan_result=scan_result,
        project_name=project,
        results_dir=results_dir,
        on_failure="stop",
    )
    if any(
        not r.passed and not r.blocked_reason for r in results
    ) or _ordered_failed_findings(scan_result, proj_config):
        output.notice(f"Resolve paused in {project}")
        output.diagnostic("hint", f"mm resolve {project} --continue")
        return ExitCode.UPDATE_FAILED

    ready_findings = _ordered_ready_findings(
        scan_result, flow=Workflow.RESOLVE, proj_config=proj_config
    )
    if not ready_findings:
        return ExitCode.OK
    if not _finalise_local_changes(
        proj_config.path, scan_result, project, results_dir, Workflow.RESOLVE
    ):
        return ExitCode.UPDATE_FAILED
    delete_bookmark(_RESOLVE_BOOKMARK, proj_config.path)
    return ExitCode.OK


def _take_over_update_progress(project_path: Path, scan_result: ScanResult) -> None:
    if not _has_update_progress(scan_result):
        return
    if current_change_has_changes(project_path):
        _fatal("Commit or discard manual changes before taking over pending updates")
    if not bookmark_exists(_UPDATE_BOOKMARK, project_path):
        _fatal("Pending update bookmark is missing; rescan or restore it")
    if not create_or_reset_bookmark(_RESOLVE_BOOKMARK, project_path, _UPDATE_BOOKMARK):
        _fatal("Could not transfer pending updates to resolve")
    if not edit_new_change(project_path, _RESOLVE_BOOKMARK):
        _fatal("Could not open pending resolve work")
    for finding in (*scan_result.vulnerabilities, *scan_result.updates):
        if finding.flow == Workflow.UPDATE:
            finding.flow = Workflow.RESOLVE


def _cleanup_update_workspace(project: str, config: ProjectConfig) -> bool:
    try:
        remove_workspace(config.path, project)
        return True
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        output.diagnostic("error", f"Cleanup failed: {project} · {exc}")
        return False


def _print_mass_update_summary(
    project_results: list[tuple[str, list[UpdateResult]]],
) -> None:
    if not project_results:
        output.notice("No projects had actionable findings")
        return
    _print_update_summary(
        [result for _, results in project_results for result in results]
    )


def _deploy_one(
    name: str,
    proj_config: ProjectConfig,
    cfg: MmConfig,
    commit_id: str | None,
    *,
    check: bool = False,
) -> DeployResult:
    """Report one project's build, deploy and health outcomes together."""
    output.heading(name)
    build_status: Literal["pass", "fail", "skip"] = "skip"
    if proj_config.build_command:
        try:
            _run_build_step(name, proj_config)
        except BuildError as exc:
            output.diagnostic("error", str(exc))
            result = DeployResult(name, "fail", "skip")
            _print_deploy_result(result)
            return result
        build_status = "pass"

    try:
        _run_deploy_step(name, proj_config, commit_id)
    except DeployError as exc:
        output.diagnostic("error", str(exc))
        result = DeployResult(name, build_status, "fail")
        _print_deploy_result(result)
        return result
    result = DeployResult(name, build_status, "pass")
    _print_deploy_result(result)
    if check and cfg.defaults.healthcheck_url:
        _run_health_check_step(cfg.defaults.healthcheck_url, name)
    return result


def _deploy_all(cfg: MmConfig, *, check: bool = False, force: bool = False) -> NoReturn:
    """Deploy configured projects, reporting each once before the next starts."""
    if not cfg.projects:
        output.notice("No projects configured · add projects to ~/.mm/config.toml")
        sys.exit(ExitCode.OK)
    activity = load_activity(_config.MM_HOME / "activity.json")
    results: list[DeployResult] = []
    not_deployable: list[str] = []
    for name, proj_config in sorted(cfg.projects.items()):
        if not proj_config.deployable:
            not_deployable.append(name)
            continue
        if not proj_config.deploy_command:
            continue
        if not proj_config.path.exists():
            output.diagnostic(
                "warning", f"{name} · path does not exist: {proj_config.path}"
            )
            result = DeployResult(name, "skip", "fail")
            _print_deploy_result(result)
        else:
            decision, current_id = should_deploy(
                name, proj_config.path, activity, force=force
            )
            if decision is GateDecision.SKIP_UNCHANGED:
                result = DeployResult(name, "skip", "unchanged")
                _print_deploy_result(result)
            elif decision is GateDecision.SKIP_BLOCKED:
                output.diagnostic(
                    "warning", f"{name} · could not resolve main revision; skipping"
                )
                output.diagnostic("hint", f"mm deploy {name} --force")
                result = DeployResult(name, "skip", "blocked")
                _print_deploy_result(result)
            else:
                result = _deploy_one(name, proj_config, cfg, current_id, check=check)
        results.append(result)
    if not_deployable:
        output.notice(
            f"{len(not_deployable)} projects are not deployable: "
            + ", ".join(not_deployable)
        )
    _print_deploy_summary(results)
    any_failed = any(
        r.deploy_status == "fail" or r.build_status == "fail" for r in results
    )
    sys.exit(ExitCode.DEPLOY_FAILED if any_failed else ExitCode.OK)


def _print_deploy_result(result: DeployResult) -> None:
    output.heading(result.project)
    output.outcome(
        result.project, "build", _DEPLOY_STATES[result.build_status], "build"
    )
    output.outcome(
        result.project,
        "deploy",
        _DEPLOY_STATES[result.deploy_status],
        "deploy",
        reason="build failed" if result.build_status == "fail" else "",
    )


def _print_deploy_summary(results: list[DeployResult]) -> None:
    if not results:
        output.notice("No projects have deploy_command configured")
        return
    counts: Counter[output.Status] = Counter(
        "failed"
        if result.build_status == "fail"
        else _DEPLOY_STATES[result.deploy_status]
        for result in results
    )
    output.summary(counts)


_DEPLOY_STATES: dict[DeployPhaseStatus, output.Status] = {
    "pass": "passed",
    "fail": "failed",
    "skip": "skipped",
    "blocked": "blocked",
    "unchanged": "unchanged",
}


def _warn_missing_healthcheck_url() -> None:
    """Warn when --check was requested but no healthcheck_url is configured."""
    output.diagnostic("warning", "--check: no healthcheck_url configured in [defaults]")


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
) -> None:
    """Run a health check and print a consistent status message."""
    result = check_health(healthcheck_url, project)
    if result.is_up:
        output.outcome(project, "health", "passed", "health check")
    else:
        output.outcome(
            project,
            "health",
            "failed",
            "health check",
            reason=result.error or "not healthy",
        )


@app.command
def deploy(
    project: str | None = None,
    *,
    verbose: bool = False,
    build: bool = False,
    check: bool = False,
    force: Annotated[bool, cyclopts.Parameter(name=["--force", "-f"])] = False,
    config: Path | None = None,
) -> None:
    """Deploy a project.

    Parameters
    ----------
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
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
    output.set_verbose(verbose)
    cfg = _load_cfg(config)

    if not project:
        if check and not cfg.defaults.healthcheck_url:
            _warn_missing_healthcheck_url()
        _deploy_all(cfg, check=check, force=force)
        return  # _deploy_all calls sys.exit(); guard against refactors

    proj_config = _resolve_proj(cfg, project)

    if not proj_config.deployable:
        output.heading(project)
        output.outcome(project, "deploy", "skipped", "deploy", reason="not deployable")
        sys.exit(ExitCode.OK)

    if not proj_config.deploy_command:
        _fatal(
            f"No deploy_command configured for {project}. "
            f"Add deploy_command to [projects.{project}] in ~/.mm/config.toml."
        )

    activity = load_activity(_config.MM_HOME / "activity.json")
    decision, current_id = should_deploy(
        project, proj_config.path, activity, force=force
    )
    if decision is GateDecision.SKIP_UNCHANGED:
        output.heading(project)
        output.outcome(
            project,
            "deploy",
            "unchanged",
            "deploy",
            reason="unchanged since last deploy",
        )
        output.diagnostic("hint", f"mm deploy {project} --force")
        sys.exit(ExitCode.OK)
    if decision is GateDecision.SKIP_BLOCKED:
        _fatal(
            f"Could not resolve main revision for {project}; refusing "
            f"to deploy unverified state (use --force to override).",
            code=ExitCode.ERROR,
        )

    output.heading(project)
    if build and proj_config.build_command:
        try:
            _run_build_step(project, proj_config)
        except BuildError as e:
            output.outcome(project, "build", "failed", "build")
            output.outcome(
                project, "deploy", "skipped", "deploy", reason="build failed"
            )
            _fatal(str(e), code=ExitCode.BUILD_FAILED)
        output.outcome(project, "build", "passed", "build")

    try:
        _run_deploy_step(project, proj_config, current_id)
    except DeployError as e:
        output.outcome(project, "deploy", "failed", "deploy")
        _fatal(str(e), code=ExitCode.DEPLOY_FAILED)

    output.outcome(project, "deploy", "passed", "deploy")

    if check:
        if not cfg.defaults.healthcheck_url:
            _warn_missing_healthcheck_url()
        else:
            _run_health_check_step(cfg.defaults.healthcheck_url, project)

    sys.exit(ExitCode.OK)


@app.command
def test(
    project: str,
    *,
    verbose: bool = False,
    config: Path | None = None,
) -> None:
    """Run a project's test suite.

    Runs configured test phases (unit → integration → component) in order,
    stopping on first failure.

    Parameters
    ----------
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
    project: str
        Project name to test.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    output.set_verbose(verbose)
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)
    _require_test_config(project, proj_config)

    output.heading(project)

    passed, failed_phase = run_test_phases(proj_config, proj_config.path)

    if passed:
        output.outcome(project, "test", "passed", "tests")
        sys.exit(ExitCode.OK)
    else:
        output.outcome(
            project, "test", "failed", "tests", reason=f"{failed_phase} failed"
        )
        sys.exit(ExitCode.TEST_FAILED)


@app.command
def build(
    project: str,
    *,
    verbose: bool = False,
    config: Path | None = None,
) -> None:
    """Build a project's artefacts.

    Parameters
    ----------
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
    project: str
        Project name to build.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    output.set_verbose(verbose)
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)

    if not proj_config.build_command:
        _fatal(
            f"No build_command configured for {project}. "
            f"Add build_command to [projects.{project}] in ~/.mm/config.toml."
        )

    output.heading(project)

    activity_path = _config.MM_HOME / "activity.json"
    branch = _current_label(proj_config.path)
    try:
        run_build(project, proj_config.build_command, proj_config.path)
    except BuildError as e:
        record_activity(activity_path, project, "build", success=False, branch=branch)
        output.outcome(project, "build", "failed", "build")
        _fatal(str(e), code=ExitCode.BUILD_FAILED)

    record_activity(activity_path, project, "build", success=True, branch=branch)
    output.outcome(project, "build", "passed", "build")
    sys.exit(ExitCode.OK)


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
    output.set_verbose(False)
    cfg = _load_cfg(config)
    if not cfg.projects:
        output.notice("No projects configured")
        output.diagnostic("hint", "mm init")
        return

    scan_results: dict[str, ScanResult] = {}
    for name in cfg.projects:
        try:
            scan_results[name] = load_scan_results(
                name, _config.MM_HOME / "scan-results"
            )
        except NoScanResultsError:
            pass
        except Exception:
            output.diagnostic("warning", f"corrupt scan results for {name}; skipped")

    if detail:
        clean = []
        unscanned = []
        for name in sorted(cfg.projects):
            result = scan_results.get(name)
            if result is None:
                unscanned.append(name)
            elif not result.has_findings:
                clean.append(name)
            else:
                _print_scan_result(result)
        if clean:
            output.notice(f"{len(clean)} projects have no findings: {', '.join(clean)}")
        if unscanned:
            output.notice(
                f"{len(unscanned)} projects have no saved scan: {', '.join(unscanned)}"
            )
        return

    activity = load_activity(_config.MM_HOME / "activity.json")
    headers = [
        "project",
        "type",
        "vulns",
        "updates",
        "secrets",
        "scanned",
        "built",
        "deployed",
    ]
    rows: list[list[str]] = []
    pipe_rows: list[list[str]] = []
    for name, project in sorted(cfg.projects.items()):
        result = scan_results.get(name)
        counts = (
            [
                str(sum(v.actionable for v in result.vulnerabilities)),
                str(len(result.updates)),
                str(len(result.secrets)),
            ]
            if result
            else ["-"] * 3
        )
        events = activity.get(name)
        built = events.last_build if events else None
        deployed = events.last_deploy if events else None
        build_status = (
            "passed" if built and built.success else "failed" if built else "-"
        )
        deploy_status = (
            "not deployable"
            if not project.deployable
            else "passed"
            if deployed and deployed.success
            else "failed"
            if deployed
            else "-"
        )
        scanned = output.timestamp(result.scanned_at) if result else "never"
        built_text = output.timestamp(built.timestamp) if built else "-"
        deployed_text = output.timestamp(deployed.timestamp) if deployed else "-"
        rows.append(
            [
                name,
                project.package_manager,
                *counts,
                scanned,
                f"failed {built_text}" if build_status == "failed" else built_text,
                "not deployable"
                if not project.deployable
                else f"failed {deployed_text}"
                if deploy_status == "failed"
                else deployed_text,
            ]
        )
        pipe_rows.append(
            [
                name,
                project.package_manager,
                *counts,
                result.scanned_at.isoformat() if result else "never",
                built.timestamp.isoformat() if built else "-",
                build_status,
                deployed.timestamp.isoformat() if deployed else "-",
                deploy_status,
            ]
        )

    hidden = []
    visible = [0]
    for index, title in enumerate(headers[1:], 1):
        values = {row[index] for row in rows}
        comparable = len(rows) > 1 and len(values) == 1
        if not comparable:
            visible.append(index)
        elif values == {"-"}:
            hidden.append(f"{title} -")
        elif values == {"0"}:
            hidden.append(f"0 {title}")
        else:
            hidden.append(f"{title} {next(iter(values))}")
    width_hidden = []
    if output.terminal():
        width = output.console().width
        for index in (5, 6, 7, 1, 4, 3, 2):
            required = sum(
                max(
                    len(headers[column]), min(24, max(len(row[column]) for row in rows))
                )
                + 2
                for column in visible
            )
            if required <= width:
                break
            if index in visible:
                visible.remove(index)
                width_hidden.append(headers[index])
    output.heading("projects", f"{len(rows)} configured")
    output.project_records(
        [headers[index] for index in visible],
        [
            [
                output.literal(row[index], "bold" if index == 0 else "")
                for index in visible
            ]
            for row in rows
        ],
        pipe_rows,
        footer=(
            " · ".join([*hidden, "hidden: " + ", ".join(width_hidden)])
            if width_hidden
            else " · ".join(hidden)
        ),
    )


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
    output.set_verbose(False)
    cfg = _load_cfg(config)

    if project:
        proj_config = _resolve_proj(cfg, project)
        _print_project_todo(project, proj_config.path)
        return

    if not cfg.projects:
        output.notice("No projects configured · add projects to ~/.mm/config.toml")
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
    path = project_path / "TODO.md"
    content = path.read_text() if path.exists() else ""
    if not content.strip():
        output.notice(f"No TODO items in {name}")
        return
    output.heading(name, "TODO.md")
    lines = content.splitlines()
    output.records(
        name,
        (),
        [[line] for line in lines],
        pipe_rows=[[str(index), line] for index, line in enumerate(lines, 1)],
    )


def _current_label(project_path: Path) -> str:
    """Get current jj label, returning 'unknown' on any failure."""
    try:
        return current_label(project_path)
    except Exception:
        return "unknown"


def _fatal(
    msg: str, code: int = ExitCode.ERROR, *, hint: str | None = None
) -> NoReturn:
    output.diagnostic("error", msg)
    if hint:
        output.diagnostic("hint", hint)
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
        _fatal(str(e), hint="mm list")


def _require_test_config(project: str, proj_config: ProjectConfig) -> None:
    if not has_test_config(proj_config):
        _fatal(
            f"No test configuration for {project}. "
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


def _scan_one(
    name: str,
    proj_config: ProjectConfig,
    min_age_days: int,
    *,
    report_clean: bool = False,
) -> ScanResult:
    """Scan a single project with timing output."""
    try:
        prune_stale_bookmarks(proj_config.path)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        output.diagnostic("warning", f"{name} · failed to sync remote: {exc}")

    t0 = time.monotonic()
    result = scan_project(name, proj_config, min_age_days)
    elapsed = time.monotonic() - t0
    if result.has_findings:
        _print_scan_result(result, elapsed_s=elapsed)
    elif report_clean:
        output.notice(f"No findings in {name} · scanned in {elapsed:.1f}s")
    return result


def _print_numbered_findings(
    vulns: list[VulnFinding], updates: list[UpdateFinding]
) -> list[VulnFinding | UpdateFinding]:
    numbered: list[VulnFinding | UpdateFinding] = [
        *sort_vulns_by_severity(vulns),
        *updates,
    ]
    screen = output.console(stderr=True)
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
    risk_width = max((len(row[1]) for row in rows), default=0)
    version_width = max((len(row[2]) for row in rows), default=0)
    for index, (kind, risk, versions, package) in enumerate(rows, 1):
        text = output.literal(
            f"  {index:>3}  {kind:<8}  {risk:<{risk_width}}  "
            f"{versions:<{version_width}}  {package}"
        )
        screen.print(
            text, no_wrap=True, overflow="ellipsis", soft_wrap=not screen.is_terminal
        )
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


def _execute_update(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
    *,
    interactive: bool,
) -> tuple[list[UpdateResult], bool]:
    output.heading(project)
    vulns = _selectable_vulns(scan_result.vulnerabilities)
    updates = _selectable_updates(scan_result.updates)
    if interactive and (vulns or updates):
        vulns, updates = _prompt_selection(vulns, updates)
    # Include all saved rows associated with selected Gradle targets so a
    # security/ordinary duplicate shares the result even when selected once.
    selected = [*vulns, *updates]
    targets = [f.gradle_target for f in selected if f.gradle_target is not None]
    selected = [
        f
        for f in (*scan_result.vulnerabilities, *scan_result.updates)
        if f in selected or (f.gradle_target is not None and f.gradle_target in targets)
    ]
    groups = group_findings(proj_config, selected)
    ready = _ordered_ready_findings(
        scan_result, flow=Workflow.UPDATE, proj_config=proj_config
    )
    _print_blocked_findings(scan_result)
    if not groups and not ready:
        output.notice(f"{project} · nothing eligible to update")
        return [], _has_update_failures(scan_result)
    if not has_test_config(proj_config):
        output.outcome(
            project, "update", "failed", "configuration", reason="no test configuration"
        )
        output.diagnostic("error", f"{project} · no test configuration")
        return [UpdateResult(project, "update", False, "configuration")], True
    results: list[UpdateResult] = []
    failed = False
    try:
        path = _enter_update_workspace(project, proj_config, scan_result)
        work_config = proj_config.model_copy(update={"path": path})
        selected_vulns = [
            f for f in selected if isinstance(f, VulnFinding) and not f.blocked_reason
        ]
        security_targets = [
            f.gradle_target for f in selected_vulns if f.gradle_target is not None
        ]
        selected_updates = [
            f
            for f in selected
            if isinstance(f, UpdateFinding)
            and not f.blocked_reason
            and (f.gradle_target is None or f.gradle_target not in security_targets)
        ]
        results = _process_selected_vulns(
            selected_vulns, work_config, scan_result, project, results_dir
        )
        if not any(r.failed_phase in {"rollback", "bookmark"} for r in results):
            results += _process_selected_updates(
                selected_updates, work_config, scan_result, project, results_dir
            )
        failed = any(
            not r.passed and not r.blocked_reason for r in results
        ) or _has_update_failures(scan_result)
        if failed:
            output.notice(f"{project}: pending because updates failed")
        elif _ordered_ready_findings(
            scan_result, flow=Workflow.UPDATE, proj_config=proj_config
        ):
            failed = not _finalise_local_changes(
                proj_config.path, scan_result, project, results_dir, Workflow.UPDATE
            )

    except (
        _UpdateSetupError,
        BookmarkLookupError,
        GradleError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        output.diagnostic("error", f"{project} · {exc}")
        output.outcome(project, "update", "failed", "setup", reason=str(exc))
        results.append(UpdateResult(project, "update", False, "setup"))
        failed = True
    finally:
        if not _cleanup_update_workspace(project, proj_config):
            failed = True
    if not failed and results and not _has_update_progress(scan_result):
        delete_bookmark(_UPDATE_BOOKMARK, proj_config.path)
    return results, failed


def _run_update_flow(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
    *,
    interactive: bool,
) -> int:
    results, failed = _execute_update(
        project, proj_config, scan_result, results_dir, interactive=interactive
    )
    _print_update_summary(results)
    return ExitCode.UPDATE_FAILED if failed else ExitCode.OK


def _update_batch(
    project: str, proj_config: ProjectConfig, results_dir: Path
) -> tuple[list[UpdateResult], bool] | None:
    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError:
        output.notice(f"{project}: no saved scan; run mm scan {project} first")
        return [], False
    try:
        _assert_supported_in_progress_state(scan_result, project)
        _assert_no_conflicting_flow(scan_result, Workflow.UPDATE, project)
    except _FlowConflictError as exc:
        output.notice(f"Skipped: {project} · {exc}")
        return None
    return _execute_update(
        project, proj_config, scan_result, results_dir, interactive=False
    )


def _update_interactive(cfg: MmConfig, project: str) -> NoReturn:
    """Update a single project with interactive selection."""
    proj_config = _resolve_proj(cfg, project)
    results_dir = _config.MM_HOME / "scan-results"
    scan_result, actionable_vulns, updates = _load_validated_scan(
        project, results_dir, proj_config, Workflow.UPDATE
    )
    exit_code = _run_update_flow(
        project, proj_config, scan_result, results_dir, interactive=True
    )
    sys.exit(exit_code)


@app.command
def resolve(
    project: str,
    continue_: Annotated[bool, cyclopts.Parameter(name="--continue")] = False,
    verbose: bool = False,
    config: Path | None = None,
) -> None:
    """Work through failed findings for a project.

    Applies each failed finding on ``mm/resolve-dependencies``, runs tests, and
    stops on the first failure so the operator can debug manually. Rerun with
    ``--continue`` after committing a manual fix to re-test and advance. Promotes
    to local main once all candidates reach READY.

    Parameters
    ----------
    verbose: bool
        Stream subprocess logs to stderr, including successful commands.
    project: str
        Project name (required).
    continue_: bool
        Re-test a paused, manually fixed finding on the resolve branch.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    output.set_verbose(verbose)
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)
    results_dir = _config.MM_HOME / "scan-results"
    try:
        check_jj_available()
    except (GitHubCLINotFoundError, JJCLINotFoundError) as e:
        _fatal(str(e))
    scan_result, actionable_vulns, updates = _load_validated_scan(
        project, results_dir, proj_config, Workflow.RESOLVE
    )
    output.heading(project)
    if continue_:
        sys.exit(
            _handle_resolve_continue(project, proj_config, scan_result, results_dir)
        )
    if _ordered_failed_findings(scan_result, proj_config):
        _fatal(f"resolve already paused for {project} — rerun with --continue")
    candidates = _ordered_resolve_candidates(scan_result, proj_config)
    if (
        not candidates
        and not _has_update_progress(scan_result)
        and not _has_ready_resolve_progress(scan_result)
    ):
        _print_blocked_findings(scan_result, Workflow.RESOLVE)
        sys.exit(ExitCode.OK)
    try:
        if current_change_has_changes(proj_config.path):
            _fatal("Commit or discard manual changes before starting resolve")
        if not ensure_main_bookmark(proj_config.path):
            _fatal("main bookmark not found")
        takeover = _has_update_progress(scan_result)
        if takeover:
            _take_over_update_progress(proj_config.path, scan_result)
            save_scan_results(project, results_dir, scan_result)
            delete_bookmark(_UPDATE_BOOKMARK, proj_config.path)
        elif not _prepare_resolve_bookmark(proj_config.path, scan_result, candidates):
            _fatal(f"aborted resolve for {project}")
        candidates = _ordered_resolve_candidates(scan_result, proj_config)
    except BookmarkLookupError as exc:
        _fatal(str(exc))
    sys.exit(
        _run_resolve_findings(
            project, proj_config, scan_result, results_dir, candidates
        )
    )


def _handle_resolve_continue(
    project: str,
    proj_config: ProjectConfig,
    scan_result: ScanResult,
    results_dir: Path,
) -> int:
    """Retest the paused blocker on the resolve bookmark."""
    failed = _ordered_failed_findings(scan_result, proj_config)[:1]
    if not failed:
        _fatal("No paused failure in the current saved scan to continue")
    _require_test_config(project, proj_config)
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
    repair_base = scan_result.resolve_repair_base
    if repair_base is None:
        repair_base = exact_commit_id(proj_config.path, _RESOLVE_BOOKMARK)
    repair = same_revision(proj_config.path, "@-", repair_base)
    if not repair.ok or repair.value:
        _fatal("--continue requires a committed manual repair after the pending tip")
    failed = _ordered_failed_findings(scan_result, proj_config)[:1]
    if failed:
        for blocker in failed:
            if blocker.gradle_target is not None:
                block = validate_gradle_recovery(proj_config, blocker.gradle_target)
                if block is not None:
                    output.diagnostic(
                        "error",
                        f"Repair does not apply the saved target: {block.reason}",
                    )
                    return ExitCode.UPDATE_FAILED
        passed, failed_phase = run_test_phases(proj_config, proj_config.path)
        for blocker in failed:
            blocker.flow = Workflow.RESOLVE
            if not passed:
                blocker.update_status = UpdateStatus.FAILED
                blocker.failed_phase = failed_phase
        if not passed:
            save_scan_results(project, results_dir, scan_result)
            names = ", ".join((b.pkg_name for b in failed))
            output.diagnostic("error", f"{failed_phase} · still blocking: {names}")
            return ExitCode.UPDATE_FAILED
        # Keep the original base before moving the bookmark. If the later
        # READY save is interrupted, --continue can verify this same repair.
        scan_result.resolve_repair_base = repair_base
        save_scan_results(project, results_dir, scan_result)
        if not create_or_reset_bookmark(_RESOLVE_BOOKMARK, proj_config.path, "@-"):
            save_scan_results(project, results_dir, scan_result)
            _fatal(f"could not move {_RESOLVE_BOOKMARK} to the committed manual fix")
        for blocker in failed:
            blocker.update_status = UpdateStatus.READY
            blocker.failed_phase = None
        scan_result.resolve_repair_base = None
        save_scan_results(project, results_dir, scan_result)
        for blocker in failed:
            output.outcome(
                project,
                "resolve",
                "passed",
                blocker.pkg_name,
                installed=blocker.installed_version,
                target=blocker.target_version,
                reason="manual repair",
            )
    return _run_resolve_findings(
        project,
        proj_config,
        scan_result,
        results_dir,
        _ordered_resolve_candidates(scan_result, proj_config),
    )


def _print_scan_result(result: ScanResult, elapsed_s: float | None = None) -> None:
    rows: list[list[str | Text]] = []
    pipe_rows: list[list[str]] = []
    wins = {}
    for vuln in result.vulnerabilities:
        group = [
            v
            for v in result.vulnerabilities
            if v.pkg_name == vuln.pkg_name and v.actionable
        ]
        if len(group) > 1:
            wins[vuln.pkg_name] = highest_fix_version(group)
    for vuln in sort_vulns_by_severity(result.vulnerabilities):
        kind = "vuln" if vuln.actionable else "advisory"
        reason = vuln.blocked_reason or ""
        if vuln.fixed_version and wins.get(vuln.pkg_name) == vuln.fixed_version:
            reason = " · ".join(filter(None, ["selected fix", reason]))
        label = "! blocked" if vuln.blocked_reason else f"! {kind}"
        versions = (
            f"{vuln.installed_version} → {vuln.fixed_version}"
            if vuln.fixed_version
            else "no fix"
        )
        detail = " · ".join(filter(None, [vuln.pkg_name, vuln.vuln_id, reason]))
        rows.append(
            [
                output.literal(
                    label,
                    "yellow" if kind == "advisory" or vuln.blocked_reason else "red",
                ),
                vuln.severity.value.lower(),
                versions,
                detail,
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
    for secret in result.secrets:
        rows.append(
            [
                output.literal("! secret", "yellow"),
                secret.severity.value.lower(),
                "-",
                f"{secret.file} · {secret.title}",
            ]
        )
        pipe_rows.append(
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
        )
    for update in result.updates:
        reason = update.blocked_reason or ""
        age = (
            f"{(datetime.now(timezone.utc) - update.published_date).days}d old"
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
        if len(visible) < 4
        else "",
    )
    if elapsed_s is not None:
        output.notice(f"Scanned {result.project} in {elapsed_s:.1f}s")


def _print_blocked_findings(
    scan_result: ScanResult, flow: Workflow = Workflow.UPDATE
) -> None:
    for finding in scan_result.blocked_findings:
        target = (
            finding.latest_version
            if isinstance(finding, UpdateFinding)
            else finding.fixed_version or "-"
        )
        output.outcome(
            scan_result.project,
            flow.value,
            "blocked",
            finding.pkg_name,
            installed=finding.installed_version,
            target=target,
            reason=finding.blocked_reason or "",
        )
