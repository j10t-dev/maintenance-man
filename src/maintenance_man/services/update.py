from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from maintenance_man import config as config_module
from maintenance_man import gradle_workflow
from maintenance_man.github import CodeHostError
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.events import (
    Emit,
    FindingsProcessed,
    Operation,
    OperationFailed,
    Outcome,
    ProcessingStarted,
    ProjectSkipped,
    ProjectStarted,
    Promoted,
    ScanReported,
    SkipReason,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    ScanResult,
    UpdateFinding,
    UpdateResult,
    UpdateStatus,
    VulnFinding,
    Workflow,
)
from maintenance_man.services import WorkflowError, flows
from maintenance_man.services.flows import FlowConflictError
from maintenance_man.updater import Finding, process_findings
from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import (
    VcsServices,
    create_workspace,
    ensure_main_bookmark,
    prune_stale_bookmarks,
    refresh_working_copy_from_main,
    remove_workspace,
)


class UpdateSetupError(WorkflowError):
    """An update workspace could not be prepared safely."""


class UpdateRoute(StrEnum):
    FINDINGS = "findings"
    GRADLE = "gradle"


type FindingChooser = Callable[
    [list[VulnFinding], list[UpdateFinding]],
    tuple[list[VulnFinding], list[UpdateFinding]],
]


@dataclass(frozen=True, slots=True)
class ProjectUpdate:
    project: str
    route: UpdateRoute
    outcome: Outcome
    results: tuple[UpdateResult, ...]


@dataclass(frozen=True, slots=True)
class BatchUpdate:
    projects: tuple[ProjectUpdate, ...]
    had_errors: bool

    @property
    def outcome(self) -> Outcome:
        failed = self.had_errors or any(
            project.outcome is Outcome.FAILED for project in self.projects
        )
        return Outcome.FAILED if failed else Outcome.SUCCEEDED


def update_project(
    name: str,
    project: ProjectConfig,
    *,
    minimum_age_days: int,
    choose: FindingChooser | None,
    choose_gradle: gradle_workflow.GradleChooser | None,
    vcs: VcsServices,
    emit: Emit,
) -> ProjectUpdate:
    if project.package_manager == "gradle":
        outcome = gradle_workflow.run_gradle_flow(
            name,
            project,
            Workflow.UPDATE,
            minimum_age_days=minimum_age_days,
            choose=choose_gradle,
            emit=emit,
            vcs=vcs,
        )
        return ProjectUpdate(name, UpdateRoute.GRADLE, outcome, ())

    scan_result = flows.load_validated_scan(name, project, Workflow.UPDATE, emit=emit)
    if scan_result is None:
        return ProjectUpdate(name, UpdateRoute.FINDINGS, Outcome.SUCCEEDED, ())
    try:
        workspace = _enter_update_workspace(name, project, scan_result, vcs=vcs)
    except (RevisionError, CodeHostError) as exc:
        raise UpdateSetupError(str(exc)) from exc

    work_config = project.model_copy(update={"path": workspace})
    finalised = False
    results: tuple[UpdateResult, ...] = ()
    try:
        emit(ScanReported(scan_result))
        results = _process_selected(
            scan_result,
            work_config,
            choose=choose,
            vcs=vcs,
            emit=emit,
        )
        if (
            not any(not result.passed for result in results)
            and not _has_update_state(scan_result, (UpdateStatus.FAILED,))
            and not scan_result.blocked_findings
        ):
            finalised = _finalise(project.path, scan_result, name, vcs=vcs, emit=emit)
    finally:
        try:
            remove_workspace(repo=vcs.repository(project.path), project=name)
        except RevisionError as exc:
            emit(OperationFailed(Operation.WORKSPACE_CLEANUP, name, str(exc)))
            finalised = False

    if finalised:
        try:
            vcs.repository(project.path).delete_bookmark(
                bookmark=WORKFLOW_BOOKMARKS[Workflow.UPDATE]
            )
        except RevisionError as exc:
            emit(OperationFailed(Operation.BOOKMARK_CLEANUP, name, str(exc)))
            finalised = False
    outcome = Outcome.SUCCEEDED if finalised else Outcome.FAILED
    return ProjectUpdate(name, UpdateRoute.FINDINGS, outcome, results)


def update_projects(
    cfg: MmConfig,
    names: Sequence[str],
    *,
    vcs: VcsServices,
    emit: Emit,
) -> BatchUpdate:
    projects: list[ProjectUpdate] = []
    had_errors = False
    for name in names:
        project = cfg.projects[name]
        if not project.path.exists():
            emit(ProjectSkipped(name, SkipReason.PATH_MISSING, str(project.path)))
            had_errors = True
            continue
        emit(ProjectStarted(name))
        try:
            result = update_project(
                name,
                project,
                minimum_age_days=cfg.defaults.min_version_age_days,
                choose=None,
                choose_gradle=None,
                vcs=vcs,
                emit=emit,
            )
        except FlowConflictError as exc:
            emit(ProjectSkipped(name, SkipReason.FLOW_CONFLICT, str(exc)))
            had_errors = True
        except UpdateSetupError as exc:
            emit(OperationFailed(Operation.UPDATE_SETUP, name, str(exc)))
            had_errors = True
        else:
            projects.append(result)
    return BatchUpdate(tuple(projects), had_errors)


def resolve_update_targets(
    cfg: MmConfig,
    names: Sequence[str],
    *,
    negate: bool,
) -> tuple[Literal["single", "batch"], list[str]]:
    ordered = config_module.validate_project_names(cfg, names)
    if negate:
        excluded = set(ordered)
        return "batch", [name for name in sorted(cfg.projects) if name not in excluded]
    if not ordered:
        return "batch", sorted(cfg.projects)
    if len(ordered) == 1:
        return "single", ordered
    return "batch", ordered


def _has_update_state(
    scan_result: ScanResult, statuses: tuple[UpdateStatus, ...]
) -> bool:
    return any(
        finding.update_status in statuses and finding.flow is Workflow.UPDATE
        for finding in scan_result.findings
    )


def _enter_update_workspace(
    project: str,
    project_config: ProjectConfig,
    scan_result: ScanResult,
    *,
    vcs: VcsServices,
) -> Path:
    bookmark = WORKFLOW_BOOKMARKS[Workflow.UPDATE]
    repo = vcs.repository(project_config.path)
    remove_workspace(repo=repo, project=project)

    if _has_update_state(scan_result, (UpdateStatus.READY, UpdateStatus.FAILED)):
        if not repo.bookmark_exists(bookmark=bookmark):
            msg = (
                f"update bookmark '{bookmark}' is missing but in-progress "
                "state exists — rescan required"
            )
            raise UpdateSetupError(msg)
        workspace_revision = bookmark
    else:
        prune_stale_bookmarks(repo=repo, host=vcs.code_host(project_config.path))
        ensure_main_bookmark(repo=repo)
        if repo.bookmark_exists(bookmark=bookmark):
            repo.delete_bookmark(bookmark=bookmark)
        repo.create_bookmark(bookmark=bookmark, revision="main")
        workspace_revision = "main"

    try:
        workspace_path = create_workspace(
            repo=repo, project=project, revision=workspace_revision
        )
        vcs.repository(workspace_path).new_change(revision=bookmark)
    except RevisionError:
        remove_workspace(repo=repo, project=project)
        raise
    return workspace_path


def _is_selectable(finding: Finding) -> bool:
    return (not isinstance(finding, VulnFinding) or finding.actionable) and (
        finding.update_status is None
        or (
            finding.update_status is UpdateStatus.FAILED
            and finding.flow is Workflow.UPDATE
        )
    )


def _finalise(
    project_path: Path,
    scan_result: ScanResult,
    name: str,
    *,
    vcs: VcsServices,
    emit: Emit,
) -> bool:
    bookmark = WORKFLOW_BOOKMARKS[Workflow.UPDATE]
    repo = vcs.repository(project_path)
    try:
        repo.promote_bookmark_to_main(bookmark=bookmark)
    except RevisionError as exc:
        emit(OperationFailed(Operation.PROMOTE, name, str(exc)))
        return False
    try:
        refresh_working_copy_from_main(repo=repo)
    except RevisionError as exc:
        emit(OperationFailed(Operation.REFRESH, name, str(exc)))
        return False

    flows.complete_ready_findings(scan_result, name, flow=Workflow.UPDATE)
    emit(Promoted(bookmark))
    return True


def _process_selected(
    scan_result: ScanResult,
    work_config: ProjectConfig,
    *,
    choose: FindingChooser | None,
    vcs: VcsServices,
    emit: Emit,
) -> tuple[UpdateResult, ...]:
    selectable_vulns = [
        vuln for vuln in scan_result.vulnerabilities if _is_selectable(vuln)
    ]
    selectable_updates = [
        update for update in scan_result.updates if _is_selectable(update)
    ]
    if choose is not None and (selectable_vulns or selectable_updates):
        selected_vulns, selected_updates = choose(selectable_vulns, selectable_updates)
    else:
        selected_vulns, selected_updates = selectable_vulns, selectable_updates

    emit(ProcessingStarted(len(selected_vulns), len(selected_updates)))
    selected = scan_result.model_copy(
        update={
            "vulnerabilities": selected_vulns,
            "updates": selected_updates,
        }
    )
    findings = flows.ordered_findings(selected, lambda _finding: True)
    results = (
        process_findings(
            findings,
            work_config,
            flow=Workflow.UPDATE,
            scan_result=scan_result,
            vcs=vcs,
            emit=emit,
        )
        if findings
        else []
    )
    result_tuple = tuple(results)
    emit(FindingsProcessed(result_tuple))
    return result_tuple
