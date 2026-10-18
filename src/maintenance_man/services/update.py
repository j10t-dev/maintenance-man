from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from maintenance_man import config as config_module
from maintenance_man.gradle import (
    GRADLE_LOCAL_PROPERTIES_RELPATH,
    workspace_environment_reason,
)
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
    ScanReported,
    SkipReason,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    GradleUpdateTarget,
    ScanResult,
    UpdateFinding,
    UpdateResult,
    UpdateStatus,
    VulnFinding,
    Workflow,
)
from maintenance_man.services import WorkflowError, flows
from maintenance_man.services.flows import FlowConflictError
from maintenance_man.updater import group_findings, is_eligible, process_findings
from maintenance_man.vcs import Repository, RevisionError, workspace_path_for_project
from maintenance_man.vcs_workflow import (
    VcsServices,
    create_workspace,
    ensure_main_bookmark,
    remove_workspace,
)


class UpdateSetupError(WorkflowError):
    """An update workspace could not be prepared safely."""


type FindingChooser = Callable[
    [list[VulnFinding], list[UpdateFinding]],
    tuple[list[VulnFinding], list[UpdateFinding]],
]


@dataclass(frozen=True, slots=True)
class ProjectUpdate:
    project: str
    outcome: Outcome
    results: tuple[UpdateResult, ...]
    blocked: int = 0


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
    choose: FindingChooser | None,
    vcs: VcsServices,
    emit: Emit,
) -> ProjectUpdate:
    scan_result = flows.load_validated_scan(name, project, Workflow.UPDATE, emit=emit)
    if scan_result is None:
        return ProjectUpdate(name, Outcome.SUCCEEDED, ())
    if flows.report_missing_test_config(name, project, emit=emit):
        return ProjectUpdate(name, Outcome.FAILED, ())
    try:
        workspace = _enter_update_workspace(name, project, scan_result, vcs=vcs)
    except RevisionError as exc:
        raise UpdateSetupError(str(exc)) from exc

    work_config = project.model_copy(update={"path": workspace})
    results: tuple[UpdateResult, ...] = ()
    may_finalise = False
    cleaned = True
    try:
        emit(ScanReported(scan_result))
        results = _process_selected(
            scan_result,
            work_config,
            choose=choose,
            vcs=vcs,
            emit=emit,
        )
        may_finalise = (
            not any(not result.passed for result in results)
            and not _has_update_state(scan_result, (UpdateStatus.FAILED,))
            and not scan_result.blocked_findings
        )
    finally:
        try:
            remove_workspace(repo=vcs.repository(project.path), project=name)
        except RevisionError as exc:
            emit(OperationFailed(Operation.WORKSPACE_CLEANUP, name, str(exc)))
            cleaned = False

    finalised = may_finalise and flows.finalise_local_changes(
        project.path, scan_result, name, Workflow.UPDATE, vcs=vcs, emit=emit
    )
    return ProjectUpdate(
        name,
        Outcome.SUCCEEDED if cleaned and finalised else Outcome.FAILED,
        results,
        blocked=len(scan_result.blocked_findings),
    )


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
                choose=None,
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
    ordered = config_module.ordered_unique_project_names(cfg, names)
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
        _require_sdk_in_workspace(project, project_config, repo, workspace_revision)
    else:
        ensure_main_bookmark(repo=repo)
        _require_sdk_in_workspace(project, project_config, repo, "main")
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


def _require_sdk_in_workspace(
    name: str, project: ProjectConfig, repo: Repository, revision: str
) -> None:
    """Refuse a workspace checkout that would lack its local.properties."""
    reason = workspace_environment_reason(
        project.path, workspace_path_for_project(name)
    )
    if reason is None:
        return
    inspected = repo.revision_file(
        revision=revision, filename=GRADLE_LOCAL_PROPERTIES_RELPATH
    )
    if not inspected.is_regular:
        raise UpdateSetupError(reason)


def _is_selectable(finding: VulnFinding | UpdateFinding) -> bool:
    return is_eligible(finding) and (
        finding.update_status is None
        or (
            finding.update_status is UpdateStatus.FAILED
            and finding.flow is Workflow.UPDATE
        )
    )


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
        targets = [
            row.gradle_target
            for row in (*selected_vulns, *selected_updates)
            if row.gradle_target is not None
        ]
        selected_vulns = _with_shared_targets(selected_vulns, selectable_vulns, targets)
        selected_updates = _with_shared_targets(
            selected_updates, selectable_updates, targets
        )
    else:
        selected_vulns, selected_updates = selectable_vulns, selectable_updates

    emit(ProcessingStarted(len(selected_vulns), len(selected_updates)))
    findings = group_findings([*selected_vulns, *selected_updates])
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
    emit(FindingsProcessed(result_tuple, len(scan_result.blocked_findings)))
    return result_tuple


def _with_shared_targets[F: VulnFinding | UpdateFinding](
    selected: list[F], selectable: list[F], targets: list[GradleUpdateTarget]
) -> list[F]:
    chosen = {id(row) for row in selected}
    return [
        *selected,
        *(
            row
            for row in selectable
            if id(row) not in chosen and row.gradle_target in targets
        ),
    ]
