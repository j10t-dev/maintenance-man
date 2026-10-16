from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from maintenance_man import paths
from maintenance_man.deployer import (
    BuildError,
    DeployError,
    check_health,
)
from maintenance_man.models.activity import ProjectActivity
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.events import (
    DeployStep,
    DeployStepFailed,
    DeployStepStarted,
    DeployStepSucceeded,
    Emit,
    HealthChecked,
    HealthcheckUnconfigured,
    ProjectSkipped,
    ProjectStarted,
    SkipReason,
)
from maintenance_man.process import run_live
from maintenance_man.services import WorkflowError
from maintenance_man.storage import load_activity, record_activity
from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import VcsServices, current_label


class GateDecision(StrEnum):
    DEPLOY = "deploy"
    SKIP_UNCHANGED = "unchanged"
    SKIP_BLOCKED = "blocked"


@dataclass(slots=True)
class DeployResult:
    project: str
    build_status: Literal["pass", "fail", "skip"]
    deploy_status: Literal["pass", "fail", "skip", "unchanged", "blocked"]


def should_deploy(
    name: str,
    project_path: Path,
    activity: Mapping[str, ProjectActivity],
    *,
    force: bool,
    vcs: VcsServices,
) -> tuple[GateDecision, str | None]:
    """Return the gate decision and the exact main revision used by it."""
    try:
        current_id = vcs.repository(project_path).resolve_revision(revision="main")
    except RevisionError:
        current_id = None

    if force:
        return GateDecision.DEPLOY, current_id
    if current_id is None:
        return GateDecision.SKIP_BLOCKED, None

    project_activity = activity.get(name)
    last = project_activity.last_deploy if project_activity else None
    if last is not None and last.success and last.commit_id == current_id:
        return GateDecision.SKIP_UNCHANGED, current_id
    return GateDecision.DEPLOY, current_id


def _record_activity(
    project: str,
    event_type: Literal["build", "deploy"],
    *,
    success: bool,
    project_path: Path,
    commit_id: str | None = None,
    vcs: VcsServices,
) -> None:
    record_activity(
        paths.activity_path(),
        project,
        event_type,
        success=success,
        branch=current_label(repo=vcs.repository(project_path)),
        commit_id=commit_id,
    )


def build_project(name: str, project: ProjectConfig, *, vcs: VcsServices) -> None:
    """Run a configured build and record its result."""
    _run_recorded(name, project, "build", None, vcs=vcs)


def _run_recorded(
    name: str,
    project: ProjectConfig,
    kind: Literal["build", "deploy"],
    commit_id: str | None,
    *,
    vcs: VcsServices,
) -> None:
    command = project.build_command if kind == "build" else project.deploy_command
    assert command is not None
    error = BuildError if kind == "build" else DeployError
    try:
        run_live(
            command,
            project.path,
            timeout=600,
            label=f"{kind.capitalize()} for {name}",
            error=error,
        )
    except BuildError, DeployError:
        _record_activity(
            name,
            kind,
            success=False,
            project_path=project.path,
            vcs=vcs,
        )
        raise
    _record_activity(
        name,
        kind,
        success=True,
        project_path=project.path,
        commit_id=commit_id if kind == "deploy" else None,
        vcs=vcs,
    )


def _run_steps(
    name: str,
    project: ProjectConfig,
    commit_id: str | None,
    *,
    build: bool,
    healthcheck_url: str | None,
    vcs: VcsServices,
    emit: Emit,
) -> DeployResult:
    build_status: Literal["pass", "fail", "skip"] = "skip"
    if build and project.build_command:
        emit(DeployStepStarted(name, DeployStep.BUILD))
        try:
            build_project(name, project, vcs=vcs)
        except BuildError as exc:
            emit(DeployStepFailed(name, DeployStep.BUILD, str(exc)))
            return DeployResult(name, "fail", "skip")
        build_status = "pass"
        emit(DeployStepSucceeded(name, DeployStep.BUILD))

    emit(DeployStepStarted(name, DeployStep.DEPLOY))
    try:
        _run_recorded(name, project, "deploy", commit_id, vcs=vcs)
    except DeployError as exc:
        emit(DeployStepFailed(name, DeployStep.DEPLOY, str(exc)))
        return DeployResult(name, build_status, "fail")
    emit(DeployStepSucceeded(name, DeployStep.DEPLOY))

    if healthcheck_url:
        emit(DeployStepStarted(name, DeployStep.HEALTH))
        result = check_health(healthcheck_url, name)
        emit(HealthChecked(name, result.is_up, result.error))

    return DeployResult(name, build_status, "pass")


def deploy_project(
    name: str,
    project: ProjectConfig,
    *,
    healthcheck_url: str | None,
    build: bool,
    check: bool,
    force: bool,
    vcs: VcsServices,
    emit: Emit,
) -> DeployResult:
    if not project.deployable:
        emit(ProjectSkipped(name, SkipReason.NOT_DEPLOYABLE))
        return DeployResult(name, "skip", "skip")
    if not project.deploy_command:
        msg = (
            f"No deploy_command configured for {name}. "
            f"Add deploy_command to [projects.{name}] in ~/.mm/config.toml."
        )
        raise WorkflowError(msg)

    decision, current_id = should_deploy(
        name,
        project.path,
        load_activity(paths.activity_path()),
        force=force,
        vcs=vcs,
    )
    if decision is GateDecision.SKIP_UNCHANGED:
        emit(ProjectSkipped(name, SkipReason.UNCHANGED))
        return DeployResult(name, "skip", "unchanged")
    if decision is GateDecision.SKIP_BLOCKED:
        msg = (
            f"Could not resolve main revision for {name}; refusing to deploy "
            "unverified state (use --force to override)."
        )
        raise WorkflowError(msg)

    result = _run_steps(
        name,
        project,
        current_id,
        build=build,
        healthcheck_url=healthcheck_url if check else None,
        vcs=vcs,
        emit=emit,
    )
    if result.deploy_status == "pass" and check and not healthcheck_url:
        emit(HealthcheckUnconfigured())
    return result


def deploy_all(
    cfg: MmConfig,
    *,
    check: bool,
    force: bool,
    vcs: VcsServices,
    emit: Emit,
) -> tuple[DeployResult, ...]:
    activity = load_activity(paths.activity_path())
    results: list[DeployResult] = []
    healthcheck_url = cfg.defaults.healthcheck_url if check else None

    for name, project in sorted(cfg.projects.items()):
        if not project.deployable:
            emit(ProjectSkipped(name, SkipReason.NOT_DEPLOYABLE))
            continue
        if not project.deploy_command:
            continue
        if not project.path.exists():
            emit(ProjectSkipped(name, SkipReason.PATH_MISSING, str(project.path)))
            results.append(DeployResult(name, "skip", "fail"))
            continue

        decision, current_id = should_deploy(
            name, project.path, activity, force=force, vcs=vcs
        )
        if decision is GateDecision.SKIP_UNCHANGED:
            emit(ProjectSkipped(name, SkipReason.UNCHANGED))
            results.append(DeployResult(name, "skip", "unchanged"))
            continue
        if decision is GateDecision.SKIP_BLOCKED:
            emit(ProjectSkipped(name, SkipReason.BLOCKED))
            results.append(DeployResult(name, "skip", "blocked"))
            continue

        emit(ProjectStarted(name))
        results.append(
            _run_steps(
                name,
                project,
                current_id,
                build=True,
                healthcheck_url=healthcheck_url,
                vcs=vcs,
                emit=emit,
            )
        )

    return tuple(results)
