from collections.abc import Mapping
from dataclasses import dataclass
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
    DeployStepFinished,
    Emit,
    HealthChecked,
    ProjectSkipped,
    ProjectStarted,
    SkipReason,
    Status,
)
from maintenance_man.process import run_shell_command
from maintenance_man.services import WorkflowError
from maintenance_man.storage import load_activity, record_activity
from maintenance_man.vcs import JjRepository, RevisionError
from maintenance_man.vcs_workflow import current_label


@dataclass(slots=True)
class DeployResult:
    project: str
    build_status: Literal["passed", "failed", "skipped"]
    deploy_status: Status


def deploy_project(
    name: str,
    project: ProjectConfig,
    *,
    healthcheck_url: str | None,
    build: bool,
    force: bool,
    emit: Emit,
) -> DeployResult:
    if not project.deployable:
        emit(ProjectSkipped(name, SkipReason.NOT_DEPLOYABLE))
        return DeployResult(name, "skipped", "skipped")
    if not project.deploy_command:
        msg = (
            f"No deploy_command configured for {name}. "
            f"Add deploy_command to [projects.{name}] in ~/.mm/config.toml."
        )
        raise WorkflowError(msg)

    skip, current_id = should_deploy(
        name,
        project.path,
        load_activity(paths.activity_path()),
        force=force,
    )
    if skip is SkipReason.UNCHANGED:
        emit(ProjectSkipped(name, SkipReason.UNCHANGED))
        return DeployResult(name, "skipped", "unchanged")
    if skip is SkipReason.BLOCKED:
        msg = (
            f"Could not resolve main revision for {name}; refusing to deploy "
            "unverified state (use --force to override)."
        )
        raise WorkflowError(msg)

    emit(ProjectStarted(name))
    return _run_steps(
        name,
        project,
        current_id,
        build=build,
        healthcheck_url=healthcheck_url,
        emit=emit,
    )


def deploy_all(
    cfg: MmConfig,
    *,
    check: bool,
    force: bool,
    emit: Emit,
) -> tuple[DeployResult, ...]:
    activity = load_activity(paths.activity_path())
    results: list[DeployResult] = []
    healthcheck_url = cfg.defaults.healthcheck_url if check else None

    for name, project in sorted(cfg.projects.items()):
        if not project.deployable:
            emit(ProjectSkipped(name, SkipReason.NOT_DEPLOYABLE))
            results.append(DeployResult(name, "skipped", "skipped"))
            continue
        if not project.deploy_command:
            continue
        if not project.path.exists():
            emit(ProjectSkipped(name, SkipReason.PATH_MISSING, str(project.path)))
            results.append(DeployResult(name, "skipped", "failed"))
            continue

        skip, current_id = should_deploy(name, project.path, activity, force=force)
        if skip is not None:
            emit(ProjectSkipped(name, skip))
            status = "unchanged" if skip is SkipReason.UNCHANGED else "blocked"
            results.append(DeployResult(name, "skipped", status))
            continue

        emit(ProjectStarted(name))
        results.append(
            _run_steps(
                name,
                project,
                current_id,
                build=True,
                healthcheck_url=healthcheck_url,
                emit=emit,
            )
        )

    return tuple(results)


def should_deploy(
    name: str,
    project_path: Path,
    activity: Mapping[str, ProjectActivity],
    *,
    force: bool,
) -> tuple[Literal[SkipReason.UNCHANGED, SkipReason.BLOCKED] | None, str | None]:
    """Return why the deploy is skipped (None to deploy) and the main revision used."""
    try:
        current_id = JjRepository(project_path).resolve_revision(revision="main")
    except RevisionError:
        current_id = None

    if force:
        return None, current_id
    if current_id is None:
        return SkipReason.BLOCKED, None

    project_activity = activity.get(name)
    last = project_activity.last_deploy if project_activity else None
    if last is not None and last.success and last.commit_id == current_id:
        return SkipReason.UNCHANGED, current_id
    return None, current_id


def build_project(name: str, project: ProjectConfig) -> None:
    """Run a configured build and record its result."""
    _run_recorded(name, project, DeployStep.BUILD, None)


def _run_recorded(
    name: str, project: ProjectConfig, step: DeployStep, commit_id: str | None
) -> None:
    """Run the step's configured command and record its result; a failure is
    recorded, then re-raised. An interrupt records nothing."""
    build = step is DeployStep.BUILD
    command = project.build_command if build else project.deploy_command
    assert command is not None

    def record(success: bool) -> None:
        record_activity(
            paths.activity_path(),
            name,
            "build" if build else "deploy",
            success=success,
            branch=current_label(repo=JjRepository(project.path)),
            commit_id=commit_id if success and not build else None,
        )

    try:
        run_shell_command(
            command,
            project.path,
            timeout=600,
            label=f"{'Build' if build else 'Deploy'} for {name}",
            error=BuildError if build else DeployError,
        )
    except BuildError, DeployError:
        record(False)
        raise
    record(True)


def _run_steps(
    name: str,
    project: ProjectConfig,
    commit_id: str | None,
    *,
    build: bool,
    healthcheck_url: str | None,
    emit: Emit,
) -> DeployResult:
    build_status: Literal["passed", "failed", "skipped"] = "skipped"
    if build and project.build_command:
        try:
            build_project(name, project)
        except BuildError as exc:
            emit(DeployStepFinished(name, DeployStep.BUILD, str(exc)))
            return DeployResult(name, "failed", "skipped")
        build_status = "passed"
        emit(DeployStepFinished(name, DeployStep.BUILD))

    try:
        _run_recorded(name, project, DeployStep.DEPLOY, commit_id)
    except DeployError as exc:
        emit(DeployStepFinished(name, DeployStep.DEPLOY, str(exc)))
        return DeployResult(name, build_status, "failed")
    emit(DeployStepFinished(name, DeployStep.DEPLOY))

    if healthcheck_url:
        result = check_health(healthcheck_url, name)
        emit(HealthChecked(name, result.is_up, result.error))

    return DeployResult(name, build_status, "passed")
