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
from maintenance_man.services import WorkflowError, report_missing_path
from maintenance_man.storage import load_activity, record_activity
from maintenance_man.vcs import JjRepository, RevisionError
from maintenance_man.vcs_workflow import current_label


@dataclass(slots=True)
class DeployResult:
    project_name: str
    build_status: Literal["passed", "failed", "skipped"]
    deploy_status: Status

    @property
    def failed(self) -> bool:
        """Whether the build or the deploy failed."""
        return "failed" in (self.build_status, self.deploy_status)


def deploy_project(
    project_name: str,
    project: ProjectConfig,
    *,
    healthcheck_url: str | None,
    build: bool,
    force: bool,
    emit: Emit,
) -> DeployResult:
    if not project.deployable:
        emit(ProjectSkipped(project_name, SkipReason.NOT_DEPLOYABLE))
        return DeployResult(project_name, "skipped", "skipped")
    if not project.deploy_command:
        msg = (
            f"No deploy_command configured for {project_name}. "
            f"Add deploy_command to [projects.{project_name}] in ~/.mm/config.toml."
        )
        raise WorkflowError(msg)

    skip, current_id = should_deploy(
        project_name,
        project.path,
        load_activity(paths.activity_path()),
        force=force,
    )
    if skip is SkipReason.UNCHANGED:
        emit(ProjectSkipped(project_name, SkipReason.UNCHANGED))
        return DeployResult(project_name, "skipped", "unchanged")
    if skip is SkipReason.BLOCKED:
        msg = (
            f"Could not resolve main revision for {project_name}; refusing to deploy "
            "unverified state (use --force to override)."
        )
        raise WorkflowError(msg)

    emit(ProjectStarted(project_name))
    return _run_steps(
        project_name,
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

    for project_name, project in sorted(cfg.projects.items()):
        if not project.deployable:
            emit(ProjectSkipped(project_name, SkipReason.NOT_DEPLOYABLE))
            results.append(DeployResult(project_name, "skipped", "skipped"))
            continue
        if not project.deploy_command:
            continue
        if report_missing_path(project_name, project, emit=emit):
            results.append(DeployResult(project_name, "skipped", "failed"))
            continue

        skip, current_id = should_deploy(
            project_name, project.path, activity, force=force
        )
        if skip is not None:
            emit(ProjectSkipped(project_name, skip))
            status = "unchanged" if skip is SkipReason.UNCHANGED else "blocked"
            results.append(DeployResult(project_name, "skipped", status))
            continue

        emit(ProjectStarted(project_name))
        results.append(
            _run_steps(
                project_name,
                project,
                current_id,
                build=True,
                healthcheck_url=healthcheck_url,
                emit=emit,
            )
        )

    return tuple(results)


def should_deploy(
    project_name: str,
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

    project_activity = activity.get(project_name)
    last = project_activity.last_deploy if project_activity else None
    if last is not None and last.success and last.commit_id == current_id:
        return SkipReason.UNCHANGED, current_id
    return None, current_id


def build_project(project_name: str, project: ProjectConfig) -> None:
    """Run a configured build and record its result."""
    _run_recorded(project_name, project, DeployStep.BUILD, None)


def _run_recorded(
    project_name: str, project: ProjectConfig, step: DeployStep, commit_id: str | None
) -> None:
    """Run the step's configured command and record its result; a failure is
    recorded, then re-raised. An interrupt records nothing."""
    build = step is DeployStep.BUILD
    command = project.build_command if build else project.deploy_command
    assert command is not None

    def record(success: bool) -> None:
        record_activity(
            paths.activity_path(),
            project_name,
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
            label=f"{'Build' if build else 'Deploy'} for {project_name}",
            error=BuildError if build else DeployError,
        )
    except BuildError, DeployError:
        record(False)
        raise
    record(True)


def _run_steps(
    project_name: str,
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
            build_project(project_name, project)
        except BuildError as exc:
            emit(DeployStepFinished(project_name, DeployStep.BUILD, str(exc)))
            return DeployResult(project_name, "failed", "skipped")
        build_status = "passed"
        emit(DeployStepFinished(project_name, DeployStep.BUILD))

    try:
        _run_recorded(project_name, project, DeployStep.DEPLOY, commit_id)
    except DeployError as exc:
        emit(DeployStepFinished(project_name, DeployStep.DEPLOY, str(exc)))
        return DeployResult(project_name, build_status, "failed")
    emit(DeployStepFinished(project_name, DeployStep.DEPLOY))

    if healthcheck_url:
        result = check_health(healthcheck_url, project_name)
        emit(HealthChecked(project_name, result.is_up, result.error))

    return DeployResult(project_name, build_status, "passed")
