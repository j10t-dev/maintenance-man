from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import Emit, ProjectSkipped, SkipReason


class WorkflowError(Exception):
    """A workflow refused to continue; the message is plain text."""


def report_missing_path(
    project_name: str, project: ProjectConfig, *, emit: Emit
) -> bool:
    """Emit ProjectSkipped(PATH_MISSING) and return True when the project's
    path does not exist."""
    if project.path.exists():
        return False
    emit(ProjectSkipped(project_name, SkipReason.PATH_MISSING, str(project.path)))
    return True
