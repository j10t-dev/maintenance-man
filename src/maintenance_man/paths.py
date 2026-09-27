"""Where mm keeps its files under its home directory."""

from pathlib import Path

MM_HOME: Path = Path.home() / ".mm"


def mm_home() -> Path:
    return MM_HOME


def config_path() -> Path:
    return mm_home() / "config.toml"


def scan_results_dir() -> Path:
    return mm_home() / "scan-results"


def activity_path() -> Path:
    return mm_home() / "activity.json"


def workspaces_dir() -> Path:
    return mm_home() / "workspaces"


def gradle_runs_dir() -> Path:
    return mm_home() / "gradle-runs"


def gradle_contexts_dir() -> Path:
    return mm_home() / "gradle-contexts"


def gradle_publications_dir() -> Path:
    return mm_home() / "gradle-publications"


def sanitise_project_name(name: str) -> str:
    return name.replace("/", "_").replace("\\", "_").replace("..", "_")


def project_file(directory: Path, project: str, suffix: str = "") -> Path:
    """Return *project*'s file or directory inside *directory*.

    Raises ValueError when the sanitised name is empty or the result's parent
    is not *directory*. The final component is not resolved.
    """
    name = sanitise_project_name(project)
    candidate = directory / f"{name}{suffix}"
    if not name or candidate.parent.resolve() != directory.resolve():
        raise ValueError(f"Invalid project name: {project!r}")
    return candidate
