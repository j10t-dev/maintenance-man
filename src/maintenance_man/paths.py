"""Where mm keeps its files under its home directory."""

import os
from pathlib import Path

MM_HOME: Path = Path.home() / ".mm"
if _home_override := os.environ.get("MM_HOME"):
    MM_HOME = Path(_home_override).expanduser().resolve()


def mm_home() -> Path:
    """Return the state root, set by MM_HOME when this process starts."""
    return MM_HOME


def config_path() -> Path:
    return mm_home() / "config.toml"


def scan_results_dir() -> Path:
    return mm_home() / "scan-results"


def activity_path() -> Path:
    return mm_home() / "activity.json"


def workspaces_dir() -> Path:
    return mm_home() / "workspaces"


def publications_dir() -> Path:
    return mm_home() / "publications"


def sanitise_project_name(project_name: str) -> str:
    return project_name.replace("/", "_").replace("\\", "_").replace("..", "_")


def project_file(directory: Path, project_name: str, suffix: str = "") -> Path:
    """Return *project_name*'s file or directory inside *directory*.

    Raises ValueError when the sanitised name is empty or the result's parent
    is not *directory*. The final component is not resolved.
    """
    safe_name = sanitise_project_name(project_name)
    candidate = directory / f"{safe_name}{suffix}"
    if not safe_name or candidate.parent.resolve() != directory.resolve():
        msg = f"Invalid project name: {project_name!r}"
        raise ValueError(msg)
    return candidate
