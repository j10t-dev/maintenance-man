import tomllib
from pathlib import Path

from pydantic import ValidationError

from maintenance_man.models.config import MmConfig, ProjectConfig


class ConfigError(Exception):
    """Raised when the configuration file is invalid or cannot be parsed."""


class ProjectNotFoundError(Exception):
    """Raised when a requested project is not found or its path does not exist."""


MM_HOME: Path = Path.home() / ".mm"


def load_config(config_path: Path | None = None) -> MmConfig:
    """Load and validate config from a TOML file.

    If config_path is None, reads from ~/.mm/config.toml (creating it if needed).
    Relative project paths are resolved against the config file's parent directory.
    """
    if config_path is None:
        ensure_mm_home()
        config_path = MM_HOME / "config.toml"

    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    try:
        with config_path.open("rb") as f:
            raw = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"Failed to parse {config_path}\n{e}") from e

    try:
        config = MmConfig(**raw)
    except ValidationError as e:
        raise ConfigError(f"Invalid config in {config_path}\n{e}") from e

    # Resolve relative project paths against config file's parent directory
    config_dir = config_path.parent.resolve()
    for project in config.projects.values():
        if not project.path.is_absolute():
            project.path = (config_dir / project.path).resolve()

    return config


def resolve_project(config: MmConfig, name: str) -> ProjectConfig:
    """Look up a project by name and validate its path exists on disk."""
    if name not in config.projects:
        raise ProjectNotFoundError(
            f"Unknown project '{name}'. "
            f"Known projects: {', '.join(config.projects) or '(none)'}"
        )

    project = config.projects[name]

    if not project.path.exists():
        raise ProjectNotFoundError(
            f"Project '{name}' path does not exist: {project.path}"
        )

    return project


def ensure_mm_home() -> None:
    """Create ~/.mm/ directory structure and skeleton config if missing."""
    MM_HOME.mkdir(parents=True, exist_ok=True)
    (MM_HOME / "scan-results").mkdir(exist_ok=True)
    (MM_HOME / "worktrees").mkdir(exist_ok=True)

    config_path = MM_HOME / "config.toml"
    if not config_path.exists():
        config_path.write_text(_SKELETON_CONFIG)


_SKELETON_CONFIG = """\
[defaults]
min_version_age_days = 7

# [projects.my-project]
# path = "/home/user/dev/my-project"
# package_manager = "bun"        # bun | uv | mvn
"""
