import tomllib
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from maintenance_man import paths
from maintenance_man.models.config import MmConfig, ProjectConfig


class ConfigError(Exception):
    """The configuration file is missing, unparseable or invalid.

    Each of *messages* is one printable line; str() joins them with newlines.
    """

    def __init__(self, *messages: str) -> None:
        super().__init__("\n".join(messages))
        self.messages = messages


class ProjectNotFoundError(Exception):
    """Raised when a requested project is not found or its path does not exist."""


class UnknownProjectError(ProjectNotFoundError):
    """Raised when a requested project name is not configured."""


def load_config(config_path: Path | None = None) -> MmConfig:
    """Load and validate config from a TOML file.

    If config_path is None, reads config.toml from MM_HOME (default ~/.mm),
    creating it if needed.
    Relative project paths are resolved against the config file's parent directory.
    """
    if config_path is None:
        ensure_mm_home()
        config_path = paths.config_path()

    if not config_path.exists():
        msg = f"Config file not found: {config_path}"
        raise ConfigError(msg)

    try:
        with config_path.open("rb") as f:
            raw = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        msg = f"{config_path}: {e}"
        raise ConfigError(msg) from e

    try:
        config = MmConfig(**raw)
    except ValidationError as e:
        raise ConfigError(*_validation_messages(config_path, e)) from e

    config_dir = config_path.parent.resolve()
    for project in config.projects.values():
        if not project.path.is_absolute():
            project.path = (config_dir / project.path).resolve()

    return config


def _validation_messages(config_path: Path, error: ValidationError) -> list[str]:
    return [
        f"{config_path}: {'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
        for item in error.errors()
    ]


def resolve_project(config: MmConfig, name: str) -> ProjectConfig:
    """Look up a project by name and validate its path exists on disk."""
    project = _configured_project(config, name)

    if not project.path.exists():
        msg = f"Project '{name}' path does not exist: {project.path}"
        raise ProjectNotFoundError(msg)

    return project


def ordered_unique_project_names(config: MmConfig, names: Sequence[str]) -> list[str]:
    """Return configured project names once each, in their requested order."""
    for name in names:
        _configured_project(config, name)
    return list(dict.fromkeys(names))


def _configured_project(config: MmConfig, name: str) -> ProjectConfig:
    try:
        return config.projects[name]
    except KeyError:
        msg = (
            f"Unknown project '{name}'. "
            f"Known projects: {', '.join(config.projects) or '(none)'}"
        )
        raise UnknownProjectError(msg) from None


def ensure_mm_home() -> None:
    """Create MM_HOME (default ~/.mm) and its skeleton config if missing."""
    paths.mm_home().mkdir(parents=True, exist_ok=True)

    config_path = paths.config_path()
    if not config_path.exists():
        config_path.write_text(_SKELETON_CONFIG)


_SKELETON_CONFIG = """\
[defaults]
min_version_age_days = 7

# [projects.my-project]
# path = "/home/user/dev/my-project"
# package_manager = "bun"        # bun | uv | mvn | gradle
"""
