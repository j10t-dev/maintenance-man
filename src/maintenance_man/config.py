import sys
import tomllib
from pathlib import Path

from pydantic import ValidationError
from rich import print as rprint

from maintenance_man.models.config import MmConfig, ProjectConfig

MM_HOME: Path = Path.home() / ".mm"

_SKELETON_CONFIG = """\
[defaults]
min_version_age_days = 7

# [projects.my-project]
# path = "/home/user/dev/my-project"
# package_manager = "bun"        # bun | uv | mvn
"""


def ensure_mm_home() -> None:
    """Create ~/.mm/ directory structure and skeleton config if missing."""
    MM_HOME.mkdir(parents=True, exist_ok=True)
    (MM_HOME / "scan-results").mkdir(exist_ok=True)
    (MM_HOME / "worktrees").mkdir(exist_ok=True)

    config_path = MM_HOME / "config.toml"
    if not config_path.exists():
        config_path.write_text(_SKELETON_CONFIG)


def load_config() -> MmConfig:
    """Load and validate config from ~/.mm/config.toml."""
    ensure_mm_home()

    config_path = MM_HOME / "config.toml"
    text = config_path.read_text()

    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        rprint(f"[bold red]Config error:[/] Failed to parse {config_path}\n{e}")
        sys.exit(1)

    try:
        return MmConfig(**raw)
    except ValidationError as e:
        rprint(f"[bold red]Config error:[/] Invalid config in {config_path}\n{e}")
        sys.exit(1)


def resolve_project(config: MmConfig, name: str) -> ProjectConfig:
    """Look up a project by name and validate its path exists on disk."""
    if name not in config.projects:
        rprint(
            f"[bold red]Error:[/] Unknown project [bold]{name}[/]. "
            f"Known projects: {', '.join(config.projects) or '(none)'}"
        )
        sys.exit(1)

    project = config.projects[name]

    if not project.path.exists():
        rprint(
            f"[bold red]Error:[/] Project [bold]{name}[/] path does not exist: "
            f"{project.path}"
        )
        sys.exit(1)

    return project
