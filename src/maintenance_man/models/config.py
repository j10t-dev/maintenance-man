from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict


class DefaultsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_version_age_days: int = 7
    healthcheck_url: str | None = None


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Path
    package_manager: Literal["bun", "uv", "mvn", "gradle"]
    scan_secrets: bool = True
    scan_skip_dirs: list[str] = []
    test_unit: str | None = None
    test_integration: str | None = None
    test_component: str | None = None
    deployable: bool = True
    build_command: str | None = None
    deploy_command: str | None = None
    gradle_repository_routing: Literal["standard-public"] | None = None

    @property
    def test_phases(self) -> tuple[tuple[str, str], ...]:
        """Configured test phases in run order, skipping blank commands."""
        phases = (
            ("unit", self.test_unit),
            ("integration", self.test_integration),
            ("component", self.test_component),
        )
        return tuple(
            (name, command)
            for name, command in phases
            if command is not None and command.strip()
        )


class MmConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaults: DefaultsConfig = DefaultsConfig()
    projects: dict[str, ProjectConfig] = {}
