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
    package_manager: Literal["bun", "uv", "mvn"]
    scan_secrets: bool = True
    scan_skip_dirs: list[str] = []
    test_unit: str | None = None
    test_integration: str | None = None
    test_component: str | None = None
    build_command: str | None = None
    deploy_command: str | None = None


class MmConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaults: DefaultsConfig = DefaultsConfig()
    projects: dict[str, ProjectConfig] = {}
