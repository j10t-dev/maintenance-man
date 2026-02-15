from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict


class DefaultsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_version_age_days: int = 7


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Path
    package_manager: Literal["bun", "uv", "mvn"]
    scan_secrets: bool = True
    test_unit: str | None = None
    test_integration: str | None = None
    test_component: str | None = None


class MmConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaults: DefaultsConfig = DefaultsConfig()
    projects: dict[str, ProjectConfig] = {}
