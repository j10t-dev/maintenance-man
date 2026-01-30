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


class MmConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaults: DefaultsConfig = DefaultsConfig()
    projects: dict[str, ProjectConfig] = {}
