"""Operations that differ between the uv, bun and mvn package managers."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from maintenance_man import dependency_age
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import UpdateFinding
from maintenance_man.outdated import bun_outdated, mvn_outdated, uv_outdated

type VulnerabilitySource = Literal["uv-audit", "trivy"]


class UnsupportedPackageManagerError(Exception):
    """The package manager has no entry in the operations table."""


@dataclass(frozen=True, slots=True)
class PackageManagerOps:
    vulnerability_source: VulnerabilitySource
    outdated: Callable[[ProjectConfig], list[UpdateFinding]]
    publish_date: Callable[[str, str, Path], datetime | None]


def package_manager_ops(name: str) -> PackageManagerOps:
    """Return the operations for a non-Gradle package manager."""
    if name == "gradle":
        raise UnsupportedPackageManagerError(
            "Gradle updates are applied through the Gradle adapter, not a "
            "package-manager command"
        )
    try:
        return PACKAGE_MANAGERS[name]
    except KeyError:
        raise UnsupportedPackageManagerError(
            f"Unsupported package manager: {name}"
        ) from None


def _npm_publish_date(pkg: str, version: str, project_path: Path) -> datetime | None:
    return dependency_age.get_npm_publish_date(pkg, version, project_path)


def _pypi_publish_date(pkg: str, version: str, project_path: Path) -> datetime | None:
    return dependency_age.get_pypi_publish_date(pkg, version)


def _maven_publish_date(pkg: str, version: str, project_path: Path) -> datetime | None:
    return dependency_age.get_maven_publish_date(pkg, version)


PACKAGE_MANAGERS: Mapping[str, PackageManagerOps] = MappingProxyType(
    {
        "bun": PackageManagerOps("trivy", bun_outdated, _npm_publish_date),
        "uv": PackageManagerOps("uv-audit", uv_outdated, _pypi_publish_date),
        "mvn": PackageManagerOps("trivy", mvn_outdated, _maven_publish_date),
    }
)
