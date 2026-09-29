"""Operations that differ between the uv, bun and mvn package managers."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.publication import PublicationSource
from maintenance_man.models.scan import UpdateFinding
from maintenance_man.outdated import bun_outdated, mvn_outdated, uv_outdated
from maintenance_man.uv_dependencies import (
    UvDependencyError,
    UvDependencyLocation,
    get_uv_dependency_locations,
)

type VulnerabilitySource = Literal["uv-audit", "trivy"]


class UnsupportedPackageManagerError(Exception):
    """The package manager has no entry in the operations table."""


class UpdateCommandError(Exception):
    """The update workspace cannot produce commands for a package update."""


@dataclass(frozen=True, slots=True)
class PackageManagerOps:
    vulnerability_source: VulnerabilitySource
    outdated: Callable[[ProjectConfig], list[UpdateFinding]]
    publication_source: PublicationSource
    update_commands: Callable[[str, str, Path], list[list[str]]]


def package_manager_ops(name: str) -> PackageManagerOps:
    """Return the operations for a non-Gradle package manager."""
    if name == "gradle":
        msg = (
            "Gradle updates are applied through the Gradle adapter, not a "
            "package-manager command"
        )
        raise UnsupportedPackageManagerError(msg)
    try:
        return PACKAGE_MANAGERS[name]
    except KeyError:
        msg = f"Unsupported package manager: {name}"
        raise UnsupportedPackageManagerError(msg) from None


def _bun_update_commands(pkg: str, version: str, workspace: Path) -> list[list[str]]:
    if not (workspace / "package.json").is_file():
        msg = (
            "package.json is missing from the update workspace; "
            "check that the project exists on main and rescan"
        )
        raise UpdateCommandError(msg)
    return [["bun", "add", f"{pkg}@{version}"]]


def _uv_update_commands(pkg: str, version: str, workspace: Path) -> list[list[str]]:
    try:
        locations = get_uv_dependency_locations(workspace, pkg)
    except UvDependencyError as e:
        raise UpdateCommandError(str(e)) from e
    return [_uv_update_command(pkg, version, location) for location in locations]


def _uv_update_command(
    pkg: str, version: str, location: UvDependencyLocation
) -> list[str]:
    if location.kind == "transitive":
        return ["uv", "lock", "--upgrade-package", pkg]
    command = ["uv", "add"]
    if location.kind == "group":
        if location.group is None:
            msg = "UV group dependency location missing group name"
            raise UpdateCommandError(msg)
        command.extend(["--group", location.group])
    command.append(f"{pkg}=={version}")
    return command


def _mvn_update_commands(pkg: str, version: str, workspace: Path) -> list[list[str]]:
    return [
        [
            "mvn",
            "versions:use-dep-version",
            f"-Dincludes={pkg}",
            f"-DdepVersion={version}",
        ],
        ["mvn", "versions:commit"],
    ]


PACKAGE_MANAGERS: Mapping[str, PackageManagerOps] = MappingProxyType(
    {
        "bun": PackageManagerOps("trivy", bun_outdated, "npm", _bun_update_commands),
        "uv": PackageManagerOps("uv-audit", uv_outdated, "pypi", _uv_update_commands),
        "mvn": PackageManagerOps(
            "trivy", mvn_outdated, "central", _mvn_update_commands
        ),
    }
)
