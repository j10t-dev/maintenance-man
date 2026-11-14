"""Update commands for the uv, bun and mvn package managers."""

from pathlib import Path

from maintenance_man.bun_dependencies import (
    BunDependencyError,
    registry_declared_bun_names,
    resolved_bun_versions,
)
from maintenance_man.models.config import PackageManager
from maintenance_man.uv_dependencies import UvDependencyError, declaring_groups


class UpdateCommandError(Exception):
    """The update workspace cannot produce commands for a package update."""


def update_commands(
    manager: PackageManager, pkg: str, installed: str, version: str, workspace: Path
) -> list[list[str]]:
    """The commands that move *pkg* to *version* in *workspace*, in run order.

    Raises UpdateCommandError for Gradle, whose saved targets go through the
    Gradle adapter, and for a workspace whose manifest cannot be read. For bun,
    raises UpdateCommandError unless *pkg* is registry-declared in *workspace* and
    resolves there to *installed*. uv and mvn do not read *installed*.
    """
    match manager:
        case "uv":
            return _uv_update_commands(pkg, version, workspace)
        case "bun":
            return _bun_update_commands(pkg, installed, version, workspace)
        case "mvn":
            return [
                [
                    "mvn",
                    "versions:use-dep-version",
                    f"-Dincludes={pkg}",
                    f"-DdepVersion={version}",
                ],
                ["mvn", "versions:commit"],
            ]
        case "gradle":
            msg = (
                "Gradle updates are applied through the Gradle adapter, not a "
                "package-manager command"
            )
            raise UpdateCommandError(msg)


def _bun_update_commands(
    pkg: str, installed: str, version: str, workspace: Path
) -> list[list[str]]:
    try:
        if pkg not in registry_declared_bun_names(workspace):
            msg = (
                f"{pkg} is not declared with a registry version in package.json; "
                "mm does not add or re-source dependencies. Run mm scan again."
            )
            raise UpdateCommandError(msg)
        resolved = resolved_bun_versions(workspace).get(pkg)
    except BunDependencyError as e:
        raise UpdateCommandError(str(e)) from e
    if resolved is None:
        msg = f"{pkg} is not a resolved direct dependency. Run mm scan again."
        raise UpdateCommandError(msg)
    if resolved != installed:
        msg = f"{pkg} is at {resolved}, not {installed} as scanned. Run mm scan again."
        raise UpdateCommandError(msg)
    return [["bun", "add", f"{pkg}@{version}"]]


def _uv_update_commands(pkg: str, version: str, workspace: Path) -> list[list[str]]:
    try:
        groups = declaring_groups(workspace, pkg)
    except UvDependencyError as e:
        raise UpdateCommandError(str(e)) from e
    if not groups:
        return [["uv", "lock", "--upgrade-package", f"{pkg}=={version}"]]
    return [
        ["uv", "add", f"{pkg}=={version}"]
        if group is None
        else ["uv", "add", "--group", group, f"{pkg}=={version}"]
        for group in groups
    ]
