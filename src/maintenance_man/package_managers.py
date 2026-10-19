"""Update commands for the uv, bun and mvn package managers."""

from pathlib import Path

from maintenance_man.models.config import PackageManager
from maintenance_man.uv_dependencies import UvDependencyError, declaring_groups


class UpdateCommandError(Exception):
    """The update workspace cannot produce commands for a package update."""


def update_commands(
    manager: PackageManager, pkg: str, version: str, workspace: Path
) -> list[list[str]]:
    """The commands that move *pkg* to *version* in *workspace*, in run order.

    Raises UpdateCommandError for Gradle, whose saved targets go through the
    Gradle adapter, and for a workspace whose manifest cannot be read.
    """
    match manager:
        case "uv":
            return _uv_update_commands(pkg, version, workspace)
        case "bun":
            if not (workspace / "package.json").is_file():
                msg = (
                    "package.json is missing from the update workspace; "
                    "check that the project exists on main and rescan"
                )
                raise UpdateCommandError(msg)
            return [["bun", "add", f"{pkg}@{version}"]]
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
