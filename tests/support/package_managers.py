"""Package-manager operations with a supplied outdated-package check."""

import dataclasses
from collections.abc import Callable

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    UpdateFinding,
)
from maintenance_man.package_managers import PackageManagerOps, package_manager_ops


def ops_with_outdated(
    outdated: Callable[[ProjectConfig], list[UpdateFinding]],
) -> Callable[[str], PackageManagerOps]:
    """Return a scanner table lookup whose entries use *outdated* instead."""

    def lookup(name: str) -> PackageManagerOps:
        return dataclasses.replace(package_manager_ops(name), outdated=outdated)

    return lookup
