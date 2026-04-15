from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from packaging.requirements import InvalidRequirement, Requirement


class UvDependencyError(Exception):
    """Raised when UV dependency declarations cannot be read or resolved."""


_PEP503_NORMALISE_RE = re.compile(r"[-_.]+")

# Intentionally excludes [project.optional-dependencies]. maintenance-man only
# supports UV runtime dependencies and dependency groups for scan/update flows.
@dataclass(frozen=True, slots=True)
class UvDependencyLocation:
    kind: Literal["runtime", "group"]
    group: str | None = None


def normalise_pkg_name(name: str) -> str:
    """Normalise a package name per PEP 503."""
    return _PEP503_NORMALISE_RE.sub("-", name).lower()


def get_uv_direct_dep_names(project_path: Path) -> set[str]:
    """Return normalised names of direct UV dependencies from pyproject.toml."""
    data = _load_pyproject(project_path)
    names: set[str] = set()

    for spec in _iter_runtime_dependency_specs(data):
        if name := _extract_requirement_name(spec):
            names.add(name)

    for _, specs in _iter_dependency_groups(data):
        for spec in specs:
            if name := _extract_requirement_name(spec):
                names.add(name)

    return names


def get_uv_dependency_locations(
    project_path: Path, pkg_name: str
) -> list[UvDependencyLocation]:
    """Return every direct UV declaration location matching *pkg_name*."""
    data = _load_pyproject(project_path)
    target = normalise_pkg_name(pkg_name)
    locations: list[UvDependencyLocation] = []

    runtime_specs = _iter_runtime_dependency_specs(data)
    if any(_extract_requirement_name(spec) == target for spec in runtime_specs):
        locations.append(UvDependencyLocation(kind="runtime"))

    for group, specs in _iter_dependency_groups(data):
        if any(_extract_requirement_name(spec) == target for spec in specs):
            locations.append(UvDependencyLocation(kind="group", group=group))

    if not locations:
        raise UvDependencyError(
            "Package reported as direct dependency but no matching declaration "
            f"was found in pyproject.toml: {pkg_name}"
        )

    return locations


def _load_pyproject(project_path: Path) -> dict:
    pyproject_path = project_path / "pyproject.toml"
    try:
        with open(pyproject_path, "rb") as f:
            return tomllib.load(f)
    except (FileNotFoundError, tomllib.TOMLDecodeError) as e:
        raise UvDependencyError(f"Failed to read {pyproject_path}: {e}") from e


def _iter_runtime_dependency_specs(data: dict) -> list[str]:
    dependencies = data.get("project", {}).get("dependencies", [])
    if not isinstance(dependencies, list):
        return []
    return [spec for spec in dependencies if isinstance(spec, str)]


def _iter_dependency_groups(data: dict) -> list[tuple[str, list[str]]]:
    groups = data.get("dependency-groups", {})
    if not isinstance(groups, dict):
        return []

    entries: list[tuple[str, list[str]]] = []
    for group, specs in groups.items():
        if not isinstance(group, str) or not isinstance(specs, list):
            continue
        entries.append((group, [spec for spec in specs if isinstance(spec, str)]))
    return entries


def _extract_requirement_name(spec: str) -> str | None:
    try:
        requirement = Requirement(spec)
    except InvalidRequirement:
        return None
    return normalise_pkg_name(requirement.name)
