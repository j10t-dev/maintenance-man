import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name


class UvDependencyError(Exception):
    """Raised when UV dependency declarations cannot be read or resolved."""


@dataclass(frozen=True, slots=True)
class UvUngroupedLocation:
    """A runtime declaration or package found only through resolution."""

    kind: Literal["runtime", "transitive"]


@dataclass(frozen=True, slots=True)
class UvGroupLocation:
    """A dependency declaration in the named uv dependency group."""

    group: str


type UvDependencyLocation = UvUngroupedLocation | UvGroupLocation


def get_uv_direct_dep_names(project_path: Path) -> set[str]:
    """Return normalised names of direct UV dependencies from pyproject.toml."""
    data = _load_pyproject(project_path)
    return set().union(*_declared_names(data).values())


def get_uv_dependency_locations(
    project_path: Path, pkg_name: str
) -> list[UvDependencyLocation]:
    """Return UV declaration locations for *pkg_name*.

    Returns runtime and/or group locations when the package is declared directly.
    Returns ``[UvUngroupedLocation(kind="transitive")]`` when no direct declaration
    is found (transitive dependency or optional-extras-only declaration).
    """
    target = canonicalize_name(pkg_name)
    locations: list[UvDependencyLocation] = [
        UvUngroupedLocation(kind="runtime")
        if group is None
        else UvGroupLocation(group=group)
        for group, names in _declared_names(_load_pyproject(project_path)).items()
        if target in names
    ]
    return locations or [UvUngroupedLocation(kind="transitive")]


def _declared_names(data: dict) -> dict[str | None, set[str]]:
    """Normalised names per declaring table: None for [project.dependencies], else
    the dependency group; optional dependencies are not read."""
    declared: dict[str | None, set[str]] = {
        None: _requirement_names(_iter_runtime_dependency_specs(data))
    }
    for group, specs in _iter_dependency_groups(data):
        declared[group] = _requirement_names(specs)
    return declared


def _requirement_names(specs: list[str]) -> set[str]:
    return {name for spec in specs if (name := _extract_requirement_name(spec))}


def _load_pyproject(project_path: Path) -> dict:
    pyproject_path = project_path / "pyproject.toml"
    try:
        with pyproject_path.open("rb") as f:
            return tomllib.load(f)
    except (FileNotFoundError, tomllib.TOMLDecodeError) as e:
        msg = f"Failed to read {pyproject_path}: {e}"
        raise UvDependencyError(msg) from e


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
    return canonicalize_name(requirement.name)
