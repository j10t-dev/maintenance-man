import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name


class UvDependencyError(Exception):
    """Raised when UV dependency declarations cannot be read or resolved."""


def get_uv_direct_dep_names(project_path: Path) -> set[str]:
    """Return normalised names of direct UV dependencies from pyproject.toml."""
    data = _load_pyproject(project_path)
    return set().union(*_declared_names(data).values())


def declaring_groups(project_path: Path, pkg_name: str) -> list[str | None]:
    """The tables that declare *pkg_name*: None for ``[project.dependencies]``, else
    the dependency group; empty when the package is only transitive or optional."""
    target = canonicalize_name(pkg_name)
    return [
        group
        for group, names in _declared_names(_load_pyproject(project_path)).items()
        if target in names
    ]


def _declared_names(data: dict) -> dict[str | None, set[str]]:
    """Normalised names per declaring table: None for [project.dependencies], else
    the dependency group; optional dependencies are not read."""
    dependencies = data.get("project", {}).get("dependencies", [])
    declared: dict[str | None, set[str]] = {
        None: _requirement_names(dependencies)
        if isinstance(dependencies, list)
        else set()
    }
    groups = data.get("dependency-groups", {})
    for group, specs in groups.items() if isinstance(groups, dict) else ():
        if isinstance(group, str) and isinstance(specs, list):
            declared[group] = _requirement_names(specs)
    return declared


def _requirement_names(specs: list[object]) -> set[str]:
    return {
        name
        for spec in specs
        if isinstance(spec, str) and (name := _extract_requirement_name(spec))
    }


def _load_pyproject(project_path: Path) -> dict:
    pyproject_path = project_path / "pyproject.toml"
    try:
        with pyproject_path.open("rb") as f:
            return tomllib.load(f)
    except (FileNotFoundError, tomllib.TOMLDecodeError) as e:
        msg = f"Failed to read {pyproject_path}: {e}"
        raise UvDependencyError(msg) from e


def _extract_requirement_name(spec: str) -> str | None:
    try:
        requirement = Requirement(spec)
    except InvalidRequirement:
        return None
    return canonicalize_name(requirement.name)
