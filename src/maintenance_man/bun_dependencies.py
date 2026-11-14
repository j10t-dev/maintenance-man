"""Registry-declared names and resolved direct versions of a bun project."""

import json
from pathlib import Path

from maintenance_man.process import run_captured

_DECLARING_TABLES = ("dependencies", "devDependencies")
_EXCLUDING_TABLES = (
    "optionalDependencies",
    "peerDependencies",
    "overrides",
    "resolutions",
)
_TREE_BRANCHES = ("├── ", "└── ")


class BunDependencyError(Exception):
    """A bun manifest or dependency tree cannot be read."""


def registry_declared_bun_names(project_path: Path) -> set[str]:
    """Names in exactly one of dependencies and devDependencies of the root
    package.json, with a string specifier without ':' or '/', and absent from
    optionalDependencies, peerDependencies, overrides and resolutions. Raises
    BunDependencyError when the file is missing, unreadable or not a JSON object,
    or when one of those tables is not an object."""
    tables = _load_tables(project_path)
    declarations: dict[str, list[object]] = {}
    for table in _DECLARING_TABLES:
        for name, specifier in tables[table].items():
            declarations.setdefault(name, []).append(specifier)
    excluded = set().union(*(tables[table] for table in _EXCLUDING_TABLES))
    return {
        name
        for name, specifiers in declarations.items()
        if len(specifiers) == 1
        and _is_registry_specifier(specifiers[0])
        and name not in excluded
    }


def resolved_bun_versions(project_path: Path) -> dict[str, str]:
    """The version bun resolves for each direct dependency, from `bun pm ls`.
    Raises BunDependencyError when the command fails, a tree line is not
    <name>@<version>, or a name is listed twice."""
    completed = run_captured(
        ["bun", "pm", "ls"],
        project_path,
        timeout=120,
        label="bun pm ls",
        error=BunDependencyError,
    )
    versions: dict[str, str] = {}
    for line in completed.stdout.splitlines()[1:]:
        if not line.strip():
            continue
        name, version = _parse_tree_line(line)
        if name in versions:
            msg = f"bun pm ls: {name} is listed twice"
            raise BunDependencyError(msg)
        versions[name] = version
    return versions


def _load_tables(project_path: Path) -> dict[str, dict[str, object]]:
    path = project_path / "package.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        msg = f"Failed to read {path}: {e}"
        raise BunDependencyError(msg) from e
    if not isinstance(data, dict):
        msg = f"Failed to read {path}: the top level is not an object"
        raise BunDependencyError(msg)
    tables: dict[str, dict[str, object]] = {}
    for table in (*_DECLARING_TABLES, *_EXCLUDING_TABLES):
        value = data.get(table, {})
        if not isinstance(value, dict):
            msg = f"Failed to read {path}: {table} is not an object"
            raise BunDependencyError(msg)
        tables[table] = value
    return tables


def _is_registry_specifier(specifier: object) -> bool:
    return isinstance(specifier, str) and ":" not in specifier and "/" not in specifier


def _parse_tree_line(line: str) -> tuple[str, str]:
    entry = line[4:] if line.startswith(_TREE_BRANCHES) else ""
    separator = entry.find("@", 1)
    name, version = entry[:separator], entry[separator + 1 :]
    if separator == -1 or not version or any(c.isspace() for c in entry):
        msg = f"bun pm ls: unrecognised line: {line!r}"
        raise BunDependencyError(msg)
    return name, version
