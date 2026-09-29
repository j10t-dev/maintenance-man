"""Staged CycloneDX inventory parsing and binding to a resolution report.

Construction validates only the envelope and top-level components. Nested
identity validation waits for :func:`bind_inventory`, so incomplete resolution
and frozen scope/producer mismatches are reported before malformed nested rows.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeIs
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import ValidationError

from maintenance_man.gradle import GradleError
from maintenance_man.models.gradle import ModuleId, ResolutionReport, ScopeId


@dataclass(frozen=True)
class CycloneDxInventory:
    components: tuple[Mapping[str, object], ...]


@dataclass(frozen=True)
class InventoryCoverage:
    modules: tuple[ModuleId, ...]
    scopes: Mapping[ModuleId, frozenset[ScopeId]]
    errors: tuple[str, ...]


def _spec_version(raw: object) -> tuple[int, ...]:
    """Parse a CycloneDX specVersion as a numeric tuple. Unparsable sorts lowest.

    A floor rather than an equality: a plugin patch bump that emits a newer
    schema must not turn every Gradle scan into a hard error.
    """
    try:
        return tuple(int(part) for part in str(raw).split("."))
    except ValueError:
        return (0,)


def _is_object(value: object) -> TypeIs[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _top_level_components(
    document: dict[str, object], source: str
) -> tuple[Mapping[str, object], ...]:
    raw = document.get("components", [])
    components = (
        tuple(row for row in raw if _is_object(row)) if isinstance(raw, list) else ()
    )
    if not isinstance(raw, list) or len(components) != len(raw):
        msg = (
            f"malformed CycloneDX inventory {source}: "
            "components must be an array of objects"
        )
        raise GradleError(msg)
    if not components:
        msg = (
            f"CycloneDX inventory {source} has no components; an empty inventory is "
            f"an unsupported scan, not a clean result"
        )
        raise GradleError(msg)
    if not any(
        str(component.get("purl", "")).startswith("pkg:maven/")
        for component in components
    ):
        msg = (
            f"CycloneDX inventory {source} has no Maven components; the scan scope "
            f"is unsupported, not clean"
        )
        raise GradleError(msg)
    return components


def parse_inventory_text(text: str, *, source: str) -> CycloneDxInventory:
    """A malformed, empty or non-Maven inventory is never a clean scan."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as e:
        msg = f"malformed CycloneDX inventory {source}: {e}"
        raise GradleError(msg) from e
    if not isinstance(document, dict):
        msg = f"malformed CycloneDX inventory {source}: expected an object"
        raise GradleError(msg)
    if document.get("bomFormat") != "CycloneDX":
        msg = f"{source} is not a CycloneDX document"
        raise GradleError(msg)
    if _spec_version(document.get("specVersion")) < (1, 5):
        msg = (
            f"unsupported CycloneDX spec version "
            f"{document.get('specVersion')!r} in {source}; mm requires 1.5 or later"
        )
        raise GradleError(msg)
    return CycloneDxInventory(components=_top_level_components(document, source))


def load_inventory(path: Path) -> tuple[bytes, CycloneDxInventory]:
    """Read *path* once; the original bytes stay available for digesting."""
    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8")
    except FileNotFoundError as e:
        msg = (
            f"cyclonedxBom produced no inventory at {path}; is org.cyclonedx.bom "
            f"3.4.1 applied with the documented fixed output paths?"
        )
        raise GradleError(msg) from e
    except (UnicodeDecodeError, OSError) as e:
        msg = f"malformed CycloneDX inventory {path}: {e}"
        raise GradleError(msg) from e
    return payload, parse_inventory_text(text, source=str(path))


def _maven_module(purl: str) -> ModuleId:
    identity = purl.removeprefix("pkg:maven/").split("?", 1)[0].split("#", 1)[0]
    coordinate, separator, version = identity.rpartition("@")
    group, slash, artifact = coordinate.partition("/")
    if not (separator and slash and group and artifact and version):
        msg = "malformed Maven purl"
        raise ValueError(msg)
    return ModuleId(
        group=unquote(group), artifact=unquote(artifact), version=unquote(version)
    )


def _row_purl(row: object) -> tuple[dict[str, object], str]:
    if not _is_object(row):
        msg = "component must be an object"
        raise ValueError(msg)
    purl = row.get("purl", "")
    if not isinstance(purl, str):
        msg = "component purl must be a string"
        raise ValueError(msg)
    return row, purl


def _visit_row(
    row: object,
    local_projects: Mapping[str, ModuleId],
    found: set[ModuleId],
) -> None:
    row, purl = _row_purl(row)
    if purl.startswith("pkg:maven/"):
        module = _maven_module(purl)
        qualifiers = parse_qs(urlsplit(purl).query, keep_blank_values=True)
        if "project_path" in qualifiers:
            paths = qualifiers["project_path"]
            if len(paths) != 1 or local_projects.get(paths[0]) != module:
                msg = "unverified local project identity"
                raise ValueError(msg)
        else:
            found.add(module)
    elif row.get("type") == "library" and not purl:
        msg = "library component has no package identity"
        raise ValueError(msg)
    _visit_rows(row.get("components", []), local_projects, found)


def _visit_rows(
    rows: object,
    local_projects: Mapping[str, ModuleId],
    found: set[ModuleId],
) -> None:
    if not isinstance(rows, (list, tuple)):
        msg = "components must be an array"
        raise ValueError(msg)
    for row in rows:
        _visit_row(row, local_projects, found)


def _bound_modules(
    inventory: CycloneDxInventory, report: ResolutionReport
) -> tuple[ModuleId, ...]:
    local_projects = {
        project.project_path: project.module for project in report.local_projects
    }
    found: set[ModuleId] = set()
    try:
        _visit_rows(inventory.components, local_projects, found)
    except (ValueError, TypeError, ValidationError) as exc:
        msg = f"Malformed CycloneDX inventory: {exc}"
        raise GradleError(msg) from exc
    return tuple(
        sorted(
            found, key=lambda module: (module.group, module.artifact, module.version)
        )
    )


def _module_scopes(
    report: ResolutionReport,
) -> dict[ModuleId, frozenset[ScopeId]]:
    scopes: dict[ModuleId, set[ScopeId]] = {}
    for result in report.scopes:
        for component in result.components:
            if component.module is not None:
                scopes.setdefault(component.module, set()).add(result.scope)
    return {module: frozenset(found) for module, found in scopes.items()}


def _coverage_errors(
    modules: tuple[ModuleId, ...], scopes: Mapping[ModuleId, frozenset[ScopeId]]
) -> tuple[str, ...]:
    inventory = set(modules)
    return tuple(
        f"Inventory module has no selected resolution identity: {module}"
        for module in modules
        if module not in scopes
    ) + tuple(
        f"resolved module missing from inventory: {module}"
        for module in scopes
        if module not in inventory
    )


def bind_inventory(
    inventory: CycloneDxInventory, report: ResolutionReport
) -> InventoryCoverage:
    """Validate nested identities and compare them with the resolved graph."""
    modules = _bound_modules(inventory, report)
    scopes = _module_scopes(report)
    return InventoryCoverage(
        modules=modules, scopes=scopes, errors=_coverage_errors(modules, scopes)
    )
