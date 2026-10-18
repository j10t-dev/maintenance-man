"""CycloneDX inventory checks: the envelope when the inventory is read, then
every nested Maven module against the resolution report."""

from collections.abc import Iterator, Mapping
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from maintenance_man.gradle import GradleError
from maintenance_man.models.gradle import ModuleId, ResolutionReport, ScopeId


def load_inventory(path: Path) -> list[dict[str, object]]:
    """Read the inventory envelope and return its top-level components; nested
    rows wait for inventory_scopes, so an incomplete resolution is reported first.

    Raises GradleError for a missing, unreadable, malformed, pre-1.5, empty or
    non-Maven inventory.
    """
    try:
        envelope = _Envelope.model_validate_json(path.read_bytes())
    except FileNotFoundError as e:
        msg = (
            f"cyclonedxBom produced no inventory at {path}; "
            "is org.cyclonedx.bom 3.4.1 applied?"
        )
        raise GradleError(msg) from e
    except (OSError, ValueError) as e:
        msg = f"malformed CycloneDX inventory {path}: {e}"
        raise GradleError(msg) from e
    if envelope.bom_format != "CycloneDX":
        msg = f"{path} is not a CycloneDX document"
        raise GradleError(msg)
    if _spec_version(envelope.spec_version) < (1, 5):
        msg = (
            f"unsupported CycloneDX spec version {envelope.spec_version!r} in {path}; "
            "mm requires 1.5 or later"
        )
        raise GradleError(msg)
    if not envelope.components:
        msg = (
            f"CycloneDX inventory {path} has no components; an empty inventory is "
            "an unsupported scan, not a clean result"
        )
        raise GradleError(msg)
    if not any(
        str(row.get("purl", "")).startswith("pkg:maven/") for row in envelope.components
    ):
        msg = (
            f"CycloneDX inventory {path} has no Maven components; "
            "the scan scope is unsupported, not clean"
        )
        raise GradleError(msg)
    return envelope.components


def inventory_scopes(
    components: list[dict[str, object]], report: ResolutionReport
) -> dict[ModuleId, frozenset[ScopeId]]:
    """Map each resolved module to its selected scopes once the inventory covers
    exactly the resolved modules.

    Local subproject rows must match the report's local project identities.
    Raises GradleError for a malformed or unverified nested row and for a
    coverage gap in either direction.
    """
    local_projects = {
        project.project_path: project.module for project in report.local_projects
    }
    try:
        modules = set(
            _maven_modules(_COMPONENTS.validate_python(components), local_projects)
        )
    except ValueError as exc:
        msg = f"Malformed CycloneDX inventory: {exc}"
        raise GradleError(msg) from exc
    scopes = report.module_scopes()
    errors = [
        *(
            f"Inventory module has no selected resolution identity: {module}"
            for module in sorted(
                modules, key=lambda m: (m.group, m.artifact, m.version)
            )
            if module not in scopes
        ),
        *(
            f"resolved module missing from inventory: {module}"
            for module in scopes
            if module not in modules
        ),
    ]
    if errors:
        msg = "Incomplete Gradle inventory: " + "; ".join(errors)
        raise GradleError(msg)
    return scopes


def _spec_version(raw: object) -> tuple[int, ...]:
    """Parse a CycloneDX specVersion as a numeric tuple. Unparsable sorts lowest.

    A floor rather than an equality: a plugin patch bump that emits a newer
    schema must not turn every Gradle scan into a hard error.
    """
    try:
        return tuple(int(part) for part in str(raw).split("."))
    except ValueError:
        return (0,)


def _maven_modules(
    rows: tuple[_Component, ...], local_projects: Mapping[str, ModuleId]
) -> Iterator[ModuleId]:
    for row in rows:
        purl = row.purl or ""
        if purl.startswith("pkg:maven/"):
            module = _maven_module(purl)
            paths = parse_qs(urlsplit(purl).query, keep_blank_values=True).get(
                "project_path"
            )
            if paths is None:
                yield module
            elif len(paths) != 1 or local_projects.get(paths[0]) != module:
                msg = "unverified local project identity"
                raise ValueError(msg)
        elif row.type == "library" and not purl:
            msg = "library component has no package identity"
            raise ValueError(msg)
        yield from _maven_modules(row.components, local_projects)


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


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="ignore")
    bom_format: object = Field(default=None, alias="bomFormat")
    spec_version: object = Field(default=None, alias="specVersion")
    components: list[dict[str, object]] = []


class _Component(BaseModel):
    model_config = ConfigDict(extra="ignore")
    type: str | None = None
    purl: str | None = None
    components: tuple[_Component, ...] = ()


_COMPONENTS = TypeAdapter(tuple[_Component, ...])
