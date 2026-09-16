"""Gradle adapter: wrapper invocation and version-catalogue target safety.

Owns every Gradle-specific concern behind catalogue *targets*: the project's
``./gradlew``, the supported catalogue declarations, grouping by shared version
reference, plugin marker coordinates, plugin report validation and the two
adapter-owned temporary outputs.  It performs subprocess and local-file I/O and
owns no persistent cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maintenance_man.env import project_env
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    GradleBlock,
    GradleBlockKind,
    GradleKind,
    GradleMember,
    GradleUpdateTarget,
    SemverTier,
    UpdateFinding,
    VulnFinding,
    classify_semver,
)

GRADLE_CATALOGUE_RELPATH = "gradle/libs.versions.toml"
GRADLE_UPDATE_REPORT_RELPATH = "gradle/libs.versions.updates.toml"
GRADLE_INVENTORY_RELPATH = ".mm-gradle-inventory"
GRADLE_INVENTORY_BOM_RELPATH = ".mm-gradle-inventory/bom.json"
GRADLE_INVENTORY_MARKER_RELPATH = ".mm-gradle-inventory/.mm-owned"
GRADLE_REPORT_MARKER_RELPATH = "gradle/.mm-owned-report"
GRADLE_LOCAL_PROPERTIES_RELPATH = "local.properties"
GRADLE_TIMEOUT_SECONDS = 900

_DISCOVER_ARGS = [
    "versionCatalogUpdate",
    "--interactive",
    "--no-daemon",
    "--console=plain",
]
_BOM_ARGS = [
    "cyclonedxBom",
    "--no-daemon",
    "--console=plain",
    "--rerun-tasks",
    "--no-build-cache",
]
_UNSAFE_TEXT_RE = re.compile(r"[\x00-\x1f\x7f]")
_EXACT_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class GradleError(Exception):
    """Gradle command failure, malformed external output, or unsafe catalogue change."""


@dataclass(frozen=True, slots=True)
class CatalogueVersion:
    """One ``[versions]`` entry. ``value`` is None when the declaration is rich."""

    name: str
    value: str | None
    unsupported: str | None = None


@dataclass(frozen=True, slots=True)
class CatalogueEntry:
    """One ``[libraries]`` or ``[plugins]`` alias as declared in the source."""

    kind: GradleKind
    alias: str
    coordinate: str
    version_ref: str | None
    inline_version: str | None
    unsupported: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind, normalise_alias(self.alias))


@dataclass(frozen=True, slots=True)
class Catalogue:
    """The parsed source catalogue. Comments are not data and are not retained."""

    versions: dict[str, CatalogueVersion]
    entries: dict[tuple[str, str], CatalogueEntry]

    def entry(self, kind: GradleKind, alias: str) -> CatalogueEntry | None:
        return self.entries.get((kind, normalise_alias(alias)))

    def version_of(self, entry: CatalogueEntry) -> CatalogueVersion | None:
        if entry.inline_version is not None:
            return CatalogueVersion(name=entry.alias, value=entry.inline_version)
        if entry.version_ref is not None:
            return self.versions.get(normalise_alias(entry.version_ref))
        return None

    def members_of_ref(self, version_ref: str) -> list[CatalogueEntry]:
        wanted = normalise_alias(version_ref)
        return [
            entry
            for entry in self.entries.values()
            if entry.version_ref is not None
            and normalise_alias(entry.version_ref) == wanted
        ]


@dataclass(frozen=True, slots=True)
class ReportProposal:
    """One entry of a version-catalogue update report."""

    kind: GradleKind
    alias: str
    coordinate: str
    version: str


def discover_gradle_updates(project: ProjectConfig) -> list[UpdateFinding]:
    """Discover catalogue updates without changing the source catalogue.

    Returns eligible-to-evaluate and structurally blocked candidates; it makes no
    age judgement.  Raises GradleError for wrapper failures, report collisions,
    malformed reports and any catalogue mutation by the discovery task.
    """
    root = Path(project.path)
    catalogue_path = root / GRADLE_CATALOGUE_RELPATH
    catalogue = parse_catalogue(catalogue_path)
    before = _digest(catalogue_path)

    with _owned_update_report(root) as report_path:
        run_gradle(root, _DISCOVER_ARGS, label="versionCatalogUpdate")
        if not report_path.is_file():
            raise GradleError(
                f"versionCatalogUpdate produced no report at "
                f"{GRADLE_UPDATE_REPORT_RELPATH} — is version-catalog-update 1.1.1 "
                f"applied to {root}?"
            )
        proposals = parse_update_report(report_path)

    if _digest(catalogue_path) != before:
        raise GradleError(
            f"versionCatalogUpdate modified {GRADLE_CATALOGUE_RELPATH}; "
            "discovery must leave the source catalogue unchanged"
        )

    return build_update_findings(catalogue, proposals)


def parse_catalogue(path: Path) -> Catalogue:
    """Parse the supported subset of a Gradle version catalogue."""
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise GradleError(f"Version catalogue not found: {path}") from e
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError) as e:
        raise GradleError(f"Failed to parse version catalogue {path}: {e}") from e

    versions: dict[str, CatalogueVersion] = {}
    for name, value in _table(raw, "versions", path).items():
        if isinstance(value, str):
            versions[normalise_alias(name)] = CatalogueVersion(name=name, value=value)
        else:
            versions[normalise_alias(name)] = CatalogueVersion(
                name=name,
                value=None,
                unsupported=(
                    f"version '{name}' uses a rich version declaration, which mm "
                    f"does not edit"
                ),
            )

    entries: dict[tuple[str, str], CatalogueEntry] = {}
    for alias, value in _table(raw, "libraries", path).items():
        entry = _parse_library(alias, value)
        entries[entry.key] = entry
    for alias, value in _table(raw, "plugins", path).items():
        entry = _parse_plugin(alias, value)
        entries[entry.key] = entry

    return Catalogue(versions=versions, entries=entries)


def parse_update_report(path: Path) -> list[ReportProposal]:
    """Parse a plugin-generated update report. Comments are not data."""
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError) as e:
        raise GradleError(
            f"malformed version catalogue update report {path}: {e}"
        ) from e

    proposals: list[ReportProposal] = []
    for alias, value in _table(raw, "libraries", path).items():
        if not isinstance(value, str) or value.count(":") != 2:
            raise GradleError(
                f"malformed library entry '{alias}' in {path}: expected "
                f"'group:artifact:version', got {value!r}"
            )
        group, name, version = value.split(":")
        proposals.append(
            ReportProposal(
                kind="library",
                alias=assert_safe_text(alias, "report alias"),
                coordinate=assert_safe_text(f"{group}:{name}", "report coordinate"),
                version=assert_safe_text(version, "report version"),
            )
        )
    for alias, value in _table(raw, "plugins", path).items():
        if not isinstance(value, str) or value.count(":") != 1:
            raise GradleError(
                f"malformed plugin entry '{alias}' in {path}: expected "
                f"'plugin.id:version', got {value!r}"
            )
        plugin_id, version = value.split(":")
        proposals.append(
            ReportProposal(
                kind="plugin",
                alias=assert_safe_text(alias, "report alias"),
                coordinate=assert_safe_text(plugin_id, "report coordinate"),
                version=assert_safe_text(version, "report version"),
            )
        )
    return proposals


def build_update_findings(
    catalogue: Catalogue, proposals: list[ReportProposal]
) -> list[UpdateFinding]:
    """Reconcile report proposals against the source catalogue and group them."""
    findings: list[UpdateFinding] = []
    grouped: dict[str, list[tuple[CatalogueEntry, ReportProposal]]] = {}
    group_refs: dict[str, str | None] = {}

    for proposal in proposals:
        entry = catalogue.entry(proposal.kind, proposal.alias)
        if entry is None:
            findings.append(
                _blocked_finding(
                    proposal.alias,
                    proposal.version,
                    "mapping",
                    f"report alias '{proposal.alias}' is not in the source catalogue",
                )
            )
            continue
        if entry.coordinate != proposal.coordinate:
            findings.append(
                _blocked_finding(
                    entry.alias,
                    proposal.version,
                    "mapping",
                    f"report coordinate '{proposal.coordinate}' does not match the "
                    f"catalogue coordinate '{entry.coordinate}' for alias "
                    f"'{entry.alias}'",
                )
            )
            continue
        if entry.unsupported is not None:
            findings.append(
                _blocked_finding(
                    entry.alias, proposal.version, "mapping", entry.unsupported
                )
            )
            continue

        version = catalogue.version_of(entry)
        if version is None:
            findings.append(
                _blocked_finding(
                    entry.alias,
                    proposal.version,
                    "mapping",
                    f"'{entry.alias}' has no catalogue version (platform/BOM managed); "
                    f"mm does not give it one",
                )
            )
            continue
        if version.value is None:
            findings.append(
                _blocked_finding(
                    version.name,
                    proposal.version,
                    "mapping",
                    version.unsupported
                    or f"version '{version.name}' is not a simple literal",
                )
            )
            continue

        key = (
            f"ref:{normalise_alias(entry.version_ref)}"
            if entry.version_ref is not None
            else f"{entry.kind}:{normalise_alias(entry.alias)}"
        )
        grouped.setdefault(key, []).append((entry, proposal))
        group_refs[key] = version.name if entry.version_ref is not None else None

    for key, pairs in grouped.items():
        version_ref = group_refs[key]
        finding = _group_finding(catalogue, version_ref, pairs)
        findings.append(finding)

    return sorted(findings, key=lambda f: f.pkg_name)


@contextmanager
def generate_gradle_inventory(project: ProjectConfig) -> Iterator[Path]:
    """Yield a freshly generated, validated CycloneDX inventory.

    The whole ``.mm-gradle-inventory`` tree is adapter-owned: marked leftovers
    are reclaimed, caller paths are refused, and owned output is released.  Normal
    Gradle build, problems-report and cache outputs are left alone.
    """
    root = Path(project.path)
    inventory_dir = root / GRADLE_INVENTORY_RELPATH
    claim_owned_dir(inventory_dir, "Gradle inventory directory")
    inventory_dir.mkdir(parents=True)
    (root / GRADLE_INVENTORY_MARKER_RELPATH).write_bytes(b"")
    try:
        run_gradle(root, _BOM_ARGS, label="cyclonedxBom")
        bom = root / GRADLE_INVENTORY_BOM_RELPATH
        _validate_inventory(bom)
        yield bom
    finally:
        _remove_owned_tree(inventory_dir)


def resolve_gradle_vulnerability_target(
    project: ProjectConfig, finding: VulnFinding
) -> GradleUpdateTarget | GradleBlock:
    """Map an advisory to an editable catalogue target, or explain the block.

    Only catalogue **libraries** can own an advisory: mm never infers that
    upgrading a parent, platform or plugin resolves a transitive finding.
    """
    fixed = (finding.fixed_version or "").strip()
    if not fixed:
        return GradleBlock(
            kind="mapping", reason=f"{finding.vuln_id} names no fix version"
        )
    if not _EXACT_VERSION_RE.fullmatch(fixed):
        return GradleBlock(
            kind="conflict",
            reason=(
                f"{finding.vuln_id} does not name a single exact fix version "
                f"({finding.fixed_version!r}); resolve manually"
            ),
        )

    catalogue = parse_catalogue(Path(project.path) / GRADLE_CATALOGUE_RELPATH)
    matches = [
        entry
        for entry in catalogue.entries.values()
        if entry.kind == "library" and entry.coordinate == finding.pkg_name
    ]
    if not matches:
        return GradleBlock(
            kind="mapping",
            reason=(
                f"no catalogue library owns {finding.pkg_name}; it is transitive, "
                f"platform-owned or a plugin implementation dependency — resolve "
                f"manually"
            ),
        )
    identities = {
        ("ref", normalise_alias(entry.version_ref))
        if entry.version_ref is not None
        else (entry.kind, entry.alias)
        for entry in matches
    }
    if len(identities) > 1:
        return GradleBlock(
            kind="conflict",
            reason=(
                f"{finding.pkg_name} is declared by more than one independently "
                f"versioned catalogue alias; resolve manually"
            ),
        )

    entry = matches[0]
    if entry.unsupported is not None:
        return GradleBlock(kind="mapping", reason=entry.unsupported)

    version = catalogue.version_of(entry)
    if version is None:
        return GradleBlock(
            kind="mapping",
            reason=(
                f"'{entry.alias}' has no catalogue version (platform/BOM managed); "
                f"mm does not give it one"
            ),
        )
    if version.value is None:
        return GradleBlock(
            kind="mapping",
            reason=version.unsupported
            or f"version '{version.name}' is not a simple literal",
        )

    entries = (
        catalogue.members_of_ref(entry.version_ref)
        if entry.version_ref is not None
        else [entry]
    )
    return GradleUpdateTarget(
        version_ref=version.name if entry.version_ref is not None else None,
        members=[
            GradleMember(
                kind=member.kind,
                alias=assert_safe_text(member.alias, "catalogue alias"),
                coordinate=assert_safe_text(member.coordinate, "catalogue coordinate"),
                installed_version=version.value,
            )
            for member in entries
        ],
        target_version=assert_safe_text(fixed, "fix version"),
    )


def run_gradle(
    root: Path, args: list[str], *, label: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the project's wrapper with a bounded timeout and isolated environment."""
    wrapper = root / "gradlew"
    if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
        raise GradleError(f"No executable Gradle wrapper at {wrapper}")

    label = label or args[0]
    try:
        completed = subprocess.run(
            [str(wrapper), *args],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=GRADLE_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            env=project_env(),
        )
    except subprocess.TimeoutExpired as e:
        raise GradleError(
            f"./gradlew {label} timed out after {GRADLE_TIMEOUT_SECONDS}s in {root}"
        ) from e

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[-2000:]
        raise GradleError(
            f"./gradlew {label} failed (exit {completed.returncode}): {detail}"
        )
    return completed


def claim_owned_file(path: Path, marker: Path, label: str) -> None:
    """Claim a generated file path, reclaiming only mm's own leftover.

    *marker* is a zero-byte sibling that mm writes before invoking Gradle, so
    a file left behind by a killed run is recognisable and a caller-authored
    file at the same path is not.  Reclaim never inspects the file's content:
    a report is written by the Gradle plugin, not by mm.
    """
    if path.is_symlink() or marker.is_symlink():
        raise _collision(path, label)
    if not path.exists():
        marker.unlink(missing_ok=True)
        return
    if not marker.is_file():
        raise _collision(path, label)
    path.unlink()


def claim_owned_dir(path: Path, label: str) -> None:
    """Claim a generated directory, reclaiming only a marked mm leftover."""
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise _collision(path, label)
    if not path.exists():
        return
    marker = path / Path(GRADLE_INVENTORY_MARKER_RELPATH).name
    if marker.is_symlink() or not marker.is_file():
        raise _collision(path, label)
    shutil.rmtree(path)


def workspace_environment_reason(source_root: Path, workspace_root: Path) -> str | None:
    """Explain why a workspace build could not resolve the Android SDK.

    ``mm update`` applies inside a jj workspace, which checks out tracked files
    only.  A gitignored ``local.properties`` — where Android projects keep
    ``sdk.dir`` — is therefore absent there, and ``project_env()`` adds nothing
    to the inherited environment.  Returns None when the SDK is reachable or
    the project does not depend on ``local.properties`` at all.
    """
    env = project_env()
    if env.get("ANDROID_HOME") or env.get("ANDROID_SDK_ROOT"):
        return None
    source = source_root / GRADLE_LOCAL_PROPERTIES_RELPATH
    if not source.is_file():
        return None
    if (workspace_root / GRADLE_LOCAL_PROPERTIES_RELPATH).is_file():
        return None
    return (
        f"{source} is untracked, so it is absent from the update workspace at "
        f"{workspace_root} and Gradle cannot resolve sdk.dir there. Export "
        f"ANDROID_HOME or ANDROID_SDK_ROOT before running mm update, or track "
        f"local.properties in the repository."
    )


def normalise_alias(name: str) -> str:
    """Gradle treats '-', '_' and '.' as equivalent alias separators."""
    return name.replace("_", "-").replace(".", "-")


def assert_safe_text(value: str, label: str) -> str:
    """Reject report data that cannot be safely written to a TOML document."""
    if not value or _UNSAFE_TEXT_RE.search(value):
        raise GradleError(f"unsafe {label}: {value!r}")
    return value


def _collision(path: Path, label: str) -> GradleError:
    return GradleError(
        f"Refusing to overwrite an existing {label} at {path}. "
        f"Move or remove it, then rerun."
    )


@contextmanager
def _owned_update_report(root: Path) -> Iterator[Path]:
    """Yield the adapter-owned report path; always release it on exit.

    The marker is written before the path is handed out, so a run killed
    between here and the ``finally`` leaves a leftover mm can recognise and
    reclaim instead of refusing every subsequent scan.
    """
    path = root / GRADLE_UPDATE_REPORT_RELPATH
    marker = root / GRADLE_REPORT_MARKER_RELPATH
    claim_owned_file(path, marker, "version catalogue update report")
    marker.write_bytes(b"")
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)
        marker.unlink(missing_ok=True)


def _group_finding(
    catalogue: Catalogue,
    version_ref: str | None,
    pairs: list[tuple[CatalogueEntry, ReportProposal]],
) -> UpdateFinding:
    """Build one finding for a shared reference or one inline alias."""
    entries = [entry for entry, _ in pairs]
    versions = {proposal.version for _, proposal in pairs}
    display = version_ref or entries[0].coordinate

    if version_ref is not None:
        expected = catalogue.members_of_ref(version_ref)
        missing = sorted(
            {entry.alias for entry in expected} - {entry.alias for entry in entries}
        )
        if missing:
            return _blocked_finding(
                display,
                sorted(versions)[-1],
                "conflict",
                f"incomplete proposal for version reference '{version_ref}': "
                f"{', '.join(missing)} not proposed",
            )
        entries = expected

    if len(versions) != 1:
        return _blocked_finding(
            display,
            sorted(versions)[-1],
            "conflict",
            f"conflicting proposed versions for '{display}': "
            f"{', '.join(sorted(versions))}",
        )

    target_version = assert_safe_text(versions.pop(), "target version")
    installed = catalogue.version_of(entries[0])
    assert installed is not None and installed.value is not None
    members = [
        GradleMember(
            kind=entry.kind,
            alias=assert_safe_text(entry.alias, "catalogue alias"),
            coordinate=assert_safe_text(entry.coordinate, "catalogue coordinate"),
            installed_version=installed.value,
        )
        for entry in entries
    ]
    return UpdateFinding(
        pkg_name=display,
        installed_version=installed.value,
        latest_version=target_version,
        semver_tier=classify_semver(installed.value, target_version),
        gradle_target=GradleUpdateTarget(
            version_ref=version_ref, members=members, target_version=target_version
        ),
    )


def _blocked_finding(
    name: str, proposed: str, kind: GradleBlockKind, reason: str
) -> UpdateFinding:
    """A visible, non-actionable candidate. No target is attached."""
    return UpdateFinding(
        pkg_name=name,
        installed_version="unknown",
        latest_version=proposed,
        semver_tier=SemverTier.UNKNOWN,
        gradle_target=None,
        blocked_reason=reason,
        gradle_block_kind=kind,
    )


def _parse_library(alias: str, value: Any) -> CatalogueEntry:
    if isinstance(value, str):
        parts = value.split(":")
        if len(parts) == 3:
            group, name, version = parts
            return CatalogueEntry("library", alias, f"{group}:{name}", None, version)
        if len(parts) == 2:
            return CatalogueEntry("library", alias, value, None, None)
        return _unsupported_entry(
            "library", alias, f"library '{alias}' is not 'group:artifact[:version]'"
        )

    if not isinstance(value, dict):
        return _unsupported_entry(
            "library", alias, f"library '{alias}' has an unsupported declaration"
        )

    module = value.get("module")
    if isinstance(module, str) and module.count(":") == 1:
        coordinate = module
    elif isinstance(value.get("group"), str) and isinstance(value.get("name"), str):
        coordinate = f"{value['group']}:{value['name']}"
    else:
        return _unsupported_entry(
            "library", alias, f"library '{alias}' has no resolvable coordinate"
        )

    version_ref, inline, unsupported = _parse_version_field(value.get("version"), alias)
    return CatalogueEntry(
        "library", alias, coordinate, version_ref, inline, unsupported
    )


def _parse_plugin(alias: str, value: Any) -> CatalogueEntry:
    if isinstance(value, str) and value.count(":") == 1:
        plugin_id, version = value.split(":")
        return CatalogueEntry("plugin", alias, plugin_id, None, version)
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        return _unsupported_entry(
            "plugin", alias, f"plugin '{alias}' has no resolvable id"
        )

    version_ref, inline, unsupported = _parse_version_field(value.get("version"), alias)
    if unsupported is None and version_ref is None and inline is None:
        unsupported = f"plugin '{alias}' has no catalogue version"
    return CatalogueEntry(
        "plugin", alias, value["id"], version_ref, inline, unsupported
    )


def _parse_version_field(
    version: Any, alias: str
) -> tuple[str | None, str | None, str | None]:
    """Return (version_ref, inline_version, unsupported_reason)."""
    match version:
        case None:
            return (None, None, None)
        case str():
            return (None, version, None)
        case {"ref": str(ref)} if len(version) == 1:
            return (ref, None, None)
        case _:
            return (
                None,
                None,
                f"'{alias}' uses a rich version declaration, which mm does not edit",
            )


def _unsupported_entry(kind: GradleKind, alias: str, reason: str) -> CatalogueEntry:
    return CatalogueEntry(kind, alias, alias, None, None, reason)


def _table(raw: dict[str, Any], name: str, path: Path) -> dict[str, Any]:
    table = raw.get(name) or {}
    if not isinstance(table, dict):
        raise GradleError(f"malformed [{name}] table in {path}")
    return table


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_inventory(path: Path) -> None:
    """A missing, empty, non-Maven or malformed inventory is never a clean scan."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise GradleError(
            f"cyclonedxBom produced no inventory at {path}; is org.cyclonedx.bom "
            f"3.4.1 applied with the documented fixed output paths?"
        ) from e
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        raise GradleError(f"malformed CycloneDX inventory {path}: {e}") from e

    if not isinstance(document, dict):
        raise GradleError(f"malformed CycloneDX inventory {path}: expected an object")
    if document.get("bomFormat") != "CycloneDX":
        raise GradleError(f"{path} is not a CycloneDX document")
    if _spec_version(document.get("specVersion")) < (1, 5):
        raise GradleError(
            f"unsupported CycloneDX spec version "
            f"{document.get('specVersion')!r} in {path}; mm requires 1.5 or later"
        )
    components = document.get("components", [])
    if not isinstance(components, list) or any(
        not isinstance(component, dict) for component in components
    ):
        raise GradleError(
            f"malformed CycloneDX inventory {path}: "
            "components must be an array of objects"
        )
    if not components:
        raise GradleError(
            f"CycloneDX inventory {path} has no components; an empty inventory is "
            f"an unsupported scan, not a clean result"
        )
    if not any(
        str(component.get("purl", "")).startswith("pkg:maven/")
        for component in components
    ):
        raise GradleError(
            f"CycloneDX inventory {path} has no Maven components; the scan scope is "
            f"unsupported, not clean"
        )


def _spec_version(raw: object) -> tuple[int, ...]:
    """Parse a CycloneDX specVersion as a numeric tuple. Unparsable sorts lowest.

    A floor rather than an equality: a plugin patch bump that emits a newer
    schema must not turn every Gradle scan into a hard error.
    """
    try:
        return tuple(int(part) for part in str(raw).split("."))
    except ValueError:
        return (0,)


def _remove_owned_tree(path: Path) -> None:
    try:
        if path.is_symlink():
            path.unlink(missing_ok=True)
            return
        shutil.rmtree(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        raise GradleError(f"failed to remove owned Gradle inventory {path}: {e}") from e
