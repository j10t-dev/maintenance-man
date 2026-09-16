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
from dataclasses import dataclass, field
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
GRADLE_NO_UPDATES_SIGNAL = "There are no updates available"

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

    preserved_semantics: dict[str, Any] = field(default_factory=dict)

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


_APPLY_ARGS = ["versionCatalogApplyUpdates", "--no-daemon", "--console=plain"]


def apply_gradle_update(
    project: ProjectConfig, target: GradleUpdateTarget
) -> GradleBlock | None:
    """Apply exactly one catalogue version group.

    Returns a typed block — and runs no command — when the target or catalogue
    has drifted.  Returns None after a verified apply.  Raises GradleError for
    command, invalid-output or post-mutation safety failures, because mutation
    may already have begun.  The caller must perform the current age check
    first; this function has no VCS side effects.
    """
    root = Path(project.path)
    catalogue_path = root / GRADLE_CATALOGUE_RELPATH

    block = validate_gradle_target(project, target)
    if block is not None:
        return block

    reclaim_gradle_outputs(root)
    before = parse_catalogue(catalogue_path)
    report_text = render_selected_report(target)

    try:
        with _owned_update_report(root) as report_path:
            late = validate_gradle_target(project, target)
            if late is not None:
                return late
            report_path.write_text(report_text, encoding="utf-8")
            run_gradle(root, _APPLY_ARGS, label="versionCatalogApplyUpdates")
            _assert_only_target_changed(before, parse_catalogue(catalogue_path), target)
    except OSError as e:
        raise GradleError(f"versionCatalogApplyUpdates failed: {e}") from e
    return None


def validate_gradle_target(
    project: ProjectConfig, target: GradleUpdateTarget
) -> GradleBlock | None:
    """Confirm the catalogue still matches the recorded pre-update target."""
    return _validate_catalogue_state(project, target, expect_applied=False)


def validate_gradle_recovery(
    project: ProjectConfig, target: GradleUpdateTarget
) -> GradleBlock | None:
    """Confirm a manual repair already carries the intended versions.

    Never applies changes; a different manual fix requires a rescan.
    """
    return _validate_catalogue_state(project, target, expect_applied=True)


def validate_gradle_target_shape(target: GradleUpdateTarget) -> GradleBlock | None:
    """Validate serialized target metadata before indexing or effect."""
    reason = None
    if not target.members:
        reason = "empty Gradle target"
    elif target.version_ref is None and len(target.members) != 1:
        reason = "inline Gradle target must have exactly one member"
    elif len({(m.kind, normalise_alias(m.alias)) for m in target.members}) != len(
        target.members
    ):
        reason = "duplicate Gradle target aliases"
    elif (
        target.version_ref is not None
        and len({member.installed_version for member in target.members}) != 1
    ):
        reason = "inconsistent installed versions in shared Gradle target"
    else:
        try:
            assert_safe_text(target.target_version, "target version")
            if target.version_ref is not None:
                assert_safe_text(target.version_ref, "version reference")
            for member in target.members:
                assert_safe_text(member.alias, "catalogue alias")
                assert_safe_text(member.coordinate, "catalogue coordinate")
                assert_safe_text(member.installed_version, "installed version")
        except GradleError as e:
            reason = str(e)
    return (
        GradleBlock(kind="stale", reason=f"{reason}; run 'mm scan' again")
        if reason
        else None
    )


def render_selected_report(target: GradleUpdateTarget) -> str:
    """Render an update report containing only *target*'s entries."""
    version = assert_safe_text(target.target_version, "target version")
    sections: list[str] = []
    for kind, heading in (("library", "[libraries]"), ("plugin", "[plugins]")):
        members = [member for member in target.members if member.kind == kind]
        if not members:
            continue
        lines = [heading]
        for member in members:
            coordinate = assert_safe_text(member.coordinate, "catalogue coordinate")
            lines.append(
                f"{_toml_string(assert_safe_text(member.alias, 'catalogue alias'))} = "
                f"{_toml_string(f'{coordinate}:{version}')}"
            )
        sections.append("\n".join(lines))
    return "\n\n".join(sections) + "\n"


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
        completed = run_gradle(root, _DISCOVER_ARGS, label="versionCatalogUpdate")
        if not report_path.is_file():
            # Plugin 1.1.1 logs this signal and omits the report when no
            # candidates remain. An unexplained missing report is still an error.
            output = f"{completed.stdout}\n{completed.stderr}"
            if not any(
                line.strip() == GRADLE_NO_UPDATES_SIGNAL for line in output.splitlines()
            ):
                raise GradleError(
                    f"versionCatalogUpdate produced no report at "
                    f"{GRADLE_UPDATE_REPORT_RELPATH} — is version-catalog-update 1.1.1 "
                    f"applied to {root}?"
                )
            proposals = []
        else:
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

    preserved: dict[str, Any] = {
        key: value
        for key, value in raw.items()
        if key not in {"versions", "libraries", "plugins"}
    }
    preserved = {"sections": preserved}
    preserved["rich_versions"] = {
        normalise_alias(name): value
        for name, value in _table(raw, "versions", path).items()
        if not isinstance(value, str)
    }
    preserved["rich_entries"] = {
        entry.key: value
        for heading, kind in (("libraries", "library"), ("plugins", "plugin"))
        for alias, value in _table(raw, heading, path).items()
        if (entry := entries[(kind, normalise_alias(alias))]).unsupported is not None
    }
    return Catalogue(versions=versions, entries=entries, preserved_semantics=preserved)


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
                _known_group_block(
                    catalogue,
                    catalogue.members_of_ref(entry.version_ref)
                    if entry.version_ref is not None
                    else [entry],
                    entry.version_ref,
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
def owned_gradle_inventory(project: ProjectConfig) -> Iterator[Path]:
    """Claim and yield the adapter-owned ``.mm-gradle-inventory`` directory.

    Marked leftovers are reclaimed, caller paths are refused, and owned output
    is released on exit.  Normal Gradle build, problems-report and cache
    outputs are left alone.
    """
    root = Path(project.path)
    inventory_dir = root / GRADLE_INVENTORY_RELPATH
    _validate_owned_output_parents(root)
    claim_owned_dir(inventory_dir, "Gradle inventory directory")
    try:
        inventory_dir.mkdir(parents=True)
    except OSError as exc:
        raise GradleError(f"Could not create Gradle inventory: {exc}") from exc
    try:
        (inventory_dir / ".mm-owned").write_bytes(b"")
    except OSError as exc:
        _remove_owned_tree(inventory_dir)
        raise GradleError(f"Could not create Gradle inventory: {exc}") from exc
    try:
        yield inventory_dir
    finally:
        _validate_owned_output_parents(root)
        marker = inventory_dir / ".mm-owned"
        if inventory_dir.is_symlink() or marker.is_symlink() or not marker.is_file():
            raise GradleError("Gradle inventory ownership changed during operation")
        _remove_owned_tree(inventory_dir)


@contextmanager
def generate_gradle_inventory(project: ProjectConfig) -> Iterator[Path]:
    """Yield a freshly generated, validated CycloneDX inventory."""
    with owned_gradle_inventory(project) as directory:
        try:
            run_gradle(Path(project.path), _BOM_ARGS, label="cyclonedxBom")
            bom = directory / "bom.json"
            _validate_inventory(bom)
        except OSError as exc:
            raise GradleError(f"Could not generate Gradle inventory: {exc}") from exc
        yield bom


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
    _validate_owned_output_parents(root)
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

    except (OSError, UnicodeDecodeError) as e:
        raise GradleError(f"Could not run ./gradlew {label} in {root}: {e}") from e

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
    try:
        if path.is_symlink() or marker.is_symlink():
            raise _collision(path, label)
        if not path.exists():
            marker.unlink(missing_ok=True)
            return
        if not marker.is_file():
            raise _collision(path, label)
        path.unlink()
    except OSError as e:
        raise GradleError(f"Could not claim {label} at {path}: {e}") from e


def claim_owned_dir(path: Path, label: str) -> None:
    """Claim a generated directory, reclaiming only a marked mm leftover."""
    try:
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise _collision(path, label)
        if not path.exists():
            return
        marker = path / Path(GRADLE_INVENTORY_MARKER_RELPATH).name
        if marker.is_symlink() or not marker.is_file():
            raise _collision(path, label)
        shutil.rmtree(path)
    except OSError as e:
        raise GradleError(f"Could not claim {label} at {path}: {e}") from e


def _validate_owned_output_parents(root: Path) -> None:
    """Refuse fixed output parents that redirect adapter ownership."""
    try:
        report_parent = (root / GRADLE_UPDATE_REPORT_RELPATH).parent
        if root.is_symlink():
            raise _collision(root, "Gradle project directory")
        if report_parent.is_symlink() or (
            report_parent.exists() and not report_parent.is_dir()
        ):
            raise _collision(report_parent, "Gradle report directory")
    except OSError as e:
        raise GradleError(
            f"Could not inspect Gradle output parents in {root}: {e}"
        ) from e


def reclaim_gradle_outputs(root: Path) -> None:
    """Release only fixed marked adapter leftovers before application or recovery."""
    report = root / GRADLE_UPDATE_REPORT_RELPATH
    marker = root / GRADLE_REPORT_MARKER_RELPATH
    inventory = root / GRADLE_INVENTORY_RELPATH
    _validate_owned_output_parents(root)
    try:
        claim_owned_file(report, marker, "version catalogue update report")
        marker.unlink(missing_ok=True)
        claim_owned_dir(inventory, "Gradle inventory directory")
    except (OSError, GradleError) as e:
        raise GradleError(
            f"Could not reclaim interrupted Gradle outputs in {root}: {e}"
        ) from e


def workspace_environment_reason(
    source_root: Path, workspace_root: Path, *, tracked_local_properties: bool = False
) -> str | None:
    """Explain why a workspace build could not resolve the Android SDK.

    ``mm update`` applies inside a jj workspace, which checks out tracked files
    only.  A gitignored ``local.properties`` — where Android projects keep
    ``sdk.dir`` — is therefore absent there, and ``project_env()`` adds nothing
    to the inherited environment. Tracked-file evidence must come from the
    selected revision, never from a prospective workspace directory. Returns
    None when that evidence or the environment supplies the SDK, or the source
    does not depend on ``local.properties``.
    """
    env = project_env()
    if env.get("ANDROID_HOME") or env.get("ANDROID_SDK_ROOT"):
        return None
    source = source_root / GRADLE_LOCAL_PROPERTIES_RELPATH
    if not source.is_file():
        return None
    if tracked_local_properties:
        return None
    return (
        f"{source} is not a tracked regular file in the selected revision, so it is "
        f"absent from the update workspace at "
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
    _validate_owned_output_parents(root)
    claim_owned_file(path, marker, "version catalogue update report")
    try:
        try:
            marker.write_bytes(b"")
        except OSError as e:
            raise GradleError(f"Could not mark Gradle update report {path}: {e}") from e
        yield path
    finally:
        try:
            _validate_owned_output_parents(root)
            path.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
        except OSError as e:
            raise GradleError(
                f"Could not remove owned Gradle update report {path}: {e}"
            ) from e


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
            {entry.key for entry in expected} - {entry.key for entry in entries}
        )
        if missing:
            return _known_group_block(
                catalogue,
                expected,
                version_ref,
                display,
                sorted(versions)[-1],
                "conflict",
                f"incomplete proposal for version reference '{version_ref}': "
                f"{', '.join(f'{kind} {alias}' for kind, alias in missing)} "
                "not proposed",
            )
        entries = expected

    if len(versions) != 1:
        return _known_group_block(
            catalogue,
            entries,
            version_ref,
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


def _known_group_block(
    catalogue: Catalogue,
    entries: list[CatalogueEntry],
    version_ref: str | None,
    name: str,
    proposed: str,
    kind: GradleBlockKind,
    reason: str,
) -> UpdateFinding:
    """Retain known group identity solely to withhold linked findings.

    The installed version is inert metadata, never an approved proposal.
    Structural blocks persist until a fresh scan.
    """
    finding = _blocked_finding(name, proposed, kind, reason)
    installed = catalogue.version_of(entries[0])
    if installed is not None and installed.value is not None:
        finding.gradle_target = GradleUpdateTarget(
            version_ref=version_ref,
            members=[
                GradleMember(
                    kind=entry.kind,
                    alias=entry.alias,
                    coordinate=entry.coordinate,
                    installed_version=installed.value,
                )
                for entry in entries
            ],
            target_version=installed.value,
        )
    return finding


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
    table = raw.get(name, {})
    if not isinstance(table, dict):
        raise GradleError(f"malformed [{name}] table in {path}")
    return table


def _digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as e:
        raise GradleError(f"Could not read Gradle catalogue {path}: {e}") from e


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


def _validate_catalogue_state(
    project: ProjectConfig, target: GradleUpdateTarget, *, expect_applied: bool
) -> GradleBlock | None:
    shape = validate_gradle_target_shape(target)
    if shape is not None:
        return shape
    try:
        catalogue = parse_catalogue(Path(project.path) / GRADLE_CATALOGUE_RELPATH)
    except GradleError as e:
        return GradleBlock(kind="stale", reason=f"{e}; rescan required")

    expected_version = target.target_version if expect_applied else None
    for member in target.members:
        entry = catalogue.entry(member.kind, member.alias)
        if entry is None:
            return GradleBlock(
                kind="stale",
                reason=(
                    f"the catalogue no longer declares {member.kind} "
                    f"'{member.alias}'; rescan required"
                ),
            )
        if entry.coordinate != member.coordinate:
            return GradleBlock(
                kind="stale",
                reason=(
                    f"'{member.alias}' now resolves to {entry.coordinate}, not "
                    f"{member.coordinate}; rescan required"
                ),
            )
        if entry.unsupported is not None:
            return GradleBlock(kind="mapping", reason=entry.unsupported)
        if _ref_key(entry) != (
            normalise_alias(target.version_ref) if target.version_ref else None
        ):
            return GradleBlock(
                kind="stale",
                reason=(
                    f"'{member.alias}' no longer shares version reference "
                    f"'{target.version_ref}'; rescan required"
                ),
            )
        version = catalogue.version_of(entry)
        if version is None or version.value is None:
            return GradleBlock(
                kind="mapping",
                reason=(
                    f"'{member.alias}' no longer has a simple catalogue version; "
                    f"resolve manually"
                ),
            )
        expected = expected_version or member.installed_version
        if version.value != expected:
            return GradleBlock(
                kind="stale",
                reason=(
                    f"'{member.alias}' is at {version.value}, expected {expected}; "
                    f"the catalogue no longer matches the scan; note that an "
                    f"uncommitted catalogue edit is not visible in the update "
                    f"workspace. Rescan required"
                ),
            )

    if target.version_ref is not None:
        current = {entry.key for entry in catalogue.members_of_ref(target.version_ref)}
        recorded = {
            (member.kind, normalise_alias(member.alias)) for member in target.members
        }
        if current != recorded:
            return GradleBlock(
                kind="stale",
                reason=(
                    f"version reference '{target.version_ref}' now covers a different "
                    f"set of aliases; rescan required"
                ),
            )
    return None


def _assert_only_target_changed(
    before: Catalogue, after: Catalogue, target: GradleUpdateTarget
) -> None:
    """The semantic change must be exactly the intended version group.

    Formatting, comment loss and equivalent coordinate notation are accepted
    because both sides are compared as parsed models, not as text.
    """
    if before.preserved_semantics != after.preserved_semantics:
        raise GradleError(
            "versionCatalogApplyUpdates changed bundles or unsupported "
            "catalogue declarations"
        )
    changed = {
        (member.kind, normalise_alias(member.alias)) for member in target.members
    }
    if set(before.entries) != set(after.entries):
        raise GradleError(
            "versionCatalogApplyUpdates added or removed catalogue aliases; "
            "the catalogue change was not the selected group"
        )

    for key, old in before.entries.items():
        new = after.entries[key]
        if old.coordinate != new.coordinate or _ref_key(old) != _ref_key(new):
            raise GradleError(
                f"alias '{old.alias}' changed identity during apply: "
                f"{old.coordinate}/{_ref_key(old)} -> {new.coordinate}/{_ref_key(new)}"
            )
        old_value = _version_value(before, old)
        new_value = _version_value(after, new)
        if key in changed:
            if new.unsupported is not None or new_value is None:
                raise GradleError(
                    f"selected alias {new.alias!r} no longer has a simple version"
                )
            if new_value != target.target_version:
                raise GradleError(
                    f"'{old.alias}' is {new_value!r} after apply, "
                    f"expected {target.target_version!r}"
                )
        elif old_value != new_value:
            raise GradleError(
                f"unexpected change to '{old.alias}': {old_value!r} -> {new_value!r}"
            )

    if set(before.versions) != set(after.versions):
        raise GradleError("versionCatalogApplyUpdates added or removed version entries")

    changed_ref = normalise_alias(target.version_ref) if target.version_ref else None
    for name, old_version in before.versions.items():
        new_version = after.versions[name]
        if name == changed_ref:
            if new_version.value != target.target_version:
                raise GradleError(
                    f"version '{old_version.name}' is {new_version.value!r} after "
                    f"apply, expected {target.target_version!r}"
                )
        elif new_version.value != old_version.value:
            raise GradleError(
                f"unexpected change to version '{old_version.name}': "
                f"{old_version.value!r} -> {new_version.value!r}"
            )


def _version_value(catalogue: Catalogue, entry: CatalogueEntry) -> str | None:
    version = catalogue.version_of(entry)
    return version.value if version is not None else None


def _ref_key(entry: CatalogueEntry) -> str | None:
    return normalise_alias(entry.version_ref) if entry.version_ref else None


def _toml_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
