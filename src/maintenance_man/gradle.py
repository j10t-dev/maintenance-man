"""Gradle adapter: wrapper invocation and version-catalogue target safety.

Runs the project's wrapper, parses catalogue declarations and update reports,
groups shared versions, and manages adapter-owned temporary outputs.
"""

import hashlib
import os
import re
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
    classify_semver,
    group_key_for,
    normalise_alias,
)
from maintenance_man.process import run_logged

GRADLE_CATALOGUE_RELPATH = "gradle/libs.versions.toml"
GRADLE_UPDATE_REPORT_RELPATH = "gradle/libs.versions.updates.toml"
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
_APPLY_ARGS = ["versionCatalogApplyUpdates", "--no-daemon", "--console=plain"]
_UNSAFE_TEXT_RE = re.compile(r"[\x00-\x1f\x7f]")
_REPORT_TABLES: tuple[tuple[str, GradleKind, int, str], ...] = (
    ("libraries", "library", 2, "group:artifact:version"),
    ("plugins", "plugin", 1, "plugin.id:version"),
)


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


def apply_gradle_update(
    project: ProjectConfig, target: GradleUpdateTarget
) -> GradleBlock | None:
    """Apply exactly one catalogue version group.

    Returns a typed block — and runs no command — when the target or catalogue
    has drifted.  Returns None after a verified apply.  Raises GradleError for
    command, invalid-output or post-mutation safety failures, because mutation
    may already have begun.  Age and routing eligibility are decided by
    ``mm scan``; this function has no VCS side effects.
    """
    root = Path(project.path)
    before = _checked_catalogue(project, target, expected_version=None)
    if isinstance(before, GradleBlock):
        return before
    try:
        with _owned_update_report(root) as report_path:
            report_path.write_text(render_selected_report(target), encoding="utf-8")
            run_gradle(root, _APPLY_ARGS, label="versionCatalogApplyUpdates")
            after = parse_catalogue(root / GRADLE_CATALOGUE_RELPATH)
            _assert_only_target_changed(before, after, target)
    except OSError as e:
        msg = f"versionCatalogApplyUpdates failed: {e}"
        raise GradleError(msg) from e
    return None


def validate_gradle_recovery(
    project: ProjectConfig, target: GradleUpdateTarget
) -> GradleBlock | None:
    """Confirm a manual repair already carries the intended versions.

    Never applies changes; a different manual fix requires a rescan.
    """
    state = _checked_catalogue(project, target, expected_version=target.target_version)
    return state if isinstance(state, GradleBlock) else None


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
    before = catalogue_digest(root)

    with _owned_update_report(root) as report_path:
        completed = run_gradle(root, _DISCOVER_ARGS, label="versionCatalogUpdate")
        if not report_path.is_file():
            # Plugin 1.1.1 logs this signal and omits the report when no
            # candidates remain. An unexplained missing report is still an error.
            output = f"{completed.stdout}\n{completed.stderr}"
            if not any(
                line.strip() == GRADLE_NO_UPDATES_SIGNAL for line in output.splitlines()
            ):
                msg = (
                    f"versionCatalogUpdate produced no report at "
                    f"{GRADLE_UPDATE_REPORT_RELPATH} — is version-catalog-update 1.1.1 "
                    f"applied to {root}?"
                )
                raise GradleError(msg)
            proposals = []
        else:
            proposals = parse_update_report(report_path)

    if catalogue_digest(root) != before:
        msg = (
            f"versionCatalogUpdate modified {GRADLE_CATALOGUE_RELPATH}; "
            "discovery must leave the source catalogue unchanged"
        )
        raise GradleError(msg)

    return build_update_findings(catalogue, proposals)


def parse_catalogue(path: Path) -> Catalogue:
    """Parse the supported subset of a Gradle version catalogue file."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        msg = f"Version catalogue not found: {path}"
        raise GradleError(msg) from e
    except (UnicodeDecodeError, OSError) as e:
        msg = f"Failed to parse version catalogue {path}: {e}"
        raise GradleError(msg) from e
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        msg = f"Failed to parse version catalogue {path}: {e}"
        raise GradleError(msg) from e

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
    """Parse a plugin-generated update report file. Comments are not data."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        msg = f"malformed version catalogue update report {path}: {e}"
        raise GradleError(msg) from e
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        msg = f"malformed version catalogue update report {path}: {e}"
        raise GradleError(msg) from e

    proposals: list[ReportProposal] = []
    for table, kind, separators, shape in _REPORT_TABLES:
        for alias, value in _table(raw, table, path).items():
            if not isinstance(value, str) or value.count(":") != separators:
                msg = (
                    f"malformed {kind} entry '{alias}' in {path}: expected "
                    f"'{shape}', got {value!r}"
                )
                raise GradleError(msg)
            coordinate, version = value.rsplit(":", 1)
            proposals.append(
                ReportProposal(
                    kind=kind,
                    alias=assert_safe_text(alias, "report alias"),
                    coordinate=assert_safe_text(coordinate, "report coordinate"),
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
        if entry is not None and entry.coordinate != proposal.coordinate:
            findings.append(
                _known_group_block(
                    catalogue,
                    _group_entries(catalogue, entry),
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
        block = _proposal_block(catalogue, entry, proposal)
        if block is not None:
            name, reason = block
            findings.append(_blocked_finding(name, proposal.version, "mapping", reason))
            continue

        assert entry is not None
        version = catalogue.version_of(entry)
        assert version is not None
        key = group_key_for(entry.kind, entry.alias, entry.version_ref)
        grouped.setdefault(key, []).append((entry, proposal))
        group_refs[key] = version.name if entry.version_ref is not None else None

    for key, pairs in grouped.items():
        version_ref = group_refs[key]
        finding = _group_finding(catalogue, version_ref, pairs)
        findings.append(finding)

    return sorted(findings, key=lambda f: f.pkg_name)


def _proposal_block(
    catalogue: Catalogue, entry: CatalogueEntry | None, proposal: ReportProposal
) -> tuple[str, str] | None:
    """The name and reason a proposal cannot be applied, or None when it maps to a
    simple catalogue version."""
    if entry is None:
        return (
            proposal.alias,
            f"report alias '{proposal.alias}' is not in the source catalogue",
        )
    if entry.unsupported is not None:
        return entry.alias, entry.unsupported
    version = catalogue.version_of(entry)
    if version is None:
        return (
            entry.alias,
            f"'{entry.alias}' has no catalogue version (platform/BOM managed); "
            f"mm does not give it one",
        )
    if version.value is None:
        return (
            version.name,
            version.unsupported or f"version '{version.name}' is not a simple literal",
        )
    return None


def run_gradle(
    root: Path, args: list[str], *, label: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the project's wrapper with a bounded timeout and isolated environment."""
    wrapper = root / "gradlew"
    if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
        msg = f"No executable Gradle wrapper at {wrapper}"
        raise GradleError(msg)

    return run_logged(
        [str(wrapper), *args],
        root,
        timeout=GRADLE_TIMEOUT_SECONDS,
        label=f"./gradlew {label or args[0]}",
        error=GradleError,
        stdin=subprocess.DEVNULL,
        capture=True,
    )


def workspace_environment_reason(source_root: Path, workspace_root: Path) -> str | None:
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
    return (
        f"{source} is not a tracked regular file in the selected revision, so it is "
        f"absent from the update workspace at "
        f"{workspace_root} and Gradle cannot resolve sdk.dir there. Export "
        f"ANDROID_HOME or ANDROID_SDK_ROOT before running mm update, or track "
        f"local.properties in the repository."
    )


def assert_safe_text(value: str, label: str) -> str:
    """Reject report data that cannot be safely written to a TOML document."""
    if not value or _UNSAFE_TEXT_RE.search(value):
        msg = f"unsafe {label}: {value!r}"
        raise GradleError(msg)
    return value


def catalogue_digest(root: Path) -> str:
    """SHA-256 of the version catalogue; an unreadable catalogue is a GradleError."""
    path = root / GRADLE_CATALOGUE_RELPATH
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as e:
        msg = f"Could not read Gradle catalogue {path}: {e}"
        raise GradleError(msg) from e


def _collision(path: Path, label: str) -> GradleError:
    return GradleError(
        f"Refusing to overwrite an existing {label} at {path}. "
        f"Move or remove it, then rerun."
    )


@contextmanager
def _owned_update_report(root: Path) -> Iterator[Path]:
    """Yield the update-report path mm owns for one task, then remove the report
    and its marker. A marked leftover from an interrupted run is reclaimed; any
    other file, a symlink, or a redirected project or report directory is
    refused untouched, at entry and again before removal."""
    path = root / GRADLE_UPDATE_REPORT_RELPATH
    marker = root / GRADLE_REPORT_MARKER_RELPATH
    try:
        _refuse_redirected_parents(root)
        _reclaim_leftover(path, marker)
        marker.write_bytes(b"")
    except OSError as e:
        msg = f"Could not claim version catalogue update report at {path}: {e}"
        raise GradleError(msg) from e
    try:
        yield path
    finally:
        try:
            _refuse_redirected_parents(root)
            path.unlink(missing_ok=True)
            marker.unlink(missing_ok=True)
        except OSError as e:
            msg = f"Could not remove owned Gradle update report {path}: {e}"
            raise GradleError(msg) from e


def _refuse_redirected_parents(root: Path) -> None:
    parent = (root / GRADLE_UPDATE_REPORT_RELPATH).parent
    if root.is_symlink():
        raise _collision(root, "Gradle project directory")
    if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
        raise _collision(parent, "Gradle report directory")


def _reclaim_leftover(path: Path, marker: Path) -> None:
    if path.is_symlink() or marker.is_symlink():
        raise _collision(path, "version catalogue update report")
    if not path.exists():
        marker.unlink(missing_ok=True)
        return
    if not marker.is_file():
        raise _collision(path, "version catalogue update report")
    path.unlink()


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
        expected = _group_entries(catalogue, entries[0])
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
    for entry in entries:
        assert_safe_text(entry.alias, "catalogue alias")
        assert_safe_text(entry.coordinate, "catalogue coordinate")
    members = _members(entries, installed.value)
    return UpdateFinding(
        pkg_name=display,
        installed_version=installed.value,
        latest_version=target_version,
        semver_tier=classify_semver(installed.value, target_version),
        gradle_target=GradleUpdateTarget(
            version_ref=version_ref, members=members, target_version=target_version
        ),
    )


def _group_entries(catalogue: Catalogue, entry: CatalogueEntry) -> list[CatalogueEntry]:
    """The entries that share *entry*'s version reference; *entry* alone when its
    version is inline."""
    if entry.version_ref is None:
        return [entry]
    return catalogue.members_of_ref(entry.version_ref)


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
            members=_members(entries, installed.value),
            target_version=installed.value,
        )
    return finding


def _members(entries: list[CatalogueEntry], installed: str) -> list[GradleMember]:
    """Target members for catalogue entries that share one installed version."""
    return [
        GradleMember(
            kind=entry.kind,
            alias=entry.alias,
            coordinate=entry.coordinate,
            installed_version=installed,
        )
        for entry in entries
    ]


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
        msg = f"malformed [{name}] table in {path}"
        raise GradleError(msg)
    return table


def _checked_catalogue(
    project: ProjectConfig, target: GradleUpdateTarget, *, expected_version: str | None
) -> Catalogue | GradleBlock:
    """The catalogue when it still matches *target* at *expected_version* (each
    member's recorded installed version when None), else the block saying why."""
    shape = validate_gradle_target_shape(target)
    if shape is not None:
        return shape
    try:
        catalogue = parse_catalogue(Path(project.path) / GRADLE_CATALOGUE_RELPATH)
    except GradleError as e:
        return GradleBlock(kind="stale", reason=f"{e}; rescan required")
    return _catalogue_block(catalogue, target, expected_version) or catalogue


def _catalogue_block(
    catalogue: Catalogue, target: GradleUpdateTarget, expected_version: str | None
) -> GradleBlock | None:
    for member in target.members:
        block = _member_block(catalogue, target, member, expected_version)
        if block is not None:
            return block
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


def _member_block(
    catalogue: Catalogue,
    target: GradleUpdateTarget,
    member: GradleMember,
    expected_version: str | None,
) -> GradleBlock | None:
    alias = member.alias
    entry = catalogue.entry(member.kind, alias)
    if entry is None:
        return GradleBlock(
            kind="stale",
            reason=(
                f"the catalogue no longer declares {member.kind} "
                f"'{alias}'; rescan required"
            ),
        )
    expected_ref = normalise_alias(target.version_ref) if target.version_ref else None
    expected = expected_version or member.installed_version
    version = catalogue.version_of(entry)
    current = version.value if version is not None else None
    checks: tuple[tuple[str | None, GradleBlockKind], ...] = (
        (
            f"'{alias}' now resolves to {entry.coordinate}, not "
            f"{member.coordinate}; rescan required"
            if entry.coordinate != member.coordinate
            else None,
            "stale",
        ),
        (entry.unsupported, "mapping"),
        (
            f"'{alias}' no longer shares version reference "
            f"'{target.version_ref}'; rescan required"
            if _ref_key(entry) != expected_ref
            else None,
            "stale",
        ),
        (
            f"'{alias}' no longer has a simple catalogue version; resolve manually"
            if current is None
            else None,
            "mapping",
        ),
        (
            f"'{alias}' is at {current}, expected {expected}; "
            f"the catalogue no longer matches the scan; note that an "
            f"uncommitted catalogue edit is not visible in the update "
            f"workspace. Rescan required"
            if current != expected
            else None,
            "stale",
        ),
    )
    return next(
        (GradleBlock(kind=kind, reason=reason) for reason, kind in checks if reason),
        None,
    )


def _assert_only_target_changed(
    before: Catalogue, after: Catalogue, target: GradleUpdateTarget
) -> None:
    """The parsed catalogue after apply must equal the parsed catalogue before
    it with only the target's members and version reference at the target
    version; formatting, comments and coordinate notation are not compared."""
    expected = _catalogue_view(before, target, at_target=True)
    actual = _catalogue_view(after, target, at_target=False)
    differences = sorted(
        key
        for key in expected.keys() | actual.keys()
        if key not in expected or key not in actual or expected[key] != actual[key]
    )
    if differences:
        msg = (
            "versionCatalogApplyUpdates did not produce exactly the selected "
            f"change; differs at: {', '.join(differences)}"
        )
        raise GradleError(msg)


def _catalogue_view(
    catalogue: Catalogue, target: GradleUpdateTarget, *, at_target: bool
) -> dict[str, object]:
    """Each alias, version entry and preserved section as a comparable value.

    With *at_target*, the target's members and version reference read as the
    target version. Only selected members carry their unsupported reason,
    because only they must keep a simple version.
    """
    selected = {(m.kind, normalise_alias(m.alias)) for m in target.members}
    selected_ref = normalise_alias(target.version_ref) if target.version_ref else None
    view: dict[str, object] = {
        f"preserved {name}": value
        for name, value in catalogue.preserved_semantics.items()
    }
    for key, entry in catalogue.entries.items():
        chosen = key in selected
        version = (
            target.target_version
            if chosen and at_target
            else _version_value(catalogue, entry)
        )
        unsupported = entry.unsupported if chosen and not at_target else None
        view[f"{key[0]} {key[1]}"] = (
            entry.coordinate,
            _ref_key(entry),
            version,
            unsupported,
        )
    for name, version in catalogue.versions.items():
        at = at_target and name == selected_ref
        view[f"version {name}"] = target.target_version if at else version.value
    return view


def _version_value(catalogue: Catalogue, entry: CatalogueEntry) -> str | None:
    version = catalogue.version_of(entry)
    return version.value if version is not None else None


def _ref_key(entry: CatalogueEntry) -> str | None:
    return normalise_alias(entry.version_ref) if entry.version_ref else None


def _toml_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
