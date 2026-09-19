"""Structured Gradle resolution and catalogue ownership; no lifecycle state."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections import deque
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlsplit

from pydantic import ValidationError

from maintenance_man.dependency_age import publication_request
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    Catalogue,
    CatalogueEntry,
    GradleError,
    ReportProposal,
    _validate_inventory,
    build_update_findings,
    normalise_alias,
    owned_gradle_inventory,
    run_gradle,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    AgeBlock,
    CandidateValidationBatch,
    CandidateWithheld,
    CompleteResolution,
    GradleCandidate,
    GradleFixPlan,
    IncompleteResolution,
    KnownOwner,
    ModuleId,
    OwnerResolution,
    ResolutionOutcome,
    ResolutionReport,
    ScopeId,
    ScopeResolution,
    UnknownOwner,
)
from maintenance_man.models.scan import (
    GradleKind,
    GradleUpdateTarget,
    UpdateFinding,
    VulnFinding,
)


def parse_resolution_report(text: str) -> ResolutionOutcome:
    try:
        report = ResolutionReport.model_validate_json(text)
        if not re.fullmatch(r"[0-9a-f]{64}", report.catalogue_digest):
            raise ValueError("invalid catalogue digest")
        for scope in report.selected_scopes:
            if not scope.project_path.startswith(":") or not scope.configuration:
                raise ValueError("invalid scope identity")
        for repository in report.repositories:
            if repository.url is not None:
                url = urlsplit(repository.url)
                if url.username or url.password or url.query or url.fragment:
                    raise ValueError(
                        "repository report contains private or ambiguous URL"
                    )
        for scope in report.scopes:
            for component in scope.components:
                if not component.id:
                    raise ValueError("empty component ID")
                if component.module is not None:
                    if any(
                        not value or re.search(r"[\s:/\\]", value)
                        for value in (
                            component.module.group,
                            component.module.artifact,
                            component.module.version,
                        )
                    ):
                        raise ValueError("invalid Maven identity")
    except (ValidationError, ValueError) as exc:
        raise GradleError(f"Malformed Gradle resolution report: {exc}") from exc
    reasons = list(report.selection_errors)
    actual = {scope.scope for scope in report.scopes}
    reasons.extend(
        f"Missing selected scope: {scope}"
        for scope in report.selected_scopes
        if scope not in actual
    )
    reasons.extend(
        f"{scope.scope}: {message}"
        for scope in report.scopes
        for message in scope.unresolved
    )
    if reasons:
        return IncompleteResolution(report=report, reasons=tuple(reasons))
    return CompleteResolution(report=report)


def _script(directory: Path) -> Path:
    script = directory / "gradle-report.gradle"
    script.write_bytes(
        files("maintenance_man.resources").joinpath("gradle-report.gradle").read_bytes()
    )
    return script


@contextmanager
def generate_gradle_report(
    project: ProjectConfig,
) -> Iterator[tuple[Path, ResolutionOutcome]]:
    root = Path(project.path)
    before = hashlib.sha256((root / GRADLE_CATALOGUE_RELPATH).read_bytes()).hexdigest()
    with owned_gradle_inventory(project) as directory:
        try:
            script = _script(directory)
            report_started = time.monotonic()
            run_gradle(
                root,
                [
                    "mmGradleReport",
                    "--init-script",
                    str(script),
                    "--no-daemon",
                    "--console=plain",
                    "--rerun-tasks",
                    "--no-build-cache",
                ],
                label="mmGradleReport",
            )
            logging.getLogger(__name__).info(
                "Gradle graph/inventory %.3fs", time.monotonic() - report_started
            )
            bom = directory / "bom.json"
            report_path = directory / "report.json"
            if bom.is_symlink() or report_path.is_symlink():
                raise GradleError("Gradle report output is a symlink")
            _validate_inventory(bom)
            outcome = parse_resolution_report(report_path.read_text(encoding="utf-8"))
            after = hashlib.sha256(
                (root / GRADLE_CATALOGUE_RELPATH).read_bytes()
            ).hexdigest()
            if before != after or outcome.report.catalogue_digest != before:
                raise GradleError("Catalogue changed during report generation")
            yield bom, outcome
        except (OSError, UnicodeError) as exc:
            raise GradleError(f"Could not capture Gradle resolution: {exc}") from exc


def collect_gradle_resolution(
    project: ProjectConfig, catalogue: Catalogue
) -> ResolutionOutcome:
    # The caller's catalogue participates in selection; digest validation binds
    # this report to the source file. No graph is reconstructed from TOML.
    with generate_gradle_report(project) as (_, outcome):
        return outcome


EXACT_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
BRANCH = re.compile(r"^(\d+)\.(\d+)(?:\D|$)")


def _entry_group(entry: CatalogueEntry) -> str:
    if entry.version_ref is not None:
        return f"ref:{normalise_alias(entry.version_ref)}"
    return f"{entry.kind}:{normalise_alias(entry.alias)}"


def _editable_version(catalogue: Catalogue, entry: CatalogueEntry) -> str | None:
    """Return *entry*'s editable version value, or ``None`` when unsupported."""
    version = catalogue.version_of(entry)
    if entry.unsupported is not None or version is None or version.value is None:
        return None
    return version.value


def _scope_owners(
    catalogue: Catalogue, scope: ScopeResolution, module: ModuleId
) -> tuple[OwnerResolution, ...]:
    components = {component.id: component for component in scope.components}
    affected = {
        key for key, component in components.items() if component.module == module
    }
    if not affected:
        return ()
    root = next(
        component.id for component in scope.components if component.kind == "root"
    )
    direct = {
        edge.target
        for edge in scope.edges
        if edge.source == root and not edge.constraint
    }
    editable = {}
    for component_id in direct:
        component = components[component_id]
        if component.module is None:
            continue
        for entry in catalogue.entries.values():
            version_value = _editable_version(catalogue, entry)
            if (
                entry.kind == "library"
                and version_value is not None
                and entry.coordinate == component.module.coordinate
                and version_value == component.module.version
            ):
                editable.setdefault(component_id, set()).add(_entry_group(entry))
    parents = {}
    for edge in scope.edges:
        parents.setdefault(edge.target, []).append(edge)
    queue = deque((component_id, 0, False) for component_id in affected)
    visited = set()
    owners = set()
    owner_distances = {}
    while queue:
        component_id, distance, constrained = queue.popleft()
        if (component_id, constrained) in visited:
            continue
        visited.add((component_id, constrained))
        if component_id in editable:
            kind = (
                "direct" if distance == 0 else ("platform" if constrained else "parent")
            )
            for group in editable[component_id]:
                owner = (group, kind)
                owners.add(owner)
                owner_distances[owner] = min(
                    distance, owner_distances.get(owner, distance)
                )
        for edge in parents.get(component_id, ()):
            if edge.source != root:
                queue.append(
                    (edge.source, distance + 1, constrained or edge.constraint)
                )
    # Plugin ownership never crosses from a buildscript graph into unrelated
    # project configurations. Standard marker roots and their exact edge supply
    # the only marker/implementation link accepted here.
    if not owners and scope.scope.domain == "buildscript":
        for component_id in direct:
            component = components[component_id]
            if component.module is None:
                continue
            for entry in catalogue.entries.values():
                version_value = _editable_version(catalogue, entry)
                if not (
                    entry.kind == "plugin"
                    and version_value is not None
                    and component.module.coordinate
                    == f"{entry.coordinate}:{entry.coordinate}.gradle.plugin"
                    and component.module.version == version_value
                ):
                    continue
                implementation_edges = [
                    edge
                    for edge in scope.edges
                    if edge.source == component_id and not edge.constraint
                ]
                if len(implementation_edges) != 1:
                    continue
                implementation = components[implementation_edges[0].target].module
                requested = implementation_edges[0].requested.split(":")
                if (
                    implementation is None
                    or len(requested) != 3
                    or not EXACT_VERSION.fullmatch(requested[-1])
                    or requested[-1] != implementation.version
                ):
                    continue
                reachable = {implementation_edges[0].target}
                pending = list(reachable)
                while pending:
                    current = pending.pop()
                    for edge in scope.edges:
                        if edge.source == current and edge.target not in reachable:
                            reachable.add(edge.target)
                            pending.append(edge.target)
                if affected & reachable:
                    owners.add((_entry_group(entry), "plugin"))
    if len({group for group, _ in owners}) == 1:
        # Check every independent root before choosing the nearest evidence
        # within the one editable group. A shorter path cannot hide ambiguity.
        group, kind = min(
            owners, key=lambda owner: (owner_distances.get(owner, 0), owner)
        )
        return (KnownOwner(kind=kind, group_key=group, scope=scope.scope),)
    reason = (
        "multiple independently versioned catalogue owners"
        if owners
        else "no supported catalogue owner in resolved graph"
    )
    return (UnknownOwner(reason=reason, scope=scope.scope),)


def resolve_gradle_owners(
    catalogue: Catalogue, resolution: CompleteResolution, module: ModuleId
) -> tuple[OwnerResolution, ...]:
    owners = tuple(
        owner
        for scope in resolution.report.scopes
        for owner in _scope_owners(catalogue, scope, module)
    )
    return owners or (UnknownOwner(reason="module absent from selected resolution"),)


def exact_fix_candidate(installed: str, fixes: str | None) -> str | None:
    tokens = tuple(dict.fromkeys(token.strip() for token in (fixes or "").split(",")))
    if not tokens or any(not EXACT_VERSION.fullmatch(token) for token in tokens):
        return None
    if len(tokens) == 1:
        return tokens[0]
    branch = BRANCH.match(installed)
    if branch is None:
        return None
    matching = [
        token
        for token in tokens
        if (match := BRANCH.match(token)) and match.groups() == branch.groups()
    ]
    return matching[0] if len(matching) == 1 else None


def _candidate_scopes(
    catalogue: Catalogue, resolution: CompleteResolution, target: GradleUpdateTarget
) -> tuple[ScopeId, ...]:
    coordinates = {
        member.coordinate for member in target.members if member.kind == "library"
    }
    plugin_markers = {
        f"{m.coordinate}:{m.coordinate}.gradle.plugin"
        for m in target.members
        if m.kind == "plugin"
    }
    return tuple(
        scope.scope
        for scope in resolution.report.scopes
        if any(
            component.module is not None
            and component.module.coordinate in coordinates | plugin_markers
            for component in scope.components
        )
    )


def select_gradle_candidates(
    catalogue: Catalogue,
    resolution: CompleteResolution,
    vulnerabilities: Sequence[VulnFinding],
    discovered: Sequence[UpdateFinding],
) -> GradleFixPlan:
    candidates = {}
    withheld = []
    conflicting = set()
    for finding in discovered:
        target = finding.gradle_target
        if target is None or (
            finding.blocked_reason and finding.gradle_block_kind != "age"
        ):
            withheld.append(
                CandidateWithheld(
                    group_key=target.group_key if target else None,
                    coordinate=finding.pkg_name,
                    installed_version=finding.installed_version,
                    reason=finding.blocked_reason or "no supported catalogue target",
                )
            )
            continue
        key = target.group_key
        if not EXACT_VERSION.fullmatch(target.target_version):
            conflicting.add(key)
        if (
            key in candidates
            and candidates[key].target.target_version != target.target_version
        ):
            conflicting.add(key)
        candidates[key] = GradleCandidate(
            target=target,
            origins=frozenset({"ordinary"}),
            owner_keys=(key,),
            scopes=_candidate_scopes(catalogue, resolution, target),
        )
    linked = {}
    for finding in vulnerabilities:
        parts = finding.pkg_name.split(":")
        if len(parts) != 2:
            withheld.append(
                CandidateWithheld(
                    group_key=None,
                    coordinate=finding.pkg_name,
                    installed_version=finding.installed_version,
                    reason="finding lacks Maven coordinate",
                    advisory_ids=frozenset({finding.vuln_id}),
                )
            )
            continue
        module = ModuleId(
            group=parts[0], artifact=parts[1], version=finding.installed_version
        )
        owners = resolve_gradle_owners(catalogue, resolution, module)
        known = [owner for owner in owners if isinstance(owner, KnownOwner)]
        groups = {owner.group_key for owner in known}
        if any(isinstance(owner, UnknownOwner) for owner in owners) or len(groups) != 1:
            withheld.append(
                CandidateWithheld(
                    group_key=None,
                    coordinate=finding.pkg_name,
                    installed_version=finding.installed_version,
                    reason="unknown or ambiguous catalogue ownership",
                    advisory_ids=frozenset({finding.vuln_id}),
                )
            )
            continue
        key = next(iter(groups))
        linked.setdefault(key, []).append((finding, known))
    for key, links in linked.items():
        advisory_ids = frozenset(finding.vuln_id for finding, _ in links)
        coordinates = frozenset(finding.pkg_name for finding, _ in links)
        scopes = tuple(
            dict.fromkeys(owner.scope for _, owners in links for owner in owners)
        )
        if key in candidates:
            existing = candidates[key]
            candidates[key] = existing.model_copy(
                update={
                    "origins": frozenset({"ordinary", "security"}),
                    "requested_advisories": advisory_ids,
                    "requested_coordinates": coordinates,
                    "scopes": tuple(dict.fromkeys((*existing.scopes, *scopes))),
                }
            )
            continue
        entries = [
            entry for entry in catalogue.entries.values() if _entry_group(entry) == key
        ]
        versions = {
            exact_fix_candidate(finding.installed_version, finding.fixed_version)
            for finding, _ in links
        }
        if (
            any(owner.kind != "direct" for _, owners in links for owner in owners)
            or None in versions
            or len(versions) != 1
        ):
            withheld.append(
                CandidateWithheld(
                    group_key=key,
                    coordinate=links[0][0].pkg_name,
                    installed_version=links[0][0].installed_version,
                    reason="owner requires one independent exact catalogue proposal",
                    advisory_ids=advisory_ids,
                )
            )
            continue
        version = next(v for v in versions if v is not None)
        proposals = [
            ReportProposal(
                kind=entry.kind,
                alias=entry.alias,
                coordinate=entry.coordinate,
                version=version,
            )
            for entry in entries
        ]
        built = build_update_findings(catalogue, proposals)
        if len(built) != 1 or built[0].blocked_reason or built[0].gradle_target is None:
            withheld.append(
                CandidateWithheld(
                    group_key=key,
                    coordinate=links[0][0].pkg_name,
                    installed_version=links[0][0].installed_version,
                    reason="incompatible shared catalogue group",
                    advisory_ids=advisory_ids,
                )
            )
            continue
        candidates[key] = GradleCandidate(
            target=built[0].gradle_target,
            origins=frozenset({"security"}),
            requested_advisories=advisory_ids,
            requested_coordinates=coordinates,
            owner_keys=(key,),
            scopes=scopes,
        )
    for key in sorted(conflicting):
        candidate = candidates.pop(key)
        withheld.append(
            CandidateWithheld(
                group_key=key,
                coordinate=candidate.target.display_name,
                installed_version=candidate.target.members[0].installed_version,
                reason="conflicting or non-exact catalogue proposals",
            )
        )
    return GradleFixPlan(
        candidates=tuple(candidates[key] for key in sorted(candidates)),
        withheld=tuple(withheld),
    )


class ValidationRequest(TypedDict):
    """One native metadata request row, keyed by field for identity checks."""

    request_id: str
    group_key: str
    alias: str
    project_path: str
    kind: GradleKind
    coordinate: str
    installed_version: str
    candidate_version: str


def _validation_requests(
    candidates: Sequence[GradleCandidate],
) -> list[ValidationRequest]:
    requests: list[ValidationRequest] = []
    for candidate in candidates:
        for member in candidate.target.members:
            paths = sorted({scope.project_path for scope in candidate.scopes}) or [":"]
            if member.kind == "plugin":
                paths = [":"]
            for project_path in paths:
                requests.append(
                    ValidationRequest(
                        request_id=str(len(requests)),
                        group_key=candidate.target.group_key,
                        alias=member.alias,
                        project_path=project_path,
                        kind=member.kind,
                        coordinate=member.coordinate,
                        installed_version=member.installed_version,
                        candidate_version=candidate.target.target_version,
                    )
                )
    return requests


def validate_gradle_candidates(
    project: ProjectConfig, candidates: Sequence[GradleCandidate]
) -> CandidateValidationBatch:
    requests = _validation_requests(candidates)
    if not requests:
        return CandidateValidationBatch(schema_version=1, results=())
    root = Path(project.path)
    before = (root / GRADLE_CATALOGUE_RELPATH).read_bytes()
    with owned_gradle_inventory(project) as directory:
        try:
            script = _script(directory)
            (directory / "candidate-requests.json").write_text(
                json.dumps({"schema_version": 1, "requests": requests}),
                encoding="utf-8",
            )
            run_gradle(
                root,
                [
                    "mmGradleValidateCandidates",
                    "--init-script",
                    str(script),
                    "--no-daemon",
                    "--console=plain",
                    "--rerun-tasks",
                    "--no-build-cache",
                ],
                label="mmGradleValidateCandidates",
            )
            logging.getLogger(__name__).info(
                "Gradle metadata candidates validated: %d requests", len(requests)
            )
            response = directory / "candidate-validation.json"
            if response.is_symlink():
                raise GradleError("Candidate validation output is a symlink")
            batch = CandidateValidationBatch.model_validate_json(response.read_text())
            expected = {request["request_id"]: request for request in requests}
            actual = {result.request_id: result for result in batch.results}
            if len(actual) != len(batch.results) or actual.keys() != expected.keys():
                raise GradleError("Candidate validation response coverage mismatch")
            for request_id, result in actual.items():
                request = expected[request_id]
                if (
                    result.group_key,
                    result.alias,
                    result.project_path,
                    result.kind,
                ) != (
                    request["group_key"],
                    request["alias"],
                    request["project_path"],
                    request["kind"],
                ):
                    raise GradleError("Candidate validation identity mismatch")
                if (
                    result.reason is None
                    and result.selected_version != request["candidate_version"]
                ):
                    raise GradleError(
                        "Candidate validation success selected a different version"
                    )
                if (
                    result.reason is None
                    and request["kind"] == "plugin"
                    and result.implementation is None
                ):
                    raise GradleError("Candidate marker success lacks implementation")
            if (root / GRADLE_CATALOGUE_RELPATH).read_bytes() != before:
                raise GradleError(
                    "Candidate metadata resolution modified the catalogue"
                )
            return batch
        except (OSError, UnicodeError, ValidationError) as exc:
            raise GradleError(f"Invalid candidate validation output: {exc}") from exc


def gradle_routing_prerequisite(project: ProjectConfig) -> AgeBlock | None:
    if project.gradle_repository_routing == "standard-public":
        return None
    return AgeBlock(
        reason=(
            "Public repository routing has not been declared; automatic "
            "publication eligibility requires "
            "gradle_repository_routing = 'standard-public'"
        )
    )


def attach_gradle_publications(
    candidate: GradleCandidate,
    resolution: CompleteResolution,
    batch: CandidateValidationBatch,
) -> GradleCandidate | CandidateWithheld:
    requests = []
    for member in candidate.target.members:
        rows = [
            row
            for row in batch.results
            if row.group_key == candidate.target.group_key
            and row.alias == member.alias
            and row.kind == member.kind
        ]
        failure = next((row.reason for row in rows if row.reason), None)
        if not rows or failure:
            return CandidateWithheld(
                group_key=candidate.target.group_key,
                coordinate=member.coordinate,
                installed_version=member.installed_version,
                reason=failure or "missing native candidate validation",
                advisory_ids=candidate.requested_advisories,
            )
        paths = {row.project_path for row in rows}
        domain = "plugin" if member.kind == "plugin" else "library"
        repositories = tuple(
            repository
            for repository in resolution.report.repositories
            if repository.domain == domain and repository.project_path in paths | {":"}
        )
        if member.kind == "plugin":
            implementations = {row.implementation for row in rows}
            if len(implementations) != 1 or None in implementations:
                return CandidateWithheld(
                    group_key=candidate.target.group_key,
                    coordinate=member.coordinate,
                    installed_version=member.installed_version,
                    reason="conflicting marker implementations",
                )
            module = ModuleId(
                group=member.coordinate,
                artifact=f"{member.coordinate}.gradle.plugin",
                version=candidate.target.target_version,
            )
            requests.append(
                publication_request(
                    module, repositories, implementation=next(iter(implementations))
                )
            )
        else:
            group, artifact = member.coordinate.split(":")
            requests.append(
                publication_request(
                    ModuleId(
                        group=group,
                        artifact=artifact,
                        version=candidate.target.target_version,
                    ),
                    repositories,
                )
            )
    return candidate.model_copy(update={"publication_requests": tuple(requests)})
