"""Structured Gradle resolution and catalogue ownership; no lifecycle state."""

from __future__ import annotations

import json
import logging
import re
import time
from collections import deque
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Literal, TypedDict
from urllib.parse import urlsplit

from pydantic import ValidationError

from maintenance_man.clock import Clock, utc_now
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    evaluate_gradle_candidate_age,
    publication_request,
)
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GRADLE_INVENTORY_BOM_RELPATH,
    Catalogue,
    CatalogueEntry,
    GradleError,
    ReportProposal,
    build_update_findings,
    file_digest,
    normalise_alias,
    owned_gradle_inventory,
    require_catalogue_unchanged,
    run_gradle,
)
from maintenance_man.gradle_inventory import CycloneDxInventory, load_inventory
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    CandidateValidationBatch,
    CandidateWithheld,
    CompleteResolution,
    GradleCandidate,
    GradleFixPlan,
    IncompleteResolution,
    KnownOwner,
    ModuleId,
    OwnerResolution,
    ResolutionEdge,
    ResolutionOutcome,
    ResolutionReport,
    ResolvedComponent,
    ScopeId,
    ScopeResolution,
    UnknownOwner,
)
from maintenance_man.models.scan import (
    GradleBlock,
    GradleKind,
    GradleUpdateTarget,
    UpdateFinding,
    VulnFinding,
)


def parse_resolution_report(text: str) -> ResolutionOutcome:
    try:
        report = ResolutionReport.model_validate_json(text)
        _validate_report_semantics(report)
    except (ValidationError, ValueError) as exc:
        msg = f"Malformed Gradle resolution report: {exc}"
        raise GradleError(msg) from exc
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


def _validate_report_semantics(report: ResolutionReport) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", report.catalogue_digest):
        msg = "invalid catalogue digest"
        raise ValueError(msg)
    for scope in report.selected_scopes:
        if not scope.project_path.startswith(":") or not scope.configuration:
            msg = "invalid scope identity"
            raise ValueError(msg)
    for repository in report.repositories:
        if repository.url is not None:
            url = urlsplit(repository.url)
            if url.username or url.password or url.query or url.fragment:
                msg = "repository report contains private or ambiguous URL"
                raise ValueError(msg)
    for scope in report.scopes:
        for component in scope.components:
            _validate_component_identity(component)


def _validate_component_identity(component: ResolvedComponent) -> None:
    if not component.id:
        msg = "empty component ID"
        raise ValueError(msg)
    if component.module is not None and any(
        not value or re.search(r"[\s:/\\]", value)
        for value in (
            component.module.group,
            component.module.artifact,
            component.module.version,
        )
    ):
        msg = "invalid Maven identity"
        raise ValueError(msg)


def _report_command(task: str, script: Path) -> list[str]:
    return [
        task,
        "--init-script",
        str(script),
        "--no-daemon",
        "--console=plain",
        "--rerun-tasks",
        "--no-build-cache",
    ]


def _script(directory: Path) -> Path:
    script = directory / "gradle-report.gradle"
    script.write_bytes(
        files("maintenance_man.resources").joinpath("gradle-report.gradle").read_bytes()
    )
    return script


@dataclass(frozen=True)
class GeneratedGradleReport:
    """One report capture; the path is usable only inside its context."""

    bom_path: Path
    inventory_bytes: bytes
    inventory: CycloneDxInventory
    resolution: ResolutionOutcome


@contextmanager
def generate_gradle_report(
    project: ProjectConfig,
) -> Iterator[GeneratedGradleReport]:
    root = Path(project.path)
    before = file_digest(root / GRADLE_CATALOGUE_RELPATH)
    with owned_gradle_inventory(project) as directory:
        try:
            script = _script(directory)
            report_started = time.monotonic()
            run_gradle(
                root,
                _report_command("mmGradleReport", script),
                label="mmGradleReport",
            )
            logging.getLogger(__name__).info(
                "Gradle graph/inventory %.3fs", time.monotonic() - report_started
            )
            bom = root / GRADLE_INVENTORY_BOM_RELPATH
            report_path = directory / "report.json"
            if bom.is_symlink() or report_path.is_symlink():
                msg = "Gradle report output is a symlink"
                raise GradleError(msg)
            inventory_bytes, inventory = load_inventory(bom)
            outcome = parse_resolution_report(report_path.read_text(encoding="utf-8"))
            require_catalogue_unchanged(
                before,
                file_digest(root / GRADLE_CATALOGUE_RELPATH),
                message="Catalogue changed during report generation",
                reported_digest=outcome.report.catalogue_digest,
            )
        except (OSError, UnicodeError) as exc:
            msg = f"Could not capture Gradle resolution: {exc}"
            raise GradleError(msg) from exc
        yield GeneratedGradleReport(
            bom_path=bom,
            inventory_bytes=inventory_bytes,
            inventory=inventory,
            resolution=outcome,
        )


def collect_gradle_resolution(project: ProjectConfig) -> ResolutionOutcome:
    # Digest validation binds this report to the source file. No graph is
    # reconstructed from TOML.
    with generate_gradle_report(project) as generated:
        return generated.resolution


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


type _OwnerKind = Literal["direct", "parent", "platform", "plugin"]
type _OwnerEvidence = tuple[str, _OwnerKind]


def _editable_library_roots(
    catalogue: Catalogue,
    components: dict[str, ResolvedComponent],
    direct: tuple[str, ...],
) -> dict[str, set[str]]:
    editable: dict[str, set[str]] = {}
    for component_id in direct:
        module = components[component_id].module
        if module is None:
            continue
        for entry in catalogue.entries.values():
            version_value = _editable_version(catalogue, entry)
            if (
                entry.kind == "library"
                and version_value is not None
                and entry.coordinate == module.coordinate
                and version_value == module.version
            ):
                editable.setdefault(component_id, set()).add(_entry_group(entry))
    return editable


def _reverse_owner_evidence(
    affected: tuple[str, ...],
    editable: dict[str, set[str]],
    parents: dict[str, list[ResolutionEdge]],
    root: str,
) -> dict[_OwnerEvidence, int]:
    queue = deque((component_id, 0, False) for component_id in affected)
    visited: set[tuple[str, bool]] = set()
    owners: dict[_OwnerEvidence, int] = {}
    while queue:
        component_id, distance, constrained = queue.popleft()
        if (component_id, constrained) in visited:
            continue
        visited.add((component_id, constrained))
        kind: _OwnerKind = (
            "direct" if distance == 0 else "platform" if constrained else "parent"
        )
        for group in editable.get(component_id, ()):
            owner = (group, kind)
            owners[owner] = min(distance, owners.get(owner, distance))
        for edge in parents.get(component_id, ()):
            if edge.source != root:
                queue.append(
                    (edge.source, distance + 1, constrained or edge.constraint)
                )
    return owners


def _reachable_from(start: str, edges: tuple[ResolutionEdge, ...]) -> set[str]:
    reachable = {start}
    pending = [start]
    while pending:
        current = pending.pop()
        for edge in edges:
            if edge.source == current and edge.target not in reachable:
                reachable.add(edge.target)
                pending.append(edge.target)
    return reachable


def _plugin_marker_evidence(
    catalogue: Catalogue,
    scope: ScopeResolution,
    components: dict[str, ResolvedComponent],
    direct: tuple[str, ...],
    affected: set[str],
) -> dict[_OwnerEvidence, int]:
    owners: dict[_OwnerEvidence, int] = {}
    if scope.scope.domain != "buildscript":
        return owners
    for component_id in direct:
        component = components[component_id]
        if component.module is None:
            continue
        for entry in catalogue.entries.values():
            version_value = _editable_version(catalogue, entry)
            marker_coordinate = f"{entry.coordinate}:{entry.coordinate}.gradle.plugin"
            if (
                entry.kind != "plugin"
                or version_value is None
                or component.module.coordinate != marker_coordinate
                or component.module.version != version_value
            ):
                continue
            implementation_edges = tuple(
                edge
                for edge in scope.edges
                if edge.source == component_id and not edge.constraint
            )
            if len(implementation_edges) != 1:
                continue
            implementation_edge = implementation_edges[0]
            implementation = components[implementation_edge.target].module
            requested = implementation_edge.requested.split(":")
            if (
                implementation is not None
                and len(requested) == 3
                and EXACT_VERSION.fullmatch(requested[-1])
                and requested[-1] == implementation.version
                and affected & _reachable_from(implementation_edge.target, scope.edges)
            ):
                owners[(_entry_group(entry), "plugin")] = 0
    return owners


def _classify_owner_evidence(
    scope: ScopeId, owners: dict[_OwnerEvidence, int]
) -> tuple[OwnerResolution, ...]:
    if len({group for group, _ in owners}) == 1:
        group, kind = min(owners, key=lambda owner: (owners[owner], owner))
        return (KnownOwner(kind=kind, group_key=group, scope=scope),)
    reason = (
        "multiple independently versioned catalogue owners"
        if owners
        else "no supported catalogue owner in resolved graph"
    )
    return (UnknownOwner(reason=reason, scope=scope),)


def _scope_owners(
    catalogue: Catalogue, scope: ScopeResolution, module: ModuleId
) -> tuple[OwnerResolution, ...]:
    components = {component.id: component for component in scope.components}
    affected = tuple(
        component.id for component in scope.components if component.module == module
    )
    if not affected:
        return ()
    root = next(
        component.id for component in scope.components if component.kind == "root"
    )
    direct = tuple(
        dict.fromkeys(
            edge.target
            for edge in scope.edges
            if edge.source == root and not edge.constraint
        )
    )
    editable = _editable_library_roots(catalogue, components, direct)
    parents: dict[str, list[ResolutionEdge]] = {}
    for edge in scope.edges:
        parents.setdefault(edge.target, []).append(edge)
    owners = _reverse_owner_evidence(affected, editable, parents, root)
    if not owners and scope.scope.domain == "buildscript":
        owners = _plugin_marker_evidence(
            catalogue, scope, components, direct, set(affected)
        )
    return _classify_owner_evidence(scope.scope, owners)


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
    resolution: CompleteResolution, target: GradleUpdateTarget
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


type _VulnerabilityLink = tuple[VulnFinding, list[KnownOwner]]


def _collect_ordinary_proposals(
    resolution: CompleteResolution, discovered: Sequence[UpdateFinding]
) -> tuple[dict[str, GradleCandidate], list[CandidateWithheld], set[str]]:
    candidates: dict[str, GradleCandidate] = {}
    withheld: list[CandidateWithheld] = []
    conflicting: set[str] = set()
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
            scopes=_candidate_scopes(resolution, target),
        )
    return candidates, withheld, conflicting


def _link_vulnerabilities(
    catalogue: Catalogue,
    resolution: CompleteResolution,
    vulnerabilities: Sequence[VulnFinding],
    withheld: list[CandidateWithheld],
) -> dict[str, list[_VulnerabilityLink]]:
    linked: dict[str, list[_VulnerabilityLink]] = {}
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
                    reason="cannot identify an unambiguous catalogue entry",
                    advisory_ids=frozenset({finding.vuln_id}),
                )
            )
            continue
        linked.setdefault(next(iter(groups)), []).append((finding, known))
    return linked


def _security_only_proposal(
    catalogue: Catalogue,
    key: str,
    links: list[_VulnerabilityLink],
    advisory_ids: frozenset[str],
    coordinates: frozenset[str],
    scopes: tuple[ScopeId, ...],
) -> GradleCandidate | CandidateWithheld:
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
        return CandidateWithheld(
            group_key=key,
            coordinate=links[0][0].pkg_name,
            installed_version=links[0][0].installed_version,
            reason="owner requires one independent exact catalogue proposal",
            advisory_ids=advisory_ids,
        )
    version = next(version for version in versions if version is not None)
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
        return CandidateWithheld(
            group_key=key,
            coordinate=links[0][0].pkg_name,
            installed_version=links[0][0].installed_version,
            reason="incompatible shared catalogue group",
            advisory_ids=advisory_ids,
        )
    return GradleCandidate(
        target=built[0].gradle_target,
        origins=frozenset({"security"}),
        requested_advisories=advisory_ids,
        requested_coordinates=coordinates,
        owner_keys=(key,),
        scopes=scopes,
    )


def _apply_vulnerability_links(
    catalogue: Catalogue,
    candidates: dict[str, GradleCandidate],
    withheld: list[CandidateWithheld],
    linked: dict[str, list[_VulnerabilityLink]],
) -> None:
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
        proposal = _security_only_proposal(
            catalogue, key, links, advisory_ids, coordinates, scopes
        )
        if isinstance(proposal, CandidateWithheld):
            withheld.append(proposal)
        else:
            candidates[key] = proposal


def select_gradle_candidates(
    catalogue: Catalogue,
    resolution: CompleteResolution,
    vulnerabilities: Sequence[VulnFinding],
    discovered: Sequence[UpdateFinding],
) -> GradleFixPlan:
    candidates, withheld, conflicting = _collect_ordinary_proposals(
        resolution, discovered
    )
    linked = _link_vulnerabilities(catalogue, resolution, vulnerabilities, withheld)
    _apply_vulnerability_links(catalogue, candidates, withheld, linked)
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
    resolution: CompleteResolution,
) -> list[ValidationRequest]:
    # A shared catalogue version can span projects with different repositories.
    # Candidate scopes also include advisory ownership; resolve each member's
    # actual consumers independently from that candidate-wide union.
    projects: dict[str, set[str]] = {}
    for scope in resolution.report.scopes:
        for component in scope.components:
            if component.module is not None:
                projects.setdefault(component.module.coordinate, set()).add(
                    scope.scope.project_path
                )
    requests: list[ValidationRequest] = []
    for candidate in candidates:
        for member in candidate.target.members:
            paths = sorted(projects.get(member.coordinate, ())) or [":"]
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
    project: ProjectConfig,
    candidates: Sequence[GradleCandidate],
    resolution: CompleteResolution,
) -> CandidateValidationBatch:
    requests = _validation_requests(candidates, resolution)
    if not requests:
        return CandidateValidationBatch(schema_version=1, results=())
    root = Path(project.path)
    before = file_digest(root / GRADLE_CATALOGUE_RELPATH)
    with owned_gradle_inventory(project) as directory:
        try:
            script = _script(directory)
            (directory / "candidate-requests.json").write_text(
                json.dumps({"schema_version": 1, "requests": requests}),
                encoding="utf-8",
            )
            run_gradle(
                root,
                _report_command("mmGradleValidateCandidates", script),
                label="mmGradleValidateCandidates",
            )
            logging.getLogger(__name__).info(
                "Gradle metadata candidates validated: %d requests", len(requests)
            )
            response = directory / "candidate-validation.json"
            if response.is_symlink():
                msg = "Candidate validation output is a symlink"
                raise GradleError(msg)
            batch = CandidateValidationBatch.model_validate_json(response.read_text())
            expected = {request["request_id"]: request for request in requests}
            actual = {result.request_id: result for result in batch.results}
            if len(actual) != len(batch.results) or actual.keys() != expected.keys():
                msg = "Candidate validation response coverage mismatch"
                raise GradleError(msg)
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
                    msg = "Candidate validation identity mismatch"
                    raise GradleError(msg)
                if (
                    result.reason is None
                    and result.selected_version != request["candidate_version"]
                ):
                    msg = "Candidate validation success selected a different version"
                    raise GradleError(msg)
                if (
                    result.reason is None
                    and request["kind"] == "plugin"
                    and result.implementation is None
                ):
                    msg = "Candidate marker success lacks implementation"
                    raise GradleError(msg)
            require_catalogue_unchanged(
                before,
                file_digest(root / GRADLE_CATALOGUE_RELPATH),
                message="Candidate metadata resolution modified the catalogue",
            )
            return batch
        except (OSError, UnicodeError, ValidationError) as exc:
            msg = f"Invalid candidate validation output: {exc}"
            raise GradleError(msg) from exc


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


@dataclass(frozen=True)
class PreparedCandidate:
    candidate: GradleCandidate
    block: GradleBlock | None = None


def prepare_gradle_candidates(
    project: ProjectConfig,
    candidates: Sequence[GradleCandidate],
    resolution: CompleteResolution,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    clock: Clock = utc_now,
) -> tuple[PreparedCandidate, ...]:
    """Validate proposed catalogue changes and apply the release-age policy."""
    batch = validate_gradle_candidates(project, candidates, resolution)
    prepared = []
    for candidate in candidates:
        bound = attach_gradle_publications(candidate, resolution, batch)
        if isinstance(bound, CandidateWithheld):
            prepared.append(
                PreparedCandidate(
                    candidate, GradleBlock(kind="mapping", reason=bound.reason)
                )
            )
        else:
            if project.gradle_repository_routing != "standard-public":
                bound = bound.model_copy(update={"publication_requests": ()})
            prepared.append(PreparedCandidate(bound))
    if minimum_age_days > 0:
        publication.prefetch(
            request
            for item in prepared
            if item.block is None
            for request in item.candidate.publication_requests
        )
    result = []
    for item in prepared:
        if item.block is not None:
            result.append(item)
            continue
        age = evaluate_gradle_candidate_age(
            item.candidate, minimum_age_days, publication, clock()
        )
        result.append(
            PreparedCandidate(
                item.candidate,
                GradleBlock(kind="age", reason=age.reason) if age else None,
            )
        )
    return tuple(result)
