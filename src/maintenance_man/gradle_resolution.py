"""Structured Gradle resolution and catalogue ownership; no lifecycle state."""

import json
import re
import shutil
import tempfile
from collections import deque
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import TypedDict

from pydantic import ValidationError

from maintenance_man import paths
from maintenance_man.clock import Clock
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    evaluate_gradle_candidate_age,
    member_module,
    publication_request,
)
from maintenance_man.gradle import (
    Catalogue,
    CatalogueEntry,
    GradleError,
    ReportProposal,
    build_update_findings,
    catalogue_digest,
    run_gradle,
)
from maintenance_man.gradle_inventory import inventory_scopes, load_inventory
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    AgeBlock,
    CandidateValidation,
    CandidateValidationBatch,
    CandidateWithheld,
    GradleCandidate,
    GradleFixPlan,
    ModuleId,
    ResolutionEdge,
    ResolutionReport,
    ResolvedComponent,
    ScopeId,
    ScopeResolution,
)
from maintenance_man.models.scan import (
    GradleKind,
    UpdateFinding,
    VulnFinding,
    group_key_for,
)

GRADLE_REPORT_DIRECTORY_PROPERTY = "mm.reportDirectory"
ROUTING_UNDECLARED = (
    "Public repository routing has not been declared; automatic publication "
    "eligibility requires gradle_repository_routing = 'standard-public'"
)
EXACT_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
BRANCH = re.compile(r"^(\d+)\.(\d+)(?:\D|$)")

_INIT_SCRIPT = files("maintenance_man.resources").joinpath("gradle-report.gradle")
_REPORT_ARGS = ("--no-daemon", "--console=plain", "--rerun-tasks", "--no-build-cache")


@contextmanager
def generate_gradle_report(
    project: ProjectConfig,
) -> Iterator[GeneratedGradleReport]:
    """Capture the CycloneDX inventory and the resolution report in a fresh
    directory under the mm home, removed on exit.

    Raises GradleError for a failed task, a catalogue changed by the task, a
    malformed inventory or report, an incomplete resolution and an inventory
    that does not cover exactly the resolved modules.
    """
    with _run_report_task(
        project,
        "mmGradleReport",
        {},
        catalogue_changed="Catalogue changed during report generation",
    ) as directory:
        bom = directory / "bom.json"
        components = load_inventory(bom)
        try:
            text = (directory / "report.json").read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            msg = f"Could not capture Gradle resolution: {exc}"
            raise GradleError(msg) from exc
        report = parse_resolution_report(text)
        yield GeneratedGradleReport(
            bom_path=bom, report=report, scopes=inventory_scopes(components, report)
        )


@dataclass(frozen=True)
class GeneratedGradleReport:
    """One report capture; the path is usable only inside its context."""

    bom_path: Path
    report: ResolutionReport
    scopes: dict[ModuleId, frozenset[ScopeId]]


@contextmanager
def _run_report_task(
    project: ProjectConfig,
    task: str,
    inputs: Mapping[str, str],
    *,
    catalogue_changed: str,
) -> Iterator[Path]:
    """Run one packaged init-script task with its outputs in a fresh directory
    under the mm home, and yield that directory once the catalogue is proven
    unchanged. The directory is removed on exit; when the task or the caller
    raises, that exception propagates and a removal failure is ignored."""
    root = Path(project.path)
    before = catalogue_digest(root)
    home = paths.mm_home()
    try:
        home.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="gradle-report-", dir=home))
    except OSError as exc:
        msg = f"Could not create a Gradle report directory under {home}: {exc}"
        raise GradleError(msg) from exc
    try:
        script = directory / "gradle-report.gradle"
        try:
            script.write_bytes(_INIT_SCRIPT.read_bytes())
            for filename, text in inputs.items():
                (directory / filename).write_text(text, encoding="utf-8")
        except OSError as exc:
            msg = f"Could not prepare {task} in {directory}: {exc}"
            raise GradleError(msg) from exc
        run_gradle(
            root,
            [
                task,
                "--init-script",
                str(script),
                f"-P{GRADLE_REPORT_DIRECTORY_PROPERTY}={directory}",
                *_REPORT_ARGS,
            ],
            label=task,
        )
        if catalogue_digest(root) != before:
            raise GradleError(catalogue_changed)
        yield directory
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    _remove_report_directory(directory)


def _remove_report_directory(directory: Path) -> None:
    try:
        shutil.rmtree(directory)
    except OSError as exc:
        msg = f"Could not remove the Gradle report directory {directory}: {exc}"
        raise GradleError(msg) from exc


def parse_resolution_report(text: str) -> ResolutionReport:
    """Parse the init script's resolution report.

    Raises GradleError for a malformed report and for an incomplete graph.
    """
    try:
        report = ResolutionReport.model_validate_json(text)
    except ValueError as exc:
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
        msg = "Incomplete Gradle resolution: " + "; ".join(reasons)
        raise GradleError(msg)
    return report


def resolve_gradle_owners(
    catalogue: Catalogue, report: ResolutionReport, module: ModuleId
) -> tuple[_Owner | None, ...]:
    """The catalogue group owning *module* in each scope that resolves it, as
    ``(group_key, direct)``; ``None`` when a scope names no group or several. The
    tuple is ``(None,)`` when no scope resolves the module."""
    owners = tuple(
        _scope_owner(catalogue, scope, affected)
        for scope in report.scopes
        if (affected := {c.id for c in scope.components if c.module == module})
    )
    return owners or (None,)


type _Owner = tuple[str, bool]


def _scope_owner(
    catalogue: Catalogue, scope: ScopeResolution, affected: set[str]
) -> _Owner | None:
    components = {component.id: component for component in scope.components}
    root = next(c.id for c in scope.components if c.kind == "root")
    direct = tuple(
        dict.fromkeys(
            edge.target
            for edge in scope.edges
            if edge.source == root and not edge.constraint
        )
    )
    editable = _editable_library_roots(catalogue, components, direct)
    reached = _ancestors(affected, scope.edges, root)
    groups = {
        group for component_id in reached for group in editable.get(component_id, ())
    }
    if not groups and scope.scope.domain == "buildscript":
        groups = _plugin_marker_groups(catalogue, scope, components, direct, reached)
    if len(groups) != 1:
        return None
    (group,) = groups
    return group, any(
        group in editable.get(component_id, ()) for component_id in affected
    )


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
                editable.setdefault(component_id, set()).add(
                    group_key_for(entry.kind, entry.alias, entry.version_ref)
                )
    return editable


def _editable_version(catalogue: Catalogue, entry: CatalogueEntry) -> str | None:
    """Return *entry*'s editable version value, or ``None`` when unsupported."""
    version = catalogue.version_of(entry)
    if entry.unsupported is not None or version is None or version.value is None:
        return None
    return version.value


def _ancestors(
    affected: set[str], edges: tuple[ResolutionEdge, ...], root: str
) -> set[str]:
    """The affected components and every non-root component that depends on them."""
    parents: dict[str, list[str]] = {}
    for edge in edges:
        if edge.source != root:
            parents.setdefault(edge.target, []).append(edge.source)
    reached = set(affected)
    queue = deque(affected)
    while queue:
        for parent in parents.get(queue.popleft(), ()):
            if parent not in reached:
                reached.add(parent)
                queue.append(parent)
    return reached


def _plugin_marker_groups(
    catalogue: Catalogue,
    scope: ScopeResolution,
    components: dict[str, ResolvedComponent],
    direct: tuple[str, ...],
    reached: set[str],
) -> set[str]:
    groups: set[str] = set()
    for component_id in direct:
        marker = components[component_id].module
        if marker is None:
            continue
        for entry in catalogue.entries.values():
            version = _editable_version(catalogue, entry)
            if (
                entry.kind == "plugin"
                and version is not None
                and marker.coordinate
                == f"{entry.coordinate}:{entry.coordinate}.gradle.plugin"
                and marker.version == version
                and _implementation_reached(scope, components, component_id, reached)
            ):
                groups.add(group_key_for(entry.kind, entry.alias, entry.version_ref))
    return groups


def _implementation_reached(
    scope: ScopeResolution,
    components: dict[str, ResolvedComponent],
    marker_id: str,
    reached: set[str],
) -> bool:
    """Whether *marker_id* has one exact implementation edge reaching the affected
    components."""
    edges = [e for e in scope.edges if e.source == marker_id and not e.constraint]
    if len(edges) != 1:
        return False
    implementation = components[edges[0].target].module
    requested = edges[0].requested.split(":")
    return (
        implementation is not None
        and len(requested) == 3
        and EXACT_VERSION.fullmatch(requested[-1]) is not None
        and requested[-1] == implementation.version
        and edges[0].target in reached
    )


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


type _VulnerabilityLink = tuple[int, VulnFinding, list[_Owner]]


def select_gradle_candidates(
    catalogue: Catalogue,
    report: ResolutionReport,
    vulnerabilities: Sequence[VulnFinding],
    discovered: Sequence[UpdateFinding],
) -> GradleFixPlan:
    """Merge ordinary and security proposals, retaining each withheld reason."""
    candidates, conflicting = _collect_ordinary_proposals(discovered)
    linked, withheld = _link_vulnerabilities(catalogue, report, vulnerabilities)
    security_candidates, security_withheld = _build_security_proposals(
        catalogue, candidates, linked
    )
    candidates.update(security_candidates)
    withheld.extend(security_withheld)
    for key in sorted(conflicting):
        candidate = candidates.pop(key)
        withheld.append(
            CandidateWithheld(
                group_key=key,
                reason="conflicting or non-exact catalogue proposals",
                vulnerability_indices=candidate.vulnerability_indices,
            )
        )
    return GradleFixPlan(
        candidates=tuple(candidates[key] for key in sorted(candidates)),
        withheld=tuple(withheld),
    )


def _collect_ordinary_proposals(
    discovered: Sequence[UpdateFinding],
) -> tuple[dict[str, GradleCandidate], set[str]]:
    candidates: dict[str, GradleCandidate] = {}
    conflicting: set[str] = set()
    for finding in discovered:
        target = finding.gradle_target
        if target is None or (
            finding.blocked_reason and finding.gradle_block_kind != "age"
        ):
            continue
        key = target.group_key
        if not EXACT_VERSION.fullmatch(target.target_version):
            conflicting.add(key)
        if (
            key in candidates
            and candidates[key].target.target_version != target.target_version
        ):
            conflicting.add(key)
        candidates[key] = GradleCandidate(target=target)
    return candidates, conflicting


def _link_vulnerabilities(
    catalogue: Catalogue,
    report: ResolutionReport,
    vulnerabilities: Sequence[VulnFinding],
) -> tuple[dict[str, list[_VulnerabilityLink]], list[CandidateWithheld]]:
    linked: dict[str, list[_VulnerabilityLink]] = {}
    withheld: list[CandidateWithheld] = []
    for index, finding in enumerate(vulnerabilities):
        if finding.fixed_version is None:
            continue
        parts = finding.pkg_name.split(":")
        if len(parts) != 2:
            withheld.append(_withheld_finding(index, "finding lacks Maven coordinate"))
            continue
        module = ModuleId(
            group=parts[0], artifact=parts[1], version=finding.installed_version
        )
        owners = resolve_gradle_owners(catalogue, report, module)
        known = [owner for owner in owners if owner is not None]
        if len(known) != len(owners):
            withheld.append(
                _withheld_finding(
                    index, "cannot identify an unambiguous catalogue entry"
                )
            )
            continue
        for key in sorted({group for group, _ in known}):
            linked.setdefault(key, []).append(
                (index, finding, [owner for owner in known if owner[0] == key])
            )
    return linked, withheld


def _withheld_finding(index: int, reason: str) -> CandidateWithheld:
    """Withhold one advisory that names no single catalogue owner."""
    return CandidateWithheld(
        group_key=None, reason=reason, vulnerability_indices=(index,)
    )


def _security_only_proposal(
    catalogue: Catalogue,
    key: str,
    links: list[_VulnerabilityLink],
    vulnerability_indices: tuple[int, ...],
) -> GradleCandidate | CandidateWithheld:
    entries = [
        entry
        for entry in catalogue.entries.values()
        if group_key_for(entry.kind, entry.alias, entry.version_ref) == key
    ]
    versions = {
        exact_fix_candidate(finding.installed_version, finding.fixed_version)
        for _, finding, _ in links
    }
    if (
        any(not direct for _, _, owners in links for _, direct in owners)
        or None in versions
        or len(versions) != 1
    ):
        return CandidateWithheld(
            group_key=key,
            reason="owner requires one independent exact catalogue proposal",
            vulnerability_indices=vulnerability_indices,
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
            reason="incompatible shared catalogue group",
            vulnerability_indices=vulnerability_indices,
        )
    return GradleCandidate(
        target=built[0].gradle_target, vulnerability_indices=vulnerability_indices
    )


def _build_security_proposals(
    catalogue: Catalogue,
    candidates: Mapping[str, GradleCandidate],
    linked: dict[str, list[_VulnerabilityLink]],
) -> tuple[dict[str, GradleCandidate], list[CandidateWithheld]]:
    proposals: dict[str, GradleCandidate] = {}
    withheld: list[CandidateWithheld] = []
    for key, links in linked.items():
        indices = tuple(index for index, _, _ in links)
        if key in candidates:
            proposals[key] = candidates[key].model_copy(
                update={"vulnerability_indices": indices}
            )
            continue
        proposal = _security_only_proposal(catalogue, key, links, indices)
        if isinstance(proposal, CandidateWithheld):
            withheld.append(proposal)
        else:
            proposals[key] = proposal
    return proposals, withheld


class ValidationRequest(TypedDict):
    """One native metadata request: a catalogue member of a candidate, resolved from
    one consuming project to the candidate version. Gradle echoes only the
    ``request_id``; the other fields stay with the request."""

    request_id: str
    group_key: str
    alias: str
    project_path: str
    kind: GradleKind
    coordinate: str
    installed_version: str
    candidate_version: str


def _validation_requests(
    candidates: Sequence[GradleCandidate], report: ResolutionReport
) -> list[ValidationRequest]:
    """One request per member and consuming project; plugins validate at the root.

    A shared catalogue version can span projects with different repositories,
    so each member resolves its own consumers.
    """
    projects: dict[str, set[str]] = {}
    for module, scopes in report.module_scopes().items():
        projects.setdefault(module.coordinate, set()).update(
            scope.project_path for scope in scopes
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


type _Validations = list[tuple[ValidationRequest, CandidateValidation]]


def validate_gradle_candidates(
    project: ProjectConfig,
    candidates: Sequence[GradleCandidate],
    report: ResolutionReport,
) -> _Validations:
    """Resolve every candidate member natively in its consuming projects and pair
    each request with its result.

    Raises GradleError for a failed task, a modified catalogue and a response
    that is invalid, incomplete or selects a different version.
    """
    requests = _validation_requests(candidates, report)
    if not requests:
        return []
    payload = json.dumps({"schema_version": 1, "requests": requests})
    with _run_report_task(
        project,
        "mmGradleValidateCandidates",
        {"candidate-requests.json": payload},
        catalogue_changed="Candidate metadata resolution modified the catalogue",
    ) as directory:
        try:
            batch = CandidateValidationBatch.model_validate_json(
                (directory / "candidate-validation.json").read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, ValidationError) as exc:
            msg = f"Invalid candidate validation output: {exc}"
            raise GradleError(msg) from exc
    return _checked_validations(requests, batch)


def _checked_validations(
    requests: list[ValidationRequest], batch: CandidateValidationBatch
) -> _Validations:
    expected = {request["request_id"]: request for request in requests}
    actual = {result.request_id: result for result in batch.results}
    if len(actual) != len(batch.results) or actual.keys() != expected.keys():
        msg = "Candidate validation response coverage mismatch"
        raise GradleError(msg)
    for request_id, result in actual.items():
        request = expected[request_id]
        if result.reason is not None:
            continue
        if result.selected_version != request["candidate_version"]:
            msg = "Candidate validation success selected a different version"
            raise GradleError(msg)
        if request["kind"] == "plugin" and result.implementation is None:
            msg = "Candidate marker success lacks implementation"
            raise GradleError(msg)
    return [(request, actual[request_id]) for request_id, request in expected.items()]


def attach_gradle_publications(
    candidate: GradleCandidate, report: ResolutionReport, validations: _Validations
) -> GradleCandidate | str:
    """Bind publication requests to *candidate*, or return the reason to withhold it."""
    requests = []
    for member in candidate.target.members:
        rows = [
            (request, result)
            for request, result in validations
            if (request["group_key"], request["alias"], request["kind"])
            == (candidate.target.group_key, member.alias, member.kind)
        ]
        failure = next((result.reason for _, result in rows if result.reason), None)
        if not rows or failure:
            return failure or "missing native candidate validation"
        project_paths = {request["project_path"] for request, _ in rows}
        domain = "plugin" if member.kind == "plugin" else "library"
        repositories = tuple(
            repository
            for repository in report.repositories
            if repository.domain == domain
            and repository.project_path in project_paths | {":"}
        )
        module = member_module(member, candidate.target.target_version)
        if module is None:
            return "unsupported catalogue member coordinate"
        if member.kind == "plugin":
            implementations = {result.implementation for _, result in rows}
            if len(implementations) != 1 or None in implementations:
                return "conflicting marker implementations"
            requests.append(
                publication_request(
                    module, repositories, implementation=next(iter(implementations))
                )
            )
        else:
            requests.append(publication_request(module, repositories))
    return candidate.model_copy(update={"publication_requests": tuple(requests)})


def prepare_gradle_candidates(
    project: ProjectConfig,
    candidates: Sequence[GradleCandidate],
    report: ResolutionReport,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    clock: Clock,
) -> tuple[GradleCandidate, ...]:
    """Validate proposed catalogue changes and apply the release-age policy.

    Each result carries the reason it is withheld, or the date its youngest
    publication evidence was published. Without declared public routing every
    candidate is withheld unvalidated.
    """
    if project.gradle_repository_routing != "standard-public":
        return tuple(
            candidate.model_copy(update={"reason": ROUTING_UNDECLARED})
            for candidate in candidates
        )
    validations = validate_gradle_candidates(project, candidates, report)
    bound = [
        attach_gradle_publications(candidate, report, validations)
        for candidate in candidates
    ]
    publication.prefetch(
        request
        for item in bound
        if isinstance(item, GradleCandidate)
        for request in item.publication_requests
    )
    return tuple(
        _aged(candidate, item, minimum_age_days, publication, clock)
        for candidate, item in zip(candidates, bound, strict=True)
    )


def _aged(
    candidate: GradleCandidate,
    bound: GradleCandidate | str,
    minimum_age_days: int,
    publication: PublicationLookupContext,
    clock: Clock,
) -> GradleCandidate:
    if isinstance(bound, str):
        return candidate.model_copy(update={"reason": bound})
    age = evaluate_gradle_candidate_age(bound, minimum_age_days, publication, clock())
    if isinstance(age, AgeBlock):
        return bound.model_copy(update={"reason": age.reason})
    return bound.model_copy(update={"published_date": age})
