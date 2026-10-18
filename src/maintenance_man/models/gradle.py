from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from maintenance_man.models.publication import UtcDatetime
from maintenance_man.models.scan import (
    GradleKind,
    GradleUpdateTarget,
)


class GradleRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ScopeId(GradleRecord):
    project_path: str
    domain: Literal["project", "buildscript"]
    configuration: str


class ModuleId(GradleRecord):
    group: str
    artifact: str
    version: str

    @property
    def coordinate(self) -> str:
        return f"{self.group}:{self.artifact}"


class RepositoryDeclaration(GradleRecord):
    project_path: str
    domain: Literal["library", "plugin"]
    url: str | None


class ResolvedComponent(GradleRecord):
    id: str
    kind: Literal["root", "project", "module"]
    module: ModuleId | None
    variants: tuple[str, ...]


class ResolutionEdge(GradleRecord):
    source: str
    target: str
    requested: str
    constraint: bool


class ScopeResolution(GradleRecord):
    scope: ScopeId
    components: tuple[ResolvedComponent, ...]
    edges: tuple[ResolutionEdge, ...]
    unresolved: tuple[str, ...]

    @model_validator(mode="after")
    def graph_references(self):
        ids = {component.id for component in self.components}
        if len(ids) != len(self.components):
            msg = "duplicate component ID"
            raise ValueError(msg)
        if sum(component.kind == "root" for component in self.components) != 1:
            msg = "scope requires exactly one root"
            raise ValueError(msg)
        for component in self.components:
            if (component.kind == "module") != (component.module is not None):
                msg = "component/module kind mismatch"
                raise ValueError(msg)
        if any(edge.source not in ids or edge.target not in ids for edge in self.edges):
            msg = "unknown graph reference"
            raise ValueError(msg)
        return self


class LocalProjectIdentity(GradleRecord):
    project_path: str
    module: ModuleId


class ResolutionReport(GradleRecord):
    schema_version: Literal[1]
    root_project: str
    producer_versions: dict[str, str]
    catalogue_digest: str
    repositories: tuple[RepositoryDeclaration, ...]
    selected_scopes: tuple[ScopeId, ...]
    scopes: tuple[ScopeResolution, ...]
    local_projects: tuple[LocalProjectIdentity, ...] = ()
    selection_errors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def unique_scopes(self):
        if len(set(self.selected_scopes)) != len(self.selected_scopes):
            msg = "duplicate selected scope"
            raise ValueError(msg)
        if len({scope.scope for scope in self.scopes}) != len(self.scopes):
            msg = "duplicate scope report"
            raise ValueError(msg)
        if any(scope.scope not in self.selected_scopes for scope in self.scopes):
            msg = "unselected scope result"
            raise ValueError(msg)
        if set(self.producer_versions) != {"gradle", "cyclonedx", "report"}:
            msg = "producer versions missing"
            raise ValueError(msg)
        paths = [project.project_path for project in self.local_projects]
        if len(set(paths)) != len(paths) or not set(paths) <= {
            scope.project_path for scope in self.selected_scopes
        }:
            msg = "duplicate or unselected local project identity"
            raise ValueError(msg)
        return self


class CompleteResolution(GradleRecord):
    kind: Literal["complete"] = "complete"
    report: ResolutionReport

    @model_validator(mode="after")
    def complete(self):
        if self.report.selection_errors or any(
            s.unresolved for s in self.report.scopes
        ):
            msg = "incomplete graph"
            raise ValueError(msg)
        if set(self.report.selected_scopes) != {s.scope for s in self.report.scopes}:
            msg = "missing scope result"
            raise ValueError(msg)
        return self


class IncompleteResolution(GradleRecord):
    kind: Literal["incomplete"] = "incomplete"
    report: ResolutionReport
    reasons: tuple[str, ...] = Field(min_length=1)


type ResolutionOutcome = Annotated[
    CompleteResolution | IncompleteResolution, Field(discriminator="kind")
]


RepositoryId = Literal["central", "google", "portal"]


class PublicationRequest(GradleRecord):
    module: ModuleId
    repositories: tuple[RepositoryId, ...]
    routing_supported: bool = False
    marker_implementation: ModuleId | None = None


class AgeBlock(GradleRecord):
    kind: Literal["age"] = "age"
    reason: str


class PublicationFact(GradleRecord):
    repository: RepositoryId
    module: ModuleId
    source_url: str
    method: Literal["last_modified", "central_timestamp"]
    artifact_digest: str
    timestamp: UtcDatetime
    checked_at: UtcDatetime
    trust_policy_version: Literal[1] = 1
    implementation: ModuleId | None = None

    @field_validator("artifact_digest")
    @classmethod
    def digest(cls, value):
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            msg = "expected SHA-256 digest"
            raise ValueError(msg)
        return value


class PublicationEvidence(GradleRecord):
    facts: tuple[PublicationFact, ...]

    @field_validator("facts")
    @classmethod
    def nonempty(cls, value):
        if not value:
            msg = "publication evidence requires facts"
            raise ValueError(msg)
        return value

    @property
    def timestamp(self):
        return max(f.timestamp for f in self.facts)


class GradleCandidate(GradleRecord):
    target: GradleUpdateTarget
    origins: frozenset[Literal["ordinary", "security"]] = Field(min_length=1)
    vulnerability_indices: tuple[int, ...] = ()
    """Positions, in the vulnerability sequence given to select_gradle_candidates,
    of the advisories this candidate fixes."""
    publication_requests: tuple[PublicationRequest, ...] = ()


type OwnerKind = Literal["direct", "parent", "platform", "plugin"]


class KnownOwner(GradleRecord):
    kind: OwnerKind
    group_key: str


class UnknownOwner(GradleRecord):
    kind: Literal["unknown"] = "unknown"


type OwnerResolution = Annotated[KnownOwner | UnknownOwner, Field(discriminator="kind")]


class CandidateWithheld(GradleRecord):
    group_key: str | None
    coordinate: str
    installed_version: str
    reason: str
    vulnerability_indices: tuple[int, ...] = ()
    """Positions, in the same sequence, of the advisories this withheld entry
    blocks."""


class GradleFixPlan(GradleRecord):
    candidates: tuple[GradleCandidate, ...]
    withheld: tuple[CandidateWithheld, ...]


class CandidateValidation(GradleRecord):
    request_id: str
    project_path: str
    group_key: str
    alias: str
    kind: GradleKind
    selected_version: str | None
    implementation: ModuleId | None
    reason: str | None

    @model_validator(mode="after")
    def result_shape(self):
        if (self.selected_version is None) == (self.reason is None):
            msg = "require success or unresolved reason"
            raise ValueError(msg)
        return self


class CandidateValidationBatch(GradleRecord):
    schema_version: Literal[1]
    results: tuple[CandidateValidation, ...]
