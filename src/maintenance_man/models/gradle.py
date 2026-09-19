from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from maintenance_man.models.scan import GradleKind, GradleUpdateTarget


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
            raise ValueError("duplicate component ID")
        if sum(component.kind == "root" for component in self.components) != 1:
            raise ValueError("scope requires exactly one root")
        for component in self.components:
            if (component.kind == "module") != (component.module is not None):
                raise ValueError("component/module kind mismatch")
        if any(edge.source not in ids or edge.target not in ids for edge in self.edges):
            raise ValueError("unknown graph reference")
        return self


class ResolutionReport(GradleRecord):
    schema_version: Literal[1]
    root_project: str
    producer_versions: dict[str, str]
    catalogue_digest: str
    repositories: tuple[RepositoryDeclaration, ...]
    selected_scopes: tuple[ScopeId, ...]
    scopes: tuple[ScopeResolution, ...]
    selection_errors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def unique_scopes(self):
        if len(set(self.selected_scopes)) != len(self.selected_scopes):
            raise ValueError("duplicate selected scope")
        if len({scope.scope for scope in self.scopes}) != len(self.scopes):
            raise ValueError("duplicate scope report")
        if any(scope.scope not in self.selected_scopes for scope in self.scopes):
            raise ValueError("unselected scope result")
        if set(self.producer_versions) != {"gradle", "cyclonedx", "report"}:
            raise ValueError("producer versions missing")
        return self


class CompleteResolution(GradleRecord):
    kind: Literal["complete"] = "complete"
    report: ResolutionReport

    @model_validator(mode="after")
    def complete(self):
        if self.report.selection_errors or any(
            s.unresolved for s in self.report.scopes
        ):
            raise ValueError("incomplete graph")
        if set(self.report.selected_scopes) != {s.scope for s in self.report.scopes}:
            raise ValueError("missing scope result")
        return self


class IncompleteResolution(GradleRecord):
    kind: Literal["incomplete"] = "incomplete"
    report: ResolutionReport
    reasons: tuple[str, ...] = Field(min_length=1)


type ResolutionOutcome = Annotated[
    CompleteResolution | IncompleteResolution, Field(discriminator="kind")
]


RepositoryId = Literal["central", "google", "portal"]


class PublicationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    module: ModuleId
    repositories: tuple[RepositoryId, ...]
    routing_supported: bool = False
    marker_implementation: ModuleId | None = None


class AgeBlock(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    kind: Literal["age"] = "age"
    reason: str


class PublicationFact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    repository: RepositoryId
    module: ModuleId
    source_url: str
    method: Literal["last_modified", "central_timestamp"]
    artifact_digest: str
    timestamp: datetime
    checked_at: datetime
    trust_policy_version: Literal[1] = 1
    implementation: ModuleId | None = None

    @field_validator("timestamp", "checked_at")
    @classmethod
    def utc_date(cls, value):
        if value.tzinfo is None:
            raise ValueError("publication dates require a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("artifact_digest")
    @classmethod
    def digest(cls, value):
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("expected SHA-256 digest")
        return value


class PublicationEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    facts: tuple[PublicationFact, ...]

    @field_validator("facts")
    @classmethod
    def nonempty(cls, value):
        if not value:
            raise ValueError("publication evidence requires facts")
        return value

    @property
    def timestamp(self):
        return max(f.timestamp for f in self.facts)


class GradleCandidate(GradleRecord):
    target: GradleUpdateTarget
    origins: frozenset[Literal["ordinary", "security"]] = Field(min_length=1)
    requested_advisories: frozenset[str] = frozenset()
    requested_coordinates: frozenset[str] = frozenset()
    owner_keys: tuple[str, ...] = ()
    scopes: tuple[ScopeId, ...] = ()
    publication_requests: tuple[PublicationRequest, ...] = ()


class KnownOwner(GradleRecord):
    kind: Literal["direct", "parent", "platform", "plugin"]
    group_key: str
    scope: ScopeId


class UnknownOwner(GradleRecord):
    kind: Literal["unknown"] = "unknown"
    reason: str
    scope: ScopeId | None = None


type OwnerResolution = Annotated[KnownOwner | UnknownOwner, Field(discriminator="kind")]


class CandidateWithheld(GradleRecord):
    group_key: str | None
    coordinate: str
    installed_version: str
    reason: str
    advisory_ids: frozenset[str] = frozenset()


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
            raise ValueError("require success or unresolved reason")
        return self


class CandidateValidationBatch(GradleRecord):
    schema_version: Literal[1]
    results: tuple[CandidateValidation, ...]
