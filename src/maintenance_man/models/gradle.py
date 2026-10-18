import re
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from maintenance_man.models.scan import GradleUpdateTarget


def _utc_date(value: datetime) -> datetime:
    if value.tzinfo is None:
        msg = "publication dates require a timezone"
        raise ValueError(msg)
    return value.astimezone(UTC)


type UtcDatetime = Annotated[datetime, AfterValidator(_utc_date)]


class GradleRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ReportRecord(GradleRecord):
    """A record of Gradle's resolution report. The report may grow fields mm does
    not read, so these ignore extra fields; the catalogue and target records are
    mm's own and stay strict."""

    model_config = ConfigDict(frozen=True, extra="ignore")


class ScopeId(ReportRecord):
    project_path: str = Field(pattern=r"^:")
    domain: Literal["project", "buildscript"]
    configuration: str = Field(min_length=1)


class ModuleId(GradleRecord):
    group: str
    artifact: str
    version: str

    @property
    def coordinate(self) -> str:
        return f"{self.group}:{self.artifact}"


class RepositoryDeclaration(ReportRecord):
    project_path: str
    domain: Literal["library", "plugin"]
    url: str | None

    @field_validator("url")
    @classmethod
    def public_url(cls, value: str | None) -> str | None:
        if value is not None:
            url = urlsplit(value)
            if url.username or url.password or url.query or url.fragment:
                msg = "repository report contains private or ambiguous URL"
                raise ValueError(msg)
        return value


class ResolvedComponent(ReportRecord):
    id: str = Field(min_length=1)
    kind: Literal["root", "project", "module"]
    module: ModuleId | None

    @field_validator("module")
    @classmethod
    def maven_identity(cls, value: ModuleId | None) -> ModuleId | None:
        if value is not None and any(
            not part or re.search(r"[\s:/\\]", part)
            for part in (value.group, value.artifact, value.version)
        ):
            msg = "invalid Maven identity"
            raise ValueError(msg)
        return value


class ResolutionEdge(ReportRecord):
    source: str
    target: str
    requested: str
    constraint: bool


class ScopeResolution(ReportRecord):
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


class LocalProjectIdentity(ReportRecord):
    project_path: str
    module: ModuleId


class ResolutionReport(ReportRecord):
    schema_version: Literal[1]
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
        paths = [project.project_path for project in self.local_projects]
        if len(set(paths)) != len(paths) or not set(paths) <= {
            scope.project_path for scope in self.selected_scopes
        }:
            msg = "duplicate or unselected local project identity"
            raise ValueError(msg)
        return self

    def module_scopes(self) -> dict[ModuleId, frozenset[ScopeId]]:
        """Every resolved module and the selected scopes it appears in."""
        scopes: dict[ModuleId, set[ScopeId]] = {}
        for result in self.scopes:
            for component in result.components:
                if component.module is not None:
                    scopes.setdefault(component.module, set()).add(result.scope)
        return {module: frozenset(found) for module, found in scopes.items()}


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
    vulnerability_indices: tuple[int, ...] = ()
    """Positions, in the vulnerability sequence given to select_gradle_candidates,
    of the advisories this candidate fixes."""
    publication_requests: tuple[PublicationRequest, ...] = ()
    reason: str | None = None
    published_date: UtcDatetime | None = None


class CandidateWithheld(GradleRecord):
    group_key: str | None
    reason: str
    vulnerability_indices: tuple[int, ...] = ()
    """Positions, in the same sequence, of the advisories this withheld entry
    blocks."""


class GradleFixPlan(GradleRecord):
    candidates: tuple[GradleCandidate, ...]
    withheld: tuple[CandidateWithheld, ...]


class CandidateValidation(GradleRecord):
    request_id: str
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
