import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from maintenance_man.models.scan import (
    GradleKind,
    GradleUpdateTarget,
    Severity,
    VulnFinding,
    Workflow,
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


def content_identity(value: BaseModel) -> str:
    def canonical(item):
        if isinstance(item, BaseModel):
            return {
                name: canonical(getattr(item, name)) for name in type(item).model_fields
            }
        if isinstance(item, dict):
            return {str(key): canonical(val) for key, val in item.items()}
        if isinstance(item, (set, frozenset)):
            return sorted(
                (canonical(val) for val in item),
                key=lambda val: json.dumps(val, sort_keys=True),
            )
        if isinstance(item, (tuple, list)):
            return [canonical(val) for val in item]
        if isinstance(item, (datetime, Path)):
            return str(item)
        if isinstance(item, Enum):
            return item.value
        return item

    return hashlib.sha256(
        json.dumps(canonical(value), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class FindingKey(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    advisory_id: str
    coordinate: str
    scope: ScopeId


class FindingEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    key: FindingKey
    affected_versions: frozenset[str]
    severity: Severity
    has_unknown: bool
    rows: tuple[VulnFinding, ...]

    @model_validator(mode="after")
    def nonempty(self):
        if not self.affected_versions or not self.rows:
            raise ValueError("finding evidence must retain versions and rows")
        if self.affected_versions != frozenset(
            row.installed_version for row in self.rows
        ):
            raise ValueError("affected versions disagree with retained rows")
        if any(
            row.vuln_id != self.key.advisory_id or row.pkg_name != self.key.coordinate
            for row in self.rows
        ):
            raise ValueError("finding rows disagree with key")
        return self


class ComparisonContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    scanner_version: str
    loaded_input_digests: dict[str, str]
    selected_scopes: tuple[ScopeId, ...]
    producer_versions: dict[str, str]
    scanner_flags: tuple[str, ...]
    created_at: datetime
    private_cache_path: Path
    owner_token: str

    @property
    def identity(self) -> str:
        return content_identity(self)

    @property
    def context_identity(self) -> str:
        return self.identity


class GradleSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    tree_id: str
    resolution: CompleteResolution
    context_identity: str
    findings: tuple[FindingEvidence, ...]
    inventory_digest: str
    inventory_modules: tuple[ModuleId, ...]

    @model_validator(mode="after")
    def unique_findings(self):
        if len({finding.key for finding in self.findings}) != len(self.findings):
            raise ValueError("duplicate snapshot finding key")
        return self

    @property
    def snapshot_id(self) -> str:
        return content_identity(self)


class VerifiedComparison(BaseModel):
    kind: Literal["verified"] = "verified"
    removed: frozenset[FindingKey]
    residual: frozenset[FindingKey]


class RejectedComparison(BaseModel):
    kind: Literal["rejected"] = "rejected"
    reasons: tuple[str, ...]


class IncomparableComparison(BaseModel):
    kind: Literal["incomparable"] = "incomparable"
    reasons: tuple[str, ...]


type ComparisonResult = VerifiedComparison | RejectedComparison | IncomparableComparison


class CheckEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    commands: tuple[str, ...]
    command_digests: tuple[str, ...]
    success: bool
    checked_at: datetime

    @model_validator(mode="after")
    def hashes_match(self):
        if self.command_digests != tuple(
            hashlib.sha256(cmd.encode()).hexdigest() for cmd in self.commands
        ):
            raise ValueError("check command digests disagree")
        if self.checked_at.tzinfo is None:
            raise ValueError("check timestamp must be timezone aware")
        return self


class VerificationReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    checked_tree_id: str
    accepted_commit_id: str
    baseline_snapshot_id: str
    after_snapshot_id: str
    context_identity: str
    checks: CheckEvidence
    publications: tuple[PublicationEvidence, ...]
    verified_fixes: frozenset[FindingKey]
    residual_keys: frozenset[FindingKey] = frozenset()

    @model_validator(mode="after")
    def successful(self):
        if not self.checks.success or not self.publications:
            raise ValueError("receipt requires passing checks and publication evidence")
        if self.verified_fixes & self.residual_keys:
            raise ValueError("residual finding cannot be a verified fix")
        return self


class PlannedAttempt(GradleRecord):
    state: Literal["planned"] = "planned"
    candidate: GradleCandidate


class WithheldAttempt(GradleRecord):
    state: Literal["withheld"] = "withheld"
    candidate: GradleCandidate
    reason: str


class ApplyingAttempt(GradleRecord):
    state: Literal["applying"] = "applying"
    candidate: GradleCandidate
    baseline: GradleSnapshot
    checks: CheckEvidence | None = None
    after: GradleSnapshot | None = None
    checked_tree_id: str | None = None
    accepted_commit_id: str | None = None


class FailedAttempt(GradleRecord):
    state: Literal["failed"] = "failed"
    candidate: GradleCandidate
    baseline: GradleSnapshot
    reason: str
    after: GradleSnapshot | None = None


class ReadyAttempt(GradleRecord):
    state: Literal["ready"] = "ready"
    candidate: GradleCandidate
    baseline: GradleSnapshot
    after: GradleSnapshot
    receipt: VerificationReceipt

    @model_validator(mode="after")
    def binding(self):
        if (
            self.receipt.checked_tree_id != self.after.tree_id
            or self.receipt.after_snapshot_id != self.after.snapshot_id
            or self.receipt.baseline_snapshot_id != self.baseline.snapshot_id
            or self.receipt.context_identity != self.after.context_identity
            or self.baseline.context_identity != self.after.context_identity
        ):
            raise ValueError("receipt does not bind the accepted snapshots")
        return self


class CompletedAttempt(GradleRecord):
    state: Literal["completed"] = "completed"
    candidate: GradleCandidate
    baseline: GradleSnapshot
    after: GradleSnapshot
    receipt: VerificationReceipt
    promoted_commit_id: str


type AttemptState = Annotated[
    PlannedAttempt
    | WithheldAttempt
    | ApplyingAttempt
    | FailedAttempt
    | ReadyAttempt
    | CompletedAttempt,
    Field(discriminator="state"),
]


class GradleRun(GradleRecord):
    schema_version: Literal[1] = 1
    project: str
    flow: Workflow
    base_commit_id: str
    managed_bookmark: str
    managed_tip_id: str
    context: ComparisonContext
    initial_snapshot: GradleSnapshot
    accepted_snapshot: GradleSnapshot
    attempts: tuple[AttemptState, ...] = ()
    selection_blocks: tuple[CandidateWithheld, ...] = ()
    promoted_commit_id: str | None = None
    refreshed: bool = False
    submitted: bool = False

    @model_validator(mode="after")
    def unique_groups(self):
        keys = [attempt.candidate.target.group_key for attempt in self.attempts]
        if len(keys) != len(set(keys)):
            raise ValueError("a run may attempt each group only once")
        expected = (
            "mm/update-dependencies"
            if self.flow == Workflow.UPDATE
            else "mm/resolve-dependencies"
        )
        if self.managed_bookmark != expected:
            raise ValueError("run bookmark and flow disagree")
        if (
            self.initial_snapshot.context_identity != self.context.identity
            or self.accepted_snapshot.context_identity != self.context.identity
        ):
            raise ValueError("run snapshots use a different context")
        if self.refreshed and not self.promoted_commit_id:
            raise ValueError("refresh requires a recorded promotion")
        return self
