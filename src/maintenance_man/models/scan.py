from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto
from typing import Any, Literal

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        """Higher is more severe; UNKNOWN ranks lowest."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class SemverTier(StrEnum):
    PATCH = auto()
    MINOR = auto()
    MAJOR = auto()
    UNKNOWN = auto()


def classify_semver(installed: str, latest: str) -> SemverTier:
    """Compare two version strings and return the semver tier of the change."""
    try:
        old = Version(installed)
        new = Version(latest)
    except InvalidVersion:
        return SemverTier.UNKNOWN

    if old == new:
        return SemverTier.UNKNOWN

    match (old.major != new.major, old.minor != new.minor):
        case (True, _):
            return SemverTier.MAJOR
        case (_, True):
            return SemverTier.MINOR
        case _:
            return SemverTier.PATCH


class UpdateStatus(StrEnum):
    FAILED = "failed"
    READY = "ready"
    COMPLETED = "completed"


class Workflow(StrEnum):
    UPDATE = "update"
    RESOLVE = "resolve"


WORKFLOW_BOOKMARKS: Mapping[Workflow, str] = {
    Workflow.UPDATE: "mm/update-dependencies",
    Workflow.RESOLVE: "mm/resolve-dependencies",
}


type GradleKind = Literal["library", "plugin"]
type GradleBlockKind = Literal["age", "mapping", "conflict", "stale"]
type UpdateKind = Literal["vuln", "update"]


@dataclass(slots=True)
class UpdateResult:
    """Outcome of one dependency update attempt."""

    pkg_name: str
    kind: UpdateKind
    passed: bool
    failed_phase: str | None = None


class GradleMember(BaseModel):
    """One catalogue alias changed by a Gradle update target."""

    kind: GradleKind
    alias: str
    coordinate: str
    installed_version: str


class GradleUpdateTarget(BaseModel):
    """An editable catalogue version and every alias that shares it."""

    version_ref: str | None = None
    members: list[GradleMember]
    target_version: str

    @property
    def group_key(self) -> str:
        """Stable identity used to group findings into one update attempt."""
        if self.version_ref is not None:
            return f"ref:{self.version_ref}"
        member = self.members[0]
        return f"{member.kind}:{member.alias}"

    @property
    def display_name(self) -> str:
        return self.version_ref or self.members[0].coordinate


class GradleBlock(BaseModel):
    """Policy state that withholds an automatic change. Not a failure."""

    kind: GradleBlockKind
    reason: str


class VulnFinding(BaseModel):
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str | None = None
    severity: Severity
    title: str
    description: str
    status: str
    primary_url: str | None = None
    published_date: datetime | None = None
    update_status: UpdateStatus | None = None
    failed_phase: str | None = None
    flow: Workflow | None = None
    gradle_target: GradleUpdateTarget | None = None
    blocked_reason: str | None = None
    gradle_block_kind: GradleBlockKind | None = None
    gradle_scopes: tuple[str, ...] = ()

    @property
    def actionable(self) -> bool:
        return self.fixed_version is not None

    @property
    def target_version(self) -> str:
        if self.fixed_version is None:
            raise ValueError("No fixed version available")
        return self.fixed_version

    @property
    def detail(self) -> str:
        return self.vuln_id


class SecretFinding(BaseModel):
    file: str
    rule_id: str
    title: str
    severity: Severity


class UpdateFinding(BaseModel):
    pkg_name: str
    installed_version: str
    latest_version: str
    semver_tier: SemverTier
    published_date: datetime | None = None
    update_status: UpdateStatus | None = None
    failed_phase: str | None = None
    flow: Workflow | None = None
    gradle_target: GradleUpdateTarget | None = None
    blocked_reason: str | None = None
    gradle_block_kind: GradleBlockKind | None = None

    @property
    def target_version(self) -> str:
        return self.latest_version

    @property
    def detail(self) -> str:
        return self.semver_tier.value


class ScanResult(BaseModel):
    project: str
    scanned_at: datetime
    trivy_target: str
    vulnerabilities: list[VulnFinding] = []
    secrets: list[SecretFinding] = []
    updates: list[UpdateFinding] = []
    gradle_resolution: dict[str, Any] | None = None

    @property
    def has_actionable_vulns(self) -> bool:
        return any(v.actionable for v in self.vulnerabilities)

    @property
    def has_updates(self) -> bool:
        return bool(self.updates)

    @property
    def findings(self) -> tuple[VulnFinding | UpdateFinding, ...]:
        return (*self.vulnerabilities, *self.updates)

    @property
    def blocked_findings(self) -> list[VulnFinding | UpdateFinding]:
        """Findings withheld by current policy. Orthogonal to update lifecycle."""
        return [f for f in self.findings if f.blocked_reason is not None]


def _fix_version_key(v: VulnFinding) -> Version:
    """Parse *fixed_version* for sorting; unparsable values sort last."""
    try:
        return Version(v.fixed_version or "0")
    except InvalidVersion:
        return Version("0")


def highest_fix_version(vulns: list[VulnFinding]) -> str:
    """Return the ``fixed_version`` of the first finding with the highest version.

    Missing and unparsable versions rank as ``0``. When that finding has no
    ``fixed_version``, fall back to the last finding's, then ``""``.
    """
    best = max(vulns, key=_fix_version_key)
    return best.fixed_version or vulns[-1].fixed_version or ""


def sort_vulns_by_severity(vulns: list[VulnFinding]) -> list[VulnFinding]:
    """Sort by package (grouped), with groups ordered by worst severity.

    Within each package group, vulns are sorted by severity (critical first),
    then fix version descending.  This keeps all vulns for a package together
    so the "fix" marker is easy to follow.
    """
    # Build a lookup of worst (lowest negative rank) severity per package.
    worst: dict[str, int] = {}
    for v in vulns:
        order = -v.severity.rank
        if v.pkg_name not in worst or order < worst[v.pkg_name]:
            worst[v.pkg_name] = order

    def _key(v: VulnFinding) -> tuple[int, str, int]:
        return (
            worst[v.pkg_name],
            v.pkg_name,
            -v.severity.rank,
        )

    # Two-pass stable sort: version desc first, then the composite key.
    # The stable sort preserves version-desc ordering within each
    # (package, severity) group.
    by_version = sorted(vulns, key=_fix_version_key, reverse=True)
    return sorted(by_version, key=_key)
