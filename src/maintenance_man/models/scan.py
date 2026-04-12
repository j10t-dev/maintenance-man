from datetime import datetime
from enum import StrEnum, auto

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, field_validator


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class SemverTier(StrEnum):
    PATCH = auto()
    MINOR = auto()
    MAJOR = auto()
    UNKNOWN = auto()


class UpdateStatus(StrEnum):
    FAILED = "failed"
    READY = "ready"
    COMPLETED = "completed"


class MaintenanceFlow(StrEnum):
    UPDATE = "update"
    RESOLVE = "resolve"


def _coerce_legacy_update_status(value: UpdateStatus | str | None) -> UpdateStatus | str | None:
    if value == "started":
        return UpdateStatus.READY
    return value


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
    flow: MaintenanceFlow | None = None

    @field_validator("update_status", mode="before")
    @classmethod
    def _migrate_update_status(cls, value: UpdateStatus | str | None):
        return _coerce_legacy_update_status(value)

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
    flow: MaintenanceFlow | None = None

    @field_validator("update_status", mode="before")
    @classmethod
    def _migrate_update_status(cls, value: UpdateStatus | str | None):
        return _coerce_legacy_update_status(value)

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

    @property
    def has_actionable_vulns(self) -> bool:
        return any(v.actionable for v in self.vulnerabilities)

    @property
    def has_updates(self) -> bool:
        return bool(self.updates)


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.UNKNOWN: 4,
}


def _fix_version_key(v: VulnFinding) -> Version:
    """Parse *fixed_version* for sorting; unparsable values sort last."""
    try:
        return Version(v.fixed_version or "0")
    except InvalidVersion:
        return Version("0")


def sort_vulns_by_severity(vulns: list[VulnFinding]) -> list[VulnFinding]:
    """Sort by package (grouped), with groups ordered by worst severity.

    Within each package group, vulns are sorted by severity (critical first),
    then fix version descending.  This keeps all vulns for a package together
    so the "fix" marker is easy to follow.
    """
    # Build a lookup of worst (lowest ordinal) severity per package.
    worst: dict[str, int] = {}
    for v in vulns:
        order = _SEVERITY_ORDER[v.severity]
        if v.pkg_name not in worst or order < worst[v.pkg_name]:
            worst[v.pkg_name] = order

    def _key(v: VulnFinding) -> tuple[int, str, int]:
        return (
            worst[v.pkg_name],
            v.pkg_name,
            _SEVERITY_ORDER[v.severity],
        )

    # Two-pass stable sort: version desc first, then the composite key.
    # The stable sort preserves version-desc ordering within each
    # (package, severity) group.
    by_version = sorted(vulns, key=_fix_version_key, reverse=True)
    return sorted(by_version, key=_key)
