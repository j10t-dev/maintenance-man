from datetime import datetime
from enum import StrEnum, auto

from pydantic import BaseModel


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
    STARTED = auto()
    COMPLETED = auto()
    FAILED = auto()


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
