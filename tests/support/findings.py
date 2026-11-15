"""Finding and scan builders; scenarios override their relevant fields."""

from datetime import UTC, datetime
from typing import Any

from maintenance_man.models.config import PackageManager
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    SecretFinding,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
)


def make_vuln(**overrides: Any) -> VulnFinding:
    """Build an actionable vulnerability with scenario-specific overrides."""
    defaults = {
        "vuln_id": "CVE-2024-0001",
        "pkg_name": "some-pkg",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
        "severity": Severity.HIGH,
        "title": "Test vuln",
        "description": "desc",
        "status": "fixed",
    }
    return VulnFinding(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_update(tier: SemverTier = SemverTier.PATCH, **overrides: Any) -> UpdateFinding:
    """Build an update whose default version pair matches the supplied tier."""
    name, installed, latest = {
        SemverTier.PATCH: ("pkg-a", "1.0.0", "1.0.1"),
        SemverTier.MINOR: ("pkg-b", "1.0.0", "1.1.0"),
        SemverTier.MAJOR: ("pkg-c", "1.0.0", "2.0.0"),
    }.get(tier, ("pkg-x", "1.0.0", "2.0.0"))
    defaults = {
        "pkg_name": name,
        "installed_version": installed,
        "latest_version": latest,
        "semver_tier": tier,
    }
    return UpdateFinding(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_scan_result(
    vulns: list[VulnFinding] | None = None,
    updates: list[UpdateFinding] | None = None,
    secrets: list[SecretFinding] | None = None,
    *,
    package_manager: PackageManager = "uv",
) -> ScanResult:
    """Build a saved scan with the supplied findings, or one vulnerability and one
    update by default and no secrets.
    """
    return ScanResult(
        project_name="vulnerable",
        package_manager=package_manager,
        scanned_at=datetime.now(tz=UTC),
        vulnerabilities=vulns if vulns is not None else [make_vuln()],
        updates=updates if updates is not None else [make_update()],
        secrets=secrets if secrets is not None else [],
    )


def make_gradle_member(**overrides: Any) -> GradleMember:
    """Build a catalogue member with scenario-specific overrides."""
    defaults = {
        "kind": "library",
        "alias": "room-runtime",
        "coordinate": "androidx.room:room-runtime",
        "installed_version": "2.8.4",
    }
    return GradleMember(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_gradle_target(**overrides: Any) -> GradleUpdateTarget:
    """Build a shared catalogue target with scenario-specific overrides."""
    defaults = {
        "version_ref": "room",
        "members": [
            make_gradle_member(
                alias="room-runtime", coordinate="androidx.room:room-runtime"
            ),
            make_gradle_member(
                alias="room-compiler", coordinate="androidx.room:room-compiler"
            ),
            make_gradle_member(
                alias="room-testing", coordinate="androidx.room:room-testing"
            ),
        ],
        "target_version": "2.8.5",
    }
    return GradleUpdateTarget(**(defaults | overrides))  # ty:ignore[invalid-argument-type]
