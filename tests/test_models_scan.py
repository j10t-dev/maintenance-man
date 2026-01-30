from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from maintenance_man.models.scan import (
    UpdateFinding,
    ScanResult,
    SecretFinding,
    SemverTier,
    Severity,
    VulnFinding,
)


def test_vuln_finding_with_fix():
    finding = VulnFinding(
        vuln_id="CVE-2026-23490",
        pkg_name="pyasn1",
        installed_version="0.6.1",
        fixed_version="0.6.2",
        severity=Severity.HIGH,
        title="pyasn1: DoS via malformed RELATIVE-OID",
        description="Memory exhaustion from malformed RELATIVE-OID.",
        status="fixed",
        primary_url="https://avd.aquasec.com/nvd/cve-2026-23490",
        published_date=datetime(2026, 1, 16, tzinfo=timezone.utc),
    )
    assert finding.vuln_id == "CVE-2026-23490"
    assert finding.fixed_version == "0.6.2"
    assert finding.actionable is True


def test_vuln_finding_advisory_no_fix():
    finding = VulnFinding(
        vuln_id="CVE-2025-99999",
        pkg_name="somelib",
        installed_version="1.0.0",
        fixed_version=None,
        severity=Severity.HIGH,
        title="somelib: advisory only",
        description="No fix available.",
        status="affected",
    )
    assert finding.fixed_version is None
    assert finding.actionable is False


def test_vuln_finding_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        VulnFinding(
            vuln_id="CVE-2025-00001",
            pkg_name="pkg",
            installed_version="1.0",
            severity="BOGUS",
            title="t",
            description="d",
            status="fixed",
        )


def test_secret_finding():
    finding = SecretFinding(
        file="creds/service.json",
        rule_id="gcp-service-account",
        title="Google (GCP) Service-account",
        severity="CRITICAL",
    )
    assert finding.rule_id == "gcp-service-account"


def test_scan_result_empty():
    result = ScanResult(
        project="feetfax",
        scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
        trivy_target="/home/user/dev/feetfax",
        vulnerabilities=[],
        secrets=[],
    )
    assert result.has_actionable_vulns is False


def test_scan_result_with_vulns():
    vuln = VulnFinding(
        vuln_id="CVE-2026-23490",
        pkg_name="pyasn1",
        installed_version="0.6.1",
        fixed_version="0.6.2",
        severity=Severity.HIGH,
        title="t",
        description="d",
        status="fixed",
    )
    result = ScanResult(
        project="lifts",
        scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
        trivy_target="/home/user/dev/lifts",
        vulnerabilities=[vuln],
        secrets=[],
    )
    assert result.has_actionable_vulns is True


def test_update_finding_minor():
    finding = UpdateFinding(
        pkg_name="axios",
        installed_version="1.6.0",
        latest_version="1.7.2",
        semver_tier=SemverTier.MINOR,
    )
    assert finding.pkg_name == "axios"
    assert finding.semver_tier == SemverTier.MINOR
    assert finding.published_date is None


def test_update_finding_with_publish_date():
    finding = UpdateFinding(
        pkg_name="lodash",
        installed_version="4.17.20",
        latest_version="4.17.21",
        semver_tier=SemverTier.PATCH,
        published_date=datetime(2026, 1, 10, tzinfo=timezone.utc),
    )
    assert finding.published_date is not None
    assert finding.semver_tier == SemverTier.PATCH


def test_semver_tier_values():
    assert SemverTier.PATCH == "patch"
    assert SemverTier.MINOR == "minor"
    assert SemverTier.MAJOR == "major"
    assert SemverTier.UNKNOWN == "unknown"


def test_scan_result_with_updates():
    finding = UpdateFinding(
        pkg_name="axios",
        installed_version="1.6.0",
        latest_version="1.7.2",
        semver_tier=SemverTier.MINOR,
    )
    result = ScanResult(
        project="myproject",
        scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
        trivy_target="/home/user/dev/myproject",
        updates=[finding],
    )
    assert result.has_updates is True
    assert len(result.updates) == 1


def test_scan_result_empty_has_no_updates():
    result = ScanResult(
        project="myproject",
        scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
        trivy_target="/home/user/dev/myproject",
    )
    assert result.has_updates is False


def test_update_finding_round_trip_json():
    finding = UpdateFinding(
        pkg_name="react",
        installed_version="18.2.0",
        latest_version="19.0.0",
        semver_tier=SemverTier.MAJOR,
        published_date=datetime(2026, 1, 20, tzinfo=timezone.utc),
    )
    result = ScanResult(
        project="myproject",
        scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
        trivy_target="/dev/null",
        updates=[finding],
    )
    json_str = result.model_dump_json()
    reloaded = ScanResult.model_validate_json(json_str)
    assert len(reloaded.updates) == 1
    assert reloaded.updates[0].pkg_name == "react"
    assert reloaded.updates[0].semver_tier == SemverTier.MAJOR
