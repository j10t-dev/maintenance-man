from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from maintenance_man.models.scan import (
    ScanResult,
    SecretFinding,
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
