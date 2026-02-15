from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from maintenance_man.models.scan import (
    ScanResult,
    SecretFinding,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
    sort_vulns_by_severity,
)


class TestVulnFinding:
    def test_vuln_finding_with_fix(self):
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

    def test_vuln_finding_advisory_no_fix(self):
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

    def test_vuln_finding_rejects_invalid_severity(self):
        with pytest.raises(ValidationError, match="severity"):
            VulnFinding(
                vuln_id="CVE-2025-00001",
                pkg_name="pkg",
                installed_version="1.0",
                severity="BOGUS",
                title="t",
                description="d",
                status="fixed",
            )


class TestSecretFinding:
    def test_secret_finding(self):
        finding = SecretFinding(
            file="creds/service.json",
            rule_id="gcp-service-account",
            title="Google (GCP) Service-account",
            severity="CRITICAL",
        )
        assert finding.rule_id == "gcp-service-account"


class TestScanResult:
    def test_scan_result_empty(self):
        result = ScanResult(
            project="project-alpha",
            scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
            trivy_target="/tmp/project-alpha",
            vulnerabilities=[],
            secrets=[],
        )
        assert result.has_actionable_vulns is False

    def test_scan_result_with_vulns(self):
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
            project="project-beta",
            scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
            trivy_target="/tmp/project-beta",
            vulnerabilities=[vuln],
            secrets=[],
        )
        assert result.has_actionable_vulns is True

    def test_scan_result_with_updates(self):
        finding = UpdateFinding(
            pkg_name="axios",
            installed_version="1.6.0",
            latest_version="1.7.2",
            semver_tier=SemverTier.MINOR,
        )
        result = ScanResult(
            project="project-gamma",
            scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
            trivy_target="/tmp/project-gamma",
            updates=[finding],
        )
        assert result.has_updates is True
        assert len(result.updates) == 1

    def test_scan_result_empty_has_no_updates(self):
        result = ScanResult(
            project="project-gamma",
            scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
            trivy_target="/tmp/project-gamma",
        )
        assert result.has_updates is False


class TestUpdateFinding:
    def test_update_finding_minor(self):
        finding = UpdateFinding(
            pkg_name="axios",
            installed_version="1.6.0",
            latest_version="1.7.2",
            semver_tier=SemverTier.MINOR,
        )
        assert finding.pkg_name == "axios"
        assert finding.semver_tier == SemverTier.MINOR
        assert finding.published_date is None

    def test_update_finding_with_publish_date(self):
        finding = UpdateFinding(
            pkg_name="lodash",
            installed_version="4.17.20",
            latest_version="4.17.21",
            semver_tier=SemverTier.PATCH,
            published_date=datetime(2026, 1, 10, tzinfo=timezone.utc),
        )
        assert finding.published_date is not None
        assert finding.semver_tier == SemverTier.PATCH

    def test_update_finding_round_trip_json(self):
        finding = UpdateFinding(
            pkg_name="react",
            installed_version="18.2.0",
            latest_version="19.0.0",
            semver_tier=SemverTier.MAJOR,
            published_date=datetime(2026, 1, 20, tzinfo=timezone.utc),
        )
        result = ScanResult(
            project="project-gamma",
            scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
            trivy_target="/tmp/project-gamma",
            updates=[finding],
        )
        json_str = result.model_dump_json()
        reloaded = ScanResult.model_validate_json(json_str)
        assert len(reloaded.updates) == 1
        assert reloaded.updates[0].pkg_name == "react"
        assert reloaded.updates[0].semver_tier == SemverTier.MAJOR


class TestSortVulnsBySeverity:
    def _make_vuln(self, severity: Severity) -> VulnFinding:
        return VulnFinding(
            vuln_id=f"CVE-{severity.value}",
            pkg_name="pkg",
            installed_version="1.0.0",
            fixed_version="1.0.1",
            severity=severity,
            title="t",
            description="d",
            status="fixed",
        )

    def test_sorts_critical_first(self):
        vulns = [
            self._make_vuln(Severity.LOW),
            self._make_vuln(Severity.CRITICAL),
            self._make_vuln(Severity.MEDIUM),
            self._make_vuln(Severity.HIGH),
            self._make_vuln(Severity.UNKNOWN),
        ]
        result = sort_vulns_by_severity(vulns)
        assert [v.severity for v in result] == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.UNKNOWN,
        ]

    def test_single_item(self):
        result = sort_vulns_by_severity([self._make_vuln(Severity.HIGH)])
        assert len(result) == 1
        assert result[0].severity == Severity.HIGH

    def test_empty_list(self):
        assert sort_vulns_by_severity([]) == []


class TestSemverTier:
    def test_semver_tier_values(self):
        assert SemverTier.PATCH == "patch"
        assert SemverTier.MINOR == "minor"
        assert SemverTier.MAJOR == "major"
        assert SemverTier.UNKNOWN == "unknown"
