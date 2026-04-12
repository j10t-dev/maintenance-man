from maintenance_man.models.scan import (
    MaintenanceFlow,
    SemverTier,
    Severity,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
)


class TestMaintenanceFlow:
    def test_flow_members_are_string_values(self):
        assert MaintenanceFlow.UPDATE == "update"
        assert MaintenanceFlow.RESOLVE == "resolve"


class TestUpdateStatus:
    def test_vuln_finding_default_status_is_none(self):
        v = VulnFinding(
            vuln_id="CVE-2024-0001",
            pkg_name="some-pkg",
            installed_version="1.0.0",
            fixed_version="1.0.1",
            severity=Severity.HIGH,
            title="Test vuln",
            description="desc",
            status="fixed",
        )
        assert v.update_status is None

    def test_update_finding_default_status_is_none(self):
        u = UpdateFinding(
            pkg_name="pkg-a",
            installed_version="1.0.0",
            latest_version="1.0.1",
            semver_tier=SemverTier.PATCH,
        )
        assert u.update_status is None

    def test_vuln_finding_accepts_all_statuses(self):
        for status in UpdateStatus:
            v = VulnFinding(
                vuln_id="CVE-2024-0001",
                pkg_name="some-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.HIGH,
                title="Test vuln",
                description="desc",
                status="fixed",
                update_status=status,
            )
            assert v.update_status == status

    def test_update_finding_serialises_null_status(self):
        u = UpdateFinding(
            pkg_name="pkg-a",
            installed_version="1.0.0",
            latest_version="1.0.1",
            semver_tier=SemverTier.PATCH,
        )
        data = u.model_dump()
        assert "update_status" in data
        assert data["update_status"] is None
