from datetime import datetime, timezone
from pathlib import Path

import pytest

from maintenance_man.cli import app
from maintenance_man.models.scan import ScanResult, Severity, VulnFinding


def _make_vulnerable_result() -> ScanResult:
    return ScanResult(
        project="vulnerable",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="tests/fixtures/vulnerable-project",
        vulnerabilities=[
            VulnFinding(
                vuln_id="CVE-2024-0001",
                pkg_name="some-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.HIGH,
                title="Test vulnerability",
                description="A test vulnerability",
                status="fixed",
            ),
        ],
    )


def _make_clean_result() -> ScanResult:
    return ScanResult(
        project="clean",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="tests/fixtures/clean-project",
    )


@pytest.fixture(autouse=True)
def _mock_trivy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent all CLI tests from calling real Trivy."""
    monkeypatch.setattr("maintenance_man.cli.check_trivy_available", lambda: None)

    def _fake_scan(name: str, project_config: object) -> ScanResult:
        if name == "vulnerable":
            return _make_vulnerable_result()
        if name == "clean":
            return _make_clean_result()
        raise FileNotFoundError(f"Unknown project: {name}")

    monkeypatch.setattr("maintenance_man.cli.scan_project", _fake_scan)


class TestScanSingleProject:
    def test_scan_project_with_vulns_exits_2(self, mm_home_with_projects: Path):
        """mm scan vulnerable — has vulns, should exit 2."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "vulnerable"])
        assert exc_info.value.code == 2

    def test_scan_project_with_vulns_shows_findings(
        self, mm_home_with_projects: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Output should contain vulnerability information."""
        with pytest.raises(SystemExit):
            app(["scan", "vulnerable"])
        output = capsys.readouterr().out
        assert "CVE-" in output or "vuln" in output.lower()

    def test_scan_clean_project_exits_0(self, mm_home_with_projects: Path):
        """mm scan clean — clean, should exit 0."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "clean"])
        assert exc_info.value.code == 0

    def test_scan_unknown_project_exits_1(self, mm_home_with_projects: Path):
        """mm scan nonexistent — should exit 1."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "nonexistent"])
        assert exc_info.value.code == 1


class TestScanAllProjects:
    def test_scan_all_exits_worst_case(self, mm_home_with_projects: Path):
        """mm scan (no args) — should exit 2 if any project has vulns."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan"])
        # vulnerable has vulns, so worst case is 2
        assert exc_info.value.code == 2
