from datetime import datetime, timezone
from pathlib import Path

import pytest

from maintenance_man.cli import app
from maintenance_man.models.scan import ScanResult, Severity, VulnFinding


def _make_lifts_result() -> ScanResult:
    return ScanResult(
        project="lifts",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="/home/glykon/dev/lifts",
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


def _make_feetfax_result() -> ScanResult:
    return ScanResult(
        project="feetfax",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="/home/glykon/dev/feetfax",
    )


@pytest.fixture(autouse=True)
def _mock_trivy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent all CLI tests from calling real Trivy."""
    monkeypatch.setattr("maintenance_man.cli.check_trivy_available", lambda: None)

    def _fake_scan(name: str, project_config: object) -> ScanResult:
        if name == "lifts":
            return _make_lifts_result()
        if name == "feetfax":
            return _make_feetfax_result()
        raise FileNotFoundError(f"Unknown project: {name}")

    monkeypatch.setattr("maintenance_man.cli.scan_project", _fake_scan)


class TestScanSingleProject:
    def test_scan_project_with_vulns_exits_2(self, mm_home_with_projects: Path):
        """mm scan lifts — has vulns, should exit 2."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "lifts"])
        assert exc_info.value.code == 2

    def test_scan_project_with_vulns_shows_findings(
        self, mm_home_with_projects: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Output should contain vulnerability information."""
        with pytest.raises(SystemExit):
            app(["scan", "lifts"])
        output = capsys.readouterr().out
        assert "CVE-" in output or "vuln" in output.lower()

    def test_scan_clean_project_exits_0(self, mm_home_with_projects: Path):
        """mm scan feetfax — clean, should exit 0."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "feetfax"])
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
        # lifts has vulns, so worst case is 2
        assert exc_info.value.code == 2
