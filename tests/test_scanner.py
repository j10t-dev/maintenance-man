import json
from pathlib import Path

import pytest

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import ScanResult, Severity
from maintenance_man.scanner import (
    TrivyNotFoundError,
    check_trivy_available,
    scan_project,
)


def _make_project(path: str, pm: str = "uv") -> ProjectConfig:
    return ProjectConfig(path=Path(path), package_manager=pm)


class TestCheckTrivyAvailable:
    def test_trivy_is_available(self):
        # Should not raise — trivy is installed on this machine
        check_trivy_available()

    def test_trivy_not_available(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("PATH", "/nonexistent")
        with pytest.raises(TrivyNotFoundError):
            check_trivy_available()


@pytest.mark.integration
class TestScanProject:
    def test_scan_project_with_vulns(self, scan_results_dir: Path):
        """Scan lifts — known to have vulnerabilities."""
        project = _make_project("/home/glykon/dev/lifts")
        result = scan_project("lifts", project)

        assert isinstance(result, ScanResult)
        assert result.project == "lifts"
        assert result.trivy_target == "/home/glykon/dev/lifts"
        assert result.scanned_at is not None
        assert len(result.vulnerabilities) > 0
        assert result.has_actionable_vulns is True

        # Structural checks on findings
        for v in result.vulnerabilities:
            assert v.vuln_id.startswith("CVE-") or v.vuln_id.startswith("GHSA-")
            assert v.pkg_name
            assert v.installed_version
            assert v.severity in Severity
            assert v.title
            assert v.status

    def test_scan_project_clean(self, scan_results_dir: Path):
        """Scan feetfax — expected to be clean."""
        project = _make_project("/home/glykon/dev/feetfax", "bun")
        result = scan_project("feetfax", project)

        assert isinstance(result, ScanResult)
        assert result.project == "feetfax"
        assert len(result.vulnerabilities) == 0
        assert result.has_actionable_vulns is False

    def test_scan_writes_results_file(self, scan_results_dir: Path):
        """Scan should write JSON results to scan-results dir."""
        project = _make_project("/home/glykon/dev/lifts")
        scan_project("lifts", project)

        results_file = scan_results_dir / "lifts.json"
        assert results_file.exists()

        data = json.loads(results_file.read_text())
        assert data["project"] == "lifts"
        assert "vulnerabilities" in data
        assert "secrets" in data

        # Round-trip: the JSON should deserialise back into a ScanResult
        reloaded = ScanResult.model_validate(data)
        assert reloaded.project == "lifts"

    def test_scan_nonexistent_path(self, scan_results_dir: Path):
        """Scan a path that doesn't exist — should raise."""
        project = _make_project("/nonexistent/path")
        with pytest.raises(FileNotFoundError):
            scan_project("ghost", project)
