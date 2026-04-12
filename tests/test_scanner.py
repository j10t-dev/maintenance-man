import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import ScanResult, SemverTier, Severity, UpdateFinding
from maintenance_man.scanner import (
    TrivyNotFoundError,
    check_trivy_available,
    scan_project,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _make_project(path: str | Path, pm: str = "uv") -> ProjectConfig:
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
        """Scan vulnerable fixture — known to have vulnerabilities."""
        project = _make_project(FIXTURES_DIR / "vulnerable-project")
        result = scan_project("vulnerable", project)

        assert isinstance(result, ScanResult)
        assert result.project == "vulnerable"
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
        """Scan clean fixture — expected to have no vulnerabilities."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        result = scan_project("clean", project)

        assert isinstance(result, ScanResult)
        assert result.project == "clean"
        assert len(result.vulnerabilities) == 0
        assert result.has_actionable_vulns is False

    def test_scan_writes_results_file(self, scan_results_dir: Path):
        """Scan should write JSON results to scan-results dir."""
        project = _make_project(FIXTURES_DIR / "vulnerable-project")
        scan_project("vulnerable", project)

        results_file = scan_results_dir / "vulnerable.json"
        assert results_file.exists()

        data = json.loads(results_file.read_text())
        assert data["project"] == "vulnerable"
        assert "vulnerabilities" in data
        assert "secrets" in data

        # Round-trip: the JSON should deserialise back into a ScanResult
        reloaded = ScanResult.model_validate(data)
        assert reloaded.project == "vulnerable"

    def test_scan_nonexistent_path(self, scan_results_dir: Path):
        """Scan a path that doesn't exist — should raise."""
        project = _make_project("/nonexistent/path")
        with pytest.raises(FileNotFoundError):
            scan_project("ghost", project)


class TestScanProjectWithUpdates:
    def test_scan_includes_updates(self, scan_results_dir: Path):
        """When outdated check returns updates, they appear in ScanResult."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        fake_updates = [
            UpdateFinding(
                pkg_name="requests",
                installed_version="2.28.0",
                latest_version="2.31.0",
                semver_tier=SemverTier.MINOR,
            ),
        ]
        with (
            patch("maintenance_man.scanner.get_outdated", return_value=fake_updates),
            patch("maintenance_man.scanner.filter_by_age", return_value=fake_updates),
        ):
            result = scan_project("clean", project)

        assert result.has_updates is True
        assert len(result.updates) == 1
        assert result.updates[0].pkg_name == "requests"

    def test_scan_deduplicates_vuln_and_update(self, scan_results_dir: Path):
        """If a package is both a vuln and an update, only the vuln appears."""
        project = _make_project(FIXTURES_DIR / "vulnerable-project")
        fake_updates = [
            UpdateFinding(
                pkg_name="cryptography",
                installed_version="42.0.0",
                latest_version="43.0.0",
                semver_tier=SemverTier.MAJOR,
            ),
            UpdateFinding(
                pkg_name="brand-new-pkg",
                installed_version="1.0.0",
                latest_version="2.0.0",
                semver_tier=SemverTier.MAJOR,
            ),
        ]
        with (
            patch("maintenance_man.scanner.get_outdated", return_value=fake_updates),
            patch("maintenance_man.scanner.filter_by_age", return_value=fake_updates),
        ):
            result = scan_project("vulnerable", project)

        vuln_pkg_names = {v.pkg_name for v in result.vulnerabilities}
        update_pkg_names = {u.pkg_name for u in result.updates}
        assert "cryptography" in vuln_pkg_names
        assert "cryptography" not in update_pkg_names
        assert "brand-new-pkg" in update_pkg_names

    def test_scan_outdated_failure_does_not_crash(self, scan_results_dir: Path):
        """If the outdated check fails, scan still returns Trivy results."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        with patch(
            "maintenance_man.scanner.get_outdated",
            side_effect=Exception("bun not found"),
        ):
            result = scan_project("clean", project)

        assert isinstance(result, ScanResult)
        assert result.updates == []

    def test_scan_passes_min_version_age_days(self, scan_results_dir: Path):
        """min_version_age_days parameter is forwarded to filter_by_age."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        with (
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
            patch("maintenance_man.scanner.filter_by_age", return_value=[]) as mock_age,
        ):
            scan_project("clean", project, min_version_age_days=14)

        mock_age.assert_called_once()
        assert mock_age.call_args.kwargs["min_age_days"] == 14


class TestRunTrivyScanSkipDirs:
    def test_skip_dirs_appended_to_command(
        self, scan_results_dir: Path, tmp_path: Path
    ):
        """scan_skip_dirs entries are forwarded as --skip-dirs flags to trivy."""
        project = ProjectConfig(
            path=tmp_path,
            package_manager="uv",
            scan_skip_dirs=["tests/fixtures", "vendor"],
        )
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Results": []}', stderr=""
        )
        with (
            patch(
                "maintenance_man.scanner.subprocess.run",
                return_value=fake_result,
            ) as mock_run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            scan_project("test-proj", project)

        cmd = mock_run.call_args.args[0]
        assert cmd.count("--skip-dirs") == 2
        dirs_indices = [i for i, v in enumerate(cmd) if v == "--skip-dirs"]
        assert cmd[dirs_indices[0] + 1] == "tests/fixtures"
        assert cmd[dirs_indices[1] + 1] == "vendor"

    def test_no_skip_dirs_by_default(self, scan_results_dir: Path, tmp_path: Path):
        """Without scan_skip_dirs, no --skip-dirs flags are added."""
        project = ProjectConfig(path=tmp_path, package_manager="uv")
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Results": []}', stderr=""
        )
        with (
            patch(
                "maintenance_man.scanner.subprocess.run",
                return_value=fake_result,
            ) as mock_run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            scan_project("test-proj", project)

        cmd = mock_run.call_args.args[0]
        assert "--skip-dirs" not in cmd
