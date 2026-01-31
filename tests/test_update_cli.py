from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.cli import app
from maintenance_man.models.scan import (
    BumpFinding,
    ScanResult,
    SemverTier,
    Severity,
    VulnFinding,
)
from maintenance_man.updater import UpdateResult


def _make_scan_result() -> ScanResult:
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
                title="Test vuln",
                description="desc",
                status="fixed",
            ),
        ],
        bumps=[
            BumpFinding(
                pkg_name="pkg-a",
                installed_version="1.0.0",
                latest_version="1.0.1",
                semver_tier=SemverTier.PATCH,
            ),
        ],
    )


@pytest.fixture(autouse=True)
def _mock_updater(monkeypatch: pytest.MonkeyPatch):
    """Mock all updater pre-checks to pass by default."""
    monkeypatch.setattr(
        "maintenance_man.cli.check_graphite_available", lambda: None
    )
    monkeypatch.setattr(
        "maintenance_man.cli.check_repo_clean", lambda p: None
    )
    monkeypatch.setattr(
        "maintenance_man.cli.load_scan_results",
        lambda name, d: _make_scan_result(),
    )


class TestUpdatePreChecks:
    def test_no_scan_results_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.updater import NoScanResultsError
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("No results")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1

    def test_dirty_repo_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.updater import RepoDirtyError
        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            MagicMock(side_effect=RepoDirtyError("dirty")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1

    def test_no_gt_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.updater import GraphiteNotFoundError
        monkeypatch.setattr(
            "maintenance_man.cli.check_graphite_available",
            MagicMock(side_effect=GraphiteNotFoundError("no gt")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1

    def test_no_test_config_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """Project without test config should refuse to proceed."""
        from maintenance_man.models.config import ProjectConfig
        monkeypatch.setattr(
            "maintenance_man.cli.resolve_project",
            MagicMock(return_value=ProjectConfig(
                path=Path("/tmp/x"), package_manager="bun", test=None
            )),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1


class TestUpdateSelection:
    @patch("maintenance_man.cli.process_vulns", return_value=[])
    @patch("maintenance_man.cli.process_bumps", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="none")
    def test_none_selection_exits_0(
        self, mock_ask, mock_bumps, mock_vulns,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_not_called()
        mock_bumps.assert_not_called()

    @patch("maintenance_man.cli.submit_stack")
    @patch("maintenance_man.cli.Confirm.ask", return_value=False)
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ],
    )
    @patch("maintenance_man.cli.process_bumps", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="vulns")
    def test_vulns_selection(
        self, mock_ask, mock_bumps, mock_vulns, mock_confirm, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_called_once()
        mock_bumps.assert_not_called()


class TestUpdateExitCodes:
    @patch("maintenance_man.cli.submit_stack")
    @patch("maintenance_man.cli.Confirm.ask", return_value=False)
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ],
    )
    @patch(
        "maintenance_man.cli.process_bumps",
        return_value=[
            UpdateResult(pkg_name="pkg-a", kind="bump", passed=True)
        ],
    )
    @patch("maintenance_man.cli.Prompt.ask", return_value="all")
    def test_all_pass_exits_0(
        self, mock_ask, mock_bumps, mock_vulns, mock_confirm, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

    @patch("maintenance_man.cli.submit_stack")
    @patch("maintenance_man.cli.Confirm.ask", return_value=False)
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=False,
                failed_phase="unit",
            )
        ],
    )
    @patch("maintenance_man.cli.process_bumps", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="all")
    def test_any_failure_exits_4(
        self, mock_ask, mock_bumps, mock_vulns, mock_confirm, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4


class TestUpdateNumberedSelection:
    @patch("maintenance_man.cli.submit_stack")
    @patch("maintenance_man.cli.Confirm.ask", return_value=False)
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=True,
            )
        ],
    )
    @patch("maintenance_man.cli.process_bumps", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="1")
    def test_select_by_number(
        self, mock_ask, mock_bumps, mock_vulns,
        mock_confirm, mock_submit,
        mm_home_with_projects: Path,
    ):
        """Selecting '1' should pick the first finding."""
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        # Should have called process_vulns with the first vuln
        mock_vulns.assert_called_once()
