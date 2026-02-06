from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.cli import app
from maintenance_man.models.scan import (
    UpdateFinding,
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
        updates=[
            UpdateFinding(
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
        "maintenance_man.cli.sync_graphite", lambda p: True
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

    def test_dirty_repo_exits_1_when_declined(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.updater import RepoDirtyError
        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            MagicMock(side_effect=RepoDirtyError("dirty")),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=False),
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
    @patch("maintenance_man.cli.process_updates", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="none")
    def test_none_selection_exits_0(
        self, mock_ask, mock_updates, mock_vulns,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_not_called()
        mock_updates.assert_not_called()

    @patch("maintenance_man.cli.submit_stack", return_value=(True, ""))
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ],
    )
    @patch("maintenance_man.cli.process_updates", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="vulns")
    def test_vulns_selection(
        self, mock_ask, mock_updates, mock_vulns, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_called_once()
        mock_updates.assert_not_called()


class TestUpdateExitCodes:
    @patch("maintenance_man.cli.submit_stack", return_value=(True, ""))
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ],
    )
    @patch(
        "maintenance_man.cli.process_updates",
        return_value=[
            UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
        ],
    )
    @patch("maintenance_man.cli.Prompt.ask", return_value="all")
    def test_all_pass_exits_0(
        self, mock_ask, mock_updates, mock_vulns, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

    @patch("maintenance_man.cli.submit_stack")
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=False,
                failed_phase="unit",
            )
        ],
    )
    @patch("maintenance_man.cli.process_updates", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="all")
    def test_any_failure_exits_4(
        self, mock_ask, mock_updates, mock_vulns, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4


class TestUpdateNumberedSelection:
    @patch("maintenance_man.cli.submit_stack", return_value=(True, ""))
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=True,
            )
        ],
    )
    @patch("maintenance_man.cli.process_updates", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="1")
    def test_select_by_number(
        self, mock_ask, mock_updates, mock_vulns,
        mock_submit,
        mm_home_with_projects: Path,
    ):
        """Selecting '1' should pick the first finding."""
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        # Should have called process_vulns with the first vuln
        mock_vulns.assert_called_once()


class TestUpdateContinue:
    def test_continue_no_failures_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue with no failed findings should error."""
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 1

    @patch("maintenance_man.cli.get_current_branch", return_value="bump/pkg-a")
    @patch("maintenance_man.cli.run_test_phases", return_value=(True, None))
    @patch("maintenance_man.cli.save_scan_results")
    @patch("maintenance_man.cli.submit_stack", return_value=(True, ""))
    def test_continue_passes_and_submits(
        self, mock_submit, mock_save, mock_test, mock_branch,
        mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue on matching failed branch, tests pass -> submit."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 0
        mock_test.assert_called_once()
        mock_submit.assert_called_once()

    @patch("maintenance_man.cli.get_current_branch", return_value="bump/pkg-a")
    @patch("maintenance_man.cli.run_test_phases", return_value=(False, "unit"))
    @patch("maintenance_man.cli.save_scan_results")
    def test_continue_fails_again_exits_4(
        self, mock_save, mock_test, mock_branch,
        mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue that fails again should exit 4."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 4

    @patch("maintenance_man.cli.get_current_branch", return_value="main")
    def test_continue_branch_mismatch_exits_1(
        self, mock_branch,
        mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue on wrong branch should error."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 1

    @patch("maintenance_man.cli.get_current_branch", return_value="fix/some-pkg")
    @patch("maintenance_man.cli.run_test_phases", return_value=(True, None))
    @patch("maintenance_man.cli.save_scan_results")
    @patch("maintenance_man.cli.submit_stack", return_value=(True, ""))
    def test_continue_with_remaining_failures_no_submit(
        self, mock_submit, mock_save, mock_test, mock_branch,
        mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue that passes but other failures remain -> no submit, exit 4."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        # Vuln is failed (matching current branch), update is also failed
        scan_result.vulnerabilities[0].update_status = UpdateStatus.FAILED
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 4
        mock_submit.assert_not_called()


class TestUpdateAutoSubmit:
    """Stack submission is now internal to process_vulns/process_updates.

    These tests verify that the CLI delegates correctly and reports the
    right exit codes — submission is tested in test_updater.py.
    """

    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ],
    )
    @patch(
        "maintenance_man.cli.process_updates",
        return_value=[
            UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
        ],
    )
    @patch("maintenance_man.cli.Prompt.ask", return_value="all")
    def test_all_pass_exits_0(
        self, mock_ask, mock_updates, mock_vulns,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=False,
                failed_phase="unit",
            )
        ],
    )
    @patch("maintenance_man.cli.process_updates", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="all")
    def test_all_failures_exits_4(
        self, mock_ask, mock_updates, mock_vulns,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4

    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=False,
                failed_phase="unit",
            )
        ],
    )
    @patch(
        "maintenance_man.cli.process_updates",
        return_value=[
            UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
        ],
    )
    @patch("maintenance_man.cli.Prompt.ask", return_value="all")
    def test_mixed_results_exits_4(
        self, mock_ask, mock_updates, mock_vulns,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4
