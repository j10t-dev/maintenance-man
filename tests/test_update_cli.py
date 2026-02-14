from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

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
        from maintenance_man.vcs import RepoDirtyError
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
        from maintenance_man.vcs import GraphiteNotFoundError
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
    def test_none_selection_exits_0(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        mock_vulns = MagicMock(return_value=[])
        mock_updates = MagicMock(return_value=[])
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="none"))
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_not_called()
        mock_updates.assert_not_called()

    def test_vulns_selection(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        mock_vulns = MagicMock(return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ])
        mock_updates = MagicMock(return_value=[])
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns"))
        monkeypatch.setattr("maintenance_man.cli.submit_stack", MagicMock(return_value=(True, "")))
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_called_once()
        mock_updates.assert_not_called()


class TestUpdateExitCodes:
    def test_all_pass_exits_0(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr("maintenance_man.cli.process_vulns", MagicMock(return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ]))
        monkeypatch.setattr("maintenance_man.cli.process_updates", MagicMock(return_value=[
            UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
        ]))
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
        monkeypatch.setattr("maintenance_man.cli.submit_stack", MagicMock(return_value=(True, "")))
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

    def test_any_failure_exits_4(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr("maintenance_man.cli.process_vulns", MagicMock(return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=False,
                failed_phase="unit",
            )
        ]))
        monkeypatch.setattr("maintenance_man.cli.process_updates", MagicMock(return_value=[]))
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
        monkeypatch.setattr("maintenance_man.cli.submit_stack", MagicMock())
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4


class TestUpdateNumberedSelection:
    def test_select_by_number(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """Selecting '1' should pick the first finding."""
        mock_vulns = MagicMock(return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ])
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", MagicMock(return_value=[]))
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="1"))
        monkeypatch.setattr("maintenance_man.cli.submit_stack", MagicMock(return_value=(True, "")))
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

    def test_continue_passes_and_submits(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue on matching failed branch, tests pass -> submit."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        mock_test = MagicMock(return_value=(True, None))
        mock_submit = MagicMock(return_value=(True, ""))
        monkeypatch.setattr("maintenance_man.cli.get_current_branch", MagicMock(return_value="bump/pkg-a"))
        monkeypatch.setattr("maintenance_man.cli.run_test_phases", mock_test)
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", MagicMock())
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 0
        mock_test.assert_called_once()
        mock_submit.assert_called_once()

    def test_continue_fails_again_exits_4(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue that fails again should exit 4."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        mock_test = MagicMock(return_value=(False, "unit"))
        monkeypatch.setattr("maintenance_man.cli.get_current_branch", MagicMock(return_value="bump/pkg-a"))
        monkeypatch.setattr("maintenance_man.cli.run_test_phases", mock_test)
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", MagicMock())
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 4

    def test_continue_branch_mismatch_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue on wrong branch should error."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        monkeypatch.setattr("maintenance_man.cli.get_current_branch", MagicMock(return_value="main"))
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 1

    def test_continue_with_remaining_failures_no_submit(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
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
        mock_submit = MagicMock(return_value=(True, ""))
        monkeypatch.setattr("maintenance_man.cli.get_current_branch", MagicMock(return_value="fix/some-pkg"))
        monkeypatch.setattr("maintenance_man.cli.run_test_phases", MagicMock(return_value=(True, None)))
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", MagicMock())
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 4
        mock_submit.assert_not_called()


class TestUpdateAutoSubmit:
    """Stack submission is now internal to process_vulns/process_updates.

    These tests verify that the CLI delegates correctly and reports the
    right exit codes — submission is tested in test_updater.py.
    """

    def test_all_pass_exits_0(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr("maintenance_man.cli.process_vulns", MagicMock(return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ]))
        monkeypatch.setattr("maintenance_man.cli.process_updates", MagicMock(return_value=[
            UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
        ]))
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

    def test_all_failures_exits_4(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr("maintenance_man.cli.process_vulns", MagicMock(return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=False,
                failed_phase="unit",
            )
        ]))
        monkeypatch.setattr("maintenance_man.cli.process_updates", MagicMock(return_value=[]))
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4

    def test_mixed_results_exits_4(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr("maintenance_man.cli.process_vulns", MagicMock(return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=False,
                failed_phase="unit",
            )
        ]))
        monkeypatch.setattr("maintenance_man.cli.process_updates", MagicMock(return_value=[
            UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
        ]))
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4
