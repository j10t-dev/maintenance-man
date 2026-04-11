from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import app
from maintenance_man.models.scan import (
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
)
from maintenance_man.updater import NoScanResultsError, UpdateResult


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
    monkeypatch.setattr("maintenance_man.cli.check_graphite_available", lambda: None)
    monkeypatch.setattr("maintenance_man.cli.check_repo_clean", lambda p: None)
    monkeypatch.setattr("maintenance_man.cli.ensure_on_main", lambda p: True)
    monkeypatch.setattr("maintenance_man.cli.sync_graphite", lambda p: True)
    monkeypatch.setattr(
        "maintenance_man.cli.load_scan_results",
        lambda name, d: _make_scan_result(),
    )


class TestUpdatePreChecks:
    def test_no_projects_configured_exits_0_without_gt(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (mm_home).mkdir(parents=True, exist_ok=True)
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")

        from maintenance_man.vcs import GraphiteNotFoundError

        monkeypatch.setattr(
            "maintenance_man.cli.check_graphite_available",
            MagicMock(side_effect=GraphiteNotFoundError("no gt")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])

        assert exc_info.value.code == 0

    def test_no_scan_results_exits_1(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
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
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.vcs import RepoDirtyError

        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            MagicMock(side_effect=RepoDirtyError("dirty")),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask",
            MagicMock(return_value=False),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1

    def test_no_gt_exits_1(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
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
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Project without test config should refuse to proceed."""
        from maintenance_man.models.config import ProjectConfig

        monkeypatch.setattr(
            "maintenance_man.cli.resolve_project",
            MagicMock(
                return_value=ProjectConfig(
                    path=Path("/tmp/x"), package_manager="bun"
                )
            ),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1


class TestUpdateSelection:
    def test_none_selection_exits_0(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_vulns = MagicMock(return_value=[])
        mock_updates = MagicMock(return_value=[])
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_not_called()
        mock_updates.assert_not_called()

    def test_vulns_selection(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_vulns = MagicMock(
            return_value=[UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)]
        )
        mock_updates = MagicMock(return_value=[])
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.submit_stack", MagicMock(return_value=(True, ""))
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_called_once()
        mock_updates.assert_not_called()


class TestUpdateExitCodes:
    def test_all_pass_exits_0(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(
                return_value=[
                    UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates",
            MagicMock(
                return_value=[
                    UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.submit_stack", MagicMock(return_value=(True, ""))
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

    def test_any_failure_exits_4(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(
                return_value=[
                    UpdateResult(
                        pkg_name="some-pkg",
                        kind="vuln",
                        passed=False,
                        failed_phase="unit",
                    )
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr("maintenance_man.cli.submit_stack", MagicMock())
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4


class TestUpdateNumberedSelection:
    def test_select_by_number(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Selecting '1' should pick the first finding."""
        mock_vulns = MagicMock(
            return_value=[UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)]
        )
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="1")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.submit_stack", MagicMock(return_value=(True, ""))
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        # Should have called process_vulns with the first vuln
        mock_vulns.assert_called_once()


class TestUpdateContinue:
    def test_continue_no_failures_exits_1(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue with no failed findings should error."""
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 1

    def test_continue_passes_and_submits(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
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
        monkeypatch.setattr(
            "maintenance_man.cli.get_current_branch",
            MagicMock(return_value="bump/pkg-a"),
        )
        monkeypatch.setattr("maintenance_man.cli.run_test_phases", mock_test)
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", MagicMock())
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 0
        mock_test.assert_called_once()
        mock_submit.assert_called_once()

    def test_continue_fails_again_exits_4(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
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
        monkeypatch.setattr(
            "maintenance_man.cli.get_current_branch",
            MagicMock(return_value="bump/pkg-a"),
        )
        monkeypatch.setattr("maintenance_man.cli.run_test_phases", mock_test)
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", MagicMock())
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 4

    def test_continue_branch_mismatch_exits_1(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue on wrong branch should error."""
        from maintenance_man.models.scan import UpdateStatus

        scan_result = _make_scan_result()
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.get_current_branch", MagicMock(return_value="main")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 1

    def test_continue_with_remaining_failures_no_submit(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
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
        monkeypatch.setattr(
            "maintenance_man.cli.get_current_branch",
            MagicMock(return_value="fix/some-pkg"),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", MagicMock(return_value=(True, None))
        )
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", MagicMock())
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 4
        mock_submit.assert_not_called()

    def test_continue_without_project_exits_1(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "--continue"])
        assert exc_info.value.code == 1


class TestUpdateAutoSubmit:
    """Stack submission is now internal to process_vulns/process_updates.

    These tests verify that the CLI delegates correctly and reports the
    right exit codes — submission is tested in test_updater.py.
    """

    def test_all_pass_exits_0(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(
                return_value=[
                    UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates",
            MagicMock(
                return_value=[
                    UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

    def test_all_failures_exits_4(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(
                return_value=[
                    UpdateResult(
                        pkg_name="some-pkg",
                        kind="vuln",
                        passed=False,
                        failed_phase="unit",
                    )
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4

    def test_mixed_results_exits_4(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(
                return_value=[
                    UpdateResult(
                        pkg_name="some-pkg",
                        kind="vuln",
                        passed=False,
                        failed_phase="unit",
                    )
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates",
            MagicMock(
                return_value=[
                    UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4


class TestUpdateAll:
    """Tests for `mm update` with no project argument (batch mode)."""

    def test_skips_projects_without_scan_results(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Projects with no scan data are skipped silently."""
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("No results")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 0

    def test_processes_all_projects(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """All projects with scan results get processed; exits 0 when all pass."""
        mock_vulns = MagicMock(
            return_value=[UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)]
        )
        mock_updates = MagicMock(
            return_value=[UpdateResult(pkg_name="pkg-a", kind="update", passed=True)]
        )
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 0
        # 6 of 7 projects have test config (no-tests is skipped)
        assert mock_vulns.call_count == 6
        assert mock_updates.call_count == 6

    def test_any_failure_exits_4(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_vulns = MagicMock(
            return_value=[
                UpdateResult(
                    pkg_name="some-pkg",
                    kind="vuln",
                    passed=False,
                    failed_phase="test_unit",
                )
            ]
        )
        mock_updates = MagicMock(
            return_value=[UpdateResult(pkg_name="pkg-a", kind="update", passed=True)]
        )
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 4

    def test_sync_failure_exits_4(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A project-level error (e.g. sync failure) causes non-zero exit."""
        monkeypatch.setattr("maintenance_man.cli.sync_graphite", lambda p: False)

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 4


class TestUpdateTargetSelection:
    def test_excluding_all_projects_exits_0_without_gt(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from maintenance_man.vcs import GraphiteNotFoundError

        monkeypatch.setattr(
            "maintenance_man.cli.check_graphite_available",
            MagicMock(side_effect=GraphiteNotFoundError("no gt")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(
                [
                    "update",
                    "-n",
                    "vulnerable",
                    "clean",
                    "outdated",
                    "no-tests",
                    "deployable",
                    "deploy-only",
                    "no-deploy",
                ]
            )

        assert exc_info.value.code == 0

    def test_no_args_uses_batch_all(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(
            "maintenance_man.cli._update_batch_targets",
            mock_batch,
            raising=False,
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])

        assert exc_info.value.code == 0
        mock_batch.assert_called_once()
        _, kwargs = mock_batch.call_args
        assert kwargs["target_names"] == [
            "clean",
            "deploy-only",
            "deployable",
            "no-deploy",
            "no-tests",
            "outdated",
            "vulnerable",
        ]

    def test_single_name_keeps_interactive_mode(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_interactive = MagicMock(side_effect=SystemExit(0))
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr("maintenance_man.cli._update_interactive", mock_interactive)
        monkeypatch.setattr(
            "maintenance_man.cli._update_batch_targets",
            mock_batch,
            raising=False,
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        mock_interactive.assert_called_once()
        mock_batch.assert_not_called()

    def test_multiple_names_use_batch_in_cli_order(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(
            "maintenance_man.cli._update_batch_targets",
            mock_batch,
            raising=False,
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "outdated", "vulnerable", "outdated"])

        assert exc_info.value.code == 0
        _, kwargs = mock_batch.call_args
        assert kwargs["target_names"] == ["outdated", "vulnerable"]

    def test_negate_mode_excludes_named_projects(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(
            "maintenance_man.cli._update_batch_targets",
            mock_batch,
            raising=False,
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "-n", "vulnerable", "clean"])

        assert exc_info.value.code == 0
        _, kwargs = mock_batch.call_args
        assert kwargs["target_names"] == [
            "deploy-only",
            "deployable",
            "no-deploy",
            "no-tests",
            "outdated",
        ]

    def test_negate_mode_treats_all_positionals_as_exclusions(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(
            "maintenance_man.cli._update_batch_targets",
            mock_batch,
            raising=False,
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "-n", "clean"])

        assert exc_info.value.code == 0
        _, kwargs = mock_batch.call_args
        assert kwargs["target_names"] == [
            "deploy-only",
            "deployable",
            "no-deploy",
            "no-tests",
            "outdated",
        ]

    def test_negate_with_no_names_matches_batch_all(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(
            "maintenance_man.cli._update_batch_targets",
            mock_batch,
            raising=False,
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "-n"])

        assert exc_info.value.code == 0
        _, kwargs = mock_batch.call_args
        assert kwargs["target_names"] == [
            "clean",
            "deploy-only",
            "deployable",
            "no-deploy",
            "no-tests",
            "outdated",
            "vulnerable",
        ]

    def test_negate_mode_excluding_all_projects_exits_0(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(
                [
                    "update",
                    "-n",
                    "vulnerable",
                    "clean",
                    "outdated",
                    "no-tests",
                    "deployable",
                    "deploy-only",
                    "no-deploy",
                ]
            )

        assert exc_info.value.code == 0
        assert "No target projects." in capsys.readouterr().out

    def test_unknown_project_in_include_mode_exits_1(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "missing"])

        assert exc_info.value.code == 1
        assert "Unknown project 'missing'" in capsys.readouterr().out

    def test_unknown_project_in_negate_mode_exits_1(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "-n", "missing"])

        assert exc_info.value.code == 1
        assert "Unknown project 'missing'" in capsys.readouterr().out

    def test_continue_rejects_batch_include_mode(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "clean", "--continue"])

        assert exc_info.value.code == 1
        assert "--continue requires exactly one project." in capsys.readouterr().out

    def test_continue_and_negate_errors(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "-n", "clean", "--continue"])

        assert exc_info.value.code == 1
        assert (
            "--continue requires exactly one project and cannot be used with -n."
            in capsys.readouterr().out
        )

    def test_batch_continues_after_project_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(
            side_effect=[
                None,
                [UpdateResult(pkg_name="pkg-a", kind="update", passed=True)],
            ]
        )
        monkeypatch.setattr("maintenance_man.cli._update_batch", mock_batch)
        monkeypatch.setattr(
            "maintenance_man.cli._print_mass_update_summary",
            MagicMock(),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "clean"])

        assert exc_info.value.code == 4
        assert [call.args[0] for call in mock_batch.call_args_list] == [
            "vulnerable",
            "clean",
        ]


class TestUpdateCliSurface:
    def test_help_does_not_expose_projects_option(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "--help"])

        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "--projects" not in output
        assert "--empty-projects" not in output

    def test_help_uses_concise_projects_description(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "--help"])

        assert exc_info.value.code == 0
        output = " ".join(capsys.readouterr().out.split())
        assert (
            "Project names to update. No names batch-updates all configured"
            in output
        )
        assert (
            "projects. With -n/--negate, names are exclusions. One name keeps"
            in output
        )
        assert "the interactive single-project flow." in output
        assert (
            "Multiple names batch only the named subset in CLI order."
            not in output
        )

    def test_projects_option_is_not_accepted(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "--projects", "vulnerable"])

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Unknown option" in (captured.out + captured.err)


class TestWorktreeMode:
    """Tests for mm update --worktree."""

    @pytest.fixture(autouse=True)
    def _mock_worktree(self, monkeypatch: pytest.MonkeyPatch):
        """Patch worktree operations by default; individual tests override as needed."""
        monkeypatch.setattr("maintenance_man.cli.create_worktree", lambda p, w: True)
        monkeypatch.setattr("maintenance_man.cli.remove_worktree", lambda p, w: None)

    def test_worktree_flag_skips_repo_clean_check(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With --worktree, check_repo_clean is NOT called."""
        mock_clean = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.check_repo_clean", mock_clean)

        mock_vulns = MagicMock(return_value=[
            UpdateResult(pkg_name="pkg", kind="vuln", passed=True)
        ])
        mock_updates = MagicMock(return_value=[
            UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
        ])
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "--worktree"])
        assert exc_info.value.code == 0
        mock_clean.assert_not_called()

    def test_single_project_worktree_mode(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Single project with --worktree succeeds."""
        mock_vulns = MagicMock(return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ])
        mock_updates = MagicMock(return_value=[
            UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
        ])
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--worktree"])
        assert exc_info.value.code == 0

    def test_single_project_worktree_create_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Single project with --worktree exits 1 when worktree creation fails."""
        monkeypatch.setattr("maintenance_man.cli.create_worktree", lambda p, w: False)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--worktree"])
        assert exc_info.value.code == 1

    def test_worktree_create_failure_skips_project(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """If worktree creation fails, the project is skipped."""
        monkeypatch.setattr("maintenance_man.cli.create_worktree", lambda p, w: False)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "--worktree"])
        assert exc_info.value.code == 4  # UPDATE_FAILED (had_errors)

    def test_worktree_not_created_on_sync_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Sync runs on original repo before worktree; no worktree to clean up."""
        mock_create = MagicMock()
        mock_remove = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.create_worktree", mock_create)
        monkeypatch.setattr("maintenance_man.cli.remove_worktree", mock_remove)
        monkeypatch.setattr("maintenance_man.cli.sync_graphite", lambda p: False)

        with pytest.raises(SystemExit):
            app(["update", "--worktree"])
        # Sync fails before worktree creation, so neither create nor remove is called
        mock_create.assert_not_called()
        mock_remove.assert_not_called()

    def test_continue_and_worktree_errors(
        self,
        mm_home_with_projects: Path,
    ) -> None:
        """--continue and --worktree together is an error."""
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue", "--worktree"])
        assert exc_info.value.code == 1
