from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import app
from maintenance_man.models.scan import (
    Workflow,
    ScanResult,
    UpdateStatus,
)
from maintenance_man.updater import NoScanResultsError, UpdateResult


class TestUpdatePreChecks:
    def test_no_projects_configured_exits_0_without_gh(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (mm_home).mkdir(parents=True, exist_ok=True)
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")

        from maintenance_man.vcs import GitHubCLINotFoundError

        monkeypatch.setattr(
            "maintenance_man.cli.check_gh_available",
            MagicMock(side_effect=GitHubCLINotFoundError("no gh")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])

        assert exc_info.value.code == 0

    def test_missing_gh_errors(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.vcs import GitHubCLINotFoundError

        monkeypatch.setattr(
            "maintenance_man.cli.check_gh_available",
            MagicMock(side_effect=GitHubCLINotFoundError("no gh")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1

    def test_missing_test_config_warns_and_proceeds(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        """Missing test config is a warning, not a hard failure."""
        from maintenance_man.models.config import ProjectConfig

        monkeypatch.setattr(
            "maintenance_man.cli.resolve_project",
            MagicMock(
                return_value=ProjectConfig(
                    path=Path("/tmp/x"), package_manager="bun"
                )
            ),
        )
        mock_vulns = MagicMock(
            return_value=[UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)]
        )
        mock_updates = MagicMock(
            return_value=[UpdateResult(pkg_name="pkg-a", kind="update", passed=True)]
        )
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        assert "no test configuration" in capsys.readouterr().out.lower()

    def test_conflicting_resolve_flow_aborts(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        capsys: pytest.CaptureFixture[str],
    ):
        """update must refuse to run when resolve-owned findings are in progress."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        scan_result.updates[0].flow = Workflow.RESOLVE

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 1
        assert "resolve" in capsys.readouterr().out.lower()

    def test_legacy_findings_missing_flow_abort(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        capsys: pytest.CaptureFixture[str],
    ):
        """Findings persisted without `flow` are unsupported — hard fail."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        scan_result.updates[0].flow = None

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 1
        assert "rescan" in capsys.readouterr().out.lower()


class TestUpdateNoOp:
    """No-op-first ordering: nothing to do => exit 0 without side effects."""

    def test_no_scan_results_is_noop(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_sync = MagicMock(return_value=True)
        mock_worktree = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.sync_remote", mock_sync)
        monkeypatch.setattr("maintenance_man.cli.create_worktree", mock_worktree)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("No results")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_sync.assert_not_called()
        mock_worktree.assert_not_called()

    def test_no_actionable_findings_is_noop(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.vulnerabilities = []
        scan_result.updates = []
        mock_sync = MagicMock(return_value=True)
        mock_worktree = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.sync_remote", mock_sync)
        monkeypatch.setattr("maintenance_man.cli.create_worktree", mock_worktree)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_sync.assert_not_called()
        mock_worktree.assert_not_called()

    def test_batch_noop_is_identical(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Batch mode also performs the no-op check before any side effects."""
        mock_sync = MagicMock(return_value=True)
        mock_worktree = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.sync_remote", mock_sync)
        monkeypatch.setattr("maintenance_man.cli.create_worktree", mock_worktree)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("No results")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 0
        mock_sync.assert_not_called()
        mock_worktree.assert_not_called()


class TestUpdateSelection:
    def test_none_selection_exits_0(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
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
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        def _mark_ready(vulns, pc, *, flow, scan_result, project_name, results_dir):
            for v in vulns:
                v.update_status = UpdateStatus.READY
                v.flow = flow
            return [UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)]

        mock_vulns = MagicMock(side_effect=_mark_ready)
        mock_updates = MagicMock(return_value=[])
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns")
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
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        def _mark_vuln(vulns, pc, *, flow, scan_result, project_name, results_dir):
            for v in vulns:
                v.update_status = UpdateStatus.READY
                v.flow = flow
            return [UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)]

        def _mark_update(updates, pc, *, flow, scan_result, project_name, results_dir):
            for u in updates:
                u.update_status = UpdateStatus.READY
                u.flow = flow
            return [UpdateResult(pkg_name="pkg-a", kind="update", passed=True)]

        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns", MagicMock(side_effect=_mark_vuln)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates",
            MagicMock(side_effect=_mark_update),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

    def test_any_failure_exits_4(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
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

    def test_branch_failure_summary_uses_friendly_label(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(
                return_value=[
                    UpdateResult(
                        pkg_name="some-pkg",
                        kind="vuln",
                        passed=False,
                        failed_phase="branch",
                    )
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 4
        assert "branch creation failed" in capsys.readouterr().out

    def test_commit_failure_summary_uses_friendly_label(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(
                return_value=[
                    UpdateResult(
                        pkg_name="some-pkg",
                        kind="vuln",
                        passed=False,
                        failed_phase="commit",
                    )
                ]
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 4
        assert "commit failed" in capsys.readouterr().out


class TestUpdateNumberedSelection:
    def test_select_by_number(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Selecting '1' should pick the first finding."""
        def _mark(vulns, pc, *, flow, scan_result, project_name, results_dir):
            for v in vulns:
                v.update_status = UpdateStatus.READY
                v.flow = flow
            return [UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)]

        mock_vulns = MagicMock(side_effect=_mark)
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="1")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_called_once()


class TestUpdateResume:
    """Interactive rerun with update-owned in-progress state."""

    def test_resume_attaches_worktree_to_existing_branch(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.updates[0].update_status = UpdateStatus.READY
        scan_result.updates[0].flow = Workflow.UPDATE
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE

        mock_worktree = MagicMock(return_value=True)
        mock_sync = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.create_worktree", mock_worktree)
        monkeypatch.setattr("maintenance_man.cli.sync_remote", mock_sync)
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

        _, kwargs = mock_worktree.call_args
        assert kwargs.get("branch") == "mm/update-dependencies"
        assert kwargs.get("detach") is False
        mock_sync.assert_not_called()

    def test_resume_ready_only_skips_selection_and_merges(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Only READY findings (no FAILED) => skip prompt, go straight to merge."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.updates[0].update_status = UpdateStatus.READY
        scan_result.updates[0].flow = Workflow.UPDATE
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE

        mock_prompt = MagicMock()
        mock_merge = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", mock_prompt)
        monkeypatch.setattr("maintenance_man.cli.git_merge_fast_forward", mock_merge)
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_prompt.assert_not_called()
        mock_merge.assert_called_once()
        assert mock_merge.call_args.args[0] == "mm/update-dependencies"

    def test_resume_shows_only_failed_findings(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        """On resume with FAILED findings, READY findings are hidden from prompt."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        scan_result.updates[0].flow = Workflow.UPDATE
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE

        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)

        with pytest.raises(SystemExit):
            app(["update", "vulnerable"])

        output = capsys.readouterr().out
        assert "pkg-a" in output
        # The READY vuln should NOT appear in the numbered selection list
        after_update_line = output.split("Select updates")[0].split("UPDATE pkg-a")[-1]
        assert "some-pkg" not in after_update_line

    def test_resume_ready_findings_preserved_through_merge(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """READY findings reach merge even though they're hidden from selection."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE
        scan_result.updates[0].update_status = UpdateStatus.READY
        scan_result.updates[0].flow = Workflow.UPDATE

        mock_merge = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.git_merge_fast_forward", mock_merge)
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_merge.assert_called_once()

    def test_resume_does_not_sync_or_rebase(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Resuming an existing branch does not call sync_remote."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE
        scan_result.updates[0].update_status = UpdateStatus.READY
        scan_result.updates[0].flow = Workflow.UPDATE

        mock_sync = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.sync_remote", mock_sync)
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )

        with pytest.raises(SystemExit):
            app(["update", "vulnerable"])
        mock_sync.assert_not_called()


class TestUpdateFinalise:
    """Merge promotes READY -> COMPLETED only on success."""

    def test_merge_success_promotes_ready_to_completed(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]

        def _mark_ready(items, pc, *, flow, scan_result, project_name, results_dir):
            for it in items:
                it.update_status = UpdateStatus.READY
                it.flow = flow
            return [UpdateResult(pkg_name=items[0].pkg_name, kind="vuln", passed=True)]

        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(side_effect=_mark_ready),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates",
            MagicMock(side_effect=_mark_ready),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.git_merge_fast_forward", MagicMock(return_value=True)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        # remove_completed_findings removes promoted findings from the result
        assert scan_result.vulnerabilities == []
        assert scan_result.updates == []

    def test_merge_failure_leaves_ready(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]

        def _mark_ready(items, pc, *, flow, scan_result, project_name, results_dir):
            for it in items:
                it.update_status = UpdateStatus.READY
                it.flow = flow
            return [UpdateResult(pkg_name=items[0].pkg_name, kind="vuln", passed=True)]

        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(side_effect=_mark_ready),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates",
            MagicMock(side_effect=_mark_ready),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.git_merge_fast_forward", MagicMock(return_value=False)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        # Merge failure surfaces as UPDATE_FAILED but findings stay READY
        assert exc_info.value.code == 4
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.READY
        assert scan_result.vulnerabilities[0].flow == Workflow.UPDATE
        assert scan_result.vulnerabilities[0].failed_phase is None
        assert scan_result.updates[0].update_status == UpdateStatus.READY
        assert scan_result.updates[0].flow == Workflow.UPDATE

    def test_failed_findings_block_merge(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """If any finding fails, don't merge."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]

        def _mark_failed(items, pc, *, flow, scan_result, project_name, results_dir):
            for it in items:
                it.update_status = UpdateStatus.FAILED
                it.failed_phase = "unit"
                it.flow = flow
            return [
                UpdateResult(
                    pkg_name=items[0].pkg_name,
                    kind="vuln",
                    passed=False,
                    failed_phase="unit",
                )
            ]

        mock_merge = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(side_effect=_mark_failed),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns")
        )
        monkeypatch.setattr("maintenance_man.cli.git_merge_fast_forward", mock_merge)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 4
        mock_merge.assert_not_called()
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.FAILED

    def test_merge_aborts_when_main_is_dirty(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """A dirty main checkout must not be merged into silently."""
        from maintenance_man.vcs import RepoDirtyError

        scan_result: ScanResult = mock_update_cli_deps["scan_result"]

        def _mark_ready(items, pc, *, flow, scan_result, project_name, results_dir):
            for it in items:
                it.update_status = UpdateStatus.READY
                it.flow = flow
            return [
                UpdateResult(pkg_name=items[0].pkg_name, kind="vuln", passed=True)
            ]

        mock_merge = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(side_effect=_mark_ready),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates",
            MagicMock(side_effect=_mark_ready),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            MagicMock(side_effect=RepoDirtyError("dirty local main")),
        )
        monkeypatch.setattr("maintenance_man.cli.git_merge_fast_forward", mock_merge)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 4
        mock_merge.assert_not_called()
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.READY
        assert scan_result.updates[0].update_status == UpdateStatus.READY

    def test_merge_removes_worktree_before_deleting_branch(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Branch delete must follow worktree removal, else git refuses."""

        def _mark_ready(items, pc, *, flow, scan_result, project_name, results_dir):
            for it in items:
                it.update_status = UpdateStatus.READY
                it.flow = flow
            return [
                UpdateResult(pkg_name=items[0].pkg_name, kind="vuln", passed=True)
            ]

        call_order: list[str] = []

        def _track_remove_worktree(p, w):
            call_order.append("remove_worktree")

        def _track_delete_branch(b, p):
            call_order.append(f"delete_branch:{b}")
            return True

        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns",
            MagicMock(side_effect=_mark_ready),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates",
            MagicMock(side_effect=_mark_ready),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.remove_worktree", _track_remove_worktree
        )
        monkeypatch.setattr(
            "maintenance_man.cli.git_delete_branch", _track_delete_branch
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        delete_idx = call_order.index("delete_branch:mm/update-dependencies")
        first_remove = call_order.index("remove_worktree")
        assert first_remove < delete_idx


class TestUpdateAll:
    """Batch mode: `mm update` with no project argument."""

    def test_skips_projects_without_scan_results(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
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
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Return passed results without mutating the shared scan_result so
        # each batch iteration sees the same actionable findings.
        def _process(items, pc, *, flow, scan_result, project_name, results_dir):
            return [
                UpdateResult(pkg_name=items[0].pkg_name, kind="vuln", passed=True)
            ]

        mock_vulns = MagicMock(side_effect=_process)
        mock_updates = MagicMock(side_effect=_process)
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 0
        # All 7 projects have findings in the stub — missing test config is
        # now a warning, not a skip.
        assert mock_vulns.call_count == 7
        assert mock_updates.call_count == 7

    def test_any_failure_exits_4(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
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

    def test_batch_no_test_config_does_not_abort(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing test config warns (not fatal) for single-project invocation."""
        def _mark(items, pc, *, flow, scan_result, project_name, results_dir):
            for it in items:
                it.update_status = UpdateStatus.READY
                it.flow = flow
            return [
                UpdateResult(pkg_name=items[0].pkg_name, kind="vuln", passed=True)
            ]

        mock_vulns = MagicMock(side_effect=_mark)
        mock_updates = MagicMock(side_effect=_mark)
        monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "no-tests"])
        assert exc_info.value.code == 0
        mock_vulns.assert_called_once()


class TestUpdateTargetSelection:
    def test_excluding_all_projects_exits_0_without_gh(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from maintenance_man.vcs import GitHubCLINotFoundError

        monkeypatch.setattr(
            "maintenance_man.cli.check_gh_available",
            MagicMock(side_effect=GitHubCLINotFoundError("no gh")),
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
        mock_update_cli_deps: dict,
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
        mock_update_cli_deps: dict,
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
        mock_update_cli_deps: dict,
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
        mock_update_cli_deps: dict,
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

    def test_negate_with_no_names_matches_batch_all(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
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

    def test_batch_continues_after_project_failure(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(
            side_effect=[
                None,
                ([UpdateResult(pkg_name="pkg-a", kind="update", passed=True)], False),
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

    def test_help_does_not_expose_continue_or_worktree(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--continue and --worktree are gone from the update surface."""
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "--help"])

        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "--continue" not in output
        assert "--worktree" not in output

    def test_continue_flag_is_rejected(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Unknown option" in (captured.out + captured.err)

    def test_worktree_flag_is_rejected(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--worktree"])
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Unknown option" in (captured.out + captured.err)

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
