from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import ExitCode, _update_batch, app
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.updater import NoScanResultsError, UpdateResult
from tests.conftest import (
    make_gradle_target,
    make_scan_result,
    make_update,
    set_maven_dates,
)


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

    def test_missing_jj_errors(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.vcs import JJCLINotFoundError

        monkeypatch.setattr(
            "maintenance_man.cli.check_jj_available",
            MagicMock(side_effect=JJCLINotFoundError("no jj")),
            raising=False,
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
                return_value=ProjectConfig(path=Path("/tmp/x"), package_manager="bun")
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
        out = capsys.readouterr().out.lower()
        assert "resolve" in out
        assert "vulnerable" in out
        assert "update" in out

    def test_batch_skips_conflicted_project_and_continues(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        """Batch mode must not abort on one project's flow conflict."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        scan_result.updates[0].flow = Workflow.RESOLVE

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "clean"])

        out = capsys.readouterr().out.lower()
        assert exc_info.value.code == ExitCode.UPDATE_FAILED
        assert "vulnerable" in out
        assert "clean" in out

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
        mock_prune = MagicMock(return_value=True)
        mock_workspace = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.prune_stale_bookmarks", mock_prune)
        monkeypatch.setattr("maintenance_man.cli.create_workspace", mock_workspace)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("No results")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_prune.assert_not_called()
        mock_workspace.assert_not_called()

    def test_no_actionable_findings_is_noop(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.vulnerabilities = []
        scan_result.updates = []
        mock_prune = MagicMock(return_value=True)
        mock_workspace = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.prune_stale_bookmarks", mock_prune)
        monkeypatch.setattr("maintenance_man.cli.create_workspace", mock_workspace)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_prune.assert_not_called()
        mock_workspace.assert_not_called()

    def test_batch_noop_is_identical(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Batch mode also performs the no-op check before any side effects."""
        mock_prune = MagicMock(return_value=True)
        mock_workspace = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.prune_stale_bookmarks", mock_prune)
        monkeypatch.setattr("maintenance_man.cli.create_workspace", mock_workspace)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("No results")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 0
        mock_prune.assert_not_called()
        mock_workspace.assert_not_called()


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

    def test_bookmark_failure_summary_uses_friendly_label(
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
        assert "bookmark creation failed" in capsys.readouterr().out

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

    def test_resume_attaches_workspace_to_existing_bookmark(
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

        mock_workspace = MagicMock(return_value=True)
        mock_prune = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.create_workspace", mock_workspace)
        monkeypatch.setattr("maintenance_man.cli.prune_stale_bookmarks", mock_prune)
        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: True)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

        args, _ = mock_workspace.call_args
        # create_workspace(repo_path, project, revision)
        assert args[1] == "vulnerable"
        assert args[2] == "mm/update-dependencies"
        mock_prune.assert_not_called()

    def test_resume_ready_only_skips_selection_and_promotes(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Only READY findings (no FAILED) => skip prompt, go straight to promote."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.updates[0].update_status = UpdateStatus.READY
        scan_result.updates[0].flow = Workflow.UPDATE
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE

        mock_prompt = MagicMock()
        mock_promote = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", mock_prompt)
        monkeypatch.setattr(
            "maintenance_man.cli.promote_bookmark_to_main", mock_promote
        )
        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: True)
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
        mock_promote.assert_called_once()
        # promote_bookmark_to_main(path, source_bookmark)
        assert mock_promote.call_args.args[1] == "mm/update-dependencies"

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
        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: True)

        with pytest.raises(SystemExit):
            app(["update", "vulnerable"])

        output = capsys.readouterr().out
        assert "pkg-a" in output
        # The READY vuln should NOT appear in the numbered selection list
        after_update_line = output.split("Select updates")[0].split("UPDATE pkg-a")[-1]
        assert "some-pkg" not in after_update_line

    def test_resume_ready_findings_preserved_through_promote(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """READY findings reach promote even though they're hidden from selection."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE
        scan_result.updates[0].update_status = UpdateStatus.READY
        scan_result.updates[0].flow = Workflow.UPDATE

        mock_promote = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.promote_bookmark_to_main", mock_promote
        )
        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: True)
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_promote.assert_called_once()

    def test_resume_does_not_sync_or_rebase(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Resuming an existing bookmark does not call prune_stale_bookmarks."""
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE
        scan_result.updates[0].update_status = UpdateStatus.READY
        scan_result.updates[0].flow = Workflow.UPDATE

        mock_prune = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.prune_stale_bookmarks", mock_prune)
        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: True)
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )

        with pytest.raises(SystemExit):
            app(["update", "vulnerable"])
        mock_prune.assert_not_called()


class TestUpdateFinalise:
    """Promote moves READY -> COMPLETED only on success."""

    def test_promote_refreshes_working_copy_from_main(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """After promoting the bookmark, the working copy must refresh from main."""

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
            "maintenance_man.cli.promote_bookmark_to_main",
            MagicMock(return_value=True),
        )
        mock_refresh = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.refresh_working_copy_from_main", mock_refresh
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        mock_refresh.assert_called_once()

    def test_promote_success_promotes_ready_to_completed(
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
            "maintenance_man.cli.promote_bookmark_to_main",
            MagicMock(return_value=True),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        # remove_completed_findings removes promoted findings from the result
        assert scan_result.vulnerabilities == []
        assert scan_result.updates == []

    @pytest.mark.parametrize(
        ("failing_operation", "expected_message"),
        [
            ("promote_bookmark_to_main", "Promotion failed"),
            ("refresh_working_copy_from_main", "Workspace refresh failed"),
        ],
    )
    def test_finalise_failure_leaves_ready(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        failing_operation: str,
        expected_message: str,
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
            f"maintenance_man.cli.{failing_operation}", MagicMock(return_value=False)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        output = capsys.readouterr().out
        assert expected_message in output
        assert exc_info.value.code == 4
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.READY
        assert scan_result.vulnerabilities[0].flow == Workflow.UPDATE
        assert scan_result.vulnerabilities[0].failed_phase is None
        assert scan_result.updates[0].update_status == UpdateStatus.READY
        assert scan_result.updates[0].flow == Workflow.UPDATE

    def test_failed_findings_block_promote(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """If any finding fails, don't promote."""
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

        mock_promote = MagicMock(return_value=True)
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
        monkeypatch.setattr(
            "maintenance_man.cli.promote_bookmark_to_main", mock_promote
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 4
        mock_promote.assert_not_called()
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.FAILED

    def test_promote_removes_workspace_before_deleting_bookmark(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Bookmark delete must follow workspace removal."""

        def _mark_ready(items, pc, *, flow, scan_result, project_name, results_dir):
            for it in items:
                it.update_status = UpdateStatus.READY
                it.flow = flow
            return [UpdateResult(pkg_name=items[0].pkg_name, kind="vuln", passed=True)]

        call_order: list[str] = []

        def _track_remove_workspace(p, project):
            call_order.append("remove_workspace")

        def _track_delete_bookmark(b, p):
            call_order.append(f"delete_bookmark:{b}")
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
            "maintenance_man.cli.remove_workspace", _track_remove_workspace
        )
        monkeypatch.setattr(
            "maintenance_man.cli.delete_bookmark", _track_delete_bookmark
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        delete_idx = call_order.index("delete_bookmark:mm/update-dependencies")
        first_remove = call_order.index("remove_workspace")
        assert first_remove < delete_idx

    def test_fresh_update_creates_workspace_bookmark_and_new_change(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        calls: list[tuple[str, tuple]] = []

        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: False)
        monkeypatch.setattr(
            "maintenance_man.cli.prune_stale_bookmarks",
            lambda p: calls.append(("prune", (p,))) or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.ensure_main_bookmark",
            lambda p: calls.append(("ensure-main", (p,))) or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.delete_bookmark",
            lambda b, p: calls.append(("delete", (b, p))) or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.create_or_reset_bookmark",
            lambda b, p, r: calls.append(("set", (b, p, r))) or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.create_workspace",
            lambda repo, project, rev: (
                calls.append(("workspace", (repo, project, rev))) or True
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.edit_new_change",
            lambda path, rev: calls.append(("new", (path, rev))) or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )

        with pytest.raises(SystemExit):
            app(["update", "vulnerable"])

        names = [name for name, _ in calls]
        assert names[:5] == ["prune", "ensure-main", "set", "workspace", "new"]
        assert calls[2][1][0] == "mm/update-dependencies"
        assert calls[2][1][2] == "main"
        assert calls[3][1][2] == "main"
        assert calls[4][1][1] == "mm/update-dependencies"


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
            return [UpdateResult(pkg_name=items[0].pkg_name, kind="vuln", passed=True)]

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
            return [UpdateResult(pkg_name=items[0].pkg_name, kind="vuln", passed=True)]

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


@pytest.fixture()
def gradle_update_cli(
    mock_update_cli_deps, mm_home_with_gradle, gradle_project, monkeypatch
):
    """Update-CLI boundaries plus Gradle spies. Returns a mutable spy record."""
    from maintenance_man.vcs import RevisionFileCheck

    monkeypatch.setattr(
        "maintenance_man.cli.revision_file",
        lambda *args: RevisionFileCheck(ok=True, value=False, commit_id="a" * 40),
    )
    monkeypatch.setattr(
        "maintenance_man.updater.discard_current_change", lambda path: None
    )
    spies: dict[str, list] = {
        "workspaces": [],
        "tests": [],
        "applies": [],
        "commits": [],
        "promotions": [],
    }
    monkeypatch.setattr(
        "maintenance_man.cli.create_workspace",
        lambda repo, project, rev: spies["workspaces"].append(project) or True,
    )
    monkeypatch.setattr(
        "maintenance_man.updater.run_test_phases",
        lambda cfg, path: (spies["tests"].append(1), (True, None))[1],
    )
    monkeypatch.setattr(
        "maintenance_man.updater.apply_gradle_update",
        lambda project, target: spies["applies"].append(target) or None,
    )
    monkeypatch.setattr(
        "maintenance_man.updater.validate_gradle_target", lambda project, target: None
    )
    monkeypatch.setattr(
        "maintenance_man.updater.current_change_has_changes", lambda path: True
    )
    monkeypatch.setattr(
        "maintenance_man.updater.commit_current_change",
        lambda path, msg: spies["commits"].append(msg) or True,
    )
    monkeypatch.setattr(
        "maintenance_man.updater.create_or_reset_bookmark", lambda b, p, r: True
    )
    monkeypatch.setattr(
        "maintenance_man.cli.promote_bookmark_to_main",
        lambda p, b: spies["promotions"].append(b) or True,
    )
    # `mm update <one project>` is the interactive single-project path, so every
    # test here must answer the selection prompt; individual tests override this.
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", lambda *a, **k: "all")
    return spies


def _gradle_scan_state(mock_update_cli_deps):
    """A room reference group and a ksp plugin group; eligibility is set by dates."""
    ksp_target = GradleUpdateTarget(
        version_ref="ksp",
        members=[
            GradleMember(
                kind="plugin",
                alias="ksp",
                coordinate="com.google.devtools.ksp",
                installed_version="2.3.10",
            )
        ],
        target_version="2.3.12",
    )
    scan_result = make_scan_result(
        vulns=[],
        updates=[
            make_update(
                pkg_name="room",
                installed_version="2.8.4",
                latest_version="2.8.5",
                gradle_target=make_gradle_target(),
            ),
            make_update(
                pkg_name="ksp",
                installed_version="2.3.10",
                latest_version="2.3.12",
                gradle_target=ksp_target,
            ),
        ],
    )
    mock_update_cli_deps["scan_result"] = scan_result
    return scan_result


def test_blocked_only_gradle_update_does_no_workspace_tests_or_commits(
    gradle_update_cli, mock_update_cli_deps, monkeypatch
):
    scan_result = _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(
        monkeypatch,
        undated={
            "androidx.room:room-runtime",
            "androidx.room:room-compiler",
            "androidx.room:room-testing",
            "com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin",
        },
    )

    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])

    assert exc.value.code == ExitCode.UPDATE_FAILED
    assert gradle_update_cli["workspaces"] == []
    assert gradle_update_cli["tests"] == []
    assert gradle_update_cli["commits"] == []
    assert gradle_update_cli["promotions"] == []
    assert all(u.gradle_block_kind == "age" for u in scan_result.updates)
    assert all(u.update_status is None for u in scan_result.updates)


def test_an_unreachable_android_sdk_refuses_before_creating_a_workspace(
    gradle_update_cli, mock_update_cli_deps, gradle_project, monkeypatch, capsys
):
    """The workspace holds tracked files only, so local.properties is not there."""
    scan_result = _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(monkeypatch, undated=set())
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (Path(gradle_project.path) / "local.properties").write_text(
        "sdk.dir=/opt/a\n", encoding="utf-8"
    )

    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])

    assert exc.value.code == ExitCode.ERROR
    assert gradle_update_cli["workspaces"] == []
    assert gradle_update_cli["applies"] == []
    assert "ANDROID_HOME" in capsys.readouterr().out
    assert all(u.update_status is None for u in scan_result.updates)


def test_mixed_gradle_update_applies_eligible_but_refuses_to_promote(
    gradle_update_cli, mock_update_cli_deps, monkeypatch, capsys
):
    _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(
        monkeypatch,
        undated={"com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin"},
    )

    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])

    out = capsys.readouterr().out
    assert exc.value.code == ExitCode.UPDATE_FAILED
    assert len(gradle_update_cli["applies"]) == 1
    assert gradle_update_cli["applies"][0].version_ref == "room"
    assert gradle_update_cli["tests"] == [1]
    assert gradle_update_cli["commits"] == ["chore: bump room 2.8.4 -> 2.8.5 (patch)"]
    assert gradle_update_cli["promotions"] == []
    assert "no Maven Central publication date" in out
    assert "1 blocked" in out


def test_configured_minimum_age_reaches_the_update_boundary(
    gradle_update_cli, mock_update_cli_deps, monkeypatch, mm_home_with_gradle
):
    config_path = mm_home_with_gradle / "config.toml"
    config_path.write_text(
        config_path.read_text().replace(
            "min_version_age_days = 7", "min_version_age_days = 60"
        )
    )
    _gradle_scan_state(mock_update_cli_deps)
    # 10 days old: eligible under the 7-day default, blocked under the configured 60.
    set_maven_dates(monkeypatch, undated=set(), days_old=10)

    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])

    assert exc.value.code == ExitCode.UPDATE_FAILED
    assert gradle_update_cli["applies"] == []
    assert gradle_update_cli["workspaces"] == []
    assert all(
        u.gradle_block_kind == "age"
        for u in mock_update_cli_deps["scan_result"].updates
    )


def test_gradle_batch_reports_outstanding_blocks_as_a_project_error(
    gradle_update_cli,
    mock_update_cli_deps,
    monkeypatch,
    mm_home_with_gradle,
    gradle_project,
):
    """The mixed batch case: some groups apply, others stay blocked."""
    _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(
        monkeypatch,
        undated={"com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin"},
    )
    results_dir = mm_home_with_gradle / "scan-results"

    outcome = _update_batch("android", gradle_project, results_dir, 7)
    assert outcome is not None
    all_results, promotion_failed = outcome

    assert len(gradle_update_cli["applies"]) == 1
    assert all(r.passed for r in all_results)
    assert promotion_failed is True
    assert gradle_update_cli["promotions"] == []


def test_interactive_selection_takes_whole_groups(
    gradle_update_cli, mock_update_cli_deps, monkeypatch, capsys
):
    _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(monkeypatch, undated=set())
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", lambda *a, **k: "1")

    with pytest.raises(SystemExit):
        app(["update", "android"])

    out = capsys.readouterr().out
    assert len(gradle_update_cli["applies"]) == 1
    assert [m.alias for m in gradle_update_cli["applies"][0].members] == [
        "room-runtime",
        "room-compiler",
        "room-testing",
    ]
    assert "room-runtime, room-compiler, room-testing" in out


def test_selecting_none_exits_ok_without_a_workspace(
    gradle_update_cli, mock_update_cli_deps, monkeypatch
):
    _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(monkeypatch, undated=set())
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", lambda *a, **k: "none")

    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])

    assert exc.value.code == ExitCode.OK
    assert gradle_update_cli["workspaces"] == []


@pytest.mark.parametrize("batch", [False, True])
def test_gradle_existing_block_on_nonactionable_vulnerability_is_reported(
    gradle_update_cli,
    mock_update_cli_deps,
    monkeypatch,
    gradle_project,
    mm_home_with_gradle,
    capsys,
    batch,
):
    from tests.conftest import make_vuln

    mock_update_cli_deps["scan_result"] = make_scan_result(
        vulns=[
            make_vuln(
                fixed_version=None,
                blocked_reason="transitive dependency cannot be mapped",
                gradle_block_kind="mapping",
            )
        ],
        updates=[],
    )
    if batch:
        assert _update_batch(
            "android", gradle_project, mm_home_with_gradle / "scan-results", 7
        ) == ([], True)
    else:
        with pytest.raises(SystemExit) as exc:
            app(["update", "android"])
        assert exc.value.code == ExitCode.UPDATE_FAILED
    assert "transitive dependency cannot be mapped" in capsys.readouterr().out
    assert gradle_update_cli["workspaces"] == []


def test_duplicate_interactive_indices_apply_group_once(
    gradle_update_cli,
    mock_update_cli_deps,
    monkeypatch,
):
    _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(monkeypatch, undated=set())
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", lambda *a, **k: "1,1")
    with pytest.raises(SystemExit):
        app(["update", "android"])
    assert len(gradle_update_cli["applies"]) == 1


def test_batch_summary_classifies_block_before_failed(capsys):
    from maintenance_man.cli import _print_mass_update_summary

    _print_mass_update_summary(
        [
            (
                "android",
                [
                    UpdateResult(
                        pkg_name="room",
                        kind="update",
                        passed=False,
                        blocked_reason="unknown age",
                    )
                ],
            )
        ]
    )
    out = capsys.readouterr().out
    assert "BLOCKED" in out
    assert "FAIL" not in out


def test_gradle_batch_skips_unreachable_sdk_as_project_error(
    gradle_update_cli,
    mock_update_cli_deps,
    gradle_project,
    mm_home_with_gradle,
    monkeypatch,
    capsys,
):
    _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(monkeypatch, undated=set())
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (gradle_project.path / "local.properties").write_text("sdk.dir=/opt/android\n")
    assert (
        _update_batch(
            "android", gradle_project, mm_home_with_gradle / "scan-results", 7
        )
        is None
    )
    out = capsys.readouterr().out
    assert "ANDROID_HOME" in out
    assert "ANDROID_SDK_ROOT" in out
    assert gradle_update_cli["workspaces"] == []
    assert gradle_update_cli["applies"] == []


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("failure", ["promotion", "refresh"])
def test_gradle_ready_only_finalization_failure_then_retry(
    gradle_update_cli,
    mock_update_cli_deps,
    monkeypatch,
    mm_home_with_gradle,
    gradle_project,
    batch,
    failure,
):
    state = _gradle_scan_state(mock_update_cli_deps)
    for finding in state.updates:
        finding.update_status = UpdateStatus.READY
        finding.flow = Workflow.UPDATE
    original = list(state.updates)
    attempts = []
    refreshes = []
    deleted = []
    monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda *args: True)
    monkeypatch.setattr(
        "maintenance_man.cli.promote_bookmark_to_main",
        lambda path, bookmark: (
            attempts.append(bookmark) or (failure != "promotion" or len(attempts) > 1)
        ),
    )
    monkeypatch.setattr(
        "maintenance_man.cli.refresh_working_copy_from_main",
        lambda path: (
            refreshes.append(path) or (failure != "refresh" or len(refreshes) > 1)
        ),
    )
    monkeypatch.setattr(
        "maintenance_man.cli.delete_bookmark",
        lambda bookmark, path: deleted.append(bookmark),
    )

    def forbidden(*args, **kwargs):
        pytest.fail("READY-only retry must skip selection and SDK workspace checks")

    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", forbidden)
    monkeypatch.setattr("maintenance_man.cli.workspace_environment_reason", forbidden)
    (mm_home_with_gradle / "config.toml").write_text(
        f'[projects.android]\npath = "{gradle_project.path}"\n'
        'package_manager = "gradle"\n'
    )
    args = ["update"] if batch else ["update", "android"]
    with pytest.raises(SystemExit) as failed:
        app(args)
    assert failed.value.code == 4
    assert attempts == ["mm/update-dependencies"]
    assert state.updates == original
    assert all(f.update_status == UpdateStatus.READY for f in original)
    assert all(f.flow == Workflow.UPDATE for f in original)
    assert deleted == []
    with pytest.raises(SystemExit) as retried:
        app(args)
    assert retried.value.code == 0
    assert attempts == ["mm/update-dependencies", "mm/update-dependencies"]
    assert state.updates == []
    assert all(f.update_status == UpdateStatus.COMPLETED for f in original)
    assert deleted == ["mm/update-dependencies"]
    for key in ("workspaces", "tests", "applies", "commits"):
        assert gradle_update_cli[key] == []


@pytest.mark.parametrize("batch", [False, True])
def test_gradle_ready_with_unresolved_block_never_finalizes(
    gradle_update_cli,
    mock_update_cli_deps,
    monkeypatch,
    mm_home_with_gradle,
    gradle_project,
    batch,
):
    from maintenance_man.models.scan import Severity, VulnFinding

    state = _gradle_scan_state(mock_update_cli_deps)
    for finding in state.updates:
        finding.update_status = UpdateStatus.READY
        finding.flow = Workflow.UPDATE
    state.vulnerabilities.append(
        VulnFinding(
            vuln_id="CVE-blocked",
            pkg_name="unmapped",
            installed_version="1",
            fixed_version=None,
            severity=Severity.HIGH,
            title="No fix",
            description="No published fix",
            status="affected",
            blocked_reason="no fixed version",
            gradle_block_kind="mapping",
        )
    )
    (mm_home_with_gradle / "config.toml").write_text(
        f'[projects.android]\npath = "{gradle_project.path}"\n'
        'package_manager = "gradle"\n'
    )
    args = ["update"] if batch else ["update", "android"]
    with pytest.raises(SystemExit) as exc:
        app(args)
    assert exc.value.code == 4
    assert all(f.update_status == UpdateStatus.READY for f in state.updates)
    assert all(not values for values in gradle_update_cli.values())


def test_gradle_ready_only_missing_bookmark_preserves_state(
    gradle_update_cli, mock_update_cli_deps, monkeypatch
):
    state = _gradle_scan_state(mock_update_cli_deps)
    for finding in state.updates:
        finding.update_status = UpdateStatus.READY
        finding.flow = Workflow.UPDATE
    monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda *args: False)
    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])
    assert exc.value.code == 4
    assert all(f.update_status == UpdateStatus.READY for f in state.updates)
    assert all(not values for values in gradle_update_cli.values())


@pytest.mark.parametrize("resume", [False, True])
def test_tracked_sdk_properties_use_inspected_revision_for_workspace(
    gradle_update_cli, mock_update_cli_deps, gradle_project, monkeypatch, resume
):
    from maintenance_man.cli import _enter_update_workspace
    from maintenance_man.vcs import RevisionFileCheck

    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (gradle_project.path / "local.properties").write_text("sdk.dir=/opt/android\n")
    scan = _gradle_scan_state(mock_update_cli_deps)
    if resume:
        for finding in scan.updates:
            finding.update_status = UpdateStatus.FAILED
            finding.failed_phase = "unit"
            finding.flow = Workflow.UPDATE
    monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda *args: resume)
    inspections = []
    effects = []

    def inspect(path, revision, filename):
        inspections.append((revision, filename))
        return RevisionFileCheck(ok=True, value=True, commit_id="a" * 40)

    monkeypatch.setattr("maintenance_man.cli.revision_file", inspect, raising=False)
    monkeypatch.setattr(
        "maintenance_man.cli.create_workspace",
        lambda p, n, r: effects.append(("workspace", r)) or True,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.edit_new_change",
        lambda p, r: effects.append(("new", r)) or True,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.create_or_reset_bookmark",
        lambda n, p, r: effects.append(("bookmark", r)) or True,
    )
    _enter_update_workspace("android", gradle_project, scan)
    assert inspections == [
        ("mm/update-dependencies" if resume else "main", "local.properties")
    ]
    assert ("workspace", "a" * 40) in effects
    assert ("new", "a" * 40) in effects
    if not resume:
        assert ("bookmark", "a" * 40) in effects


@pytest.mark.parametrize("inspection_failure", [False, True])
def test_sdk_preflight_ignores_leftover_workspace_and_fails_closed(
    gradle_update_cli,
    mock_update_cli_deps,
    gradle_project,
    monkeypatch,
    tmp_path,
    inspection_failure,
):
    from maintenance_man.vcs import RevisionFileCheck

    _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(monkeypatch, undated=set())
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (gradle_project.path / "local.properties").write_text("sdk.dir=/opt/android\n")
    leftover = tmp_path / "leftover-workspace"
    monkeypatch.setattr(
        "maintenance_man.cli.workspace_path_for_project", lambda *args: leftover
    )
    leftover.mkdir(parents=True)
    (leftover / "local.properties").write_text("sdk.dir=/opt/android\n")
    effects = []
    monkeypatch.setattr(
        "maintenance_man.cli.remove_workspace", lambda *args: effects.append("remove")
    )
    monkeypatch.setattr(
        "maintenance_man.cli.prune_stale_bookmarks",
        lambda *args: effects.append("sync") or True,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.revision_file",
        lambda *args: RevisionFileCheck(
            ok=not inspection_failure, value=False, error="cannot inspect"
        ),
    )
    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])
    assert exc.value.code == ExitCode.ERROR
    assert effects == []
    assert gradle_update_cli["workspaces"] == []
    assert gradle_update_cli["applies"] == []
    assert (leftover / "local.properties").is_file()


@pytest.mark.parametrize("post_sync_tracked", [False, True])
def test_sdk_revalidated_after_sync_before_removal_or_bookmark_reset(
    gradle_update_cli,
    mock_update_cli_deps,
    gradle_project,
    monkeypatch,
    post_sync_tracked,
):
    from maintenance_man.vcs import RevisionFileCheck

    _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(monkeypatch, undated=set())
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (gradle_project.path / "local.properties").write_text("sdk.dir=/opt/android\n")
    synced = False
    effects = []
    inspections = []

    def sync(*args):
        nonlocal synced
        synced = True
        return True

    def inspect(path, revision, filename):
        assert revision == "main"
        inspections.append(synced)
        return RevisionFileCheck(
            ok=True,
            value=post_sync_tracked if synced else True,
            commit_id=("b" if synced else "a") * 40,
        )

    monkeypatch.setattr("maintenance_man.cli.prune_stale_bookmarks", sync)
    monkeypatch.setattr("maintenance_man.cli.revision_file", inspect)
    monkeypatch.setattr(
        "maintenance_man.cli.remove_workspace",
        lambda *args: effects.append(("remove", "")),
    )
    monkeypatch.setattr(
        "maintenance_man.cli.create_workspace",
        lambda p, n, r: effects.append(("workspace", r)) or True,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.create_or_reset_bookmark",
        lambda n, p, r: effects.append(("bookmark", r)) or True,
    )
    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])
    assert inspections == [False, True]
    if post_sync_tracked:
        assert exc.value.code == ExitCode.OK
        assert ("workspace", "b" * 40) in effects
        assert ("bookmark", "b" * 40) in effects
    else:
        assert exc.value.code == ExitCode.ERROR
        assert effects == []
        assert gradle_update_cli["applies"] == []


@pytest.mark.parametrize("sdk_env, properties", [(True, True), (False, False)])
def test_sdk_preflight_bypasses_revision_inspection_when_unneeded(
    gradle_update_cli,
    mock_update_cli_deps,
    gradle_project,
    monkeypatch,
    sdk_env,
    properties,
):
    _gradle_scan_state(mock_update_cli_deps)
    set_maven_dates(monkeypatch, undated=set())
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    if sdk_env:
        monkeypatch.setenv("ANDROID_HOME", "/opt/android")
    if properties:
        (gradle_project.path / "local.properties").write_text("sdk.dir=/opt/android\n")

    def forbidden(*args):
        pytest.fail("SDK independent build must not inspect tracked properties")

    monkeypatch.setattr("maintenance_man.cli.revision_file", forbidden)
    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])
    assert exc.value.code == ExitCode.OK
    assert gradle_update_cli["workspaces"] == ["android"]


@pytest.mark.parametrize("inspection_error", [False, True])
def test_resumed_sdk_refusal_precedes_workspace_removal(
    gradle_update_cli,
    mock_update_cli_deps,
    gradle_project,
    monkeypatch,
    inspection_error,
):
    from maintenance_man.cli import _enter_update_workspace, _UpdateSetupError
    from maintenance_man.vcs import RevisionFileCheck

    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (gradle_project.path / "local.properties").write_text("sdk.dir=/opt/android\n")
    scan = _gradle_scan_state(mock_update_cli_deps)
    scan.updates[0].update_status = UpdateStatus.FAILED
    scan.updates[0].flow = Workflow.UPDATE
    scan.updates[0].failed_phase = "unit"
    effects = []
    monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda *args: True)
    monkeypatch.setattr(
        "maintenance_man.cli.remove_workspace", lambda *args: effects.append("remove")
    )

    def inspect(path, revision, filename):
        assert revision == "mm/update-dependencies"
        return RevisionFileCheck(
            ok=not inspection_error, value=False, error="inspection failed"
        )

    monkeypatch.setattr("maintenance_man.cli.revision_file", inspect)
    with pytest.raises(_UpdateSetupError):
        _enter_update_workspace("android", gradle_project, scan)
    assert effects == []
    assert gradle_update_cli["workspaces"] == []


@pytest.mark.parametrize("malformed_first", [False, True])
def test_automatic_update_known_inline_malformed_sibling_withholds_before_workspace(
    gradle_update_cli,
    mock_update_cli_deps,
    gradle_project,
    monkeypatch,
    malformed_first,
):
    from tests.test_updater import _actual_inline_sibling_scan

    scan = _actual_inline_sibling_scan(gradle_project, malformed_first=malformed_first)
    scan.updates = [
        u for u in scan.updates if u.pkg_name == "com.google.code.gson:gson"
    ]
    mock_update_cli_deps["scan_result"] = scan
    set_maven_dates(monkeypatch, undated=set())
    for _ in range(2):
        with pytest.raises(SystemExit) as exc:
            app(["update", "android"])
        assert exc.value.code == ExitCode.UPDATE_FAILED
        assert gradle_update_cli == {
            "workspaces": [],
            "tests": [],
            "applies": [],
            "commits": [],
            "promotions": [],
        }
        assert all(
            f.gradle_block_kind == "stale"
            for f in (*scan.vulnerabilities, *scan.updates)
        )
