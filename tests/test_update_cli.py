from contextlib import contextmanager
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
    UpdateStatus,
    VulnFinding,
)
from maintenance_man.updater import NoScanResultsError, UpdateResult

pytestmark = pytest.mark.usefixtures("mock_update_cli_deps")

UPDATE_BRANCH = "mm/update-dependencies"


class TestUpdatePreChecks:
    def test_update_aborts_on_resolve_owned_in_progress_findings(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result(
            vuln_status=UpdateStatus.FAILED,
            vuln_flow="resolve",
            include_update=False,
        )
        mock_sync = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.sync_graphite", mock_sync)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 1
        mock_sync.assert_not_called()

    def test_update_aborts_when_in_progress_findings_lack_flow(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result(
            vuln_status=UpdateStatus.READY,
            include_update=False,
        )
        mock_sync = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.sync_graphite", mock_sync)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 1
        mock_sync.assert_not_called()

    def test_no_projects_configured_exits_0(self, mm_home: Path) -> None:
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])

        assert exc_info.value.code == 0

    def test_no_scan_results_exits_1(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("No results")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 1

    def test_no_findings_exits_0_before_repo_side_effects(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result(include_vuln=False, include_update=False)
        mock_sync = MagicMock(return_value=True)
        mock_worktree = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.sync_graphite", mock_sync)
        monkeypatch.setattr("maintenance_man.cli.create_worktree", mock_worktree)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        mock_sync.assert_not_called()
        mock_worktree.assert_not_called()

    def test_missing_graphite_fails_cleanly_before_sync(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        from maintenance_man.vcs import GraphiteNotFoundError

        mock_sync = MagicMock(return_value=True)
        mock_worktree = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.check_graphite_available",
            MagicMock(side_effect=GraphiteNotFoundError("missing gt")),
        )
        monkeypatch.setattr("maintenance_man.cli.sync_graphite", mock_sync)
        monkeypatch.setattr("maintenance_man.cli.create_worktree", mock_worktree)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 1
        assert "missing gt" in capsys.readouterr().out
        mock_sync.assert_not_called()
        mock_worktree.assert_not_called()

    def test_dirty_repo_exits_before_worktree_side_effects(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.vcs import RepoDirtyError

        mock_sync = MagicMock(return_value=True)
        mock_worktree = MagicMock(return_value=True)
        mock_vulns = MagicMock(return_value=[])
        mock_updates = MagicMock(return_value=[])
        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            MagicMock(side_effect=RepoDirtyError("dirty")),
        )
        monkeypatch.setattr("maintenance_man.cli.sync_graphite", mock_sync)
        monkeypatch.setattr("maintenance_man.cli.create_worktree", mock_worktree)
        monkeypatch.setattr("maintenance_man.cli.process_vulns_local", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates_local", mock_updates)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 1
        mock_sync.assert_not_called()
        mock_worktree.assert_not_called()
        mock_vulns.assert_not_called()
        mock_updates.assert_not_called()

    def test_missing_test_config_warns_only(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        make_pass_side_effect,
    ):
        mock_updates = MagicMock(
            side_effect=make_pass_side_effect(
                flow="update",
                kind="update",
            )
        )
        monkeypatch.setattr("maintenance_man.cli.process_updates_local", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="updates")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "no-tests"])

        assert exc_info.value.code == 0
        assert "no test configuration" in capsys.readouterr().out
        mock_updates.assert_called_once()


class TestUpdateInteractiveFlow:
    def test_none_selection_exits_0_without_processing(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_vulns = MagicMock(return_value=[])
        mock_updates = MagicMock(return_value=[])
        monkeypatch.setattr("maintenance_man.cli.process_vulns_local", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates_local", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        mock_vulns.assert_not_called()
        mock_updates.assert_not_called()

    def test_syncs_trunk_before_preparing_branch_on_fresh_run(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        events: list[str] = []
        monkeypatch.setattr(
            "maintenance_man.cli.sync_graphite",
            lambda p: events.append("sync") or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.git_create_branch",
            lambda b, p: events.append("branch") or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )

        with pytest.raises(SystemExit):
            app(["update", "vulnerable"])

        assert events == ["sync", "branch"]

    def test_existing_branch_discard_uses_replace_helper_on_fresh_run(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_replace = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr("maintenance_man.cli.git_replace_branch", mock_replace)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(side_effect=["d", "none"])
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        mock_replace.assert_called_once()
        assert mock_replace.call_args.args[:2] == (UPDATE_BRANCH, "main")

    def test_resume_reopens_existing_update_branch_in_worktree(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result(
            vuln_status=UpdateStatus.READY,
            vuln_flow="update",
            include_update=False,
        )
        mock_worktree = MagicMock(return_value=True)
        mock_sync = MagicMock(return_value=True)
        mock_create_branch = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr("maintenance_man.cli.create_worktree", mock_worktree)
        monkeypatch.setattr("maintenance_man.cli.sync_graphite", mock_sync)
        monkeypatch.setattr("maintenance_man.cli.git_create_branch", mock_create_branch)
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        assert mock_worktree.call_args.kwargs["branch"] == UPDATE_BRANCH
        assert mock_worktree.call_args.kwargs["detach"] is False
        mock_sync.assert_not_called()
        mock_create_branch.assert_not_called()

    def test_resume_hides_ready_findings_and_retries_only_failed(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_pass_side_effect,
    ):
        scan_result = ScanResult(
            project="vulnerable",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="tests/fixtures/vulnerable-project",
            vulnerabilities=[
                VulnFinding(
                    vuln_id="CVE-ready",
                    pkg_name="ready-pkg",
                    installed_version="1.0.0",
                    fixed_version="1.0.1",
                    severity=Severity.HIGH,
                    title="ready",
                    description="desc",
                    status="fixed",
                    update_status=UpdateStatus.READY,
                    flow="update",
                )
            ],
            updates=[
                UpdateFinding(
                    pkg_name="failed-update",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    semver_tier=SemverTier.PATCH,
                    update_status=UpdateStatus.FAILED,
                    flow="update",
                )
            ],
        )
        mock_vulns = MagicMock(return_value=[])
        mock_updates = MagicMock(
            side_effect=make_pass_side_effect(
                flow="update",
                kind="update",
            )
        )
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr("maintenance_man.cli.process_vulns_local", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates_local", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        mock_vulns.assert_not_called()
        retried = mock_updates.call_args.args[0]
        assert [f.pkg_name for f in retried] == ["failed-update"]

    def test_selecting_none_on_resume_retries_nothing_and_exits_cleanly(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result(
            update_status=UpdateStatus.FAILED,
            update_flow="update",
            include_vuln=False,
        )
        mock_updates = MagicMock(return_value=[])
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr("maintenance_man.cli.process_updates_local", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        mock_updates.assert_not_called()

    def test_resume_with_only_ready_findings_goes_straight_to_merge_retry(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result(
            vuln_status=UpdateStatus.READY,
            vuln_flow="update",
            update_status=UpdateStatus.READY,
            update_flow="update",
        )
        mock_merge = MagicMock(return_value=True)
        mock_prompt = MagicMock()
        mock_vulns = MagicMock(return_value=[])
        mock_updates = MagicMock(return_value=[])
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr("maintenance_man.cli.git_merge_fast_forward", mock_merge)
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", mock_prompt)
        monkeypatch.setattr("maintenance_man.cli.process_vulns_local", mock_vulns)
        monkeypatch.setattr("maintenance_man.cli.process_updates_local", mock_updates)
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        mock_prompt.assert_not_called()
        mock_vulns.assert_not_called()
        mock_updates.assert_not_called()
        mock_merge.assert_called_once()

    def test_merge_success_promotes_ready_findings_to_completed(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result()
        mock_remove = MagicMock()
        mock_save = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.remove_completed_findings", mock_remove
        )
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", mock_save)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.COMPLETED
        assert scan_result.updates[0].update_status == UpdateStatus.COMPLETED
        assert scan_result.vulnerabilities[0].flow is None
        assert scan_result.updates[0].flow is None
        mock_remove.assert_called_once_with(scan_result)
        mock_save.assert_called_once()

    def test_merge_failure_leaves_ready_findings_ready(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result()
        mock_remove = MagicMock()
        mock_save = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.git_merge_fast_forward", MagicMock(return_value=False)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.remove_completed_findings", mock_remove
        )
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", mock_save)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 4
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.READY
        assert scan_result.updates[0].update_status == UpdateStatus.READY
        assert scan_result.vulnerabilities[0].flow == "update"
        assert scan_result.updates[0].flow == "update"
        mock_remove.assert_not_called()
        mock_save.assert_not_called()

    def test_declining_merge_leaves_ready_findings_ready(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result()
        mock_delete = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=False)
        )
        monkeypatch.setattr("maintenance_man.cli.git_delete_branch", mock_delete)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.READY
        assert scan_result.updates[0].update_status == UpdateStatus.READY
        assert scan_result.vulnerabilities[0].flow == "update"
        assert scan_result.updates[0].flow == "update"
        mock_delete.assert_not_called()

    def test_all_failures_keep_branch_for_retry(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_scan_result,
    ):
        scan_result = make_scan_result()

        def fail_vulns(findings, *_args, **_kwargs):
            for finding in findings:
                finding.update_status = UpdateStatus.FAILED
                finding.flow = "update"
            return [
                UpdateResult(
                    pkg_name=f.pkg_name,
                    kind="vuln",
                    passed=False,
                    failed_phase="unit",
                )
                for f in findings
            ]

        def fail_updates(findings, *_args, **_kwargs):
            for finding in findings:
                finding.update_status = UpdateStatus.FAILED
                finding.flow = "update"
            return [
                UpdateResult(
                    pkg_name=f.pkg_name,
                    kind="update",
                    passed=False,
                    failed_phase="unit",
                )
                for f in findings
            ]

        mock_delete = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_vulns_local", MagicMock(side_effect=fail_vulns)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_updates_local",
            MagicMock(side_effect=fail_updates),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr("maintenance_man.cli.git_delete_branch", mock_delete)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 4
        mock_delete.assert_not_called()

    def test_merge_and_delete_use_original_repo_path(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        real_repo = Path("/repo/real")
        worktree = Path("/repo/worktree")
        mock_resolve = MagicMock(
            return_value=MagicMock(
                path=real_repo,
                package_manager="uv",
                test_unit="uv run pytest",
            )
        )
        mock_checkout = MagicMock(return_value=True)
        mock_merge = MagicMock(return_value=True)
        mock_delete = MagicMock(return_value=True)

        @contextmanager
        def fake_worktree_context(
            proj_config,
            project,
            *,
            branch="main",
            detach=True,
        ):
            assert proj_config.path == real_repo
            assert branch == "main"
            assert detach is True
            yield proj_config.model_copy(update={"path": worktree})

        monkeypatch.setattr("maintenance_man.cli.resolve_project", mock_resolve)
        monkeypatch.setattr(
            "maintenance_man.cli._worktree_context",
            fake_worktree_context,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )
        monkeypatch.setattr("maintenance_man.cli.git_checkout", mock_checkout)
        monkeypatch.setattr("maintenance_man.cli.git_merge_fast_forward", mock_merge)
        monkeypatch.setattr("maintenance_man.cli.git_delete_branch", mock_delete)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        assert any(
            call.args == ("main", real_repo)
            for call in mock_checkout.call_args_list
        )
        assert mock_merge.call_args.args == (UPDATE_BRANCH, real_repo)
        assert mock_delete.call_args.args == (UPDATE_BRANCH, real_repo)


class TestUpdateBatchFlow:
    def test_batch_no_test_config_warns_only(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])

        assert exc_info.value.code == 0
        assert "no test configuration" in capsys.readouterr().out

    def test_batch_merge_failure_adds_synthetic_merge_result_and_continues(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_merge = MagicMock(side_effect=[False, True])
        summary = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )
        monkeypatch.setattr("maintenance_man.cli.git_merge_fast_forward", mock_merge)
        monkeypatch.setattr("maintenance_man.cli._print_mass_update_summary", summary)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "clean"])

        assert exc_info.value.code == 4
        project_results = summary.call_args.args[0]
        vulnerable_results = dict(project_results)["vulnerable"]
        assert any(r.failed_phase == "merge" for r in vulnerable_results)

    def test_batch_syncs_against_original_repo_path(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        sync_paths: list[Path] = []
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=True)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.sync_graphite",
            lambda path: sync_paths.append(path) or True,
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])

        assert exc_info.value.code == 0
        assert sync_paths
        assert all(path != (Path("/tmp") / "fake") for path in sync_paths)


class TestUpdateTargetSelection:
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


class TestUpdateCliSurface:
    def test_help_does_not_expose_continue_or_worktree(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "--help"])

        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "--continue" not in output
        assert "--worktree" not in output

    def test_worktree_option_is_not_accepted(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "--worktree"])

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
