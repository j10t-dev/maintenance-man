from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import (
    ExitCode,
    _ordered_failed_findings,
    _ordered_ready_findings,
    _ordered_resolve_candidates,
    app,
)
from maintenance_man.github import CodeHostError
from maintenance_man.models.scan import (
    ScanResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.storage import load_scan_results
from maintenance_man.updater import UpdateResult
from maintenance_man.vcs import RevisionError
from tests.conftest import (
    make_gradle_target,
    make_scan_result,
    make_update,
    make_vuln,
)
from tests.fakes import FakeFindingProcessor

_RESOLVE_BOOKMARK = "mm/resolve-dependencies"


def _clear_resolve_progress(scan_result: ScanResult) -> None:
    for f in (*scan_result.vulnerabilities, *scan_result.updates):
        f.update_status = None
        f.failed_phase = None
        f.flow = None


@pytest.fixture()
def mock_resolve_fresh(mock_resolve_cli_deps: dict) -> dict[str, object]:
    """mock_resolve_cli_deps with all resolve progress cleared."""
    _clear_resolve_progress(mock_resolve_cli_deps["scan_result"])
    mock_resolve_cli_deps["save_scan"]()
    return mock_resolve_cli_deps


class TestResolveCandidates:
    def test_ordered_resolve_candidates_excludes_other_flows(self):
        scan_result = make_scan_result(
            vulns=[
                make_vuln(pkg_name="pkg-a", vuln_id="CVE-1"),
                make_vuln(
                    pkg_name="pkg-b",
                    vuln_id="CVE-2",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                ),
            ],
            updates=[
                make_update(
                    pkg_name="pkg-c",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.UPDATE,
                    failed_phase="apply",
                ),
                make_update(
                    pkg_name="pkg-d",
                    update_status=UpdateStatus.READY,
                    flow=Workflow.RESOLVE,
                ),
                make_update(pkg_name="pkg-e"),
            ],
        )

        candidates = _ordered_resolve_candidates(scan_result)

        assert {f.pkg_name for f in candidates} == {"pkg-a", "pkg-b", "pkg-e"}

    def test_ordered_resolve_candidates_include_update_owned_test_failures(self):
        scan_result = make_scan_result(
            updates=[
                make_update(
                    pkg_name="pkg-a",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.UPDATE,
                    failed_phase="unit",
                )
            ],
            vulns=[],
        )

        candidates = _ordered_resolve_candidates(scan_result)

        assert [f.pkg_name for f in candidates] == ["pkg-a"]

    def test_ordered_failed_findings_only_resolve_failed(self):
        scan_result = make_scan_result(
            updates=[
                make_update(
                    pkg_name="keep",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                ),
                make_update(
                    pkg_name="skip-flow",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.UPDATE,
                ),
                make_update(
                    pkg_name="skip-status",
                    update_status=UpdateStatus.READY,
                    flow=Workflow.RESOLVE,
                ),
                make_update(pkg_name="skip-none"),
            ],
        )

        failed = _ordered_failed_findings(scan_result)

        assert [f.pkg_name for f in failed] == ["keep"]

    def test_ordered_ready_findings_only_resolve_ready(self):
        scan_result = make_scan_result(
            updates=[
                make_update(
                    pkg_name="keep",
                    update_status=UpdateStatus.READY,
                    flow=Workflow.RESOLVE,
                ),
                make_update(
                    pkg_name="skip-update-ready",
                    update_status=UpdateStatus.READY,
                    flow=Workflow.UPDATE,
                ),
                make_update(
                    pkg_name="skip-failed",
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                ),
            ],
        )

        ready = _ordered_ready_findings(scan_result, flow=Workflow.RESOLVE)

        assert [f.pkg_name for f in ready] == ["keep"]


class TestResolvePreChecks:
    def test_code_host_pruning_failure_refuses_before_processing(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
    ) -> None:
        path = mock_resolve_fresh["project_paths"]["vulnerable"]
        host = mock_resolve_fresh["vcs_state"].code_host(path)
        host.fail("pr_bookmarks", error=CodeHostError("host unavailable"))

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        assert not any(
            call.method == "commit" for call in mock_resolve_fresh["vcs_state"].attempts
        )

    def test_update_owned_test_failure_is_claimable_by_resolve(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result = make_scan_result(
            vulns=[],
            updates=[
                make_update(
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.UPDATE,
                    failed_phase="unit",
                )
            ],
        )
        mock_resolve_cli_deps["scan_result"] = scan_result
        mock_resolve_cli_deps["save_scan"]()
        mock_process = MagicMock(
            return_value=[
                UpdateResult(
                    pkg_name="pkg-a",
                    kind="update",
                    passed=False,
                    failed_phase="unit",
                )
            ]
        )
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 4
        assert [f.pkg_name for f in mock_process.call_args.args[0]] == ["pkg-a"]


class TestResolveFlow:
    def test_missing_non_gradle_resume_bookmark_refuses_before_processing(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        for finding in scan_result.findings:
            finding.update_status = UpdateStatus.READY
            finding.failed_phase = None
            finding.flow = Workflow.RESOLVE
        mock_resolve_cli_deps["save_scan"]()
        path = mock_resolve_cli_deps["project_paths"]["vulnerable"]
        repo = mock_resolve_cli_deps["services"].repository(path)
        repo.delete_bookmark(bookmark=_RESOLVE_BOOKMARK)
        mock_resolve_cli_deps["vcs_state"].clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        assert not any(
            call.method in {"commit", "push_bookmark"}
            for call in mock_resolve_cli_deps["vcs_state"].attempts
        )

    def test_creates_resolve_bookmark(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state = mock_resolve_fresh["vcs_state"]
        state.clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        created = next(
            call for call in state.effects if call.method == "create_bookmark"
        )
        assert dict(created.arguments)["bookmark"] == _RESOLVE_BOOKMARK

    def test_stops_on_first_failure_and_instructs_continue(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
            FakeFindingProcessor({"some-pkg": (False, "unit"), "pkg-a": (True, None)}),
        )
        host = mock_resolve_fresh["vcs_state"].code_host(
            mock_resolve_fresh["project_paths"]["vulnerable"]
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 4
        assert not any(call.method == "create_pr" for call in host.attempts)
        assert "mm resolve vulnerable --continue" in capsys.readouterr().out

    def test_all_pass_submits_pr(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        host = mock_resolve_fresh["vcs_state"].code_host(
            mock_resolve_fresh["project_paths"]["vulnerable"]
        )
        assert sum(call.method == "create_pr" for call in host.attempts) == 1

    def test_existing_ready_resolve_progress_preserves_bookmark_and_submits(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.vulnerabilities = []
        scan_result.updates = [
            make_update(
                update_status=UpdateStatus.READY,
                flow=Workflow.RESOLVE,
            )
        ]
        mock_resolve_cli_deps["save_scan"]()
        state = mock_resolve_cli_deps["vcs_state"]
        state.clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert not any(
            call.method in {"delete_bookmark", "create_bookmark", "new_change"}
            for call in state.effects
        )
        assert state.code_host(
            mock_resolve_cli_deps["project_paths"]["vulnerable"]
        ).effects

    def test_existing_failed_resolve_progress_requires_continue(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mock_process = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)
        state = mock_resolve_cli_deps["vcs_state"]
        state.clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        assert "--continue" in capsys.readouterr().out
        assert not any(call.method == "delete_bookmark" for call in state.effects)
        mock_process.assert_not_called()

    def test_startup_creates_resolve_bookmark_and_new_change(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state = mock_resolve_fresh["vcs_state"]
        state.clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        setup = [
            call.method
            for call in state.effects
            if call.method in {"delete_bookmark", "create_bookmark", "new_change"}
        ]
        assert setup[:3] == ["delete_bookmark", "create_bookmark", "new_change"]


class TestResolveSubmit:
    def test_submit_success_promotes_ready_to_completed(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        saved = load_scan_results("vulnerable", mm_home_with_projects / "scan-results")
        assert saved.vulnerabilities == []
        assert saved.updates == []

    def test_submit_failure_leaves_ready(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result: ScanResult = mock_resolve_fresh["scan_result"]
        scan_result.vulnerabilities.append(
            make_vuln(pkg_name="unrelated", vuln_id="CVE-open", fixed_version=None)
        )
        mock_resolve_fresh["save_scan"]()
        host = mock_resolve_fresh["vcs_state"].code_host(
            mock_resolve_fresh["project_paths"]["vulnerable"]
        )
        host.fail("create_pr", error=CodeHostError("host rejected"))

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 4
        saved = load_scan_results("vulnerable", mm_home_with_projects / "scan-results")
        assert saved.vulnerabilities[0].update_status == UpdateStatus.READY
        assert saved.vulnerabilities[0].flow == Workflow.RESOLVE
        assert saved.vulnerabilities[0].failed_phase is None
        assert saved.updates[0].update_status == UpdateStatus.READY
        assert saved.updates[0].flow == Workflow.RESOLVE
        assert any(
            call.method == "push_bookmark"
            for call in mock_resolve_fresh["vcs_state"].effects
        )
        path = mock_resolve_fresh["project_paths"]["vulnerable"]
        local_tip = (
            mock_resolve_fresh["services"]
            .repository(path)
            .resolve_revision(revision=_RESOLVE_BOOKMARK)
        )
        assert mock_resolve_fresh["vcs_state"].remote_bookmark_targets(
            path, bookmark=_RESOLVE_BOOKMARK
        ) == (local_tip,)

        with pytest.raises(SystemExit) as retry:
            app(["resolve", "vulnerable"])

        assert retry.value.code == 0
        assert [call.method for call in host.attempts].count("create_pr") == 2
        completed = load_scan_results(
            "vulnerable", mm_home_with_projects / "scan-results"
        )
        assert [finding.pkg_name for finding in completed.findings] == ["unrelated"]

    def test_push_failure_never_calls_host_and_retains_ready_state(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
    ) -> None:
        path = mock_resolve_fresh["project_paths"]["vulnerable"]
        state = mock_resolve_fresh["vcs_state"]
        state.fail(
            "push_bookmark",
            error=RevisionError("push rejected"),
            path=path,
        )
        host = state.code_host(path)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == ExitCode.UPDATE_FAILED
        assert not any(call.method == "create_pr" for call in host.attempts)
        saved = load_scan_results("vulnerable", mm_home_with_projects / "scan-results")
        assert all(
            finding.update_status == UpdateStatus.READY for finding in saved.findings
        )


class TestResolveContinue:
    def test_unknown_repository_inspection_refuses_before_tests(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        path = mock_resolve_cli_deps["project_paths"]["vulnerable"]
        state = mock_resolve_cli_deps["vcs_state"]
        state.fail("has_changes", error=RevisionError("cannot inspect"), path=path)
        tests = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.run_test_phases", tests)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 1
        tests.assert_not_called()
        assert not any(call.method == "commit" for call in state.attempts)

    def test_not_on_resolve_bookmark_errors(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_resolve_cli_deps["vcs_state"].seed_bookmark(
            mock_resolve_cli_deps["project_paths"]["vulnerable"],
            bookmark=_RESOLVE_BOOKMARK,
            targets=(),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 1

    def test_non_empty_current_change_aborts_before_tests(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_tests = MagicMock()
        project_path = mock_resolve_cli_deps["project_paths"]["vulnerable"]
        (project_path / "dep.txt").write_text("dirty\n", encoding="utf-8")
        monkeypatch.setattr("maintenance_man.cli.run_test_phases", mock_tests)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 1
        mock_tests.assert_not_called()

    def test_continue_never_calls_apply_update(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--continue is retest-only: it must not invoke apply_update."""
        from maintenance_man import updater

        mock_apply = MagicMock(return_value=True)
        monkeypatch.setattr(updater, "_apply_update", mock_apply)
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
            MagicMock(return_value=[]),
        )

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.updates = []
        scan_result.vulnerabilities = [
            make_vuln(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="apply",
            )
        ]
        mock_resolve_cli_deps["save_scan"]()

        with pytest.raises(SystemExit):
            app(["resolve", "vulnerable", "--continue"])

        mock_apply.assert_not_called()

    def test_continue_never_creates_auto_commit(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
            MagicMock(return_value=[]),
        )

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.updates = []
        scan_result.vulnerabilities = [
            make_vuln(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="unit",
            )
        ]
        mock_resolve_cli_deps["save_scan"]()

        state = mock_resolve_cli_deps["vcs_state"]
        state.clear_calls()
        with pytest.raises(SystemExit):
            app(["resolve", "vulnerable", "--continue"])

        assert not any(call.method == "commit" for call in state.attempts)

    def test_committed_manual_repair_continues_without_apply_or_auto_commit(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from maintenance_man import updater

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.updates = []
        scan_result.vulnerabilities = [
            make_vuln(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="unit",
            )
        ]
        mock_resolve_cli_deps["save_scan"]()
        path = mock_resolve_cli_deps["project_paths"]["vulnerable"]
        repo = mock_resolve_cli_deps["services"].repository(path)
        (path / "dep.txt").write_text("manual repair\n", encoding="utf-8")
        repo.commit(message="manual repair")
        manual_tip = repo.resolve_revision(revision="@-")
        state = mock_resolve_cli_deps["vcs_state"]
        state.clear_calls()
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda _cfg, _path: (True, None)
        )
        monkeypatch.setattr(
            updater,
            "_apply_update",
            lambda *args: pytest.fail("--continue must not apply a package update"),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        assert not any(call.method == "commit" for call in state.attempts)
        moved = next(call for call in state.effects if call.method == "set_bookmark")
        assert dict(moved.arguments)["revision"] == "@-"
        assert state.remote_bookmark_targets(path, bookmark=_RESOLVE_BOOKMARK) == (
            manual_tip,
        )
        saved = load_scan_results("vulnerable", mm_home_with_projects / "scan-results")
        assert not saved.findings

    def test_continue_passing_tests_promotes_blocker_to_ready(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.updates = []
        mock_resolve_cli_deps["save_scan"]()

        mock_process = MagicMock(return_value=[])
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        assert any(
            call.method == "set_bookmark"
            for call in mock_resolve_cli_deps["vcs_state"].effects
        )
        saved = load_scan_results("vulnerable", mm_home_with_projects / "scan-results")
        assert saved.vulnerabilities == []

    def test_continue_bookmark_move_failure_does_not_save_ready_state(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        blocker = scan_result.vulnerabilities[0]
        scan_result.updates = []
        mock_resolve_cli_deps["save_scan"]()
        from maintenance_man.vcs import RevisionError

        mock_resolve_cli_deps["vcs_state"].fail(
            "set_bookmark",
            error=RevisionError("cannot move bookmark"),
            path=mock_resolve_cli_deps["project_paths"]["vulnerable"],
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 1
        saved = load_scan_results("vulnerable", mm_home_with_projects / "scan-results")
        assert saved.vulnerabilities[0].update_status == UpdateStatus.FAILED
        assert saved.vulnerabilities[0].flow == Workflow.RESOLVE
        assert blocker.update_status == UpdateStatus.FAILED
        assert blocker.flow == Workflow.RESOLVE

    def test_continue_promoted_finding_not_reselected(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )

        mock_process = MagicMock(return_value=[])
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit):
            app(["resolve", "vulnerable", "--continue"])

        passed_findings = mock_process.call_args.args[0]
        assert "some-pkg" not in {f.pkg_name for f in passed_findings}

    def test_continue_failing_tests_updates_phase_and_exits_4(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (False, "unit")
        )

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.updates = []
        blocker = scan_result.vulnerabilities[0]
        blocker.failed_phase = "apply"
        mock_resolve_cli_deps["save_scan"]()

        mock_process = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 4
        saved = load_scan_results("vulnerable", mm_home_with_projects / "scan-results")
        assert saved.vulnerabilities[0].update_status == UpdateStatus.FAILED
        assert saved.vulnerabilities[0].failed_phase == "unit"
        assert saved.vulnerabilities[0].flow == Workflow.RESOLVE
        mock_process.assert_not_called()

    def test_continue_commit_phase_failure_can_become_ready(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A commit-phase failure can become READY when the bookmark is clean
        and tests pass (operator committed the fix manually)."""
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.updates = []
        blocker = scan_result.vulnerabilities[0]
        blocker.failed_phase = "commit"
        mock_resolve_cli_deps["save_scan"]()

        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(return_value=[])
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        saved = load_scan_results("vulnerable", mm_home_with_projects / "scan-results")
        assert saved.vulnerabilities == []

    def test_continue_with_no_failed_blockers_exits_noop(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        for f in (*scan_result.vulnerabilities, *scan_result.updates):
            f.update_status = UpdateStatus.READY
            f.flow = Workflow.RESOLVE
        mock_resolve_cli_deps["save_scan"]()

        mock_tests = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.run_test_phases", mock_tests)
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(return_value=[])
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        mock_tests.assert_not_called()
        host = mock_resolve_cli_deps["vcs_state"].code_host(
            mock_resolve_cli_deps["project_paths"]["vulnerable"]
        )
        assert sum(call.method == "create_pr" for call in host.attempts) == 1


class TestResolveCliSurface:
    def test_requires_project_arg(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["resolve"])

        assert exc_info.value.code == 1

    def test_unknown_project_exits_1(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "missing"])

        assert exc_info.value.code == 1


@pytest.mark.parametrize("continue_", [False, True])
@pytest.mark.parametrize("status", [UpdateStatus.FAILED, UpdateStatus.READY])
@pytest.mark.parametrize(
    "target_shape", ["valid", "missing", "empty", "mixed-history", "cross-kind"]
)
def test_gradle_legacy_resolve_history_never_authorizes_effects(
    mm_home_with_gradle,
    monkeypatch,
    continue_,
    status,
    target_shape,
):
    """Even a manually repaired catalogue cannot replace a revision-bound ledger."""
    import subprocess

    target = make_gradle_target()
    if target_shape == "missing":
        target = None
    elif target_shape == "empty":
        target.members = []
    elif target_shape == "mixed-history":
        target.members[1].installed_version = "9.9.9"
    updates = [
        make_update(
            pkg_name="room",
            installed_version="2.8.4",
            latest_version="2.8.5",
            gradle_target=target,
            update_status=status,
            failed_phase="unit",
            flow=Workflow.RESOLVE,
        )
    ]
    vulns = (
        [
            make_vuln(
                pkg_name="androidx.room:room-runtime",
                installed_version="2.8.4",
                fixed_version=None,
                gradle_target=make_gradle_target(),
                update_status=status,
                failed_phase="unit",
                flow=Workflow.RESOLVE,
            )
        ]
        if target_shape == "cross-kind"
        else []
    )
    scan = make_scan_result(vulns=vulns, updates=updates)
    results = mm_home_with_gradle / "scan-results" / "android.json"
    results.parent.mkdir(exist_ok=True)
    results.write_text(scan.model_dump_json())
    before = results.read_bytes()

    def forbidden(*args, **kwargs):
        pytest.fail("legacy history must not run commands or alter bookmarks")

    monkeypatch.setattr(subprocess, "run", forbidden)
    args = ["resolve", "android"] + (["--continue"] if continue_ else [])
    with pytest.raises(SystemExit) as exc:
        app(args)
    assert exc.value.code == 4
    assert results.read_bytes() == before
    assert not (mm_home_with_gradle / "gradle-runs" / "android.json").exists()


@pytest.mark.parametrize("owned", [False, True])
def test_gradle_continuation_without_ledger_preserves_interrupted_outputs(
    mm_home_with_gradle,
    gradle_project,
    monkeypatch,
    owned,
):
    import subprocess

    report = gradle_project.path / "gradle/libs.versions.updates.toml"
    report.write_bytes(b"preserved output")
    marker = gradle_project.path / "gradle/.mm-owned-report"
    if owned:
        marker.write_bytes(b"")
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: pytest.fail("no ledger")
    )
    with pytest.raises(SystemExit) as exc:
        app(["resolve", "android", "--continue"])
    assert exc.value.code == 4
    assert report.read_bytes() == b"preserved output"
    assert marker.exists() is owned
