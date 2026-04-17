from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import (
    _ordered_failed_findings,
    _ordered_ready_findings,
    _ordered_resolve_candidates,
    app,
)
from maintenance_man.models.scan import (
    Workflow,
    ScanResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.updater import NoScanResultsError, UpdateResult
from tests.conftest import make_scan_result, make_update, make_vuln

_RESOLVE_BRANCH = "mm/resolve-dependencies"


@pytest.fixture()
def mock_resolve_cli_deps(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Patch all resolve-CLI boundaries so tests focus on orchestration."""
    scan_result = make_scan_result(
        vulns=[
            make_vuln(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="unit",
            ),
        ],
        updates=[
            make_update(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="unit",
            ),
        ],
    )
    state: dict[str, object] = {"scan_result": scan_result}

    monkeypatch.setattr("maintenance_man.cli.check_gh_available", lambda: None)
    monkeypatch.setattr("maintenance_man.cli.sync_remote", lambda p: True)
    monkeypatch.setattr(
        "maintenance_man.cli.load_scan_results",
        lambda name, d: state["scan_result"],
    )
    monkeypatch.setattr(
        "maintenance_man.cli.save_scan_results",
        lambda name, d, sr: None,
    )
    monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: False)
    monkeypatch.setattr("maintenance_man.cli.git_create_branch", lambda b, p: True)
    monkeypatch.setattr("maintenance_man.cli.git_replace_branch", lambda b, p: True)
    monkeypatch.setattr("maintenance_man.cli.git_delete_branch", lambda b, p: True)
    monkeypatch.setattr("maintenance_man.cli.ensure_on_main", lambda p: True)
    monkeypatch.setattr("maintenance_man.cli.check_repo_clean", lambda p: None)
    monkeypatch.setattr(
        "maintenance_man.cli.get_current_branch", lambda p: _RESOLVE_BRANCH
    )
    monkeypatch.setattr(
        "maintenance_man.cli.push_and_create_pr", lambda p: (True, "PR #1")
    )
    return state


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
    def test_missing_gh_errors(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from maintenance_man.vcs import GitHubCLINotFoundError

        monkeypatch.setattr(
            "maintenance_man.cli.check_gh_available",
            MagicMock(side_effect=GitHubCLINotFoundError("no gh")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])
        assert exc_info.value.code == 1

    def test_conflicting_update_flow_aborts(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.updates[0].flow = Workflow.UPDATE
        mock_process = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        assert "update" in capsys.readouterr().out.lower()
        mock_process.assert_not_called()

    def test_legacy_findings_missing_flow_abort(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.updates[0].flow = None
        mock_process = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        assert "rescan" in capsys.readouterr().out.lower()
        mock_process.assert_not_called()

    def test_missing_test_config_warns_and_proceeds(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from maintenance_man.models.config import ProjectConfig

        monkeypatch.setattr(
            "maintenance_man.cli.resolve_project",
            MagicMock(
                return_value=ProjectConfig(path=Path("/tmp/x"), package_manager="bun")
            ),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
            MagicMock(
                return_value=[
                    UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True),
                    UpdateResult(pkg_name="pkg-a", kind="update", passed=True),
                ]
            ),
        )

        def _mark_ready(scan_result):
            for f in (*scan_result.vulnerabilities, *scan_result.updates):
                f.update_status = UpdateStatus.READY
                f.flow = Workflow.RESOLVE

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        _mark_ready(scan_result)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        out = capsys.readouterr().out.lower()
        assert exc_info.value.code == 0
        assert "no test configuration" in out


class TestResolveNoOp:
    def test_no_scan_results_is_noop(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_create = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("no results")),
        )
        monkeypatch.setattr("maintenance_man.cli.git_create_branch", mock_create)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        mock_create.assert_not_called()

    def test_no_actionable_findings_is_noop(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.vulnerabilities = []
        scan_result.updates = []
        mock_create = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.git_create_branch", mock_create)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert "nothing to resolve" in capsys.readouterr().out.lower()
        mock_create.assert_not_called()


class TestResolveFlow:
    def test_creates_resolve_branch(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def _mark_ready(findings, *args, **kwargs):
            for f in findings:
                f.update_status = UpdateStatus.READY
                f.flow = Workflow.RESOLVE
            return [
                UpdateResult(pkg_name=f.pkg_name, kind="update", passed=True)
                for f in findings
            ]

        mock_create = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.git_create_branch", mock_create)
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(side_effect=_mark_ready)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert mock_create.call_args.args[0] == _RESOLVE_BRANCH

    def test_stops_on_first_failure_and_instructs_continue(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mock_push = MagicMock(return_value=(True, "PR #1"))
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
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
        monkeypatch.setattr("maintenance_man.cli.push_and_create_pr", mock_push)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 4
        mock_push.assert_not_called()
        assert "mm resolve vulnerable --continue" in capsys.readouterr().out

    def test_all_pass_submits_pr(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def _mark_ready(findings, *args, **kwargs):
            for f in findings:
                f.update_status = UpdateStatus.READY
                f.flow = Workflow.RESOLVE
            return [
                UpdateResult(pkg_name=f.pkg_name, kind="update", passed=True)
                for f in findings
            ]

        mock_push = MagicMock(return_value=(True, "PR #1"))
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(side_effect=_mark_ready)
        )
        monkeypatch.setattr("maintenance_man.cli.push_and_create_pr", mock_push)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        mock_push.assert_called_once()

    def test_branch_collision_uses_replace_helper(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_replace = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr("maintenance_man.cli.git_replace_branch", mock_replace)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="d")
        )

        def _mark_ready(findings, *args, **kwargs):
            for f in findings:
                f.update_status = UpdateStatus.READY
                f.flow = Workflow.RESOLVE
            return [
                UpdateResult(pkg_name=f.pkg_name, kind="update", passed=True)
                for f in findings
            ]

        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(side_effect=_mark_ready)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert mock_replace.call_args.args[0] == _RESOLVE_BRANCH

    def test_dirty_tree_aborts_when_user_declines(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from maintenance_man.vcs import RepoDirtyError

        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            MagicMock(side_effect=RepoDirtyError("dirty")),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Confirm.ask", MagicMock(return_value=False)
        )
        mock_process = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        mock_process.assert_not_called()


class TestResolveSubmit:
    def test_submit_success_promotes_ready_to_completed(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]

        def _mark_ready(findings, *args, **kwargs):
            for f in findings:
                f.update_status = UpdateStatus.READY
                f.flow = Workflow.RESOLVE
            return [
                UpdateResult(pkg_name=f.pkg_name, kind="update", passed=True)
                for f in findings
            ]

        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(side_effect=_mark_ready)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.push_and_create_pr",
            MagicMock(return_value=(True, "PR #1")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert scan_result.vulnerabilities == []
        assert scan_result.updates == []

    def test_submit_failure_leaves_ready(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]

        def _mark_ready(findings, *args, **kwargs):
            for f in findings:
                f.update_status = UpdateStatus.READY
                f.flow = Workflow.RESOLVE
            return [
                UpdateResult(pkg_name=f.pkg_name, kind="update", passed=True)
                for f in findings
            ]

        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(side_effect=_mark_ready)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.push_and_create_pr",
            MagicMock(return_value=(False, "push rejected")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 4
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.READY
        assert scan_result.vulnerabilities[0].flow == Workflow.RESOLVE
        assert scan_result.vulnerabilities[0].failed_phase is None
        assert scan_result.updates[0].update_status == UpdateStatus.READY
        assert scan_result.updates[0].flow == Workflow.RESOLVE


class TestResolveContinue:
    def test_not_on_resolve_branch_errors(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("maintenance_man.cli.get_current_branch", lambda p: "main")

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 1

    def test_dirty_tree_aborts_before_tests(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from maintenance_man.vcs import RepoDirtyError

        mock_tests = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            MagicMock(side_effect=RepoDirtyError("dirty")),
        )
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
        monkeypatch.setattr(
            "maintenance_man.cli.push_and_create_pr",
            MagicMock(return_value=(True, "PR #1")),
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

        with pytest.raises(SystemExit):
            app(["resolve", "vulnerable", "--continue"])

        mock_apply.assert_not_called()

    def test_continue_never_creates_auto_commit(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from maintenance_man import updater

        mock_commit = MagicMock(return_value=True)
        monkeypatch.setattr(updater, "git_commit_all", mock_commit)
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
            MagicMock(return_value=[]),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.push_and_create_pr",
            MagicMock(return_value=(True, "PR #1")),
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

        with pytest.raises(SystemExit):
            app(["resolve", "vulnerable", "--continue"])

        mock_commit.assert_not_called()

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
        blocker = scan_result.vulnerabilities[0]
        scan_result.updates = []

        mock_process = MagicMock(return_value=[])
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)
        monkeypatch.setattr(
            "maintenance_man.cli.push_and_create_pr",
            MagicMock(return_value=(True, "PR #1")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        assert blocker.update_status == UpdateStatus.COMPLETED
        assert blocker.flow is None

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
        monkeypatch.setattr(
            "maintenance_man.cli.push_and_create_pr",
            MagicMock(return_value=(True, "PR #1")),
        )

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

        mock_process = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 4
        assert blocker.update_status == UpdateStatus.FAILED
        assert blocker.failed_phase == "unit"
        assert blocker.flow == Workflow.RESOLVE
        mock_process.assert_not_called()

    def test_continue_commit_phase_failure_can_become_ready(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A commit-phase failure can become READY when the branch is clean
        and tests pass (operator committed the fix manually)."""
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        scan_result.updates = []
        blocker = scan_result.vulnerabilities[0]
        blocker.failed_phase = "commit"

        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(return_value=[])
        )
        monkeypatch.setattr(
            "maintenance_man.cli.push_and_create_pr",
            MagicMock(return_value=(True, "PR #1")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        assert blocker.update_status == UpdateStatus.COMPLETED

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

        mock_tests = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.run_test_phases", mock_tests)
        mock_push = MagicMock(return_value=(True, "PR #1"))
        monkeypatch.setattr("maintenance_man.cli.push_and_create_pr", mock_push)
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(return_value=[])
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        mock_tests.assert_not_called()
        mock_push.assert_called_once()


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
