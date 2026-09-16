from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import (
    _ordered_failed_findings,
    _ordered_ready_findings,
    _ordered_resolve_candidates,
    app,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    ScanResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.updater import NoScanResultsError, UpdateResult
from tests.conftest import (
    make_gradle_target,
    make_scan_result,
    make_update,
    make_vuln,
    set_maven_dates,
)

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
    return mock_resolve_cli_deps


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
    monkeypatch.setattr("maintenance_man.cli.check_jj_available", lambda: None)
    monkeypatch.setattr("maintenance_man.cli.prune_stale_bookmarks", lambda p: True)
    monkeypatch.setattr("maintenance_man.cli.ensure_main_bookmark", lambda p: True)
    monkeypatch.setattr(
        "maintenance_man.cli.load_scan_results",
        lambda name, d: state["scan_result"],
    )
    monkeypatch.setattr(
        "maintenance_man.cli.save_scan_results",
        lambda name, d, sr: None,
    )
    monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: False)
    monkeypatch.setattr(
        "maintenance_man.cli.create_or_reset_bookmark", lambda b, p, r: True
    )
    monkeypatch.setattr("maintenance_man.cli.delete_bookmark", lambda b, p: True)
    monkeypatch.setattr("maintenance_man.cli.edit_new_change", lambda p, r: True)
    monkeypatch.setattr(
        "maintenance_man.cli.resolve_bookmark_contains_current_change",
        lambda p, b: True,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.current_change_has_changes", lambda p: False
    )
    monkeypatch.setattr(
        "maintenance_man.cli.push_bookmark_and_create_pr",
        lambda p, b: (True, "PR #1"),
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

        candidates = _ordered_resolve_candidates(scan_result, _uv_project(), 7)

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

        candidates = _ordered_resolve_candidates(scan_result, _uv_project(), 7)

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

        failed = _ordered_failed_findings(scan_result, _uv_project(), 7)

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

        ready = _ordered_ready_findings(
            scan_result, flow=Workflow.RESOLVE, proj_config=_uv_project()
        )

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

    def test_missing_jj_errors(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from maintenance_man.vcs import JJCLINotFoundError

        monkeypatch.setattr(
            "maintenance_man.cli.check_jj_available",
            MagicMock(side_effect=JJCLINotFoundError("no jj")),
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
        scan_result.updates[0].failed_phase = "apply"
        mock_process = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        out = capsys.readouterr().out.lower()
        assert exc_info.value.code == 1
        assert "update" in out
        assert "resolve" in out
        assert "vulnerable" in out
        mock_process.assert_not_called()

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
        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: True)

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
        monkeypatch.setattr("maintenance_man.cli.create_or_reset_bookmark", mock_create)

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
        monkeypatch.setattr("maintenance_man.cli.create_or_reset_bookmark", mock_create)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert "nothing to resolve" in capsys.readouterr().out.lower()
        mock_create.assert_not_called()


class TestResolveFlow:
    def test_creates_resolve_bookmark(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
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
        monkeypatch.setattr("maintenance_man.cli.create_or_reset_bookmark", mock_create)
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings", MagicMock(side_effect=_mark_ready)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert mock_create.call_args.args[0] == _RESOLVE_BOOKMARK

    def test_stops_on_first_failure_and_instructs_continue(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
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
        monkeypatch.setattr(
            "maintenance_man.cli.push_bookmark_and_create_pr", mock_push
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 4
        mock_push.assert_not_called()
        assert "mm resolve vulnerable --continue" in capsys.readouterr().out

    def test_all_pass_submits_pr(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
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
        monkeypatch.setattr(
            "maintenance_man.cli.push_bookmark_and_create_pr", mock_push
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        mock_push.assert_called_once()

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
        mock_delete = MagicMock(return_value=True)
        mock_set = MagicMock(return_value=True)
        mock_new = MagicMock(return_value=True)
        mock_push = MagicMock(return_value=(True, "PR #1"))
        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: True)
        monkeypatch.setattr("maintenance_man.cli.delete_bookmark", mock_delete)
        monkeypatch.setattr("maintenance_man.cli.create_or_reset_bookmark", mock_set)
        monkeypatch.setattr("maintenance_man.cli.edit_new_change", mock_new)
        monkeypatch.setattr(
            "maintenance_man.cli.push_bookmark_and_create_pr", mock_push
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        mock_delete.assert_not_called()
        mock_set.assert_not_called()
        mock_new.assert_not_called()
        mock_push.assert_called_once()

    def test_existing_failed_resolve_progress_requires_continue(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mock_delete = MagicMock(return_value=True)
        mock_process = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: True)
        monkeypatch.setattr("maintenance_man.cli.delete_bookmark", mock_delete)
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        assert "--continue" in capsys.readouterr().out
        mock_delete.assert_not_called()
        mock_process.assert_not_called()

    def test_startup_creates_resolve_bookmark_and_new_change(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[tuple[str, tuple]] = []
        monkeypatch.setattr(
            "maintenance_man.cli.prune_stale_bookmarks",
            lambda p: calls.append(("prune", (p,))) or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.ensure_main_bookmark",
            lambda p: calls.append(("ensure-main", (p,))) or True,
        )
        monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: True)
        monkeypatch.setattr(
            "maintenance_man.cli.delete_bookmark",
            lambda b, p: calls.append(("delete", (b, p))) or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.create_or_reset_bookmark",
            lambda b, p, r: calls.append(("set", (b, p, r))) or True,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.edit_new_change",
            lambda p, r: calls.append(("new", (p, r))) or True,
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
        assert [name for name, _ in calls[:5]] == [
            "prune",
            "ensure-main",
            "delete",
            "set",
            "new",
        ]
        assert calls[3][1][0] == _RESOLVE_BOOKMARK
        assert calls[3][1][1].name == "vulnerable-project"
        assert calls[3][1][2] == "main"
        assert calls[4][1][0].name == "vulnerable-project"
        assert calls[4][1][1] == _RESOLVE_BOOKMARK


class TestResolveSubmit:
    def test_submit_success_promotes_ready_to_completed(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result: ScanResult = mock_resolve_fresh["scan_result"]

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
            "maintenance_man.cli.push_bookmark_and_create_pr",
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
        mock_resolve_fresh: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result: ScanResult = mock_resolve_fresh["scan_result"]

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
            "maintenance_man.cli.push_bookmark_and_create_pr",
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
    def test_not_on_resolve_bookmark_errors(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.cli.resolve_bookmark_contains_current_change",
            lambda p, b: False,
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
        monkeypatch.setattr(
            "maintenance_man.cli.current_change_has_changes",
            MagicMock(return_value=True),
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
            "maintenance_man.cli.push_bookmark_and_create_pr",
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
        monkeypatch.setattr(updater, "commit_current_change", mock_commit)
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
            MagicMock(return_value=[]),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.push_bookmark_and_create_pr",
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
        mock_move = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)
        monkeypatch.setattr("maintenance_man.cli.create_or_reset_bookmark", mock_move)
        monkeypatch.setattr(
            "maintenance_man.cli.push_bookmark_and_create_pr",
            MagicMock(return_value=(True, "PR #1")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        mock_move.assert_called_once()
        assert mock_move.call_args.args[0] == _RESOLVE_BOOKMARK
        assert mock_move.call_args.args[1].name == "vulnerable-project"
        assert mock_move.call_args.args[2] == "@-"
        assert blocker.update_status == UpdateStatus.COMPLETED
        assert blocker.flow is None

    def test_continue_bookmark_move_failure_does_not_save_ready_state(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        saved: list[ScanResult] = []
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (True, None)
        )
        monkeypatch.setattr(
            "maintenance_man.cli.create_or_reset_bookmark",
            MagicMock(return_value=False),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.save_scan_results",
            lambda name, d, sr: saved.append(deepcopy(sr)),
        )

        scan_result: ScanResult = mock_resolve_cli_deps["scan_result"]
        blocker = scan_result.vulnerabilities[0]
        scan_result.updates = []

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 1
        assert saved
        assert saved[-1].vulnerabilities[0].update_status == UpdateStatus.FAILED
        assert saved[-1].vulnerabilities[0].flow == Workflow.RESOLVE
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
        monkeypatch.setattr(
            "maintenance_man.cli.push_bookmark_and_create_pr",
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
        """A commit-phase failure can become READY when the bookmark is clean
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
            "maintenance_man.cli.push_bookmark_and_create_pr",
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
        monkeypatch.setattr(
            "maintenance_man.cli.push_bookmark_and_create_pr", mock_push
        )
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


@pytest.fixture()
def gradle_resolve_cli(mm_home_with_gradle, monkeypatch):
    spies = {"tests": [], "pushes": [], "bookmarks": []}
    for name in ("check_gh_available", "check_jj_available"):
        monkeypatch.setattr(f"maintenance_man.cli.{name}", lambda: None)
    for name in (
        "prune_stale_bookmarks",
        "ensure_main_bookmark",
        "bookmark_exists",
        "delete_bookmark",
        "edit_new_change",
    ):
        monkeypatch.setattr(f"maintenance_man.cli.{name}", lambda *args: True)
    monkeypatch.setattr(
        "maintenance_man.cli.resolve_bookmark_contains_current_change",
        lambda *args: True,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.current_change_has_changes", lambda *args: False
    )
    monkeypatch.setattr(
        "maintenance_man.cli.run_test_phases",
        lambda *args: (spies["tests"].append(1), (True, None))[1],
    )
    monkeypatch.setattr(
        "maintenance_man.cli.create_or_reset_bookmark",
        lambda b, *args: spies["bookmarks"].append(b) or True,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.push_bookmark_and_create_pr",
        lambda p, b: (spies["pushes"].append(b), (True, ""))[1],
    )
    return spies


def _gradle_state(monkeypatch, **overrides):
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(
                pkg_name="room",
                installed_version="2.8.4",
                latest_version="2.8.5",
                gradle_target=make_gradle_target(),
                update_status=UpdateStatus.FAILED,
                failed_phase="unit",
                flow=Workflow.RESOLVE,
                **overrides,
            )
        ],
    )
    monkeypatch.setattr("maintenance_man.cli.load_scan_results", lambda *args: scan)
    monkeypatch.setattr("maintenance_man.cli.save_scan_results", lambda *args: None)
    return scan


def _repair(gradle_project):
    catalogue = Path(gradle_project.path) / "gradle/libs.versions.toml"
    catalogue.write_text(
        catalogue.read_text().replace('room = "2.8.4"', 'room = "2.8.5"')
    )


def _resolve_code(*args):
    with pytest.raises(SystemExit) as exc:
        app(["resolve", "android", *args])
    return exc.value.code


def test_continue_promotes_verified_manual_repair(
    gradle_resolve_cli, gradle_project, monkeypatch
):
    scan = _gradle_state(monkeypatch)
    _repair(gradle_project)
    set_maven_dates(monkeypatch, undated=set())
    assert _resolve_code("--continue") == 0
    assert gradle_resolve_cli["tests"] == [1]
    assert gradle_resolve_cli["pushes"] == [_RESOLVE_BOOKMARK]
    assert scan.updates == []


@pytest.mark.parametrize(
    "repair,undated,fragment",
    [
        (False, set(), "expected 2.8.5"),
        (True, {"androidx.room:room-testing"}, "no Maven Central publication date"),
    ],
)
def test_continue_blocks_then_verifies_intended_repair(
    gradle_resolve_cli, gradle_project, monkeypatch, capsys, repair, undated, fragment
):
    scan = _gradle_state(monkeypatch)
    if repair:
        _repair(gradle_project)
    set_maven_dates(monkeypatch, undated=undated)
    assert _resolve_code("--continue") == 4
    assert gradle_resolve_cli["tests"] == []
    assert gradle_resolve_cli["pushes"] == []
    finding = scan.updates[0]
    assert finding.update_status == UpdateStatus.FAILED
    assert finding.failed_phase == "unit"
    assert finding.blocked_reason is not None
    assert fragment in finding.blocked_reason
    assert fragment in capsys.readouterr().out
    if not repair:
        _repair(gradle_project)
    set_maven_dates(monkeypatch, undated=set())
    assert _resolve_code("--continue") == 0
    assert finding.blocked_reason is None
    assert finding.gradle_block_kind is None
    assert gradle_resolve_cli["tests"] == [1]


@pytest.mark.parametrize(
    "status,target",
    [
        (UpdateStatus.FAILED, None),
        (UpdateStatus.FAILED, make_gradle_target(members=[])),
        (UpdateStatus.READY, None),
        (UpdateStatus.READY, make_gradle_target(members=[])),
    ],
)
def test_invalid_recorded_progress_never_tests_or_submits(
    gradle_resolve_cli, gradle_project, monkeypatch, status, target
):
    scan = _gradle_state(monkeypatch)
    scan.updates[0].update_status = status
    scan.updates[0].gradle_target = target
    _repair(gradle_project)
    set_maven_dates(monkeypatch, undated=set())
    assert (
        _resolve_code(*(["--continue"] if status == UpdateStatus.FAILED else [])) == 4
    )
    assert gradle_resolve_cli["tests"] == []
    assert gradle_resolve_cli["pushes"] == []
    assert scan.updates[0].update_status == status
    assert scan.updates[0].gradle_block_kind == "stale"


@pytest.mark.parametrize(
    "change",
    [
        "target",
        "members",
        "status",
        "flow",
        "phase",
        "latest",
        "structural",
        "malformed_ready",
        "missing_ready",
    ],
)
def test_recovery_rejects_entire_inconsistent_group(
    gradle_resolve_cli, gradle_project, monkeypatch, change
):
    scan = _gradle_state(monkeypatch)
    sibling = scan.updates[0].model_copy(deep=True)
    if change == "target":
        assert sibling.gradle_target is not None
        sibling.gradle_target.target_version = "2.9.0"
        sibling.latest_version = "2.9.0"
    elif change == "members":
        assert sibling.gradle_target is not None
        sibling.gradle_target.members.pop()
    elif change == "status":
        sibling.update_status = UpdateStatus.READY
    elif change == "flow":
        sibling.flow = None
    elif change == "phase":
        sibling.failed_phase = "integration"
    elif change == "latest":
        sibling.latest_version = "2.9.0"
    elif change == "missing_ready":
        sibling.gradle_target = None
        sibling.update_status = UpdateStatus.READY
    elif change == "malformed_ready":
        sibling.gradle_target = make_gradle_target(members=[])
        sibling.update_status = UpdateStatus.READY
    else:
        sibling.gradle_block_kind = "mapping"
        sibling.blocked_reason = None
    scan.updates.append(sibling)
    _repair(gradle_project)
    set_maven_dates(monkeypatch, undated=set())
    assert _resolve_code("--continue") == 4
    assert gradle_resolve_cli["tests"] == []
    assert gradle_resolve_cli["pushes"] == []
    assert scan.updates[0].update_status == UpdateStatus.FAILED
    assert sibling.blocked_reason


def test_ready_submission_rejects_remaining_block(gradle_resolve_cli, monkeypatch):
    scan = _gradle_state(monkeypatch)
    scan.updates[0].update_status = UpdateStatus.READY
    scan.updates.append(
        make_update(
            pkg_name="ksp",
            blocked_reason="no catalogue mapping",
            gradle_block_kind="mapping",
        )
    )
    set_maven_dates(monkeypatch, undated=set())
    assert _resolve_code() == 4
    assert gradle_resolve_cli["pushes"] == []
    assert scan.updates[0].update_status == UpdateStatus.READY


def test_nonactionable_raw_vulnerability_blocks_before_resolve_bookmark(
    gradle_resolve_cli, monkeypatch
):
    scan = _gradle_state(monkeypatch)
    scan.updates = []
    scan.vulnerabilities = [make_vuln(fixed_version=None)]
    assert _resolve_code() == 4
    assert gradle_resolve_cli["bookmarks"] == []
    assert gradle_resolve_cli["tests"] == []
    assert scan.vulnerabilities[0].gradle_block_kind == "stale"


def _uv_project() -> ProjectConfig:
    return ProjectConfig(path=Path("/tmp/fake"), package_manager="uv")


def test_submission_guard_preserves_ready_state(
    gradle_resolve_cli, gradle_project, monkeypatch, tmp_path
):
    from maintenance_man.cli import _submit_resolve_bookmark

    scan = _gradle_state(monkeypatch)
    ready = scan.updates[0]
    ready.update_status = UpdateStatus.READY
    scan.vulnerabilities = [
        make_vuln(
            fixed_version=None, blocked_reason="no mapping", gradle_block_kind="mapping"
        )
    ]
    assert (
        _submit_resolve_bookmark(
            "android", gradle_project.path, tmp_path, scan, [ready]
        )
        == 4
    )
    assert gradle_resolve_cli["pushes"] == []
    assert ready.update_status == UpdateStatus.READY
    assert ready.failed_phase == "unit"


@pytest.mark.parametrize("kind", ["mapping", "conflict"])
def test_missing_reason_does_not_clear_structural_block(
    gradle_resolve_cli, monkeypatch, kind
):
    scan = _gradle_state(monkeypatch)
    scan.updates[0].gradle_target = None
    scan.updates[0].gradle_block_kind = kind
    scan.updates[0].blocked_reason = None
    assert _resolve_code("--continue") == 4
    assert scan.updates[0].gradle_block_kind == kind
    assert scan.updates[0].blocked_reason
    assert gradle_resolve_cli["tests"] == []


def test_verified_cross_kind_repair_promotes_every_original_once(
    gradle_resolve_cli, gradle_project, monkeypatch
):
    scan = _gradle_state(monkeypatch)
    vuln = make_vuln(
        pkg_name="androidx.room:room-runtime",
        installed_version="2.8.4",
        fixed_version="2.8.5",
        gradle_target=make_gradle_target(),
        update_status=UpdateStatus.FAILED,
        failed_phase="unit",
        flow=Workflow.RESOLVE,
    )
    scan.vulnerabilities.append(vuln)
    _repair(gradle_project)
    set_maven_dates(monkeypatch, undated=set())
    assert _resolve_code("--continue") == 0
    assert gradle_resolve_cli["tests"] == [1]
    assert gradle_resolve_cli["pushes"] == [_RESOLVE_BOOKMARK]
    assert scan.vulnerabilities == []
    assert scan.updates == []
    assert vuln.update_status == UpdateStatus.COMPLETED


@pytest.mark.parametrize("malformed", [True, False])
def test_automatic_resolve_blocks_every_recorded_cross_kind_sibling(
    gradle_resolve_cli, gradle_project, monkeypatch, malformed
):
    scan = _gradle_state(monkeypatch)
    scan.updates[0].update_status = None
    scan.updates[0].flow = None
    scan.updates[0].failed_phase = None
    scan.vulnerabilities = [
        make_vuln(
            pkg_name="androidx.room:room-runtime"
            if malformed
            else "org.example:transitive",
            installed_version="2.8.4",
            fixed_version="2.8.5",
            gradle_target=make_gradle_target(members=[])
            if malformed
            else make_gradle_target(),
        )
    ]
    effects = {"apply": [], "tests": [], "commits": []}
    monkeypatch.setattr(
        "maintenance_man.updater.apply_gradle_update",
        lambda *args: effects["apply"].append(1),
    )
    monkeypatch.setattr(
        "maintenance_man.updater.run_test_phases",
        lambda *args: (effects["tests"].append(1), (True, None))[1],
    )
    monkeypatch.setattr(
        "maintenance_man.updater.commit_current_change",
        lambda *args: effects["commits"].append(1) or True,
    )
    monkeypatch.setattr(
        "maintenance_man.updater.current_change_has_changes", lambda *args: True
    )
    monkeypatch.setattr(
        "maintenance_man.updater.create_or_reset_bookmark", lambda *args: True
    )
    set_maven_dates(monkeypatch, undated=set())

    assert _resolve_code() == 4
    assert effects == {"apply": [], "tests": [], "commits": []}
    assert gradle_resolve_cli["bookmarks"] == []
    assert gradle_resolve_cli["pushes"] == []
    for finding in (*scan.vulnerabilities, *scan.updates):
        assert finding.blocked_reason
        assert finding.gradle_block_kind == ("stale" if malformed else "mapping")
        assert finding.update_status is None

    assert _resolve_code() == 4
    assert effects == {"apply": [], "tests": [], "commits": []}
    assert all(
        finding.blocked_reason for finding in (*scan.vulnerabilities, *scan.updates)
    )


def test_nonactionable_recorded_vulnerability_blocks_its_update_sibling(
    gradle_resolve_cli, monkeypatch
):
    scan = _gradle_state(monkeypatch)
    _clear_resolve_progress(scan)
    scan.vulnerabilities = [
        make_vuln(
            pkg_name="androidx.room:room-runtime",
            installed_version="2.8.4",
            fixed_version=None,
            gradle_target=make_gradle_target(),
        )
    ]
    assert _resolve_code() == 4
    assert gradle_resolve_cli["tests"] == []
    assert gradle_resolve_cli["bookmarks"] == []
    for finding in (*scan.vulnerabilities, *scan.updates):
        assert finding.gradle_block_kind == "mapping"
        assert finding.blocked_reason


@pytest.mark.parametrize(
    "fixture", ["updates-conflict.toml", "updates-incomplete.toml"]
)
def test_automatic_resolve_real_discovery_conflict_never_applies_or_finalizes(
    gradle_resolve_cli, gradle_project, monkeypatch, fixture
):
    import subprocess

    from maintenance_man.gradle import (
        GRADLE_UPDATE_REPORT_RELPATH,
        discover_gradle_updates,
    )
    from tests.conftest import GRADLE_FIXTURES

    def run(cmd, **kwargs):
        assert cmd[1] == "versionCatalogUpdate"
        (Path(kwargs["cwd"]) / GRADLE_UPDATE_REPORT_RELPATH).write_bytes(
            (GRADLE_FIXTURES / fixture).read_bytes()
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    scan = _gradle_state(monkeypatch)
    scan.updates = discover_gradle_updates(gradle_project)
    scan.vulnerabilities = [
        make_vuln(
            pkg_name="androidx.room:room-runtime",
            installed_version="2.8.4",
            fixed_version="2.8.5",
            gradle_target=make_gradle_target(),
        )
    ]
    effects = []
    monkeypatch.setattr(
        "maintenance_man.updater.current_change_has_changes", lambda *args: True
    )
    for name in (
        "apply_gradle_update",
        "commit_current_change",
        "create_or_reset_bookmark",
    ):
        monkeypatch.setattr(
            f"maintenance_man.updater.{name}",
            lambda *args: effects.append(args) or True,
        )
    monkeypatch.setattr(
        "maintenance_man.updater.run_test_phases",
        lambda *args: (effects.append(args), (True, None))[1],
    )
    set_maven_dates(monkeypatch, undated=set())
    for _ in range(2):
        assert _resolve_code() == 4
        assert effects == []
        assert gradle_resolve_cli == {"tests": [], "pushes": [], "bookmarks": []}
        assert all(
            f.gradle_block_kind == "conflict"
            for f in (*scan.vulnerabilities, *scan.updates)
        )


@pytest.mark.parametrize("outputs", [True, False])
def test_continue_reclaims_interrupted_owned_outputs_before_revision_checks(
    gradle_resolve_cli, gradle_project, monkeypatch, outputs
):
    import subprocess

    from maintenance_man.gradle import (
        GRADLE_INVENTORY_MARKER_RELPATH,
        GRADLE_INVENTORY_RELPATH,
        GRADLE_REPORT_MARKER_RELPATH,
        GRADLE_UPDATE_REPORT_RELPATH,
    )

    _gradle_state(monkeypatch)
    _repair(gradle_project)
    set_maven_dates(monkeypatch, undated=set())
    root = Path(gradle_project.path)
    report = root / GRADLE_UPDATE_REPORT_RELPATH
    marker = root / GRADLE_REPORT_MARKER_RELPATH
    inventory = root / GRADLE_INVENTORY_RELPATH
    marker.write_bytes(b"")
    inventory.mkdir()
    (root / GRADLE_INVENTORY_MARKER_RELPATH).write_bytes(b"")
    if outputs:
        report.write_bytes(b"interrupted generated report\n")
        (inventory / "bom.json").write_bytes(b"interrupted generated inventory\n")
    checks = []

    def ancestry(*args):
        assert not report.exists()
        assert not marker.exists()
        assert not inventory.exists()
        checks.append("ancestry")
        return True

    def dirty(*args):
        assert not report.exists() and not marker.exists() and not inventory.exists()
        checks.append("dirty")
        return False

    def forbidden(*args, **kwargs):
        pytest.fail("continuation must not launch Gradle or VCS subprocesses")

    monkeypatch.setattr(
        "maintenance_man.cli.resolve_bookmark_contains_current_change", ancestry
    )
    monkeypatch.setattr("maintenance_man.cli.current_change_has_changes", dirty)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr("maintenance_man.updater.apply_gradle_update", forbidden)
    assert _resolve_code("--continue") == 0
    assert checks == ["ancestry", "dirty"]
    assert gradle_resolve_cli["tests"] == [1]
    assert gradle_resolve_cli["pushes"] == [_RESOLVE_BOOKMARK]


@pytest.mark.parametrize(
    "collision",
    [
        "report",
        "report-symlink",
        "report-marker-symlink",
        "report-marker-directory",
        "inventory",
        "inventory-symlink",
        "inventory-marker-symlink",
        "report-parent-symlink",
    ],
)
def test_continue_refuses_caller_outputs_before_revision_or_test_checks(
    gradle_resolve_cli, gradle_project, monkeypatch, tmp_path, collision
):
    import subprocess

    from maintenance_man.gradle import (
        GRADLE_INVENTORY_RELPATH,
        GRADLE_REPORT_MARKER_RELPATH,
        GRADLE_UPDATE_REPORT_RELPATH,
    )

    _gradle_state(monkeypatch)
    root = Path(gradle_project.path)
    report = root / GRADLE_UPDATE_REPORT_RELPATH
    marker = root / GRADLE_REPORT_MARKER_RELPATH
    inventory = root / GRADLE_INVENTORY_RELPATH
    caller = tmp_path / "caller-bytes"
    caller.write_bytes(b"caller bytes")
    if collision == "report":
        report.write_bytes(b"caller report")
    elif collision == "report-symlink":
        report.symlink_to(caller)
        marker.write_bytes(b"")
    elif collision == "report-marker-symlink":
        marker.symlink_to(caller)
    elif collision == "report-marker-directory":
        marker.mkdir()
    elif collision == "inventory":
        inventory.mkdir()
        (inventory / "caller.json").write_bytes(b"caller inventory")
    elif collision == "inventory-symlink":
        inventory.symlink_to(tmp_path, target_is_directory=True)
    elif collision == "inventory-marker-symlink":
        inventory.mkdir()
        (inventory / ".mm-owned").symlink_to(caller)
    else:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "libs.versions.updates.toml").write_bytes(b"outside report")
        (outside / ".mm-owned-report").write_bytes(b"")
        root = tmp_path / "project-with-symlink-parent"
        root.mkdir()
        (root / "gradle").symlink_to(outside, target_is_directory=True)
        from maintenance_man import config as mm_config

        config_path = mm_config.MM_HOME / "config.toml"
        config_path.write_text(
            config_path.read_text().replace(str(gradle_project.path), str(root))
        )

    def forbidden(*args, **kwargs):
        pytest.fail("collision must refuse before revision, tests or subprocesses")

    monkeypatch.setattr(
        "maintenance_man.cli.resolve_bookmark_contains_current_change", forbidden
    )
    monkeypatch.setattr("maintenance_man.cli.current_change_has_changes", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert _resolve_code("--continue") == 1
    assert caller.read_bytes() == b"caller bytes"
    assert gradle_resolve_cli == {"tests": [], "pushes": [], "bookmarks": []}
    if collision == "report":
        assert report.read_bytes() == b"caller report"
    elif collision == "inventory":
        assert (inventory / "caller.json").read_bytes() == b"caller inventory"
    elif collision == "report-parent-symlink":
        assert (
            outside / "libs.versions.updates.toml"
        ).read_bytes() == b"outside report"
        assert (outside / ".mm-owned-report").exists()
        assert (root / "gradle").is_symlink()
    else:
        preserved = (
            report
            if collision == "report-symlink"
            else inventory
            if collision == "inventory-symlink"
            else inventory / ".mm-owned"
            if collision == "inventory-marker-symlink"
            else marker
        )
        assert preserved.exists()


def test_continue_reclaims_outputs_but_still_refuses_uncommitted_manual_change(
    gradle_resolve_cli, gradle_project, monkeypatch, capsys
):
    from maintenance_man.gradle import (
        GRADLE_REPORT_MARKER_RELPATH,
        GRADLE_UPDATE_REPORT_RELPATH,
    )

    _gradle_state(monkeypatch)
    root = Path(gradle_project.path)
    report = root / GRADLE_UPDATE_REPORT_RELPATH
    report.write_bytes(b"generated report")
    (root / GRADLE_REPORT_MARKER_RELPATH).write_bytes(b"")

    def dirty(*args):
        assert not report.exists()
        return True

    monkeypatch.setattr("maintenance_man.cli.current_change_has_changes", dirty)
    assert _resolve_code("--continue") == 1
    assert "manual changes first" in " ".join(capsys.readouterr().out.split())
    assert gradle_resolve_cli == {"tests": [], "pushes": [], "bookmarks": []}


@pytest.mark.parametrize("artifact", ["report", "inventory"])
def test_continue_cleanup_failure_refuses_with_actionable_error(
    gradle_resolve_cli, gradle_project, monkeypatch, capsys, artifact
):
    from maintenance_man.gradle import (
        GRADLE_INVENTORY_MARKER_RELPATH,
        GRADLE_INVENTORY_RELPATH,
        GRADLE_REPORT_MARKER_RELPATH,
        GRADLE_UPDATE_REPORT_RELPATH,
    )

    _gradle_state(monkeypatch)
    root = Path(gradle_project.path)
    if artifact == "report":
        report = root / GRADLE_UPDATE_REPORT_RELPATH
        report.write_bytes(b"generated report")
        (root / GRADLE_REPORT_MARKER_RELPATH).write_bytes(b"")
        unlink = Path.unlink

        def fail(path, *args, **kwargs):
            if path == report:
                raise PermissionError("cannot remove report")
            return unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail)
    else:
        (root / GRADLE_INVENTORY_RELPATH).mkdir()
        (root / GRADLE_INVENTORY_MARKER_RELPATH).write_bytes(b"")

        def fail(*args, **kwargs):
            raise PermissionError("cannot remove inventory")

        monkeypatch.setattr("maintenance_man.gradle.shutil.rmtree", fail)

    def forbidden(*args):
        pytest.fail("cleanup failure must precede revision checks")

    monkeypatch.setattr(
        "maintenance_man.cli.resolve_bookmark_contains_current_change", forbidden
    )
    monkeypatch.setattr("maintenance_man.cli.current_change_has_changes", forbidden)
    assert _resolve_code("--continue") == 1
    assert "Could not reclaim interrupted Gradle outputs" in capsys.readouterr().out
    assert gradle_resolve_cli == {"tests": [], "pushes": [], "bookmarks": []}


@pytest.mark.parametrize("malformed_first", [False, True])
def test_automatic_resolve_known_inline_malformed_sibling_has_no_effects_on_retry(
    gradle_resolve_cli, gradle_project, monkeypatch, malformed_first
):
    import subprocess

    from tests.test_updater import _actual_inline_sibling_scan

    scan = _actual_inline_sibling_scan(gradle_project, malformed_first=malformed_first)
    scan.updates = [
        u for u in scan.updates if u.pkg_name == "com.google.code.gson:gson"
    ]
    monkeypatch.setattr("maintenance_man.cli.load_scan_results", lambda *args: scan)
    monkeypatch.setattr("maintenance_man.cli.save_scan_results", lambda *args: None)
    effects = []
    for name in (
        "apply_gradle_update",
        "commit_current_change",
        "create_or_reset_bookmark",
    ):
        monkeypatch.setattr(
            f"maintenance_man.updater.{name}",
            lambda *args: effects.append(args) or True,
        )
    monkeypatch.setattr(
        "maintenance_man.updater.current_change_has_changes", lambda *args: True
    )
    monkeypatch.setattr(
        "maintenance_man.updater.run_test_phases",
        lambda *args: (effects.append(args), (True, None))[1],
    )
    monkeypatch.setattr(
        "maintenance_man.updater.discard_current_change",
        lambda *args: effects.append(args),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail(
            "all blocked resolve must not launch a subprocess"
        ),
    )
    set_maven_dates(monkeypatch, undated=set())
    for _ in range(2):
        assert _resolve_code() == 4
        assert effects == []
        assert gradle_resolve_cli == {"tests": [], "pushes": [], "bookmarks": []}
        assert all(
            f.gradle_block_kind == "stale"
            for f in (*scan.vulnerabilities, *scan.updates)
        )


@pytest.mark.parametrize("reverse", [False, True])
def test_vulnerability_only_continue_blocks_mixed_shared_history_before_evidence(
    gradle_resolve_cli, gradle_project, monkeypatch, reverse
):
    scan = _gradle_state(monkeypatch)
    target = make_gradle_target()
    target.members[1].installed_version = "9.9.9"
    if reverse:
        target.members.reverse()
    vuln = make_vuln(
        pkg_name="androidx.room:room-runtime",
        installed_version="2.8.4",
        fixed_version="2.8.5",
        gradle_target=target,
        update_status=UpdateStatus.FAILED,
        failed_phase="unit",
        flow=Workflow.RESOLVE,
    )
    scan.vulnerabilities = [vuln]
    scan.updates = []
    _repair(gradle_project)

    def forbidden(*args, **kwargs):
        pytest.fail("mixed recorded history must block before publication or apply")

    monkeypatch.setattr(
        "maintenance_man.dependency_age._get_maven_publish_date", forbidden
    )
    monkeypatch.setattr("maintenance_man.updater.apply_gradle_update", forbidden)
    assert _resolve_code("--continue") == 4
    assert gradle_resolve_cli == {"tests": [], "pushes": [], "bookmarks": []}
    assert vuln.gradle_block_kind == "stale"
    assert vuln.update_status == UpdateStatus.FAILED
    assert vuln.failed_phase == "unit"
    assert vuln.flow == Workflow.RESOLVE


@pytest.mark.parametrize("reverse", [False, True])
def test_vulnerability_only_same_shared_history_recovers_intended_manual_repair(
    gradle_resolve_cli, gradle_project, monkeypatch, reverse
):
    scan = _gradle_state(monkeypatch)
    target = make_gradle_target()
    if reverse:
        target.members.reverse()
    vuln = make_vuln(
        pkg_name="androidx.room:room-runtime",
        installed_version="2.8.4",
        fixed_version="2.8.5",
        gradle_target=target,
        update_status=UpdateStatus.FAILED,
        failed_phase="unit",
        flow=Workflow.RESOLVE,
        gradle_block_kind="stale",
        blocked_reason="intended repair awaiting verification",
    )
    scan.vulnerabilities = [vuln]
    scan.updates = []
    _repair(gradle_project)
    set_maven_dates(monkeypatch, undated=set())
    monkeypatch.setattr(
        "maintenance_man.updater.apply_gradle_update",
        lambda *args: pytest.fail("manual recovery must not reapply"),
    )
    assert _resolve_code("--continue") == 0
    assert gradle_resolve_cli["tests"] == [1]
    assert gradle_resolve_cli["pushes"] == [_RESOLVE_BOOKMARK]
    assert vuln.update_status == UpdateStatus.COMPLETED
    assert vuln.failed_phase is None
    assert vuln.flow is None
    assert vuln.blocked_reason is None
    assert vuln.gradle_block_kind is None
