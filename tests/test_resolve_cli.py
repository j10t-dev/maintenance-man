from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import ExitCode
from maintenance_man.models.scan import (
    ScanResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.storage import load_scan_results
from tests.fakes import FakeFindingProcessor
from tests.support.cli import CliDeps, run_mm
from tests.support.findings import (
    make_update,
    make_vuln,
)

_RESOLVE_BOOKMARK = "mm/resolve-dependencies"


def _clear_resolve_progress(scan_result: ScanResult) -> None:
    for f in (*scan_result.vulnerabilities, *scan_result.updates):
        f.update_status = None
        f.failed_phase = None
        f.flow = None


@pytest.fixture()
def mock_resolve_fresh(mock_resolve_cli_deps: CliDeps) -> CliDeps:
    """mock_resolve_cli_deps with all resolve progress cleared."""
    _clear_resolve_progress(mock_resolve_cli_deps.scan_result)
    mock_resolve_cli_deps.save_scan()
    return mock_resolve_cli_deps


class TestResolveFlow:
    def test_existing_ready_resolve_progress_promotes_without_reapplying(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps.scan_result
        scan_result.vulnerabilities = []
        scan_result.updates = [
            make_update(
                update_status=UpdateStatus.READY,
                flow=Workflow.RESOLVE,
            )
        ]
        mock_resolve_cli_deps.save_scan()
        state = mock_resolve_cli_deps.vcs_state
        repo = state.repository(mock_resolve_cli_deps.project_paths["vulnerable"])
        resolve_tip = repo.resolve_revision(revision=_RESOLVE_BOOKMARK)
        state.clear_calls()

        assert run_mm("resolve", "vulnerable") == 0
        assert not any(
            call.method in {"create_bookmark", "new_change"} for call in state.effects
        )
        assert repo.resolve_revision(revision="main") == resolve_tip
        assert not any(call.method == "push_bookmark" for call in state.attempts)


def test_given_failed_resolve_when_run_then_exits_four_with_continuation(
    mm_home_with_projects: Path,
    mock_resolve_fresh: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "maintenance_man.services.resolve.process_findings",
        FakeFindingProcessor({"some-pkg": (False, "unit")}),
    )
    assert run_mm("resolve", "vulnerable") == ExitCode.UPDATE_FAILED
    assert capsys.readouterr().err.splitlines()[-2:] == [
        "Resolve paused",
        "hint: mm resolve vulnerable --continue",
    ]


def test_given_paused_resolve_when_run_then_exits_one_with_instruction(
    mm_home_with_projects: Path,
    mock_resolve_cli_deps: CliDeps,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_mm("resolve", "vulnerable") == ExitCode.ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "error: resolve already paused for vulnerable — rerun with --continue"
    ]


class TestResolveContinue:
    def test_not_on_resolve_bookmark_errors(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_resolve_cli_deps.vcs_state.seed_bookmark(
            mock_resolve_cli_deps.project_paths["vulnerable"],
            bookmark=_RESOLVE_BOOKMARK,
            targets=(),
        )

        assert run_mm("resolve", "vulnerable", "--continue") == 1

    def test_continue_never_calls_apply_update(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--continue is retest-only: it must not invoke apply_update."""
        from maintenance_man import updater

        mock_apply = MagicMock(return_value=True)
        monkeypatch.setattr(updater, "_apply_update", mock_apply)
        monkeypatch.setattr(
            "maintenance_man.services.resolve.run_test_phases",
            lambda cfg, p, *, emit: None,
        )
        monkeypatch.setattr(
            "maintenance_man.services.resolve.process_findings",
            MagicMock(return_value=[]),
        )

        scan_result: ScanResult = mock_resolve_cli_deps.scan_result
        scan_result.updates = []
        scan_result.vulnerabilities = [
            make_vuln(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="apply",
            )
        ]
        mock_resolve_cli_deps.save_scan()

        assert run_mm("resolve", "vulnerable", "--continue") == 0

        mock_apply.assert_not_called()

    def test_continue_never_creates_auto_commit(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.services.resolve.run_test_phases",
            lambda cfg, p, *, emit: None,
        )
        monkeypatch.setattr(
            "maintenance_man.services.resolve.process_findings",
            MagicMock(return_value=[]),
        )

        scan_result: ScanResult = mock_resolve_cli_deps.scan_result
        scan_result.updates = []
        scan_result.vulnerabilities = [
            make_vuln(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="unit",
            )
        ]
        mock_resolve_cli_deps.save_scan()

        state = mock_resolve_cli_deps.vcs_state
        state.clear_calls()
        assert run_mm("resolve", "vulnerable", "--continue") == 0

        assert not any(call.method == "commit" for call in state.attempts)

    def test_committed_manual_repair_continues_without_apply_or_auto_commit(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from maintenance_man import updater

        scan_result: ScanResult = mock_resolve_cli_deps.scan_result
        scan_result.updates = []
        scan_result.vulnerabilities = [
            make_vuln(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="unit",
            )
        ]
        mock_resolve_cli_deps.save_scan()
        path = mock_resolve_cli_deps.project_paths["vulnerable"]
        repo = mock_resolve_cli_deps.vcs_state.services().repository(path)
        (path / "dep.txt").write_text("manual repair\n", encoding="utf-8")
        repo.commit(message="manual repair")
        manual_tip = repo.resolve_revision(revision="@-")
        state = mock_resolve_cli_deps.vcs_state
        state.clear_calls()
        monkeypatch.setattr(
            "maintenance_man.services.resolve.run_test_phases",
            lambda _cfg, _path, *, emit: None,
        )
        monkeypatch.setattr(
            updater,
            "_apply_update",
            lambda *args: pytest.fail("--continue must not apply a package update"),
        )

        assert run_mm("resolve", "vulnerable", "--continue") == 0
        assert not any(call.method == "commit" for call in state.attempts)
        moved = next(call for call in state.effects if call.method == "set_bookmark")
        assert dict(moved.arguments)["revision"] == "@-"
        assert repo.resolve_revision(revision="main") == manual_tip
        saved = load_scan_results("vulnerable")
        assert not saved.findings

    def test_continue_promoted_finding_not_reselected(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.services.resolve.run_test_phases",
            lambda cfg, p, *, emit: None,
        )

        mock_process = MagicMock(return_value=[])
        monkeypatch.setattr(
            "maintenance_man.services.resolve.process_findings", mock_process
        )

        assert run_mm("resolve", "vulnerable", "--continue") == 0

        passed_findings = mock_process.call_args.args[0]
        assert "some-pkg" not in {f.pkg_name for f in passed_findings}

    def test_continue_commit_phase_failure_can_become_ready(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A commit-phase failure can become READY when the bookmark is clean
        and tests pass (operator committed the fix manually)."""
        monkeypatch.setattr(
            "maintenance_man.services.resolve.run_test_phases",
            lambda cfg, p, *, emit: None,
        )

        scan_result: ScanResult = mock_resolve_cli_deps.scan_result
        scan_result.updates = []
        blocker = scan_result.vulnerabilities[0]
        blocker.failed_phase = "commit"
        mock_resolve_cli_deps.save_scan()

        monkeypatch.setattr(
            "maintenance_man.services.resolve.process_findings",
            MagicMock(return_value=[]),
        )

        assert run_mm("resolve", "vulnerable", "--continue") == 0
        saved = load_scan_results("vulnerable")
        assert saved.vulnerabilities == []

    def test_continue_with_no_failed_blockers_exits_noop(
        self,
        mm_home_with_projects: Path,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan_result: ScanResult = mock_resolve_cli_deps.scan_result
        for f in (*scan_result.vulnerabilities, *scan_result.updates):
            f.update_status = UpdateStatus.READY
            f.flow = Workflow.RESOLVE
        mock_resolve_cli_deps.save_scan()

        mock_tests = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.services.resolve.run_test_phases", mock_tests
        )
        monkeypatch.setattr(
            "maintenance_man.services.resolve.process_findings",
            MagicMock(return_value=[]),
        )

        assert run_mm("resolve", "vulnerable", "--continue") == 0
        mock_tests.assert_not_called()
        assert not any(
            call.method == "push_bookmark"
            for call in mock_resolve_cli_deps.vcs_state.attempts
        )


class TestResolveCliSurface:
    def test_requires_project_arg(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("resolve") == 1

    def test_unknown_project_exits_1(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("resolve", "missing") == 1
