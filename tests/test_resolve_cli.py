from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import ExitCode
from maintenance_man.models.scan import (
    ScanResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.storage import load_scan_results
from maintenance_man.vcs import JjRepository
from tests.fakes import FakeFindingProcessor
from tests.support.cli import CliDeps, run_mm
from tests.support.findings import (
    make_update,
    make_vuln,
)
from tests.support.repository import commit_file, remote_bookmark_target

_RESOLVE_BOOKMARK = "mm/resolve-dependencies"


def _clear_resolve_progress(scan_result: ScanResult) -> None:
    for f in (*scan_result.vulnerabilities, *scan_result.updates):
        f.update_status = None
        f.failed_phase = None
        f.flow = None


def _commit_repair(deps: CliDeps) -> None:
    repo = JjRepository(deps.project_paths["vulnerable"])
    commit_file(repo, "dep.txt", "repaired\n", "repair")


@pytest.fixture()
def mock_resolve_fresh(mock_resolve_cli_deps: CliDeps) -> CliDeps:
    """mock_resolve_cli_deps with all resolve progress cleared."""
    _clear_resolve_progress(mock_resolve_cli_deps.scan_result)
    mock_resolve_cli_deps.save_scan()
    return mock_resolve_cli_deps


class TestResolveFlow:
    def test_existing_ready_resolve_progress_promotes_without_reapplying(
        self,
        mock_resolve_cli_deps: CliDeps,
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
        path = mock_resolve_cli_deps.project_paths["vulnerable"]
        repo = JjRepository(path)
        resolve_tip = commit_file(repo, "resolved.txt", "resolved\n", "fix: resolved")
        repo.set_bookmark(bookmark=_RESOLVE_BOOKMARK, revision="@-")
        origin_main = repo.resolve_revision(revision="main@origin")

        assert run_mm("resolve", "vulnerable") == 0
        assert repo.resolve_revision(revision="main") == resolve_tip
        assert not (path / "mm-fixture-pkg-a.txt").exists()
        assert remote_bookmark_target(repo, "main") == origin_main


def test_given_failed_resolve_when_run_then_exits_four_with_continuation(
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
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        JjRepository(mock_resolve_cli_deps.project_paths["vulnerable"]).delete_bookmark(
            bookmark=_RESOLVE_BOOKMARK
        )

        assert run_mm("resolve", "vulnerable", "--continue") == 1

    @pytest.mark.parametrize("failed_phase", ["apply", "unit"])
    def test_committed_manual_repair_continues_without_apply_or_auto_commit(
        self,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        failed_phase: str,
    ) -> None:
        from maintenance_man import updater

        scan_result: ScanResult = mock_resolve_cli_deps.scan_result
        scan_result.updates = []
        scan_result.vulnerabilities = [
            make_vuln(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase=failed_phase,
            )
        ]
        mock_resolve_cli_deps.save_scan()
        repo = JjRepository(mock_resolve_cli_deps.project_paths["vulnerable"])
        manual_tip = commit_file(repo, "dep.txt", "manual repair\n", "manual repair")
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
        assert repo.resolve_revision(revision="main") == manual_tip
        saved = load_scan_results("vulnerable")
        assert not saved.findings

    def test_continue_promoted_finding_not_reselected(
        self,
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
        _commit_repair(mock_resolve_cli_deps)

        assert run_mm("resolve", "vulnerable", "--continue") == 0

        passed_findings = mock_process.call_args.args[0]
        assert "some-pkg" not in {f.pkg_name for f in passed_findings}

    def test_continue_commit_phase_failure_can_become_ready(
        self,
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
        _commit_repair(mock_resolve_cli_deps)

        monkeypatch.setattr(
            "maintenance_man.services.resolve.process_findings",
            MagicMock(return_value=[]),
        )

        assert run_mm("resolve", "vulnerable", "--continue") == 0
        saved = load_scan_results("vulnerable")
        assert saved.vulnerabilities == []

    def test_continue_with_no_failed_blockers_refuses(
        self,
        mock_resolve_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
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

        assert run_mm("resolve", "vulnerable", "--continue") == ExitCode.ERROR
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [
            "error: No paused resolve failure is saved for vulnerable. "
            "Run mm resolve vulnerable to start resolving."
        ]
        mock_tests.assert_not_called()


class TestResolveCliSurface:
    def test_requires_project_arg(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("resolve") == 1

    def test_unknown_project_exits_1(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("resolve", "missing") == 1
