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
from tests.support.findings import make_vuln
from tests.support.repository import commit_file

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

    @pytest.mark.parametrize("failed_phase", ["apply", "unit", "commit"])
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
