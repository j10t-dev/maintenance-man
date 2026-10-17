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
from maintenance_man.vcs import RevisionError
from tests.conftest import (
    CliDeps,
    make_gradle_target,
    make_scan_result,
    make_update,
    make_vuln,
    run_mm,
)
from tests.fakes import FakeFindingProcessor

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
    def test_existing_ready_resolve_progress_preserves_bookmark_and_submits(
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
        state.clear_calls()

        assert run_mm("resolve", "vulnerable") == 0
        assert not any(
            call.method in {"delete_bookmark", "create_bookmark", "new_change"}
            for call in state.effects
        )
        assert state.code_host(
            mock_resolve_cli_deps.project_paths["vulnerable"]
        ).effects


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
    assert capsys.readouterr().out.splitlines() == [
        "Error: resolve already paused for vulnerable — rerun with --continue"
    ]


class TestResolveSubmit:
    def test_push_failure_never_calls_host_and_retains_ready_state(
        self,
        mm_home_with_projects: Path,
        mock_resolve_fresh: CliDeps,
    ) -> None:
        path = mock_resolve_fresh.project_paths["vulnerable"]
        state = mock_resolve_fresh.vcs_state
        state.fail(
            "push_bookmark",
            error=RevisionError("push rejected"),
            path=path,
        )
        host = state.code_host(path)

        assert run_mm("resolve", "vulnerable") == ExitCode.UPDATE_FAILED
        assert not any(call.method == "create_pr" for call in host.attempts)
        saved = load_scan_results("vulnerable")
        assert all(
            finding.update_status == UpdateStatus.READY for finding in saved.findings
        )


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
        assert state.remote_bookmark_targets(path, bookmark=_RESOLVE_BOOKMARK) == (
            manual_tip,
        )
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
        host = mock_resolve_cli_deps.vcs_state.code_host(
            mock_resolve_cli_deps.project_paths["vulnerable"]
        )
        assert sum(call.method == "create_pr" for call in host.attempts) == 1


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
    monkeypatch.setattr("maintenance_man.gradle.run_logged", forbidden)
    args = ["resolve", "android"] + (["--continue"] if continue_ else [])
    assert run_mm(*args) == 4
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

    def forbidden(*args, **kwargs):
        pytest.fail("no ledger")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr("maintenance_man.gradle.run_logged", forbidden)
    assert run_mm("resolve", "android", "--continue") == 4
    assert report.read_bytes() == b"preserved output"
    assert marker.exists() is owned
