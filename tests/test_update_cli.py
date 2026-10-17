import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man import cli
from maintenance_man.cli import ExitCode
from maintenance_man.github import CodeHostError
from maintenance_man.models.events import Operation, OperationFailed, Outcome
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    UpdateResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.process import ProcessError
from maintenance_man.services import update as update_service
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs import RevisionError
from tests.conftest import (
    CliDeps,
    completed,
    make_config,
    make_gradle_target,
    make_scan_result,
    make_update,
    make_vuln,
    missing_tool,
    run_mm,
    write_config,
)
from tests.fake_vcs import FakeJjState
from tests.fakes import RecordingEmit


@pytest.mark.parametrize(
    "text,count,expected",
    [
        ("all", 3, "all"),
        (" ALL ", 3, "all"),
        (" ALL ", 2, "all"),
        ("none", 3, "none"),
        ("none", 2, "none"),
        ("Vulns", 3, "vulns"),
        ("VuLnS", 2, "vulns"),
        ("updates", 3, "updates"),
        (" updates ", 2, "updates"),
        ("2,1", 3, (2, 1)),
        ("2,1,2", 2, (2, 1)),
        ("1,1", 3, (1,)),
        ("3", 3, (3,)),
        ("0", 3, None),
        ("0", 2, None),
        ("4", 3, None),
        ("3", 2, None),
        ("", 3, None),
        ("", 2, None),
        ("1,,2", 3, None),
        ("1,", 2, None),
        ("a", 3, None),
        ("1,x", 2, None),
    ],
)
def test_parse_selection(text, count, expected):
    assert cli._parse_selection(text, count) == expected


def _seed_update_bookmark(deps: CliDeps) -> None:
    repo = deps.vcs_state.services().repository(deps.project_paths["vulnerable"])
    repo.set_bookmark(bookmark="mm/update-dependencies", revision="main")


def _use_real_mixed_processor(
    deps: CliDeps,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, MagicMock]:
    from maintenance_man import updater

    scan_result = make_scan_result()
    scan_result.project = "outdated"
    save_scan_results(scan_result.project, scan_result)
    project_path = deps.project_paths["outdated"]
    state = deps.vcs_state
    state.register_files(project_path, "package.json")
    (project_path / "package.json").write_text("{}\n", encoding="utf-8")
    repo = deps.vcs_state.services().repository(project_path)
    repo.commit(message="test: add package manifest")
    repo.set_bookmark(bookmark="main", revision="@-")
    state.clear_calls()

    def run_package(cmd, cwd, **kwargs):
        assert cmd[:2] == ["bun", "add"]
        assert cwd == home / "workspaces" / "outdated"
        current = (cwd / "dep.txt").read_text(encoding="utf-8")
        (cwd / "dep.txt").write_text(f"{current}{cmd[-1]}\n", encoding="utf-8")
        return completed(cmd, returncode=0, stdout="", stderr="")

    package = MagicMock(side_effect=run_package)
    phase = MagicMock(return_value=None)
    monkeypatch.setattr(
        "maintenance_man.services.update.process_findings", updater.process_findings
    )
    monkeypatch.setattr("maintenance_man.updater.run_logged", package)
    monkeypatch.setattr("maintenance_man.updater.run_live", phase)
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
    return package, phase


_COMMAND_FIXTURES = [
    pytest.param("update", "mock_update_cli_deps", id="update"),
    pytest.param("resolve", "mock_resolve_cli_deps", id="resolve"),
]


@pytest.mark.parametrize("command,deps_fixture", _COMMAND_FIXTURES)
class TestSharedCommandPrerequisites:
    @pytest.mark.parametrize("tool", ["gh", "jj"])
    def test_missing_tool_exits_one(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
        monkeypatch: pytest.MonkeyPatch,
        tool: str,
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        deps.vcs_state.clear_calls()
        monkeypatch.setattr(
            "maintenance_man.vcs_workflow.require_tool", missing_tool(tool)
        )

        assert run_mm(command, "vulnerable") == 1
        assert deps.vcs_state.attempts == []

    def test_legacy_finding_without_flow_exits_one_before_processing(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        finding = deps.scan_result.updates[0]
        finding.update_status = UpdateStatus.FAILED
        finding.flow = None
        deps.save_scan()
        deps.vcs_state.clear_calls()

        assert run_mm(command, "vulnerable") == 1
        assert "rescan" in capsys.readouterr().out.lower()
        assert deps.vcs_state.effects == []

    def test_given_code_host_pruning_failure_when_run_then_exits_one(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        project_path = deps.project_paths["vulnerable"]
        deps.vcs_state.code_host(project_path).fail(
            "pr_bookmarks", error=CodeHostError("host unavailable")
        )

        assert run_mm(command, "vulnerable") == 1
        assert not any(call.method == "commit" for call in deps.vcs_state.attempts)


def test_batch_reports_bookmark_access_error_without_requesting_rescan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from maintenance_man.models.config import ProjectConfig

    scan = make_scan_result(
        vulns=[],
        updates=[make_update(update_status=UpdateStatus.FAILED, flow=Workflow.UPDATE)],
    )
    from maintenance_man.storage import save_scan_results
    from maintenance_man.vcs import RevisionError

    save_scan_results("example", scan)
    project = ProjectConfig(path=tmp_path, package_manager="bun", test_unit="bun test")
    state = FakeJjState()
    state.seed_repository(tmp_path, files={"dep.txt": "version=1\n"})
    state.fail(
        "bookmark_exists",
        error=RevisionError("permission denied"),
        path=tmp_path,
    )
    emit = RecordingEmit()
    result = update_service.update_projects(
        make_config(projects={"example": project}),
        ["example"],
        vcs=state.services(),
        emit=emit,
    )
    assert result.had_errors is True
    assert emit.events[-1] == OperationFailed(
        Operation.UPDATE_SETUP, "example", "permission denied"
    )


@pytest.mark.parametrize(
    ("scenario", "expected_line"),
    [
        ("missing", "vulnerable — no scan results; nothing to do."),
        ("blocked", "vulnerable — nothing to update."),
    ],
)
def test_given_update_noop_when_command_runs_then_it_exits_zero_and_prints_literal_line(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    capsys: pytest.CaptureFixture[str],
    scenario: str,
    expected_line: str,
) -> None:
    if scenario == "missing":
        (mm_home_with_projects / "scan-results" / "vulnerable.json").unlink()
    else:
        save_scan_results(
            "vulnerable",
            make_scan_result(vulns=[make_vuln(fixed_version=None)], updates=[]),
        )

    assert run_mm("update", "vulnerable") == ExitCode.OK
    assert expected_line in capsys.readouterr().out.splitlines()


@pytest.mark.parametrize(
    ("command", "deps_fixture", "other_flow", "expected_lines"),
    [
        pytest.param(
            "update",
            "mock_update_cli_deps",
            Workflow.RESOLVE,
            [
                "Error: Cannot run update on vulnerable: 1 finding(s) owned by the "
                "'resolve' ",
                "flow. Complete or abandon that flow first.",
            ],
            id="update",
        ),
        pytest.param(
            "resolve",
            "mock_resolve_cli_deps",
            Workflow.UPDATE,
            [
                "Error: Cannot run resolve on vulnerable: 1 finding(s) owned by the "
                "'update' ",
                "flow. Complete or abandon that flow first.",
            ],
            id="resolve",
        ),
    ],
)
def test_given_opposite_workflow_when_run_then_flow_conflict_is_reported(
    mm_home_with_projects: Path,
    request: pytest.FixtureRequest,
    capsys: pytest.CaptureFixture[str],
    command: str,
    deps_fixture: str,
    other_flow: Workflow,
    expected_lines: list[str],
) -> None:
    deps: CliDeps = request.getfixturevalue(deps_fixture)
    for existing in deps.scan_result.findings:
        existing.update_status = None
        existing.failed_phase = None
        existing.flow = None
    finding = deps.scan_result.updates[0]
    finding.update_status = UpdateStatus.FAILED
    finding.failed_phase = "apply"
    finding.flow = other_flow
    deps.save_scan()

    assert run_mm(command, "vulnerable") == ExitCode.ERROR
    assert capsys.readouterr().out.splitlines() == expected_lines


@pytest.mark.parametrize("command,deps_fixture", _COMMAND_FIXTURES)
def test_given_missing_test_config_when_run_then_warns_and_succeeds(
    mm_home_with_projects: Path,
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    deps_fixture: str,
) -> None:
    deps: CliDeps = request.getfixturevalue(deps_fixture)
    if command == "resolve":
        for finding in deps.scan_result.findings:
            finding.update_status = None
            finding.failed_phase = None
            finding.flow = None
        save_scan_results("no-tests", deps.scan_result)
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))

    assert run_mm(command, "no-tests") == ExitCode.OK
    assert (
        "  Warning: no-tests — no test configuration (test phases will be skipped)"
        in capsys.readouterr().out.splitlines()
    )


def test_given_missing_update_bookmark_when_run_then_exits_one_with_error(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    capsys: pytest.CaptureFixture[str],
) -> None:
    finding = mock_update_cli_deps.scan_result.updates[0]
    finding.update_status = UpdateStatus.FAILED
    finding.flow = Workflow.UPDATE
    mock_update_cli_deps.save_scan()

    assert run_mm("update", "vulnerable") == ExitCode.ERROR
    assert capsys.readouterr().out.splitlines() == [
        "Error: update bookmark 'mm/update-dependencies' is missing but in-progress "
        "state",
        "exists — rescan required",
    ]


def test_given_batch_flow_conflict_when_run_then_exits_four_with_both_projects(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    capsys: pytest.CaptureFixture[str],
) -> None:
    finding = mock_update_cli_deps.scan_result.updates[0]
    finding.update_status = UpdateStatus.FAILED
    finding.flow = Workflow.RESOLVE
    mock_update_cli_deps.save_scan()

    assert run_mm("update", "vulnerable", "clean") == ExitCode.UPDATE_FAILED
    lines = capsys.readouterr().out.splitlines()
    assert "vulnerable" in lines
    assert "clean" in lines


class TestUpdatePreChecks:
    def test_no_projects_configured_exits_0_without_gh(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (mm_home).mkdir(parents=True, exist_ok=True)
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")

        monkeypatch.setattr(
            "maintenance_man.vcs_workflow.require_tool",
            missing_tool("gh"),
        )

        assert run_mm("update") == 0

    def test_batch_code_host_pruning_failure_continues_other_projects(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
    ) -> None:
        vulnerable = mock_update_cli_deps.project_paths["vulnerable"]
        host = mock_update_cli_deps.vcs_state.code_host(vulnerable)
        host.fail("pr_bookmarks", error=CodeHostError("host unavailable"))

        assert run_mm("update", "vulnerable", "clean") == ExitCode.UPDATE_FAILED
        clean = load_scan_results("clean")
        assert not clean.findings


class TestUpdateNoOp:
    """No-op-first ordering: nothing to do => exit 0 without side effects."""

    def test_batch_noop_is_identical(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Batch mode also performs the no-op check before any side effects."""
        for result in (mm_home_with_projects / "scan-results").glob("*.json"):
            result.unlink()
        state = mock_update_cli_deps.vcs_state
        state.clear_calls()

        assert run_mm("update") == 0
        assert state.attempts == []


class TestUpdateSelection:
    def test_out_of_range_selection_reprompts_and_processes_valid_choice(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        prompt = MagicMock(side_effect=["9", "1"])
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", prompt)

        assert run_mm("update", "vulnerable") == 0
        assert prompt.call_count == 2
        assert capsys.readouterr().out.count("Invalid selection: '9'. Try again.") == 1
        project_path = mock_update_cli_deps.project_paths["vulnerable"]
        assert (project_path / "mm-fixture-some-pkg.txt").is_file()
        assert not (project_path / "mm-fixture-pkg-a.txt").exists()

    def test_none_selection_exits_0(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ):
        processor = MagicMock(return_value=[])
        monkeypatch.setattr(
            "maintenance_man.services.update.process_findings", processor
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )
        assert run_mm("update", "vulnerable") == 0
        processor.assert_not_called()

    def test_vulns_selection(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns")
        )
        assert run_mm("update", "vulnerable") == 0
        project_path = mock_update_cli_deps.project_paths["vulnerable"]
        assert (project_path / "mm-fixture-some-pkg.txt").is_file()
        assert not (project_path / "mm-fixture-pkg-a.txt").exists()


class TestUpdateCrossCategoryStops:
    @pytest.mark.parametrize(
        "failure",
        ["unknown-dirty", "failed-discard", "bookmark"],
    )
    def test_unsafe_vulnerability_failure_does_not_attempt_update_category(
        self,
        failure: str,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        package, phase = _use_real_mixed_processor(
            mock_update_cli_deps, mm_home_with_projects, monkeypatch
        )
        state = mock_update_cli_deps.vcs_state
        if failure == "unknown-dirty":
            state.fail("has_changes", error=RevisionError("cannot inspect"))
        elif failure == "failed-discard":
            phase.side_effect = ProcessError("unit failed")
            state.fail("discard", error=RevisionError("cannot discard"))
        else:
            state.fail("set_bookmark", error=RevisionError("cannot advance"))

        assert run_mm("update", "outdated") == ExitCode.UPDATE_FAILED
        assert package.call_count == 1
        saved = load_scan_results("outdated")
        assert saved.vulnerabilities[0].update_status == UpdateStatus.FAILED
        assert saved.updates[0].update_status is None

    def test_safely_discarded_vulnerability_failure_continues_to_update_category(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        package, phase = _use_real_mixed_processor(
            mock_update_cli_deps, mm_home_with_projects, monkeypatch
        )
        phase.side_effect = [ProcessError("unit failed"), None]

        assert run_mm("update", "outdated") == ExitCode.UPDATE_FAILED
        assert package.call_count == 2
        saved = load_scan_results("outdated")
        assert saved.vulnerabilities[0].update_status == UpdateStatus.FAILED
        assert saved.updates[0].update_status == UpdateStatus.READY

    def test_any_failure_exits_4(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.services.update.process_findings",
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
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        assert run_mm("update", "vulnerable") == 4

    def test_commit_failure_summary_uses_friendly_label(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        monkeypatch.setattr(
            "maintenance_man.services.update.process_findings",
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
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns")
        )

        assert run_mm("update", "vulnerable") == 4
        assert "commit failed" in capsys.readouterr().out


class TestUpdateNumberedSelection:
    def test_select_by_number(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Selecting '1' should pick the first finding."""

        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="1")
        )
        assert run_mm("update", "vulnerable") == 0
        project_path = mock_update_cli_deps.project_paths["vulnerable"]
        assert (project_path / "mm-fixture-some-pkg.txt").is_file()
        assert not (project_path / "mm-fixture-pkg-a.txt").exists()

    def test_given_typed_order_when_run_then_exits_zero_with_prompt(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        save_scan_results(
            "vulnerable",
            make_scan_result(
                vulns=[],
                updates=[make_update(pkg_name="pkg-a"), make_update(pkg_name="pkg-b")],
            ),
        )
        prompt = MagicMock(return_value="2,1")
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", prompt)

        assert run_mm("update", "vulnerable") == ExitCode.OK
        assert "Select updates \\[all/updates/1,2,.../none]" in prompt.call_args.args[0]


class TestUpdateResume:
    """Interactive rerun with update-owned in-progress state."""

    def test_resume_ready_only_attaches_workspace_and_promotes(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result: ScanResult = mock_update_cli_deps.scan_result
        scan_result.updates[0].update_status = UpdateStatus.READY
        scan_result.updates[0].flow = Workflow.UPDATE
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE
        mock_update_cli_deps.save_scan()
        _seed_update_bookmark(mock_update_cli_deps)

        state = mock_update_cli_deps.vcs_state
        state.clear_calls()
        mock_prompt = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", mock_prompt)

        assert run_mm("update", "vulnerable") == 0

        workspace = next(
            call for call in state.effects if call.method == "add_workspace"
        )
        assert dict(workspace.arguments)["revision"] == "mm/update-dependencies"
        assert not any(call.method == "fetch" for call in state.attempts)
        mock_prompt.assert_not_called()
        assert not load_scan_results("vulnerable").findings

    def test_resume_shows_only_failed_findings(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        """On resume with FAILED findings, READY findings are hidden from prompt."""
        scan_result: ScanResult = mock_update_cli_deps.scan_result
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        scan_result.updates[0].flow = Workflow.UPDATE
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE
        mock_update_cli_deps.save_scan()
        _seed_update_bookmark(mock_update_cli_deps)

        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )

        assert run_mm("update", "vulnerable") == 4

        output = capsys.readouterr().out
        assert "some-pkg" not in output
        numbered_rows = [
            re.sub(r"\s+", " ", line.strip())
            for line in output.splitlines()
            if re.match(r"\s*\d+\.", line)
        ]
        assert numbered_rows == ["1. UPDATE pkg-a 1.0.0 -> 1.0.1 (patch)"]


class TestUpdateAll:
    """Batch mode: `mm update` with no project argument."""

    def test_processes_all_projects(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        assert run_mm("update") == 0
        for project in mock_update_cli_deps.project_paths:
            saved = load_scan_results(project)
            assert not saved.findings

    def test_any_failure_exits_4(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.services.update.process_findings",
            MagicMock(
                return_value=[
                    UpdateResult(
                        pkg_name="some-pkg",
                        kind="vuln",
                        passed=False,
                        failed_phase="test_unit",
                    )
                ]
            ),
        )

        assert run_mm("update") == 4

    def test_batch_continues_after_final_bookmark_cleanup_failure(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        vulnerable_path = mock_update_cli_deps.project_paths["vulnerable"]
        clean_path = mock_update_cli_deps.project_paths["clean"]
        state = mock_update_cli_deps.vcs_state
        state.fail(
            "delete_bookmark",
            ordinal=1,
            error=RevisionError("injected final cleanup failure"),
            path=vulnerable_path,
        )

        assert run_mm("update", "vulnerable", "clean") == ExitCode.UPDATE_FAILED
        output = capsys.readouterr().out
        assert "Bookmark cleanup failed" in output
        vulnerable_repo = mock_update_cli_deps.vcs_state.services().repository(
            vulnerable_path
        )
        clean_repo = mock_update_cli_deps.vcs_state.services().repository(clean_path)
        assert vulnerable_repo.same_revision(
            left="main", right="mm/update-dependencies"
        )
        assert not clean_repo.bookmark_exists(bookmark="mm/update-dependencies")
        assert (clean_path / "mm-fixture-some-pkg.txt").read_text() == "1.0.1"
        for project in ("vulnerable", "clean"):
            saved = load_scan_results(project)
            assert not saved.findings


@pytest.mark.parametrize(
    ("failing_operation", "expected_line"),
    [
        ("promote_bookmark_to_main", "Promotion failed: injected"),
        (
            "working_copy_state",
            "Workspace refresh failed: vulnerable: injected",
        ),
    ],
)
def test_given_finalisation_failure_when_run_then_exits_four_with_error(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failing_operation: str,
    expected_line: str,
) -> None:
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
    mock_update_cli_deps.vcs_state.fail(
        failing_operation,
        error=RevisionError("injected"),
        path=mock_update_cli_deps.project_paths["vulnerable"],
    )

    assert run_mm("update", "vulnerable") == ExitCode.UPDATE_FAILED
    assert expected_line in capsys.readouterr().out.splitlines()


def test_given_successful_update_when_run_then_exits_zero_with_promotion(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))

    assert run_mm("update", "vulnerable") == ExitCode.OK
    assert (
        "Promoted mm/update-dependencies to main."
        in capsys.readouterr().out.splitlines()
    )


def test_given_workspace_cleanup_failure_when_run_then_exits_four_with_error(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
    mock_update_cli_deps.vcs_state.fail(
        "forget_workspace",
        error=RevisionError("injected"),
        path=mock_update_cli_deps.project_paths["vulnerable"],
    )

    assert run_mm("update", "vulnerable") == ExitCode.UPDATE_FAILED
    assert "Workspace cleanup failed: injected" in capsys.readouterr().out.splitlines()


def test_update_end_to_end_uses_one_graph_and_persists_completion(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.conftest import make_vuln

    scan_result: ScanResult = mock_update_cli_deps.scan_result
    scan_result.vulnerabilities.append(
        make_vuln(pkg_name="unrelated", vuln_id="CVE-open", fixed_version=None)
    )
    mock_update_cli_deps.save_scan()
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
    state = mock_update_cli_deps.vcs_state
    source = mock_update_cli_deps.vcs_state.services().repository(
        mock_update_cli_deps.project_paths["vulnerable"]
    )
    promoted_tip: list[str] = []
    state.hook(
        "promote_bookmark_to_main",
        phase="before",
        action=lambda: promoted_tip.append(
            source.resolve_revision(revision="mm/update-dependencies")
        ),
        path=mock_update_cli_deps.project_paths["vulnerable"],
    )
    state.clear_calls()

    assert run_mm("update", "vulnerable") == 0
    project_path = mock_update_cli_deps.project_paths["vulnerable"]
    assert (project_path / "mm-fixture-some-pkg.txt").read_text() == "1.0.1"
    assert (project_path / "mm-fixture-pkg-a.txt").read_text() == "1.0.1"
    repo = mock_update_cli_deps.vcs_state.services().repository(project_path)
    assert promoted_tip and repo.resolve_revision(revision="main") == promoted_tip[0]
    assert not repo.bookmark_exists(bookmark="mm/update-dependencies")
    assert "mm-vulnerable" not in repo.workspace_names()
    assert not (mm_home_with_projects / "workspaces" / "vulnerable").exists()
    saved = load_scan_results("vulnerable")
    assert [finding.pkg_name for finding in saved.findings] == ["unrelated"]
    effects = [call.method for call in state.effects]
    assert any(call.method == "working_copy_state" for call in state.attempts)
    assert effects.index("promote_bookmark_to_main") < effects.index(
        "rebase_working_copy"
    )
    assert effects.index("rebase_working_copy") < effects.index("forget_workspace")
    assert effects.index("forget_workspace") < effects.index("delete_bookmark")


class TestUpdateTargetSelection:
    def test_excluding_all_projects_exits_0_without_gh(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.vcs_workflow.require_tool",
            missing_tool("gh"),
        )

        assert (
            run_mm(
                "update",
                "-n",
                "vulnerable",
                "clean",
                "outdated",
                "no-tests",
                "deployable",
                "deploy-only",
                "no-deploy",
            )
            == 0
        )

    def test_no_args_uses_batch_all(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        assert run_mm("update") == 0
        mock_batch.assert_called_once()
        assert mock_batch.call_args.args[1] == [
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
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_interactive = MagicMock(side_effect=SystemExit(0))
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_project", mock_interactive)
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        assert run_mm("update", "vulnerable") == 0
        mock_interactive.assert_called_once()
        mock_batch.assert_not_called()

    def test_multiple_names_use_batch_in_cli_order(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        assert run_mm("update", "outdated", "vulnerable", "outdated") == 0
        assert mock_batch.call_args.args[1] == ["outdated", "vulnerable"]

    def test_negate_mode_excludes_named_projects(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        assert run_mm("update", "-n", "vulnerable", "clean") == 0
        assert mock_batch.call_args.args[1] == [
            "deploy-only",
            "deployable",
            "no-deploy",
            "no-tests",
            "outdated",
        ]

    def test_negate_with_no_names_matches_batch_all(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        assert run_mm("update", "-n") == 0
        assert mock_batch.call_args.args[1] == [
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
        assert (
            run_mm(
                "update",
                "-n",
                "vulnerable",
                "clean",
                "outdated",
                "no-tests",
                "deployable",
                "deploy-only",
                "no-deploy",
            )
            == 0
        )
        assert "No target projects." in capsys.readouterr().out

    def test_unknown_project_in_include_mode_exits_1(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("update", "missing") == 1
        assert "Unknown project 'missing'" in capsys.readouterr().out

    def test_unknown_project_in_negate_mode_exits_1(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("update", "-n", "missing") == 1
        assert "Unknown project 'missing'" in capsys.readouterr().out

    def test_batch_continues_after_project_failure(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_project = MagicMock(
            side_effect=[
                update_service.UpdateSetupError("setup failed"),
                update_service.ProjectUpdate(
                    "clean",
                    update_service.UpdateRoute.FINDINGS,
                    Outcome.SUCCEEDED,
                    (UpdateResult(pkg_name="pkg-a", kind="update", passed=True),),
                ),
            ]
        )
        monkeypatch.setattr(update_service, "update_project", mock_project)
        monkeypatch.setattr(
            "maintenance_man.cli._print_mass_update_summary",
            MagicMock(),
        )

        assert run_mm("update", "vulnerable", "clean") == 4
        assert [call.args[0] for call in mock_project.call_args_list] == [
            "vulnerable",
            "clean",
        ]


class TestUpdateCliSurface:
    def test_help_does_not_expose_projects_option(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("update", "--help") == 0
        output = capsys.readouterr().out
        assert "--projects" not in output
        assert "--empty-projects" not in output

    def test_help_does_not_expose_continue_or_worktree(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--continue and --worktree are gone from the update surface."""
        assert run_mm("update", "--help") == 0
        output = capsys.readouterr().out
        assert "--continue" not in output
        assert "--worktree" not in output

    def test_continue_flag_is_rejected(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("update", "vulnerable", "--continue") == 1
        captured = capsys.readouterr()
        assert "Unknown option" in (captured.out + captured.err)

    def test_worktree_flag_is_rejected(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("update", "vulnerable", "--worktree") == 1
        captured = capsys.readouterr()
        assert "Unknown option" in (captured.out + captured.err)

    def test_projects_option_is_not_accepted(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("update", "--projects", "vulnerable") == 1
        captured = capsys.readouterr()
        assert "Unknown option" in (captured.out + captured.err)


@pytest.fixture()
def gradle_update_cli(
    mock_update_cli_deps, mm_home_with_gradle, gradle_project, monkeypatch
):
    """Update-CLI boundaries plus Gradle spies. Returns a mutable spy record."""
    monkeypatch.setattr(
        "maintenance_man.gradle_workflow.load_scan_results",
        lambda *args: mock_update_cli_deps.scan_result,
    )
    mock_update_cli_deps.vcs_state.seed_repository(
        gradle_project.path,
        files={
            "gradlew": (gradle_project.path / "gradlew").read_text(),
            "gradle/libs.versions.toml": (
                gradle_project.path / "gradle/libs.versions.toml"
            ).read_text(),
        },
    )
    spies: dict[str, list] = {"tests": [], "applies": []}
    monkeypatch.setattr(
        "maintenance_man.updater.run_test_phases",
        lambda cfg, path: spies["tests"].append(1),
    )
    monkeypatch.setattr(
        "maintenance_man.gradle_updates.apply_gradle_update",
        lambda project, target: spies["applies"].append(target) or None,
    )
    monkeypatch.setattr(
        "maintenance_man.gradle_updates.validate_gradle_target",
        lambda project, target: None,
    )
    # `mm update <one project>` is the interactive single-project path, so every
    # test here must answer the selection prompt; individual tests override this.
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", lambda *a, **k: "all")
    return spies


_GRADLE_REPOSITORY_MUTATIONS = {
    "add_workspace",
    "commit",
    "create_bookmark",
    "delete_bookmark",
    "discard",
    "forget_workspace",
    "new_change",
    "promote_bookmark_to_main",
    "push_bookmark",
    "rebase_working_copy",
    "reset_verified_bookmark",
    "set_bookmark",
}


def _assert_no_gradle_repository_mutations(state: FakeJjState, path: Path) -> None:
    attempts = [call for call in state.attempts if call.path == path.resolve()]
    effects = [call for call in state.effects if call.path == path.resolve()]
    assert not ({call.method for call in attempts} & _GRADLE_REPOSITORY_MUTATIONS)
    assert not ({call.method for call in effects} & _GRADLE_REPOSITORY_MUTATIONS)


def _gradle_scan_state(mock_update_cli_deps: CliDeps) -> ScanResult:
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
    mock_update_cli_deps.scan_result.vulnerabilities = scan_result.vulnerabilities
    mock_update_cli_deps.scan_result.updates = scan_result.updates
    return mock_update_cli_deps.scan_result


def test_batch_summary_labels_pass_and_fail(capsys):
    from maintenance_man.cli import _print_mass_update_summary

    _print_mass_update_summary(
        [
            (
                "a[b]",
                [
                    UpdateResult(pkg_name="room[x]", kind="update", passed=True),
                    UpdateResult(
                        pkg_name="okhttp",
                        kind="vuln",
                        passed=False,
                        failed_phase="unit",
                    ),
                ],
            )
        ]
    )
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "FAIL (unit)" in out
    assert "BLOCKED" not in out
    assert "a[b]" in out
    assert "room[x]" in out


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
    write_config(
        mm_home_with_gradle,
        f'[projects.android]\npath = "{gradle_project.path}"\n'
        'package_manager = "gradle"\n',
    )
    args = ["update"] if batch else ["update", "android"]
    vcs_state = mock_update_cli_deps.vcs_state
    vcs_state.clear_calls()
    assert run_mm(*args) == 4
    assert all(f.update_status == UpdateStatus.READY for f in state.updates)
    assert gradle_update_cli == {"tests": [], "applies": []}
    _assert_no_gradle_repository_mutations(vcs_state, gradle_project.path)


def test_gradle_ready_only_missing_bookmark_preserves_state(
    gradle_update_cli, mock_update_cli_deps, monkeypatch, gradle_project
):
    state = _gradle_scan_state(mock_update_cli_deps)
    for finding in state.updates:
        finding.update_status = UpdateStatus.READY
        finding.flow = Workflow.UPDATE
    vcs_state = mock_update_cli_deps.vcs_state
    vcs_state.clear_calls()
    assert run_mm("update", "android") == 4
    assert all(f.update_status == UpdateStatus.READY for f in state.updates)
    assert gradle_update_cli == {"tests": [], "applies": []}
    _assert_no_gradle_repository_mutations(vcs_state, gradle_project.path)


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("status", [UpdateStatus.FAILED, UpdateStatus.READY])
def test_gradle_legacy_update_history_is_preserved_without_effects(
    gradle_update_cli,
    mock_update_cli_deps,
    monkeypatch,
    gradle_project,
    batch,
    status,
):

    scan = _gradle_scan_state(mock_update_cli_deps)
    for row in scan.updates:
        row.update_status = status
        row.flow = Workflow.UPDATE
        row.failed_phase = "unit"
    before = scan.model_dump_json()

    def forbidden(*args, **kwargs):
        pytest.fail("legacy history cannot authorize commands")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr("maintenance_man.gradle.run_logged", forbidden)
    vcs_state = mock_update_cli_deps.vcs_state
    vcs_state.clear_calls()
    exit_code = run_mm("update") if batch else run_mm("update", "android")
    assert exit_code == ExitCode.UPDATE_FAILED
    assert scan.model_dump_json() == before
    assert gradle_update_cli == {"tests": [], "applies": []}
    _assert_no_gradle_repository_mutations(vcs_state, gradle_project.path)
