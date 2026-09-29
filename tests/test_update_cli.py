import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man import cli
from maintenance_man.cli import ExitCode, app
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
from maintenance_man.process import ProcessError, ToolNotFoundError
from maintenance_man.services import update as update_service
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs import RevisionError
from tests.conftest import (
    make_config,
    make_gradle_target,
    make_scan_result,
    make_update,
)
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeFindingProcessor, RecordingEmit


@pytest.mark.parametrize(
    "text, expected",
    [
        ("all", "all"),
        (" ALL ", "all"),
        ("none", "none"),
        ("Vulns", "vulns"),
        ("updates", "updates"),
        ("2,1", (2, 1)),
        ("1,1", (1,)),
        ("3", (3,)),
        ("0", None),
        ("4", None),
        ("", None),
        ("1,,2", None),
        ("a", None),
    ],
)
def test_parse_selection(text, expected):
    assert cli._parse_selection(text, 3) == expected


def _missing(tool):
    def require(name, hint):
        if name == tool:
            raise ToolNotFoundError(f"{name} is not installed or not on PATH. {hint}")
        return Path("/usr/bin") / name

    return require


def _seed_update_bookmark(deps: dict) -> None:
    repo = deps["services"].repository(deps["project_paths"]["vulnerable"])
    repo.set_bookmark(bookmark="mm/update-dependencies", revision="main")


def _use_real_mixed_processor(
    deps: dict,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, MagicMock]:
    from maintenance_man import updater

    save_scan_results("outdated", make_scan_result())
    project_path = deps["project_paths"]["outdated"]
    state = deps["vcs_state"]
    state.register_files(project_path, "package.json")
    (project_path / "package.json").write_text("{}\n", encoding="utf-8")
    repo = deps["services"].repository(project_path)
    repo.commit(message="test: add package manifest")
    repo.set_bookmark(bookmark="main", revision="@-")
    state.clear_calls()

    def run_package(cmd, cwd, **kwargs):
        assert cmd[:2] == ["bun", "add"]
        assert cwd == home / "workspaces" / "outdated"
        current = (cwd / "dep.txt").read_text(encoding="utf-8")
        (cwd / "dep.txt").write_text(f"{current}{cmd[-1]}\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    package = MagicMock(side_effect=run_package)
    phase = MagicMock(return_value=None)
    monkeypatch.setattr(
        "maintenance_man.services.update.process_findings", updater.process_findings
    )
    monkeypatch.setattr("maintenance_man.updater.run_captured", package)
    monkeypatch.setattr("maintenance_man.updater.run_live", phase)
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
    return package, phase


_COMMAND_FIXTURES = [
    pytest.param("update", "mock_update_cli_deps", id="update"),
    pytest.param("resolve", "mock_resolve_cli_deps", id="resolve"),
]


@pytest.mark.parametrize("command,deps_fixture", _COMMAND_FIXTURES)
class TestSharedCommandPrerequisites:
    def test_missing_gh_exits_one(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        deps["vcs_state"].clear_calls()
        monkeypatch.setattr("maintenance_man.vcs_workflow.require_tool", _missing("gh"))

        with pytest.raises(SystemExit) as exc_info:
            app([command, "vulnerable"])

        assert exc_info.value.code == 1
        assert deps["vcs_state"].attempts == []

    def test_missing_jj_exits_one(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        deps["vcs_state"].clear_calls()
        monkeypatch.setattr("maintenance_man.vcs_workflow.require_tool", _missing("jj"))

        with pytest.raises(SystemExit) as exc_info:
            app([command, "vulnerable"])

        assert exc_info.value.code == 1
        assert deps["vcs_state"].attempts == []

    def test_opposite_workflow_exits_one_before_processing(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        scan_result: ScanResult = deps["scan_result"]
        finding = scan_result.updates[0]
        finding.update_status = UpdateStatus.FAILED
        finding.flow = Workflow.RESOLVE if command == "update" else Workflow.UPDATE
        finding.failed_phase = "apply"
        deps["save_scan"]()
        deps["vcs_state"].clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app([command, "vulnerable"])

        output = capsys.readouterr().out.lower()
        assert exc_info.value.code == 1
        assert all(word in output for word in ("update", "resolve", "vulnerable"))
        assert deps["vcs_state"].effects == []

    def test_legacy_finding_without_flow_exits_one_before_processing(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        finding = deps["scan_result"].updates[0]
        finding.update_status = UpdateStatus.FAILED
        finding.flow = None
        deps["save_scan"]()
        deps["vcs_state"].clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app([command, "vulnerable"])

        assert exc_info.value.code == 1
        assert "rescan" in capsys.readouterr().out.lower()
        assert deps["vcs_state"].effects == []

    def test_missing_test_config_warns_and_succeeds(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        scan_result: ScanResult = deps["scan_result"]
        if command == "resolve":
            for finding in scan_result.findings:
                finding.update_status = None
                finding.failed_phase = None
                finding.flow = None
        from maintenance_man.storage import save_scan_results

        save_scan_results("no-tests", scan_result)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )

        with pytest.raises(SystemExit) as exc_info:
            app([command, "no-tests"])

        assert exc_info.value.code == 0
        assert "no test configuration" in capsys.readouterr().out.lower()

    def test_no_scan_results_exits_zero_before_repository_mutation(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
        mm_home_with_projects: Path,
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        (mm_home_with_projects / "scan-results" / "vulnerable.json").unlink()
        deps["vcs_state"].clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app([command, "vulnerable"])

        assert exc_info.value.code == 0
        assert deps["vcs_state"].attempts == []

    def test_no_actionable_findings_exits_zero_before_repository_mutation(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        deps = request.getfixturevalue(deps_fixture)
        scan_result: ScanResult = deps["scan_result"]
        scan_result.vulnerabilities = []
        scan_result.updates = []
        deps["save_scan"]()
        deps["vcs_state"].clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app([command, "vulnerable"])

        assert exc_info.value.code == 0
        assert deps["vcs_state"].attempts == []


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


class TestUpdatePreChecks:
    def test_no_projects_configured_exits_0_without_gh(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (mm_home).mkdir(parents=True, exist_ok=True)
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")

        monkeypatch.setattr(
            "maintenance_man.vcs_workflow.require_tool",
            _missing("gh"),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])

        assert exc_info.value.code == 0

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
        mock_update_cli_deps["save_scan"]()

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "clean"])

        out = capsys.readouterr().out.lower()
        assert exc_info.value.code == ExitCode.UPDATE_FAILED
        assert "vulnerable" in out
        assert "clean" in out

    def test_code_host_pruning_failure_refuses_before_processing(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        project_path = mock_update_cli_deps["project_paths"]["vulnerable"]
        host = mock_update_cli_deps["vcs_state"].code_host(project_path)
        host.fail("pr_bookmarks", error=CodeHostError("host unavailable"))

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 1
        assert not any(
            call.method == "commit"
            for call in mock_update_cli_deps["vcs_state"].attempts
        )

    def test_batch_code_host_pruning_failure_continues_other_projects(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
    ) -> None:
        vulnerable = mock_update_cli_deps["project_paths"]["vulnerable"]
        host = mock_update_cli_deps["vcs_state"].code_host(vulnerable)
        host.fail("pr_bookmarks", error=CodeHostError("host unavailable"))

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "clean"])

        assert exc_info.value.code == ExitCode.UPDATE_FAILED
        clean = load_scan_results("clean")
        assert not clean.findings


class TestUpdateNoOp:
    """No-op-first ordering: nothing to do => exit 0 without side effects."""

    def test_batch_noop_is_identical(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Batch mode also performs the no-op check before any side effects."""
        for result in (mm_home_with_projects / "scan-results").glob("*.json"):
            result.unlink()
        state = mock_update_cli_deps["vcs_state"]
        state.clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 0
        assert state.attempts == []


class TestUpdateSelection:
    def test_out_of_range_selection_reprompts_and_processes_valid_choice(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        prompt = MagicMock(side_effect=["9", "1"])
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", prompt)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        assert prompt.call_count == 2
        assert capsys.readouterr().out.count("Invalid selection: '9'. Try again.") == 1
        project_path = mock_update_cli_deps["project_paths"]["vulnerable"]
        assert (project_path / "mm-fixture-some-pkg.txt").is_file()
        assert not (project_path / "mm-fixture-pkg-a.txt").exists()

    def test_none_selection_exits_0(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        processor = MagicMock(return_value=[])
        monkeypatch.setattr(
            "maintenance_man.services.update.process_findings", processor
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        processor.assert_not_called()

    def test_vulns_selection(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        project_path = mock_update_cli_deps["project_paths"]["vulnerable"]
        assert (project_path / "mm-fixture-some-pkg.txt").is_file()
        assert not (project_path / "mm-fixture-pkg-a.txt").exists()


class TestUpdateExitCodes:
    def test_all_pass_exits_0(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0


class TestUpdateCrossCategoryStops:
    @pytest.mark.parametrize(
        "failure",
        ["unknown-dirty", "failed-discard", "bookmark"],
    )
    def test_unsafe_vulnerability_failure_does_not_attempt_update_category(
        self,
        failure: str,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        package, phase = _use_real_mixed_processor(
            mock_update_cli_deps, mm_home_with_projects, monkeypatch
        )
        state = mock_update_cli_deps["vcs_state"]
        if failure == "unknown-dirty":
            state.fail("has_changes", error=RevisionError("cannot inspect"))
        elif failure == "failed-discard":
            phase.side_effect = ProcessError("unit failed")
            state.fail("discard", error=RevisionError("cannot discard"))
        else:
            state.fail("set_bookmark", error=RevisionError("cannot advance"))

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "outdated"])

        assert exc_info.value.code == ExitCode.UPDATE_FAILED
        assert package.call_count == 1
        saved = load_scan_results("outdated")
        assert saved.vulnerabilities[0].update_status == UpdateStatus.FAILED
        assert saved.updates[0].update_status is None

    def test_safely_discarded_vulnerability_failure_continues_to_update_category(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        package, phase = _use_real_mixed_processor(
            mock_update_cli_deps, mm_home_with_projects, monkeypatch
        )
        phase.side_effect = [ProcessError("unit failed"), None]

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "outdated"])

        assert exc_info.value.code == ExitCode.UPDATE_FAILED
        assert package.call_count == 2
        saved = load_scan_results("outdated")
        assert saved.vulnerabilities[0].update_status == UpdateStatus.FAILED
        assert saved.updates[0].update_status == UpdateStatus.READY

    def test_any_failure_exits_4(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
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
            "maintenance_man.services.update.process_findings",
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

        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="1")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        project_path = mock_update_cli_deps["project_paths"]["vulnerable"]
        assert (project_path / "mm-fixture-some-pkg.txt").is_file()
        assert not (project_path / "mm-fixture-pkg-a.txt").exists()

    def test_typed_indices_preserve_equal_risk_update_order(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        scan = make_scan_result(
            vulns=[],
            updates=[make_update(pkg_name="pkg-a"), make_update(pkg_name="pkg-b")],
        )
        save_scan_results("vulnerable", scan)
        processed: list[str] = []
        processor = FakeFindingProcessor({"pkg-a": (True, None), "pkg-b": (True, None)})

        def process(findings, project_config, **kwargs):
            processed.extend(finding.pkg_name for finding in findings)
            return processor(findings, project_config, **kwargs)

        monkeypatch.setattr(update_service, "process_findings", process)
        prompt = MagicMock(return_value="2,1")
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", prompt)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        assert processed == ["pkg-b", "pkg-a"]
        assert "Select updates \\[all/updates/1,2,.../none]" in prompt.call_args.args[0]


def test_update_event_renderers_preserve_text_and_batch_silence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from maintenance_man.models.events import (
        FindingsProcessed,
        MissingTestConfig,
        ProcessingStarted,
        Promoted,
    )

    cli._Renderer(batch=False)(MissingTestConfig("a[b]"))
    cli._Renderer(batch=False)(ProcessingStarted(1, 2))
    cli._Renderer(batch=False)(
        FindingsProcessed((UpdateResult("pkg", "update", True),))
    )
    cli._Renderer(batch=False)(Promoted("mm/update-dependencies"))
    output = capsys.readouterr().out
    assert "Warning: a[b] — no test configuration" in output
    assert "Processing 1 vuln fix(es)..." in output
    assert "Processing 2 update(s)..." in output
    assert "Summary:" in output
    assert "Promoted mm/update-dependencies to main." in output

    cli._Renderer(batch=True)(FindingsProcessed((UpdateResult("pkg", "update", True),)))
    assert capsys.readouterr().out == ""


class TestUpdateResume:
    def test_missing_non_gradle_resume_bookmark_refuses_before_processing(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
    ) -> None:
        scan_result: ScanResult = mock_update_cli_deps["scan_result"]
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        scan_result.updates[0].flow = Workflow.UPDATE
        mock_update_cli_deps["save_scan"]()
        state = mock_update_cli_deps["vcs_state"]
        state.clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 1
        assert not any(call.method == "commit" for call in state.attempts)

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
        mock_update_cli_deps["save_scan"]()
        _seed_update_bookmark(mock_update_cli_deps)

        state = mock_update_cli_deps["vcs_state"]
        state.clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

        workspace = next(
            call for call in state.effects if call.method == "add_workspace"
        )
        assert dict(workspace.arguments)["revision"] == "mm/update-dependencies"
        assert not any(call.method == "fetch" for call in state.attempts)

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
        mock_update_cli_deps["save_scan"]()
        _seed_update_bookmark(mock_update_cli_deps)

        mock_prompt = MagicMock()
        monkeypatch.setattr("maintenance_man.cli.Prompt.ask", mock_prompt)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_prompt.assert_not_called()
        assert not load_scan_results("vulnerable").findings

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
        mock_update_cli_deps["save_scan"]()
        _seed_update_bookmark(mock_update_cli_deps)

        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )

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
        mock_update_cli_deps["save_scan"]()
        _seed_update_bookmark(mock_update_cli_deps)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        assert not load_scan_results("vulnerable").findings

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
        mock_update_cli_deps["save_scan"]()
        _seed_update_bookmark(mock_update_cli_deps)

        state = mock_update_cli_deps["vcs_state"]
        state.clear_calls()

        with pytest.raises(SystemExit):
            app(["update", "vulnerable"])
        assert not any(call.method == "fetch" for call in state.attempts)


class TestUpdateFinalise:
    """Promote moves READY -> COMPLETED only on success."""

    def test_promote_refreshes_working_copy_from_main(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """After promoting the bookmark, the working copy must refresh from main."""

        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        state = mock_update_cli_deps["vcs_state"]
        state.clear_calls()

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        assert any(call.method == "working_copy_state" for call in state.attempts)

    def test_promote_success_promotes_ready_to_completed(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        # remove_completed_findings removes promoted findings from the result
        saved = load_scan_results("vulnerable")
        assert saved.vulnerabilities == []
        assert saved.updates == []

    @pytest.mark.parametrize(
        ("failing_operation", "expected_message"),
        [
            ("promote_bookmark_to_main", "Promotion failed"),
            ("working_copy_state", "Workspace refresh failed"),
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
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )
        from maintenance_man.vcs import RevisionError

        mock_update_cli_deps["vcs_state"].fail(
            failing_operation,
            error=RevisionError("injected"),
            path=mock_update_cli_deps["project_paths"]["vulnerable"],
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        output = capsys.readouterr().out
        assert expected_message in output
        assert exc_info.value.code == 4
        saved = load_scan_results("vulnerable")
        assert saved.vulnerabilities[0].update_status == UpdateStatus.READY
        assert saved.vulnerabilities[0].flow == Workflow.UPDATE
        assert saved.vulnerabilities[0].failed_phase is None
        assert saved.updates[0].update_status == UpdateStatus.READY
        assert saved.updates[0].flow == Workflow.UPDATE

    def test_failed_findings_block_promote(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """If any finding fails, don't promote."""
        state = mock_update_cli_deps["vcs_state"]
        state.clear_calls()
        monkeypatch.setattr(
            "maintenance_man.services.update.process_findings",
            FakeFindingProcessor({"some-pkg": (False, "unit")}),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="vulns")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 4
        assert not any(
            call.method == "promote_bookmark_to_main" for call in state.attempts
        )
        saved = load_scan_results("vulnerable")
        assert saved.vulnerabilities[0].update_status == UpdateStatus.FAILED

    def test_promote_removes_workspace_before_deleting_bookmark(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Bookmark delete must follow workspace removal."""

        state = mock_update_cli_deps["vcs_state"]
        state.clear_calls()

        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == 0
        effects = [call.method for call in state.effects]
        assert effects.index("forget_workspace") < effects.index("delete_bookmark")

    def test_final_bookmark_cleanup_failure_preserves_completed_update(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        project_path = mock_update_cli_deps["project_paths"]["vulnerable"]
        state = mock_update_cli_deps["vcs_state"]
        state.fail(
            "delete_bookmark",
            ordinal=1,
            error=RevisionError("injected final cleanup failure"),
            path=project_path,
        )
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == ExitCode.UPDATE_FAILED
        output = capsys.readouterr().out
        assert "Bookmark cleanup failed" in output
        assert "injected final cleanup failure" in output
        repo = mock_update_cli_deps["services"].repository(project_path)
        assert repo.same_revision(left="main", right="mm/update-dependencies")
        assert (project_path / "mm-fixture-some-pkg.txt").read_text() == "1.0.1"
        saved = load_scan_results("vulnerable")
        assert not saved.findings

    def test_failed_workspace_removal_retains_directory_and_reports_failure(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state = mock_update_cli_deps["vcs_state"]
        state.fail("forget_workspace", error=RevisionError("cannot forget"))
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])

        assert exc_info.value.code == ExitCode.UPDATE_FAILED
        assert (mm_home_with_projects / "workspaces" / "vulnerable").is_dir()
        source = mock_update_cli_deps["services"].repository(
            mock_update_cli_deps["project_paths"]["vulnerable"]
        )
        assert "mm-vulnerable" in source.workspace_names()

    def test_fresh_update_creates_workspace_bookmark_and_new_change(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ):
        state = mock_update_cli_deps["vcs_state"]
        state.clear_calls()
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="none")
        )

        with pytest.raises(SystemExit):
            app(["update", "vulnerable"])

        effects = [call.method for call in state.effects]
        setup = [
            method
            for method in effects
            if method in {"create_bookmark", "add_workspace", "new_change"}
        ]
        assert setup[:3] == ["create_bookmark", "add_workspace", "new_change"]
        bookmark = next(
            call for call in state.effects if call.method == "create_bookmark"
        )
        assert dict(bookmark.arguments)["bookmark"] == "mm/update-dependencies"


class TestUpdateAll:
    """Batch mode: `mm update` with no project argument."""

    def test_skips_projects_without_scan_results(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        for result in (mm_home_with_projects / "scan-results").glob("*.json"):
            result.unlink()
        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 0

    def test_processes_all_projects(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 0
        for project in mock_update_cli_deps["project_paths"]:
            saved = load_scan_results(project)
            assert not saved.findings

    def test_any_failure_exits_4(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
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

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 4

    def test_batch_continues_after_final_bookmark_cleanup_failure(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        vulnerable_path = mock_update_cli_deps["project_paths"]["vulnerable"]
        clean_path = mock_update_cli_deps["project_paths"]["clean"]
        state = mock_update_cli_deps["vcs_state"]
        state.fail(
            "delete_bookmark",
            ordinal=1,
            error=RevisionError("injected final cleanup failure"),
            path=vulnerable_path,
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "clean"])

        assert exc_info.value.code == ExitCode.UPDATE_FAILED
        output = capsys.readouterr().out
        assert "Bookmark cleanup failed" in output
        vulnerable_repo = mock_update_cli_deps["services"].repository(vulnerable_path)
        clean_repo = mock_update_cli_deps["services"].repository(clean_path)
        assert vulnerable_repo.same_revision(
            left="main", right="mm/update-dependencies"
        )
        assert not clean_repo.bookmark_exists(bookmark="mm/update-dependencies")
        assert (clean_path / "mm-fixture-some-pkg.txt").read_text() == "1.0.1"
        for project in ("vulnerable", "clean"):
            saved = load_scan_results(project)
            assert not saved.findings

    def test_batch_no_test_config_does_not_abort(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Missing test config warns (not fatal) for single-project invocation."""

        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="all")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "no-tests"])
        assert exc_info.value.code == 0
        saved = load_scan_results("no-tests")
        assert not saved.findings


def test_update_end_to_end_uses_one_graph_and_persists_completion(
    mm_home_with_projects: Path,
    mock_update_cli_deps: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.conftest import make_vuln

    scan_result: ScanResult = mock_update_cli_deps["scan_result"]
    scan_result.vulnerabilities.append(
        make_vuln(pkg_name="unrelated", vuln_id="CVE-open", fixed_version=None)
    )
    mock_update_cli_deps["save_scan"]()
    monkeypatch.setattr("maintenance_man.cli.Prompt.ask", MagicMock(return_value="all"))
    state = mock_update_cli_deps["vcs_state"]
    source = mock_update_cli_deps["services"].repository(
        mock_update_cli_deps["project_paths"]["vulnerable"]
    )
    promoted_tip: list[str] = []
    state.hook(
        "promote_bookmark_to_main",
        phase="before",
        action=lambda: promoted_tip.append(
            source.resolve_revision(revision="mm/update-dependencies")
        ),
        path=mock_update_cli_deps["project_paths"]["vulnerable"],
    )
    state.clear_calls()

    with pytest.raises(SystemExit) as exc_info:
        app(["update", "vulnerable"])

    assert exc_info.value.code == 0
    project_path = mock_update_cli_deps["project_paths"]["vulnerable"]
    assert (project_path / "mm-fixture-some-pkg.txt").read_text() == "1.0.1"
    assert (project_path / "mm-fixture-pkg-a.txt").read_text() == "1.0.1"
    repo = mock_update_cli_deps["services"].repository(project_path)
    assert promoted_tip and repo.resolve_revision(revision="main") == promoted_tip[0]
    assert not repo.bookmark_exists(bookmark="mm/update-dependencies")
    assert "mm-vulnerable" not in repo.workspace_names()
    assert not (mm_home_with_projects / "workspaces" / "vulnerable").exists()
    saved = load_scan_results("vulnerable")
    assert [finding.pkg_name for finding in saved.findings] == ["unrelated"]
    effects = [call.method for call in state.effects]
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
            _missing("gh"),
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
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        with pytest.raises(SystemExit) as exc_info:
            app(["update"])

        assert exc_info.value.code == 0
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
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_interactive = MagicMock(side_effect=SystemExit(0))
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_project", mock_interactive)
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

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
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "outdated", "vulnerable", "outdated"])

        assert exc_info.value.code == 0
        assert mock_batch.call_args.args[1] == ["outdated", "vulnerable"]

    def test_negate_mode_excludes_named_projects(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "-n", "vulnerable", "clean"])

        assert exc_info.value.code == 0
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
        mock_update_cli_deps: dict,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "-n"])

        assert exc_info.value.code == 0
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

        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "clean"])

        assert exc_info.value.code == 4
        assert [call.args[0] for call in mock_project.call_args_list] == [
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
    monkeypatch.setattr(
        "maintenance_man.gradle_workflow.load_scan_results",
        lambda *args: mock_update_cli_deps["scan_result"],
    )
    mock_update_cli_deps["vcs_state"].seed_repository(
        gradle_project.path,
        files={
            "gradlew": (gradle_project.path / "gradlew").read_text(),
            "gradle/libs.versions.toml": (
                gradle_project.path / "gradle/libs.versions.toml"
            ).read_text(),
        },
    )
    spies: dict[str, list] = {
        "workspaces": [],
        "tests": [],
        "applies": [],
        "commits": [],
        "promotions": [],
    }
    monkeypatch.setattr(
        "maintenance_man.updater.run_test_phases",
        lambda cfg, path: (spies["tests"].append(1), (True, None))[1],
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
    with pytest.raises(SystemExit) as exc:
        app(["update", "android"])
    assert exc.value.code == 4
    assert all(f.update_status == UpdateStatus.READY for f in state.updates)
    assert all(not values for values in gradle_update_cli.values())


def test_gradle_workspace_revision_reports_uninspectable_local_properties(
    gradle_project, monkeypatch
):
    from maintenance_man.gradle import GradleError
    from maintenance_man.gradle_workflow import pin_workspace_revision
    from maintenance_man.vcs import RevisionError

    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (gradle_project.path / "local.properties").write_text("sdk.dir=/opt/android\n")
    state = FakeJjState()
    state.seed_repository(
        gradle_project.path, files={"local.properties": "sdk.dir=/opt/android\n"}
    )
    state.fail(
        "revision_file",
        error=RevisionError("inspection failed"),
        path=gradle_project.path,
    )

    with pytest.raises(
        GradleError,
        match=(
            r"Cannot inspect local.properties in mm/update-dependencies: "
            r"inspection failed"
        ),
    ):
        pin_workspace_revision(
            "android",
            gradle_project,
            "mm/update-dependencies",
            vcs=state.services(),
        )


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("status", [UpdateStatus.FAILED, UpdateStatus.READY])
def test_gradle_legacy_update_history_is_preserved_without_effects(
    gradle_update_cli,
    mock_update_cli_deps,
    monkeypatch,
    batch,
    status,
):

    scan = _gradle_scan_state(mock_update_cli_deps)
    for row in scan.updates:
        row.update_status = status
        row.flow = Workflow.UPDATE
        row.failed_phase = "unit"
    before = scan.model_dump_json()
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("legacy history cannot authorize commands"),
    )
    with pytest.raises(SystemExit) as exc:
        app(["update"] if batch else ["update", "android"])
    assert exc.value.code == ExitCode.UPDATE_FAILED
    assert scan.model_dump_json() == before
    assert all(not effects for effects in gradle_update_cli.values())
