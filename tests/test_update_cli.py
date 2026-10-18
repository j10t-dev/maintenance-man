import re
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man import cli, paths
from maintenance_man.cli import ExitCode
from maintenance_man.models.events import Outcome
from maintenance_man.models.scan import (
    UpdateResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.process import ProcessError
from maintenance_man.services import update as update_service
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs import JjRepository, RevisionError
from tests.support.cli import CliDeps, refuse_jj_commands, run_mm
from tests.support.findings import (
    make_scan_result,
    make_update,
    make_vuln,
)
from tests.support.process import completed, missing_tool
from tests.support.projects import write_config
from tests.support.repository import (
    MANAGED,
    commit_file,
    commit_to_main,
    copy_jj_peer,
    copy_jj_repository,
    fail_repository_method,
    operation_id,
    push_peer_main,
    write_file,
)


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


def test_given_numeric_reply_when_choosing_findings_then_choices_and_prompt_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", StringIO("2\n"))
    update = make_update()

    chosen = cli._choose_findings([make_vuln()], [update])

    captured = capsys.readouterr()
    assert chosen == ([], [update])
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert "  1  ! vuln" in lines[0]
    assert "some-pkg" in lines[0]
    assert "  2  ~ update" in lines[1]
    assert "pkg-a" in lines[1]
    assert lines[2] == "Select updates [all/vulns/updates/1,2,.../none] (all): "


def test_given_invalid_reply_when_choosing_findings_then_error_precedes_next_prompt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", StringIO("bogus\nnone\n"))

    chosen = cli._choose_findings([make_vuln()], [make_update()])

    captured = capsys.readouterr()
    assert chosen == ([], [])
    assert captured.out == ""
    assert "error: Invalid selection: bogus" in captured.err


def _seed_pending_update(deps: CliDeps) -> tuple[JjRepository, str]:
    repo = JjRepository(deps.project_paths["vulnerable"])
    tip = commit_file(repo, "pending.txt", "1.0.1\n", "fixture: pending update")
    repo.set_bookmark(bookmark=MANAGED, revision="@-")
    return repo, tip


def _use_real_mixed_processor(
    deps: CliDeps,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, MagicMock]:
    from maintenance_man import updater

    scan_result = make_scan_result()
    scan_result.project = "outdated"
    save_scan_results(scan_result.project, scan_result)
    repo = JjRepository(deps.project_paths["outdated"])
    write_file(repo, "package.json", "{}\n")
    commit_to_main(repo, "test: add package manifest")

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
    monkeypatch.setattr("maintenance_man.updater.run_shell_command", phase)
    monkeypatch.setattr("maintenance_man.output.prompt", MagicMock(return_value="all"))
    return package, phase


_COMMAND_FIXTURES = [
    pytest.param("update", "mock_update_cli_deps", id="update"),
    pytest.param("resolve", "mock_resolve_cli_deps", id="resolve"),
]


@pytest.mark.parametrize("command,deps_fixture", _COMMAND_FIXTURES)
class TestSharedCommandPrerequisites:
    def test_missing_tool_exits_one(
        self,
        command: str,
        deps_fixture: str,
        request: pytest.FixtureRequest,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        request.getfixturevalue(deps_fixture)
        monkeypatch.setattr(
            "maintenance_man.vcs_workflow.require_tool", missing_tool("jj")
        )
        refuse_jj_commands(monkeypatch)

        assert run_mm(command, "vulnerable") == 1

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
        repo = JjRepository(deps.project_paths["vulnerable"])
        before = operation_id(repo)

        assert run_mm(command, "vulnerable") == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "rescan" in captured.err.lower()
        assert operation_id(repo) == before


def test_given_unreadable_update_bookmark_when_batch_updated_then_setup_error_no_hint(
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    example = copy_jj_repository(tmp_path / "example")
    write_config(
        mm_home,
        f'[projects.example]\npath = "{example.path}"\n'
        'package_manager = "bun"\ntest_unit = "bun test"\n',
    )
    save_scan_results(
        "example",
        make_scan_result(
            vulns=[],
            updates=[
                make_update(update_status=UpdateStatus.FAILED, flow=Workflow.UPDATE)
            ],
        ),
    )
    fail_repository_method(
        monkeypatch, example.path, "bookmark_exists", RevisionError("permission denied")
    )

    assert run_mm("update") == ExitCode.UPDATE_FAILED
    stderr = capsys.readouterr().err
    assert "error: example · update setup · permission denied" in stderr.splitlines()
    assert "rescan" not in stderr


@pytest.mark.parametrize(
    ("scenario", "expected_line"),
    [
        ("missing", "No scan results for vulnerable"),
        ("blocked", "Nothing to update in vulnerable"),
    ],
)
def test_given_update_noop_when_command_runs_then_it_exits_zero_and_notices_on_stderr(
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
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [expected_line]


@pytest.mark.parametrize(
    ("command", "deps_fixture", "other_flow", "expected_line"),
    [
        pytest.param(
            "update",
            "mock_update_cli_deps",
            Workflow.RESOLVE,
            "error: Cannot run update on vulnerable: 1 finding(s) owned by the "
            "'resolve' flow. Complete or abandon that flow first.",
            id="update",
        ),
        pytest.param(
            "resolve",
            "mock_resolve_cli_deps",
            Workflow.UPDATE,
            "error: Resolve cannot take over pending updates: bookmark "
            "mm/update-dependencies is missing. Run mm scan vulnerable to start "
            "again from main.",
            id="resolve",
        ),
    ],
)
def test_given_opposite_workflow_when_run_then_it_is_refused(
    request: pytest.FixtureRequest,
    capsys: pytest.CaptureFixture[str],
    command: str,
    deps_fixture: str,
    other_flow: Workflow,
    expected_line: str,
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
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [expected_line]


@pytest.mark.parametrize("command,deps_fixture", _COMMAND_FIXTURES)
def test_given_missing_test_config_when_run_then_fails_before_effects(
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
    monkeypatch.setattr("maintenance_man.output.prompt", MagicMock(return_value="all"))
    repo = JjRepository(deps.project_paths["no-tests"])
    before = operation_id(repo)

    assert run_mm(command, "no-tests") == ExitCode.UPDATE_FAILED
    assert (
        "error: no-tests · no test configuration · automatic updates need "
        "test_unit, test_integration or test_component"
        in capsys.readouterr().err.splitlines()
    )
    assert operation_id(repo) == before


def test_given_missing_update_bookmark_when_run_then_exits_one_with_error(
    mock_update_cli_deps: CliDeps,
    capsys: pytest.CaptureFixture[str],
) -> None:
    finding = mock_update_cli_deps.scan_result.updates[0]
    finding.update_status = UpdateStatus.FAILED
    finding.flow = Workflow.UPDATE
    mock_update_cli_deps.save_scan()

    assert run_mm("update", "vulnerable") == ExitCode.ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "error: update bookmark 'mm/update-dependencies' is missing but in-progress "
        "state exists — rescan required"
    ]


def test_given_batch_flow_conflict_when_run_then_exits_four_with_both_projects(
    mock_update_cli_deps: CliDeps,
    capsys: pytest.CaptureFixture[str],
) -> None:
    finding = mock_update_cli_deps.scan_result.updates[0]
    finding.update_status = UpdateStatus.FAILED
    finding.flow = Workflow.RESOLVE
    mock_update_cli_deps.save_scan()

    assert run_mm("update", "vulnerable", "clean") == ExitCode.UPDATE_FAILED
    captured = capsys.readouterr()
    assert any(
        line.startswith("warning: vulnerable · Cannot run update on vulnerable")
        for line in captured.err.splitlines()
    )
    assert "clean\tpromotion\tpassed\tlocal main\t-\t-\t-" in captured.out.splitlines()


class TestUpdatePreChecks:
    def test_no_projects_configured_exits_0_without_jj(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (mm_home).mkdir(parents=True, exist_ok=True)
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")

        monkeypatch.setattr(
            "maintenance_man.vcs_workflow.require_tool",
            missing_tool("jj"),
        )

        assert run_mm("update") == 0


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
        refuse_jj_commands(monkeypatch)

        assert run_mm("update") == 0


class TestUpdateSelection:
    @pytest.mark.parametrize(
        ("replies", "invalid_replies"),
        [(["vulns"], 0), (["1"], 0), (["9", "1"], 1)],
        ids=["vulns", "number", "out-of-range-then-number"],
    )
    def test_given_prompt_replies_when_updating_then_only_vulnerability_is_processed(
        self,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        replies: list[str],
        invalid_replies: int,
    ) -> None:
        prompt = MagicMock(side_effect=replies)
        monkeypatch.setattr("maintenance_man.output.prompt", prompt)

        assert run_mm("update", "vulnerable") == 0
        assert prompt.call_count == len(replies)
        assert (
            capsys.readouterr().err.count("error: Invalid selection: 9")
            == invalid_replies
        )
        project_path = mock_update_cli_deps.project_paths["vulnerable"]
        assert (project_path / "mm-fixture-some-pkg.txt").is_file()
        assert not (project_path / "mm-fixture-pkg-a.txt").exists()

    def test_none_selection_exits_0(
        self,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ):
        processor = MagicMock(return_value=[])
        monkeypatch.setattr(
            "maintenance_man.services.update.process_findings", processor
        )
        monkeypatch.setattr(
            "maintenance_man.output.prompt", MagicMock(return_value="none")
        )
        assert run_mm("update", "vulnerable") == 0
        processor.assert_not_called()


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
        workspace = paths.workspaces_dir() / "outdated"
        if failure == "unknown-dirty":
            fail_repository_method(
                monkeypatch, workspace, "has_changes", RevisionError("cannot inspect")
            )
        elif failure == "failed-discard":
            phase.side_effect = ProcessError("unit failed")
            fail_repository_method(
                monkeypatch, workspace, "discard", RevisionError("cannot discard")
            )
        else:
            fail_repository_method(
                monkeypatch, workspace, "set_bookmark", RevisionError("cannot advance")
            )

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

    @pytest.mark.parametrize("argv", [("vulnerable",), ("vulnerable", "clean")])
    def test_given_failing_package_when_updating_then_exits_four(
        self,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        argv: tuple[str, ...],
    ):
        def fail_first(findings, *_, **__):
            finding = findings[0]
            finding.update_status = UpdateStatus.FAILED
            finding.failed_phase = "unit"
            finding.flow = Workflow.UPDATE
            return [
                UpdateResult(
                    pkg_name=finding.pkg_name,
                    kind="vuln",
                    passed=False,
                    failed_phase="unit",
                )
            ]

        monkeypatch.setattr(
            "maintenance_man.services.update.process_findings", fail_first
        )
        monkeypatch.setattr(
            "maintenance_man.output.prompt", MagicMock(return_value="all")
        )
        assert run_mm("update", *argv) == 4

    def test_given_commit_failure_when_updated_then_record_and_totals_report_it(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        _use_real_mixed_processor(
            mock_update_cli_deps, mm_home_with_projects, monkeypatch
        )
        monkeypatch.setattr(
            "maintenance_man.output.prompt", MagicMock(return_value="vulns")
        )
        fail_repository_method(
            monkeypatch,
            paths.workspaces_dir() / "outdated",
            "commit",
            RevisionError("cannot commit"),
        )

        assert run_mm("update", "outdated") == 4

        captured = capsys.readouterr()
        assert captured.out.splitlines() == [
            "outdated\tupdate\tfailed\tsome-pkg\t1.0.0\t1.0.1\tcommit failed",
            "outdated\tpromotion\tfailed\tlocal main\t-\t-\t"
            "failed updates remain pending · rerun mm update outdated "
            "or repair with mm resolve outdated",
        ]
        assert "error: outdated · commit · cannot commit" in captured.err.splitlines()
        assert captured.err.splitlines()[-1] == "1 failed"


class TestUpdateOutcomeRecords:
    def test_given_one_failing_package_when_updated_then_records_and_totals_split(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _, phase = _use_real_mixed_processor(
            mock_update_cli_deps, mm_home_with_projects, monkeypatch
        )
        phase.side_effect = [None, ProcessError("unit tests failed (exit 1)")]

        assert run_mm("update", "outdated") == ExitCode.UPDATE_FAILED

        captured = capsys.readouterr()
        assert captured.out.splitlines() == [
            "outdated\tupdate\tpassed\tsome-pkg\t1.0.0\t1.0.1\t-",
            "outdated\tupdate\tfailed\tpkg-a\t1.0.0\t1.0.1\tunit failed",
            "outdated\tpromotion\tfailed\tlocal main\t-\t-\t"
            "failed updates remain pending · rerun mm update outdated "
            "or repair with mm resolve outdated",
        ]
        assert captured.err.splitlines()[-1] == "1 passed · 1 failed"

    def test_given_all_packages_pass_when_updated_then_promotion_is_a_third_record(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _use_real_mixed_processor(
            mock_update_cli_deps, mm_home_with_projects, monkeypatch
        )

        assert run_mm("update", "outdated") == ExitCode.OK

        captured = capsys.readouterr()
        assert captured.out.splitlines() == [
            "outdated\tupdate\tpassed\tsome-pkg\t1.0.0\t1.0.1\t-",
            "outdated\tupdate\tpassed\tpkg-a\t1.0.0\t1.0.1\t-",
            "outdated\tpromotion\tpassed\tlocal main\t-\t-\t-",
        ]
        assert captured.err.splitlines()[-1] == "2 passed"

    def test_given_blocked_vulnerability_when_updated_then_passing_rows_promote(
        self,
        mm_home_with_projects: Path,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _use_real_mixed_processor(
            mock_update_cli_deps, mm_home_with_projects, monkeypatch
        )
        saved = load_scan_results("outdated")
        saved.vulnerabilities.append(
            make_vuln(
                pkg_name="stuck",
                installed_version="2.0",
                fixed_version=None,
                status="affected",
                blocked_reason="no fixed version",
            )
        )
        save_scan_results("outdated", saved)

        assert run_mm("update", "outdated") == ExitCode.OK

        captured = capsys.readouterr()
        assert captured.out.splitlines() == [
            "outdated\tupdate\tblocked\tstuck\t2.0\t-\tno fixed version",
            "outdated\tupdate\tpassed\tsome-pkg\t1.0.0\t1.0.1\t-",
            "outdated\tupdate\tpassed\tpkg-a\t1.0.0\t1.0.1\t-",
            "outdated\tpromotion\tpassed\tlocal main\t-\t-\t-",
        ]
        assert captured.err.splitlines()[-1] == "2 passed · 1 blocked"


class TestUpdateNumberedSelection:
    def test_given_typed_order_when_run_then_exits_zero_with_prompt(
        self,
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
        monkeypatch.setattr("maintenance_man.output.prompt", prompt)

        assert run_mm("update", "vulnerable") == ExitCode.OK
        assert "Select updates [all/updates/1,2,.../none]" in prompt.call_args.args[0]


class TestUpdateResume:
    """Interactive rerun with update-owned in-progress state."""

    def test_resume_ready_only_attaches_workspace_and_promotes(
        self,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result = mock_update_cli_deps.scan_result
        scan_result.updates[0].update_status = UpdateStatus.READY
        scan_result.updates[0].flow = Workflow.UPDATE
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE
        mock_update_cli_deps.save_scan()
        repo, pending_tip = _seed_pending_update(mock_update_cli_deps)
        origin_main = repo.resolve_revision(revision="main@origin")
        peer = copy_jj_peer(repo)
        commit_file(peer, "elsewhere.txt", "pushed\n", "elsewhere: advance origin")
        push_peer_main(peer)
        mock_prompt = MagicMock()
        monkeypatch.setattr("maintenance_man.output.prompt", mock_prompt)

        assert run_mm("update", "vulnerable") == 0

        assert repo.resolve_revision(revision="main") == pending_tip
        assert repo.resolve_revision(revision="main@origin") == origin_main
        assert not repo.bookmark_exists(bookmark=MANAGED)
        assert "mm-vulnerable" not in repo.workspace_names()
        mock_prompt.assert_not_called()
        assert not load_scan_results("vulnerable").findings

    def test_resume_shows_only_failed_findings(
        self,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        """On resume with FAILED findings, READY findings are hidden from prompt."""
        scan_result = mock_update_cli_deps.scan_result
        scan_result.updates[0].update_status = UpdateStatus.FAILED
        scan_result.updates[0].flow = Workflow.UPDATE
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.vulnerabilities[0].flow = Workflow.UPDATE
        mock_update_cli_deps.save_scan()
        _seed_pending_update(mock_update_cli_deps)

        monkeypatch.setattr(
            "maintenance_man.output.prompt", MagicMock(return_value="none")
        )

        assert run_mm("update", "vulnerable") == 4

        captured = capsys.readouterr()
        assert "some-pkg" not in captured.err
        numbered_rows = [
            re.sub(r"\s+", " ", line.strip())
            for line in captured.err.splitlines()
            if re.match(r"\s*\d+\s", line)
        ]
        assert numbered_rows == ["1 ~ update patch 1.0.0 → 1.0.1 pkg-a"]


class TestUpdateAll:
    """Batch mode: `mm update` with no project argument."""

    def test_given_project_without_tests_when_batch_updated_then_only_it_keeps_findings(
        self,
        mock_update_cli_deps: CliDeps,
    ) -> None:
        assert run_mm("update") == ExitCode.UPDATE_FAILED
        for project in mock_update_cli_deps.project_paths:
            saved = load_scan_results(project)
            assert bool(saved.findings) is (project == "no-tests")

    def test_batch_continues_after_final_bookmark_cleanup_failure(
        self,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        vulnerable_path = mock_update_cli_deps.project_paths["vulnerable"]
        clean_path = mock_update_cli_deps.project_paths["clean"]
        fail_repository_method(
            monkeypatch,
            vulnerable_path,
            "delete_bookmark",
            RevisionError("injected final cleanup failure"),
        )

        assert run_mm("update", "vulnerable", "clean") == ExitCode.UPDATE_FAILED
        output = capsys.readouterr().err
        assert "error: vulnerable · bookmark cleanup · " in output
        vulnerable_repo = JjRepository(vulnerable_path)
        clean_repo = JjRepository(clean_path)
        assert vulnerable_repo.same_revision(left="main", right=MANAGED)
        assert not clean_repo.bookmark_exists(bookmark=MANAGED)
        assert (clean_path / "mm-fixture-some-pkg.txt").read_text() == "1.0.1"
        for project in ("vulnerable", "clean"):
            saved = load_scan_results(project)
            assert not saved.findings


@pytest.mark.parametrize(
    ("failing_operation", "stream", "expected_line"),
    [
        (
            "promote_bookmark_to_main",
            "out",
            "vulnerable\tpromotion\tfailed\tlocal main\t-\t-\t"
            "injected · rebase with jj rebase -b mm/update-dependencies "
            "-d main, then rerun",
        ),
        (
            "is_blank_working_copy",
            "err",
            "error: vulnerable · workspace refresh · injected",
        ),
        (
            "forget_workspace",
            "err",
            "error: vulnerable · workspace cleanup · injected",
        ),
    ],
)
def test_given_finalisation_failure_when_run_then_exits_four_with_error(
    mock_update_cli_deps: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failing_operation: str,
    stream: str,
    expected_line: str,
) -> None:
    monkeypatch.setattr("maintenance_man.output.prompt", MagicMock(return_value="all"))
    fail_repository_method(
        monkeypatch,
        mock_update_cli_deps.project_paths["vulnerable"],
        failing_operation,
        RevisionError("injected"),
    )

    assert run_mm("update", "vulnerable") == ExitCode.UPDATE_FAILED
    captured = capsys.readouterr()
    expected, other = (
        (captured.out, captured.err)
        if stream == "out"
        else (captured.err, captured.out)
    )
    assert expected_line in expected.splitlines()
    assert expected_line not in other.splitlines()


def test_update_end_to_end_uses_one_graph_and_persists_completion(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_result = mock_update_cli_deps.scan_result
    scan_result.vulnerabilities.append(
        make_vuln(pkg_name="unrelated", vuln_id="CVE-open", fixed_version=None)
    )
    mock_update_cli_deps.save_scan()
    monkeypatch.setattr("maintenance_man.output.prompt", MagicMock(return_value="all"))
    project_path = mock_update_cli_deps.project_paths["vulnerable"]
    promoted_tip: list[str] = []
    promote = JjRepository.promote_bookmark_to_main

    def record_tip_then_promote(repository: JjRepository, *, bookmark: str) -> None:
        if repository.path.resolve() == project_path.resolve():
            promoted_tip.append(repository.resolve_revision(revision=bookmark))
        promote(repository, bookmark=bookmark)

    monkeypatch.setattr(
        JjRepository, "promote_bookmark_to_main", record_tip_then_promote
    )

    assert run_mm("update", "vulnerable") == 0
    assert (project_path / "mm-fixture-some-pkg.txt").read_text() == "1.0.1"
    assert (project_path / "mm-fixture-pkg-a.txt").read_text() == "1.0.1"
    repo = JjRepository(project_path)
    assert promoted_tip == [repo.resolve_revision(revision="main")]
    assert not repo.bookmark_exists(bookmark=MANAGED)
    assert "mm-vulnerable" not in repo.workspace_names()
    assert not (mm_home_with_projects / "workspaces" / "vulnerable").exists()
    saved = load_scan_results("vulnerable")
    assert [finding.pkg_name for finding in saved.findings] == ["unrelated"]


class TestUpdateTargetSelection:
    def test_excluding_all_projects_exits_0_without_jj(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.vcs_workflow.require_tool",
            missing_tool("jj"),
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
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "No target projects\n"

    @pytest.mark.parametrize(
        ("argv", "expected"),
        [
            (
                (),
                [
                    "clean",
                    "deploy-only",
                    "deployable",
                    "no-deploy",
                    "no-tests",
                    "outdated",
                    "vulnerable",
                ],
            ),
            (("outdated", "vulnerable", "outdated"), ["outdated", "vulnerable"]),
            (
                ("-n", "vulnerable", "clean"),
                ["deploy-only", "deployable", "no-deploy", "no-tests", "outdated"],
            ),
            (
                ("-n",),
                [
                    "clean",
                    "deploy-only",
                    "deployable",
                    "no-deploy",
                    "no-tests",
                    "outdated",
                    "vulnerable",
                ],
            ),
        ],
    )
    def test_given_target_arguments_when_batch_updating_then_projects_are_ordered(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        argv: tuple[str, ...],
        expected: list[str],
    ) -> None:
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        assert run_mm("update", *argv) == 0
        mock_batch.assert_called_once()
        assert mock_batch.call_args.args[1] == expected

    def test_single_name_keeps_interactive_mode(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_interactive = MagicMock(side_effect=SystemExit(0))
        mock_batch = MagicMock(side_effect=SystemExit(0))
        monkeypatch.setattr(update_service, "update_project", mock_interactive)
        monkeypatch.setattr(update_service, "update_projects", mock_batch)

        assert run_mm("update", "vulnerable") == 0
        mock_interactive.assert_called_once()
        mock_batch.assert_not_called()

    @pytest.mark.parametrize("argv", [("missing",), ("-n", "missing")])
    def test_given_unknown_project_when_updating_then_exits_one_with_hint(
        self,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
        argv: tuple[str, ...],
    ) -> None:
        assert run_mm("update", *argv) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.startswith("error: Unknown project 'missing'")
        assert captured.err.splitlines()[-1] == "hint: mm list"

    def test_batch_continues_after_project_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_project = MagicMock(
            side_effect=[
                update_service.UpdateSetupError("setup failed"),
                update_service.ProjectUpdate(
                    "clean",
                    Outcome.SUCCEEDED,
                    (UpdateResult(pkg_name="pkg-a", kind="update", passed=True),),
                ),
            ]
        )
        monkeypatch.setattr(update_service, "update_project", mock_project)

        assert run_mm("update", "vulnerable", "clean") == 4
        assert [call.args[0] for call in mock_project.call_args_list] == [
            "vulnerable",
            "clean",
        ]


def test_given_batch_with_blocked_findings_when_updated_then_totals_sum_them(
    mm_home_with_projects: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    passed = UpdateResult(pkg_name="pkg-a", kind="update", passed=True)
    mock_project = MagicMock(
        side_effect=[
            update_service.ProjectUpdate(
                "vulnerable",
                Outcome.FAILED,
                (passed,),
                blocked=1,
            ),
            update_service.ProjectUpdate(
                "clean",
                Outcome.FAILED,
                (),
                blocked=2,
            ),
        ]
    )
    monkeypatch.setattr(update_service, "update_project", mock_project)

    assert run_mm("update", "vulnerable", "clean") == ExitCode.UPDATE_FAILED

    assert capsys.readouterr().err.splitlines()[-1] == "1 passed · 3 blocked"


@pytest.mark.parametrize(
    "argv",
    [
        ("vulnerable", "--continue"),
        ("vulnerable", "--worktree"),
        ("--projects", "vulnerable"),
    ],
)
def test_given_removed_option_when_update_runs_then_it_is_rejected(
    mm_home_with_projects: Path,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, ...],
) -> None:
    assert run_mm("update", *argv) == 1
    captured = capsys.readouterr()
    assert "Unknown option" in (captured.out + captured.err)


def test_given_mixed_results_when_totals_printed_then_stderr_counts_each_state(capsys):
    cli._print_result_totals(
        [
            UpdateResult(pkg_name="room", kind="update", passed=True),
            UpdateResult(
                pkg_name="okhttp", kind="vuln", passed=False, failed_phase="unit"
            ),
        ],
        blocked=0,
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "1 passed · 1 failed\n"
