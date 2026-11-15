import re
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import ExitCode
from maintenance_man.finding_selection import choose_findings, parse_selection
from maintenance_man.models.events import Outcome
from maintenance_man.models.scan import (
    Failed,
    GradleBlock,
    Ready,
    SemverTier,
    UpdateFinding,
    UpdateResult,
    VulnFinding,
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
from tests.support.projects import write_bun_manifest, write_config
from tests.support.repository import (
    MANAGED,
    commit_file,
    commit_to_main,
    copy_jj_peer,
    copy_jj_repository,
    fail_repository_method,
    operation_id,
    push_peer_main,
)

_VULN = make_vuln(pkg_name="v1")
_UPDATES = [make_update(pkg_name="u1"), make_update(SemverTier.MINOR, pkg_name="u2")]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("all", (["v1"], ["u1", "u2"]), id="all"),
        pytest.param(
            " ALL ", (["v1"], ["u1", "u2"]), id="keyword-ignores-case-and-space"
        ),
        pytest.param("Vulns", (["v1"], []), id="vulns"),
        pytest.param("updates", ([], ["u1", "u2"]), id="updates"),
        pytest.param("none", ([], []), id="none"),
        pytest.param("3", ([], ["u2"]), id="single-index"),
        pytest.param("2,1", (["v1"], ["u1"]), id="several-indexes"),
        pytest.param("3,1,3", (["v1"], ["u2"]), id="duplicate-index-once"),
        pytest.param("4", None, id="out-of-range"),
        pytest.param("0", None, id="zero"),
        pytest.param("1,x", None, id="non-numeric"),
        pytest.param("", None, id="empty"),
        pytest.param("1,,2", None, id="empty-part"),
    ],
)
def test_given_reply_when_selection_parsed_then_chosen_findings_or_none(text, expected):
    selected = parse_selection(text, [_VULN, *_UPDATES], [_VULN], _UPDATES)

    names = (
        None
        if selected is None
        else (
            [finding.pkg_name for finding in selected[0]],
            [finding.pkg_name for finding in selected[1]],
        )
    )
    assert names == expected


@pytest.mark.parametrize(
    ("vulns", "updates", "reply", "expected_names", "expected_rows", "expected_prompt"),
    [
        pytest.param(
            [make_vuln()],
            [make_update()],
            "2\n",
            ([], ["pkg-a"]),
            [
                "    1  ! vuln    high · CVE-2024-0001  1.0.0 → 1.0.1  some-pkg",
                "    2  ~ update  patch                 1.0.0 → 1.0.1  pkg-a",
            ],
            "Select updates [all/vulns/updates/1,2,.../none] (all): ",
            id="vulnerability-and-update",
        ),
        pytest.param(
            [],
            [make_update(pkg_name="pkg-a"), make_update(pkg_name="pkg-b")],
            "2,1\n",
            ([], ["pkg-b", "pkg-a"]),
            [
                "    1  ~ update  patch  1.0.0 → 1.0.1  pkg-a",
                "    2  ~ update  patch  1.0.0 → 1.0.1  pkg-b",
            ],
            "Select updates [all/updates/1,2,.../none] (all): ",
            id="typed-order-without-vulnerabilities",
        ),
    ],
)
def test_given_numeric_reply_when_choosing_findings_then_choices_and_prompt_on_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    vulns: list[VulnFinding],
    updates: list[UpdateFinding],
    reply: str,
    expected_names: tuple[list[str], list[str]],
    expected_rows: list[str],
    expected_prompt: str,
) -> None:
    monkeypatch.setattr("sys.stdin", StringIO(reply))

    chosen = choose_findings(vulns, updates)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert [
        [finding.pkg_name for finding in chosen[0]],
        [finding.pkg_name for finding in chosen[1]],
    ] == list(expected_names)
    *rows, prompt = captured.err.splitlines()
    assert rows == expected_rows
    assert prompt == expected_prompt


def test_given_invalid_reply_when_choosing_findings_then_error_precedes_next_prompt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", StringIO("bogus\nnone\n"))

    chosen = choose_findings([make_vuln()], [make_update()])

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

    scan_result = make_scan_result(package_manager="bun")
    scan_result.project_name = "outdated"
    save_scan_results(scan_result.project_name, scan_result)
    repo = JjRepository(deps.project_paths["outdated"])
    versions = {"some-pkg": "1.0.0", "pkg-a": "1.0.0"}
    write_bun_manifest(repo, versions)
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
    monkeypatch.setattr(
        "maintenance_man.package_managers.resolved_bun_versions",
        lambda _path: versions,
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
        monkeypatch.setattr("maintenance_man.cli.require_tool", missing_tool("jj"))
        refuse_jj_commands(monkeypatch)

        assert run_mm(command, "vulnerable") == 1


_OLD_SHAPE_SCAN = (
    '{"project_name": "vulnerable", "scanned_at": "2026-01-15T12:00:00Z", '
    '"vulnerabilities": [], "updates": [], "secrets": [], "update_status": null}'
)


@pytest.mark.parametrize("command", ["update", "resolve"])
def test_given_corrupt_scan_file_when_project_command_runs_then_one_line_and_hint(
    mm_home_with_projects: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    (mm_home_with_projects / "scan-results" / "vulnerable.json").write_text(
        _OLD_SHAPE_SCAN, encoding="utf-8"
    )

    assert run_mm(command, "vulnerable") == ExitCode.ERROR

    err = capsys.readouterr().err.splitlines()
    assert err[0].startswith("error: corrupt scan results for vulnerable: ")
    assert err[1:] == ["hint: mm scan vulnerable"]


def test_given_corrupt_scan_file_when_batch_updated_then_skipped_and_exit_failed(
    mm_home_with_projects: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (mm_home_with_projects / "scan-results" / "vulnerable.json").write_text(
        _OLD_SHAPE_SCAN, encoding="utf-8"
    )
    real_update_project = update_service.update_project

    def only_vulnerable_runs(name, project, *, choose, emit):
        if name == "vulnerable":
            return real_update_project(name, project, choose=choose, emit=emit)
        return update_service.ProjectUpdate(name, Outcome.SUCCEEDED, ())

    monkeypatch.setattr(update_service, "update_project", only_vulnerable_runs)

    assert run_mm("update") == ExitCode.UPDATE_FAILED

    expected = "warning: vulnerable · corrupt scan results; run mm scan vulnerable"
    assert expected in capsys.readouterr().err.splitlines()


def test_given_closed_stdin_when_findings_prompted_then_one_line_error(
    mock_update_cli_deps: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.stdin", StringIO(""))

    assert run_mm("update", "vulnerable") == ExitCode.ERROR

    assert capsys.readouterr().err.splitlines()[-1] == (
        "error: input closed before a selection was made"
    )


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
            updates=[make_update(state=Failed(flow=Workflow.UPDATE, phase="unit"))],
            package_manager="bun",
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
    ("scenario", "expected_out", "expected_lines"),
    [
        ("missing", "", ["No scan results for vulnerable"]),
        ("unfixable", "", ["Nothing to update in vulnerable"]),
        (
            "blocked",
            "vulnerable\tupdate\tblocked\tpkg-a\t1.0.0\t1.0.1\ttoo young\n",
            ["1 blocked"],
        ),
    ],
)
def test_given_update_noop_when_command_runs_then_it_exits_zero_and_notices_on_stderr(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    capsys: pytest.CaptureFixture[str],
    scenario: str,
    expected_out: str,
    expected_lines: list[str],
) -> None:
    if scenario == "missing":
        (mm_home_with_projects / "scan-results" / "vulnerable.json").unlink()
    elif scenario == "unfixable":
        save_scan_results(
            "vulnerable",
            make_scan_result(vulns=[make_vuln(fixed_version=None)], updates=[]),
        )
    else:
        save_scan_results(
            "vulnerable",
            make_scan_result(
                vulns=[],
                updates=[
                    make_update(state=GradleBlock(kind="age", reason="too young"))
                ],
            ),
        )

    assert run_mm("update", "vulnerable") == ExitCode.OK
    captured = capsys.readouterr()
    assert captured.out == expected_out
    assert captured.err.splitlines() == expected_lines


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
        existing.state = None
    deps.scan_result.updates[0].state = Failed(flow=other_flow, phase="apply")
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
            finding.state = None
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
    mock_update_cli_deps.scan_result.updates[0].state = Failed(
        flow=Workflow.UPDATE, phase="unit"
    )
    mock_update_cli_deps.save_scan()

    assert run_mm("update", "vulnerable") == ExitCode.ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "error: update bookmark 'mm/update-dependencies' is missing but in-progress "
        "state exists — rescan required"
    ]


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


def test_given_blocked_passing_and_failing_rows_when_updated_then_records_split(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, phase = _use_real_mixed_processor(
        mock_update_cli_deps, mm_home_with_projects, monkeypatch
    )
    phase.side_effect = [None, ProcessError("unit tests failed (exit 1)")]
    saved = load_scan_results("outdated")
    saved.vulnerabilities.append(
        make_vuln(
            pkg_name="stuck",
            installed_version="2.0",
            fixed_version=None,
            status="affected",
            state=GradleBlock(kind="mapping", reason="no fixed version"),
        )
    )
    save_scan_results("outdated", saved)

    assert run_mm("update", "outdated") == ExitCode.UPDATE_FAILED

    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "outdated\tupdate\tblocked\tstuck\t2.0\t-\tno fixed version",
        "outdated\tupdate\tpassed\tsome-pkg\t1.0.0\t1.0.1\t-",
        "outdated\tupdate\tfailed\tpkg-a\t1.0.0\t1.0.1\tunit failed",
        "outdated\tpromotion\tfailed\tlocal main\t-\t-\t"
        "failed updates remain pending · rerun mm update outdated "
        "or repair with mm resolve outdated",
    ]
    assert captured.err.splitlines()[-1] == "1 passed · 1 failed · 1 blocked"


def test_given_passing_updates_when_updated_then_totals_follow_the_promotion_record(
    mm_home_with_projects: Path,
    mock_update_cli_deps: CliDeps,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_real_mixed_processor(mock_update_cli_deps, mm_home_with_projects, monkeypatch)
    combined = StringIO()
    monkeypatch.setattr("sys.stdout", combined)
    monkeypatch.setattr("sys.stderr", combined)

    assert run_mm("update", "outdated") == ExitCode.OK

    assert combined.getvalue().splitlines()[-2:] == [
        "outdated\tpromotion\tpassed\tlocal main\t-\t-\t-",
        "2 passed",
    ]


class TestUpdateResume:
    """Interactive rerun with update-owned in-progress state."""

    def test_resume_ready_only_attaches_workspace_and_promotes(
        self,
        mock_update_cli_deps: CliDeps,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result = mock_update_cli_deps.scan_result
        scan_result.updates[0].state = Ready(flow=Workflow.UPDATE)
        scan_result.vulnerabilities[0].state = Ready(flow=Workflow.UPDATE)
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
        """On resume with failed findings, ready findings are hidden from prompt."""
        scan_result = mock_update_cli_deps.scan_result
        scan_result.updates[0].state = Failed(flow=Workflow.UPDATE, phase="unit")
        scan_result.vulnerabilities[0].state = Ready(flow=Workflow.UPDATE)
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


class TestUpdateTargetSelection:
    def test_excluding_all_projects_exits_0_without_jj(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            "maintenance_man.cli.require_tool",
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
