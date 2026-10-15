from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import pytest
from rich.cells import cell_len

from maintenance_man.cli import app
from maintenance_man.models.scan import ScanResult
from tests.conftest import make_update


class TerminalStream(StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture
def output_home(mm_home: Path, tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (mm_home / "scan-results").mkdir(parents=True)
    (mm_home / "config.toml").write_text(
        "[projects.a-project-with-a-long-name-that-must-survive]\n"
        f'path = "{project}"\npackage_manager = "uv"\ndeployable = false\n'
    )
    return mm_home


def test_given_saved_scan_when_list_is_piped_then_full_record_survives(
    output_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = ScanResult(
        project="a-project-with-a-long-name-that-must-survive",
        scanned_at=datetime(2026, 1, 15, 12, tzinfo=timezone.utc),
        trivy_target=".",
    )
    (output_home / "scan-results" / f"{result.project}.json").write_text(
        result.model_dump_json()
    )

    with pytest.raises(SystemExit) as exc:
        app(["list"])

    captured = capsys.readouterr()
    assert exc.value.code == 0
    assert captured.out.splitlines() == [
        "a-project-with-a-long-name-that-must-survive\tuv\t0\t0\t0\t"
        "2026-01-15T12:00:00+00:00\t-\t-\t-\tnot deployable"
    ]
    assert captured.err == ""


def test_given_literal_finding_when_detail_is_piped_then_data_stays_in_one_record(
    output_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = ScanResult(
        project="a-project-with-a-long-name-that-must-survive",
        scanned_at=datetime(2026, 1, 15, 12, tzinfo=timezone.utc),
        trivy_target=".",
        updates=[
            make_update(
                pkg_name="literal[red]package[/red]",
                blocked_reason="needs\treview\nthen repair",
            )
        ],
    )
    (output_home / "scan-results" / f"{result.project}.json").write_text(
        result.model_dump_json()
    )

    with pytest.raises(SystemExit):
        app(["list", "--detail"])

    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "a-project-with-a-long-name-that-must-survive\tupdate\t"
        "literal[red]package[/red]\t1.0.0\t1.0.1\tpatch\t-\t-\t"
        "blocked\tneeds\\treview\\nthen repair"
    ]
    assert captured.err == ""


def test_given_unscanned_project_when_list_is_piped_then_counts_are_unknown(
    output_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit):
        app(["list"])

    assert capsys.readouterr().out.splitlines() == [
        "a-project-with-a-long-name-that-must-survive\tuv\t-\t-\t-\t"
        "never\t-\t-\t-\tnot deployable"
    ]


@pytest.mark.parametrize("width", [40, 80, 120])
def test_given_long_records_when_terminal_renders_then_each_record_stays_on_one_line(
    monkeypatch: pytest.MonkeyPatch, width: int
) -> None:
    from maintenance_man import output

    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setenv("NO_COLOR", "1")
    output.records(
        "api",
        ["status", "package"],
        [["! blocked", "org.example:" + "a" * 150], ["~ update", "literal[red]"]],
        pipe_rows=[],
    )

    lines = stream.getvalue().splitlines()
    assert len(lines) == 3
    assert all(cell_len(line) <= width for line in lines)
    assert "…" in lines[1]
    assert "literal[red]" in lines[2]
    assert not any(char in stream.getvalue() for char in "┏┓┃━╭╮")


@pytest.mark.parametrize(
    "term,no_colour,expected_ansi",
    [
        ("xterm", False, True),
        ("xterm", True, False),
        ("dumb", False, False),
        (None, False, False),
    ],
)
def test_given_terminal_environment_when_heading_prints_then_colour_obeys_policy(
    monkeypatch: pytest.MonkeyPatch,
    term: str | None,
    no_colour: bool,
    expected_ansi: bool,
) -> None:
    from maintenance_man import output

    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    if term is None:
        monkeypatch.delenv("TERM", raising=False)
    else:
        monkeypatch.setenv("TERM", term)
    if no_colour:
        monkeypatch.setenv("NO_COLOR", "1")
    else:
        monkeypatch.delenv("NO_COLOR", raising=False)

    output.heading("literal[red]", "3 packages")

    assert ("\x1b[" in stream.getvalue()) is expected_ansi
    assert "literal[red]" in stream.getvalue()


def test_given_unknown_project_when_build_runs_then_error_and_hint_use_stderr(
    output_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        app(["build", "missing"])

    captured = capsys.readouterr()
    assert exc.value.code == 1
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert "missing" in captured.err
    assert "hint: mm list" in captured.err


def test_given_selection_when_prompt_runs_then_choices_are_literal_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from maintenance_man.cli import _prompt_selection

    monkeypatch.setattr("sys.stdin", StringIO("none\n"))
    assert _prompt_selection([], [make_update()]) == ([], [])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "all/updates/1,2,.../none" in captured.err


def test_given_root_help_when_printed_then_commands_are_unboxed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        app(["--help"])
    captured = capsys.readouterr()
    assert "resolve" in captured.out and "deploy" in captured.out
    assert not any(char in captured.out for char in "╭╮│─┏━┃")


def test_given_failed_build_when_deploy_summary_prints_then_both_outcomes_survive(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from maintenance_man.cli import (
        DeployResult,
        _print_deploy_result,
        _print_deploy_summary,
    )

    _print_deploy_result(DeployResult("api", "fail", "skip"))
    _print_deploy_summary([DeployResult("api", "fail", "skip")])

    captured = capsys.readouterr()
    rows = [line.split("\t") for line in captured.out.splitlines()]
    assert [(row[0], row[1], row[2]) for row in rows] == [
        ("api", "build", "failed"),
        ("api", "deploy", "skipped"),
    ]


def test_given_verbose_invocation_when_scan_starts_then_child_logs_reset(
    output_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maintenance_man import cli, output

    output.set_verbose(True)
    monkeypatch.setattr(cli, "check_trivy_available", lambda: None)
    monkeypatch.setattr(cli, "prune_stale_bookmarks", lambda path: None)

    def scan_project(name, config, age):
        assert not output.is_verbose()
        return ScanResult(
            project=name, scanned_at=datetime.now(timezone.utc), trivy_target="."
        )

    monkeypatch.setattr(cli, "scan_project", scan_project)
    with pytest.raises(SystemExit) as exc:
        app(["scan"])
    assert exc.value.code == 0


def test_given_invalid_option_when_parsing_then_error_uses_plain_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        app(["build", "--unknown-option"])
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert "Unknown option" in captured.err
    assert "\x1b" not in captured.err


def test_given_two_clean_scans_when_batch_runs_then_empty_states_collapse(
    mm_home_with_projects: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from maintenance_man import cli

    monkeypatch.setattr(cli, "check_trivy_available", lambda: None)
    monkeypatch.setattr(cli, "prune_stale_bookmarks", lambda path: None)
    monkeypatch.setattr(
        cli,
        "scan_project",
        lambda name, *_: ScanResult(
            project=name, scanned_at=datetime.now(timezone.utc), trivy_target="."
        ),
    )
    with pytest.raises(SystemExit):
        app(["scan"])
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("projects have no findings:") == 1
    assert "No findings in" not in captured.err


@pytest.mark.parametrize("width", [40, 80, 120])
def test_given_maven_finding_when_terminal_renders_then_kind_remains_visible(
    monkeypatch: pytest.MonkeyPatch,
    width: int,
) -> None:
    from maintenance_man.cli import _print_scan_result
    from tests.conftest import make_vuln

    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setenv("NO_COLOR", "1")
    _print_scan_result(
        ScanResult(
            project="api",
            scanned_at=datetime.now(timezone.utc),
            trivy_target=".",
            vulnerabilities=[
                make_vuln(pkg_name="org.springframework.boot:spring-boot-starter-web")
            ],
        )
    )
    lines = stream.getvalue().splitlines()
    assert any("! vuln" in line and "org." in line for line in lines)
    assert all(cell_len(line) <= width for line in lines)


def test_given_indented_todo_when_piped_then_source_lines_are_preserved(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from maintenance_man.cli import _print_project_todo

    (tmp_path / "TODO.md").write_text("\n  - [ ] literal[red]\n\n")
    _print_project_todo("api", tmp_path)
    assert capsys.readouterr().out == (
        "api\t1\t\napi\t2\t  - [ ] literal[red]\napi\t3\t\n"
    )


def test_given_resolve_apply_block_when_reported_then_each_block_uses_resolve_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from maintenance_man import cli, output
    from maintenance_man.models.config import ProjectConfig
    from maintenance_man.updater import UpdateResult

    pending = make_update(pkg_name="pending")
    saved = make_update(pkg_name="saved", blocked_reason="manual prerequisite")
    scan = ScanResult(
        project="api",
        scanned_at=datetime.now(timezone.utc),
        trivy_target=".",
        updates=[pending, saved],
    )

    def process(*args, **kwargs):
        pending.blocked_reason = "catalogue changed"
        output.outcome(
            "api", "resolve", "blocked", "pending", reason=pending.blocked_reason
        )
        return [
            UpdateResult(
                "pending", "update", False, blocked_reason=pending.blocked_reason
            )
        ]

    monkeypatch.setattr(cli, "process_findings", process)
    project = ProjectConfig(path=tmp_path, package_manager="bun", test_unit="bun test")
    assert cli._run_resolve_findings("api", project, scan, tmp_path, [pending]) == 0
    rows = [line.split("\t") for line in capsys.readouterr().out.splitlines()]
    assert [(row[1], row[2], row[3]) for row in rows] == [
        ("resolve", "blocked", "saved"),
        ("resolve", "blocked", "pending"),
    ]


def test_given_closed_input_when_prompt_runs_then_eof_does_not_accept_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maintenance_man import output

    monkeypatch.setattr("sys.stdin", StringIO(""))
    with pytest.raises(EOFError):
        output.prompt("Select updates [all/none]", default="all")


def test_given_short_success_when_narrow_then_padding_does_not_create_ellipsis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maintenance_man import output

    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("COLUMNS", "40")
    monkeypatch.setenv("NO_COLOR", "1")
    output.outcome(
        "api", "update", "passed", "http-client", installed="1.0.0", target="1.0.1"
    )
    assert stream.getvalue().strip() == "✓ passed   http-client  1.0.0 → 1.0.1"


def test_given_choices_when_numbered_then_risk_and_advisory_are_visible(capsys):
    from maintenance_man.cli import _print_numbered_findings
    from maintenance_man.models.scan import SemverTier, Severity
    from tests.conftest import make_vuln

    _print_numbered_findings(
        [
            make_vuln(
                pkg_name="requests", severity=Severity.CRITICAL, vuln_id="CVE-2026-1234"
            )
        ],
        [make_update(pkg_name="web", semver_tier=SemverTier.MAJOR)],
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert all(
        value in lines[0] for value in ("1", "critical", "CVE-2026-1234", "requests")
    )
    assert all(value in lines[1] for value in ("2", "major", "web"))


def test_given_batch_deploy_when_checked_then_each_group_contains_all_outcomes(
    mm_home_with_projects,
    monkeypatch,
):
    from maintenance_man import cli
    from maintenance_man.deployer import HealthCheckResult

    path = mm_home_with_projects / "config.toml"
    path.write_text(
        path.read_text().replace(
            "[defaults]", '[defaults]\nhealthcheck_url = "http://fixture"'
        )
    )
    monkeypatch.setattr(
        cli, "should_deploy", lambda *a, **k: (cli.GateDecision.DEPLOY, "abc")
    )
    monkeypatch.setattr(cli, "_run_build_step", lambda *a: None)
    monkeypatch.setattr(cli, "_run_deploy_step", lambda *a: None)
    monkeypatch.setattr(cli, "check_health", lambda *a: HealthCheckResult(is_up=True))
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("NO_COLOR", "1")
    with pytest.raises(SystemExit) as exc:
        cli.app(["deploy", "--check"])
    assert exc.value.code == 0
    text = stream.getvalue()
    assert text.splitlines().count("deploy-only") == 1
    assert text.splitlines().count("deployable") == 1
    first, second = text.split("deployable\n")
    assert all(value in first for value in ("build", "deploy", "health check"))
    assert all(value in second for value in ("build", "deploy", "health check"))


@pytest.mark.parametrize("control", ["\x85", "\x9b", "\u2028", "\u2029"])
def test_given_unicode_control_when_piped_then_record_cannot_split(control, capsys):
    from maintenance_man import output

    output.records("api", (), (), pipe_rows=[("before" + control + "after",)])
    text = capsys.readouterr().out
    assert len(text.splitlines()) == 1
    assert control not in text


def test_given_terminal_stderr_when_stdout_is_piped_then_width_uses_stderr(monkeypatch):
    import fcntl
    import os
    import pty
    import struct
    import termios

    from maintenance_man import output

    master, slave = pty.openpty()
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 111, 0, 0))
        with os.fdopen(os.dup(slave), "w") as stderr:
            monkeypatch.setattr("sys.stderr", stderr)
            monkeypatch.setattr("sys.stdout", StringIO())
            output.set_verbose(False)
            assert output.console(stderr=True).width == 111
    finally:
        os.close(master)
        os.close(slave)


def test_given_help_aliases_when_rendered_then_description_stays_with_names(capsys):
    with pytest.raises(SystemExit):
        app(["--help"])
    lines = capsys.readouterr().out.splitlines()
    assert any("list, status, st:" in line and "List all" in line for line in lines)


def test_given_clean_and_unscanned_projects_when_listed_then_counts_stay_distinct(
    output_home,
    monkeypatch,
):
    from maintenance_man import output

    name = "a-project-with-a-long-name-that-must-survive"
    (output_home / "config.toml").write_text(
        (output_home / "config.toml").read_text()
        + f'\n[projects.unscanned]\npath = "{output_home}"\npackage_manager = "uv"\n'
    )
    scan = ScanResult(
        project=name, scanned_at=datetime.now(timezone.utc), trivy_target="."
    )
    (output_home / "scan-results" / f"{name}.json").write_text(scan.model_dump_json())
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("COLUMNS", "120")
    monkeypatch.setenv("NO_COLOR", "1")
    output.set_verbose(False)
    with pytest.raises(SystemExit):
        app(["list"])
    lines = stream.getvalue().splitlines()
    assert all(name in lines[1] for name in ("vulns", "updates", "secrets"))
    assert lines[2].split()[1:4] == ["0", "0", "0"]
    assert lines[3].split()[1:4] == ["-", "-", "-"]


@pytest.mark.parametrize("error", [None, "connection refused"])
def test_given_failed_health_check_when_reported_then_pipe_has_failed_record(
    error, monkeypatch, capsys
):
    from maintenance_man import cli
    from maintenance_man.deployer import HealthCheckResult

    monkeypatch.setattr(
        cli, "check_health", lambda *a: HealthCheckResult(is_up=False, error=error)
    )
    cli._run_health_check_step("http://fixture", "api")
    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "api\thealth\tfailed\thealth check\t-\t-\t" + (error or "not healthy")
    ]
    assert captured.err == ""


def test_given_tab_indented_todo_when_terminal_renders_then_tabs_expand_to_spaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maintenance_man.cli import _print_project_todo

    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("NO_COLOR", "1")
    (tmp_path / "TODO.md").write_text("- item\n\t- nested\n")

    _print_project_todo("api", tmp_path)

    assert stream.getvalue().splitlines() == [
        "api · TODO.md",
        "  - item",
        "          - nested",
    ]


@pytest.mark.parametrize(
    "stderr_is_terminal, verbose, shown",
    [(False, False, False), (True, False, True), (True, True, False)],
    ids=["pipe", "terminal", "verbose"],
)
def test_given_stderr_stream_when_progress_runs_then_only_quiet_terminal_sees_it(
    monkeypatch: pytest.MonkeyPatch,
    stderr_is_terminal: bool,
    verbose: bool,
    shown: bool,
) -> None:
    import time

    from maintenance_man import output

    stream = TerminalStream() if stderr_is_terminal else StringIO()
    monkeypatch.setattr("sys.stderr", stream)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setattr(output, "_PROGRESS_DELAY_SECONDS", 0)
    output.set_verbose(verbose)

    with output.progress("Running tests"):
        time.sleep(0.1)

    assert ("Running tests" in stream.getvalue()) is shown
    assert ("\x1b[?25h" in stream.getvalue()) is shown


def test_given_terminal_stdout_when_summary_prints_then_totals_go_to_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maintenance_man import output

    stdout, stderr = TerminalStream(), TerminalStream()
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)
    monkeypatch.setenv("NO_COLOR", "1")
    output.set_verbose(False)

    output.summary({"passed": 2, "failed": 1})

    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "2 passed · 1 failed\n"
