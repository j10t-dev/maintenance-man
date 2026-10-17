import fcntl
import os
import pty
import struct
import termios
import time
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest
from rich.cells import cell_len

from maintenance_man import output
from maintenance_man.cli import _print_project_todo, _print_scan_result
from maintenance_man.exit_codes import ExitCode
from maintenance_man.models.scan import ScanResult
from tests.conftest import (
    TerminalStream,
    make_update,
    make_vuln,
    run_mm,
    write_config,
)

_LONG_NAME = "a-project-with-a-long-name-that-must-survive"


def _save_scan(home: Path, result: ScanResult) -> None:
    (home / "scan-results" / f"{result.project}.json").write_text(
        result.model_dump_json(), encoding="utf-8"
    )


def _scanned_result(**overrides: object) -> ScanResult:
    return ScanResult.model_validate(
        {
            "project": _LONG_NAME,
            "scanned_at": datetime(2026, 1, 15, 12, tzinfo=UTC),
            "trivy_target": ".",
        }
        | overrides
    )


@pytest.fixture
def output_home(mm_home: Path, tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (mm_home / "scan-results").mkdir(parents=True)
    write_config(
        mm_home,
        f'[projects.{_LONG_NAME}]\npath = "{project}"\n'
        'package_manager = "uv"\ndeployable = false\n',
    )
    return mm_home


def test_given_saved_scan_when_list_is_piped_then_full_record_survives(
    output_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _save_scan(output_home, _scanned_result())

    assert run_mm("list") == 0

    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "a-project-with-a-long-name-that-must-survive\tuv\t0\t0\t0\t"
        "2026-01-15T12:00:00+00:00\t-\t-\t-\tnot deployable"
    ]
    assert captured.err == ""


def test_given_literal_finding_when_detail_is_piped_then_data_stays_in_one_record(
    output_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    update = make_update(
        pkg_name="literal[red]package[/red]",
        blocked_reason="needs\treview\nthen repair",
    )
    _save_scan(output_home, _scanned_result(updates=[update]))

    assert run_mm("list", "--detail") == 0

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
    assert run_mm("list") == 0

    assert capsys.readouterr().out.splitlines() == [
        "a-project-with-a-long-name-that-must-survive\tuv\t-\t-\t-\t"
        "never\t-\t-\t-\tnot deployable"
    ]


@pytest.mark.parametrize("width", [40, 80, 120])
def test_given_long_records_when_terminal_renders_then_each_record_stays_on_one_line(
    monkeypatch: pytest.MonkeyPatch, width: int
) -> None:
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
    ("term", "no_colour", "expected_ansi"),
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
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    if term is None:
        monkeypatch.delenv("TERM", raising=False)
    else:
        monkeypatch.setenv("TERM", term)
    if no_colour:
        monkeypatch.setenv("NO_COLOR", "1")

    output.heading("literal[red]", "3 packages")

    assert ("\x1b[" in stream.getvalue()) is expected_ansi
    assert "literal[red]" in stream.getvalue()


@pytest.mark.parametrize("control", ["\x85", "\x9b", "\u2028", "\u2029"])
def test_given_unicode_control_when_piped_then_record_cannot_split(
    control: str, capsys: pytest.CaptureFixture[str]
) -> None:
    output.records("api", (), (), pipe_rows=[("before" + control + "after",)])

    text = capsys.readouterr().out
    assert len(text.splitlines()) == 1
    assert control not in text


def test_given_clean_and_unscanned_projects_when_listed_then_counts_stay_distinct(
    output_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = output_home / "config.toml"
    write_config(
        output_home,
        config.read_text(encoding="utf-8")
        + f'\n[projects.unscanned]\npath = "{output_home}"\npackage_manager = "uv"\n',
    )
    _save_scan(output_home, _scanned_result())
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("COLUMNS", "120")
    monkeypatch.setenv("NO_COLOR", "1")

    assert run_mm("list") == 0

    lines = stream.getvalue().splitlines()
    assert all(name in lines[1] for name in ("vulns", "updates", "secrets"))
    assert lines[2].split()[1:4] == ["0", "0", "0"]
    assert lines[3].split()[1:4] == ["-", "-", "-"]


def test_given_indented_todo_when_piped_then_source_lines_are_preserved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "TODO.md").write_text("\n  - [ ] literal[red]\n\n")

    _print_project_todo("api", tmp_path)

    assert capsys.readouterr().out == (
        "api\t1\t\napi\t2\t  - [ ] literal[red]\napi\t3\t\n"
    )


def test_given_tab_indented_todo_when_terminal_renders_then_tabs_expand_to_spaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def test_given_terminal_stderr_when_stdout_is_piped_then_width_uses_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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


def test_given_short_success_when_narrow_then_padding_does_not_create_ellipsis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("COLUMNS", "40")
    monkeypatch.setenv("NO_COLOR", "1")

    output.outcome(
        "api", "update", "passed", "http-client", installed="1.0.0", target="1.0.1"
    )

    assert stream.getvalue().strip() == "✓ passed    http-client  1.0.0 → 1.0.1"


@pytest.mark.parametrize("width", [40, 80, 120])
def test_given_maven_finding_when_terminal_renders_then_kind_remains_visible(
    monkeypatch: pytest.MonkeyPatch, width: int
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setenv("NO_COLOR", "1")
    vuln = make_vuln(pkg_name="org.springframework.boot:spring-boot-starter-web")

    _print_scan_result(_scanned_result(project="api", vulnerabilities=[vuln]))

    lines = stream.getvalue().splitlines()
    assert any("! vuln" in line and "org." in line for line in lines)
    assert all(cell_len(line) <= width for line in lines)


def test_given_tab_indented_todo_when_todo_is_piped_then_tab_is_escaped_in_text(
    mm_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "TODO.md").write_text("- item\n\tindented\n", encoding="utf-8")
    write_config(
        mm_home, f'[projects.project]\npath = "{project}"\npackage_manager = "uv"\n'
    )

    assert run_mm("todo") == 0

    assert capsys.readouterr().out.splitlines() == [
        "project\t1\t- item",
        "project\t2\t\\tindented",
    ]


def test_given_one_clean_project_when_batch_scanned_then_notice_names_only_it(
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in ("first", "second"):
        (tmp_path / name).mkdir()
    write_config(
        mm_home,
        f'[projects.first]\npath = "{tmp_path / "first"}"\npackage_manager = "uv"\n'
        f'[projects.second]\npath = "{tmp_path / "second"}"\npackage_manager = "uv"\n',
    )
    monkeypatch.setattr(
        "maintenance_man.services.scan.prune_stale_bookmarks", lambda **kwargs: None
    )
    monkeypatch.setattr(
        "maintenance_man.services.scan.scan_project",
        lambda name, project, days: _scanned_result(
            project=name, updates=[make_update()] if name == "second" else []
        ),
    )

    assert run_mm("scan") == ExitCode.UPDATES_FOUND

    assert (
        capsys.readouterr()
        .err.splitlines()[-1]
        .startswith("1 projects have no findings: first · scanned in ")
    )


def test_given_closed_input_when_prompt_runs_then_eof_does_not_accept_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin", StringIO(""))

    with pytest.raises(EOFError):
        output.prompt("Select updates [all/none]", default="all")


def test_given_choice_rows_when_printed_then_columns_align_and_text_stays_literal(
    capsys: pytest.CaptureFixture[str],
) -> None:
    output.choices([("! vuln", "high · CVE-1", "a[b]"), ("~ update", "patch", "u[p]")])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "    1  ! vuln    high · CVE-1  a[b]\n    2  ~ update  patch         u[p]\n"
    )


def test_given_long_last_column_when_choices_print_then_it_wraps_under_itself(
    capsys: pytest.CaptureFixture[str],
) -> None:
    members = " · ".join(
        f"alias{number}: group:artifact{number} 1.{number} → 2.{number}"
        for number in range(4)
    )

    output.choices([("room → 2.8.5", members)])

    lines = capsys.readouterr().err.splitlines()
    prefix = "    1  room → 2.8.5  "
    assert len(lines) > 1
    assert lines[0].startswith(prefix)
    assert all(line.startswith(" " * len(prefix)) for line in lines[1:])
    assert all(cell_len(line) <= 80 for line in lines)
    assert "…" not in "".join(lines)
    assert " ".join([lines[0][len(prefix) :], *map(str.strip, lines[1:])]) == members


def test_given_help_aliases_when_rendered_then_description_stays_with_names(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run_mm("--help") == ExitCode.OK

    lines = capsys.readouterr().out.splitlines()
    assert any("list, status, st:" in line and "List all" in line for line in lines)


@pytest.mark.parametrize(
    ("stderr_is_terminal", "verbose", "shown"),
    [(False, False, False), (True, False, True), (True, True, False)],
    ids=["pipe", "terminal", "verbose"],
)
def test_given_stderr_stream_when_progress_runs_then_only_quiet_terminal_sees_it(
    monkeypatch: pytest.MonkeyPatch,
    stderr_is_terminal: bool,
    verbose: bool,
    shown: bool,
) -> None:
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
    stdout, stderr = TerminalStream(), TerminalStream()
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)
    monkeypatch.setenv("NO_COLOR", "1")

    output.summary({"passed": 2, "failed": 1})

    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "2 passed · 1 failed\n"
