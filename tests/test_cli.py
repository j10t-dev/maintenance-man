from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man import __version__, cli
from maintenance_man.cli import ExitCode
from maintenance_man.config import ConfigError
from maintenance_man.gradle import GradleError
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.scanner import ScanError
from maintenance_man.services import WorkflowError
from maintenance_man.services.update import UpdateSetupError
from maintenance_man.vcs import RevisionError
from tests.support.cli import refuse_jj_commands, run_mm, terminal_stdout
from tests.support.process import missing_tool
from tests.support.projects import write_config
from tests.support.repository import configure_jj_projects


@pytest.mark.parametrize(
    ("argv", "service_seam", "error", "expected_code"),
    [
        (
            ("scan", "vulnerable"),
            "maintenance_man.services.scan.scan_one",
            ScanError("trivy failed"),
            1,
        ),
        (
            ("scan", "vulnerable"),
            "maintenance_man.services.scan.scan_one",
            GradleError("report failed"),
            1,
        ),
        (
            ("scan", "vulnerable"),
            "maintenance_man.services.scan.scan_one",
            RevisionError("jj failed"),
            1,
        ),
        (
            ("scan", "vulnerable"),
            "maintenance_man.services.scan.scan_one",
            OutdatedCheckError("uv failed"),
            1,
        ),
        (
            ("update", "vulnerable"),
            "maintenance_man.services.update.update_project",
            WorkflowError("refused"),
            1,
        ),
        (
            ("update", "vulnerable"),
            "maintenance_man.services.update.update_project",
            UpdateSetupError("refused"),
            1,
        ),
    ],
    ids=[
        "scan-error",
        "gradle-error",
        "revision-error",
        "outdated-check-error",
        "workflow-error",
        "workflow-error-subclass",
    ],
)
def test_given_a_service_refusal_when_a_command_runs_then_it_maps_to_one_error_line(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, str],
    service_seam: str,
    error: Exception,
    expected_code: int,
) -> None:
    configure_jj_projects(mm_home_with_projects, tmp_path)
    monkeypatch.setattr(service_seam, MagicMock(side_effect=error))

    code = run_mm(*argv)
    captured = capsys.readouterr()
    error_lines = [
        line for line in captured.err.splitlines() if line.startswith("error:")
    ]

    assert (code, captured.out, error_lines) == (
        expected_code,
        "",
        [f"error: {error}"],
    )


_NO_PROJECTS = ["No projects configured", "hint: add projects to {home}/config.toml"]
_UNKNOWN_PROJECT = [
    "error: Unknown project 'missing'. Known projects: api",
    "hint: mm list",
]
_NO_PROJECTS_CONFIG = "[defaults]\n"
_ONE_PROJECT_CONFIG = '[projects.api]\npath = "{path}"\npackage_manager = "uv"\n'


@pytest.mark.parametrize(
    ("argv", "config", "expected_code", "expected_stderr"),
    [
        *[
            pytest.param(
                (command,),
                _NO_PROJECTS_CONFIG,
                ExitCode.OK,
                _NO_PROJECTS,
                id=f"{command}-empty",
            )
            for command in ("list", "scan", "update", "sync", "todo")
        ],
        pytest.param(
            ("list", "--config", "{elsewhere}"),
            _NO_PROJECTS_CONFIG,
            ExitCode.OK,
            ["No projects configured", "hint: add projects to {elsewhere}"],
            id="list-empty-config-flag",
        ),
        pytest.param(
            ("update", "missing"),
            _NO_PROJECTS_CONFIG,
            ExitCode.OK,
            _NO_PROJECTS,
            id="update-named-empty",
        ),
        *[
            pytest.param(
                (command, "missing"),
                _ONE_PROJECT_CONFIG,
                ExitCode.ERROR,
                _UNKNOWN_PROJECT,
                id=f"{command}-unknown",
            )
            for command in (
                "scan",
                "update",
                "resolve",
                "deploy",
                "build",
                "test",
                "todo",
            )
        ],
        pytest.param(
            ("update", "-n", "missing"),
            _ONE_PROJECT_CONFIG,
            ExitCode.ERROR,
            _UNKNOWN_PROJECT,
            id="update-negated-unknown",
        ),
    ],
)
def test_given_missing_project_when_a_command_runs_then_it_stops_before_any_tool(
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, ...],
    config: str,
    expected_code: ExitCode,
    expected_stderr: list[str],
) -> None:
    elsewhere = tmp_path / "elsewhere.toml"
    text = config.format(path=tmp_path)
    write_config(mm_home, text)
    elsewhere.write_text(text, encoding="utf-8")
    monkeypatch.setattr("maintenance_man.cli.require_tool", missing_tool("jj"))
    monkeypatch.setattr("maintenance_man.scanner.require_tool", missing_tool("trivy"))
    refuse_jj_commands(monkeypatch)

    code = run_mm(*(part.format(elsewhere=elsewhere) for part in argv))

    captured = capsys.readouterr()
    assert (code, captured.out, captured.err.splitlines()) == (
        expected_code,
        "",
        [line.format(home=mm_home, elsewhere=elsewhere) for line in expected_stderr],
    )


class TestHelp:
    def test_help_contains_description(self, capsys: pytest.CaptureFixture[str]):
        assert run_mm("--help") == 0
        assert "maintenance" in capsys.readouterr().out.lower()

    def test_given_help_when_printed_then_commands_are_listed_without_panels(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert run_mm("--help") == ExitCode.OK

        out = capsys.readouterr().out
        assert "Commands:" in out
        assert not set("╭╮╰╯│─") & set(out)

    def test_given_invalid_option_when_parsing_then_error_is_plain_stderr_exit_one(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert run_mm("scan", "--bogus") == ExitCode.ERROR

        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.startswith("error: ")
        assert "--bogus" in captured.err
        assert not set("╭╮╰╯│─") & set(captured.err)


class TestVersion:
    def test_version_prints_version(self, capsys: pytest.CaptureFixture[str]):
        assert run_mm("--version") == 0
        assert __version__ in capsys.readouterr().out


class TestInitCommand:
    def test_init_uses_redirected_home(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        assert run_mm("init") == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert str(mm_home) in captured.err.replace("\n", "")
        assert (mm_home / "config.toml").is_file()

    def test_init_prints_bracketed_home_path_literally(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        home = tmp_path / "[home]"
        monkeypatch.setattr("maintenance_man.paths.MM_HOME", home)

        assert run_mm("init") == 0

        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [
            f"Initialised {home}",
            f"Add projects to {home / 'config.toml'}",
        ]


def test_fatal_prints_bracketed_plain_text_literally(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli, "load_config", MagicMock(side_effect=ConfigError("bad [projects.x]"))
    )

    assert run_mm("scan") == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: bad [projects.x]\n"


@pytest.mark.parametrize(
    ("project", "expects_hint"),
    [("unlisted", True), ("ghost", False)],
    ids=["unknown-name", "missing-path"],
)
def test_given_unresolvable_project_when_build_runs_then_only_unknown_name_hints_list(
    mm_home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    project: str,
    expects_hint: bool,
) -> None:
    write_config(
        mm_home,
        f'[projects.ghost]\npath = "{tmp_path / "gone"}"\npackage_manager = "uv"\n',
    )

    assert run_mm("build", project) == ExitCode.ERROR

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: ")
    assert project in captured.err
    assert ("hint: mm list" in captured.err.splitlines()) is expects_hint


def test_config_validation_error_keeps_pydantic_type_suffix(
    mm_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mm_home.mkdir(parents=True)
    write_config(mm_home, '[projects.api]\npackage_manager = "uv"\n')

    assert run_mm("scan") == 1

    assert "[type=missing" in capsys.readouterr().err


@pytest.mark.parametrize("use_config_flag", [False, True], ids=["default", "flag"])
@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("deploy", "Add deploy_command to [projects.api] in ~/.mm/config.toml."),
        ("build", "hint: add build_command to [projects.api] in {config}"),
        ("test", "hint: add test_unit to [projects.api] in {config}"),
    ],
)
def test_missing_command_error_keeps_config_table_literal(
    mm_home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    expected: str,
    use_config_flag: bool,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    mm_home.mkdir(parents=True)
    write_config(
        mm_home,
        f'[projects.api]\npath = "{project}"\npackage_manager = "uv"\n',
    )
    config = mm_home / "config.toml"
    argv = [command, "api"]
    if use_config_flag:
        config = write_config(
            tmp_path,
            f'[projects.api]\npath = "{project}"\npackage_manager = "uv"\n',
            filename="elsewhere.toml",
        )
        argv += ["--config", str(config)]

    assert run_mm(*argv) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert expected.format(config=config) in " ".join(captured.err.split())


class TestDeployCommand:
    def test_deploy_no_project_is_mass_mode(self, mm_home: Path):
        """Deploy with no project triggers mass mode (exits OK with no projects)."""
        mm_home.mkdir(parents=True, exist_ok=True)
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")
        assert run_mm("deploy") == 0


_ITEMS = "- Fix the widget\n"


@pytest.mark.parametrize(
    ("argv", "files", "terminal", "expected_stdout", "expected_stderr"),
    [
        (
            ("todo", "alpha"),
            {"alpha": _ITEMS},
            False,
            ["alpha\t1\t- Fix the widget"],
            "",
        ),
        (
            ("todo",),
            {"alpha": _ITEMS, "beta": None},
            False,
            ["alpha\t1\t- Fix the widget"],
            "1 projects have no TODO items: beta\n",
        ),
        (
            ("todo",),
            {"alpha": "   \n\n  ", "beta": None},
            False,
            [],
            "2 projects have no TODO items: alpha, beta\n",
        ),
        (("todo", "beta"), {"beta": None}, False, [], "No TODO items in beta\n"),
        (
            ("todo", "api"),
            {"api": "\n  - [ ] literal[red]\n\n"},
            False,
            ["api\t1\t", "api\t2\t  - [ ] literal[red]", "api\t3\t"],
            "",
        ),
        (
            ("todo",),
            {"api": "- item\n\tindented\n"},
            False,
            ["api\t1\t- item", "api\t2\t\\tindented"],
            "",
        ),
        (
            ("todo", "api"),
            {"api": "- item\n\t- nested\n"},
            True,
            ["api · TODO.md", "  - item", "          - nested"],
            "",
        ),
        (
            ("todo", "a[b]"),
            {"a[b]": "# Keep *Markdown*\n"},
            False,
            ["a[b]\t1\t# Keep *Markdown*"],
            "",
        ),
    ],
    ids=[
        "single",
        "all-with-a-missing-file",
        "blank-and-missing-collapse-to-one-notice",
        "single-missing-file",
        "pipe-keeps-source-lines",
        "pipe-escapes-tabs",
        "terminal-expands-tabs",
        "bracketed-name-and-markdown-stay-literal",
    ],
)
def test_given_todo_files_when_todo_runs_then_items_and_notices_split_by_stream(
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, ...],
    files: dict[str, str | None],
    terminal: bool,
    expected_stdout: list[str],
    expected_stderr: str,
) -> None:
    config = ""
    for name, content in files.items():
        project = tmp_path / name
        project.mkdir()
        if content is not None:
            (project / "TODO.md").write_text(content, encoding="utf-8")
        config += f'[projects."{name}"]\npath = "{project}"\npackage_manager = "uv"\n'
    write_config(mm_home, config)
    stream = terminal_stdout(monkeypatch) if terminal else None

    assert run_mm(*argv) == ExitCode.OK

    captured = capsys.readouterr()
    stdout = stream.getvalue() if stream else captured.out
    assert (stdout.splitlines(), captured.err) == (expected_stdout, expected_stderr)
