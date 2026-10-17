from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man import __version__, cli
from maintenance_man.config import ConfigError
from maintenance_man.exit_codes import ExitCode
from maintenance_man.gradle import GradleError
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.scanner import ScanError
from maintenance_man.services import WorkflowError
from maintenance_man.services.update import UpdateSetupError
from maintenance_man.vcs import RevisionError
from tests.conftest import configure_fake_vcs, run_mm, write_config


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
    configure_fake_vcs(mm_home_with_projects, tmp_path, monkeypatch)
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
        cli, "_load_cfg", MagicMock(side_effect=ConfigError("bad [projects.x]"))
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


def test_given_empty_config_when_listed_then_notice_and_hint_use_stderr_exit_zero(
    mm_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mm_home.mkdir(parents=True)
    write_config(mm_home, "[defaults]\n")

    assert run_mm("list") == ExitCode.OK

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "No projects configured",
        f"hint: add projects to {mm_home / 'config.toml'}",
    ]


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


def test_given_empty_config_flag_when_listed_then_hint_names_that_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = write_config(tmp_path, "[defaults]\n", filename="elsewhere.toml")

    assert run_mm("list", "--config", str(config)) == ExitCode.OK

    assert capsys.readouterr().err.splitlines() == [
        "No projects configured",
        f"hint: add projects to {config}",
    ]


def test_deploy_check_hint_keeps_defaults_table_literal(
    mm_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mm_home.mkdir(parents=True)
    write_config(mm_home, "[defaults]\n")

    assert run_mm("deploy", "--check") == 0

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "configured in [defaults]" in captured.err


class TestDeployCommand:
    def test_deploy_no_project_is_mass_mode(self, mm_home: Path):
        """Deploy with no project triggers mass mode (exits OK with no projects)."""
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")
        assert run_mm("deploy") == 0

    def test_deploy_unknown_project_exits_error(self, mm_home):
        """Deploy with unknown project exits with ERROR."""
        assert run_mm("deploy", "project-alpha") == 1


class TestTodoCommand:
    """Tests for mm todo."""

    @pytest.fixture()
    def mm_home_with_todos(self, mm_home: Path) -> Path:
        """mm_home with two projects: 'alpha' has a TODO.md, 'beta' does not."""
        alpha_dir = mm_home.parent / "alpha"
        alpha_dir.mkdir()
        (alpha_dir / "TODO.md").write_text("- Fix the widget\n- Refactor utils\n")

        beta_dir = mm_home.parent / "beta"
        beta_dir.mkdir()

        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(
            mm_home,
            f'[projects.alpha]\npath = "{alpha_dir}"\npackage_manager = "uv"\n\n'
            f'[projects.beta]\npath = "{beta_dir}"\npackage_manager = "uv"\n',
        )
        return mm_home

    def test_todo_all_shows_content_and_missing_file(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo pipes items for alpha and notices that beta has none."""
        assert run_mm("todo") == 0
        captured = capsys.readouterr()
        assert captured.out.splitlines() == [
            "alpha\t1\t- Fix the widget",
            "alpha\t2\t- Refactor utils",
        ]
        assert captured.err == "1 projects have no TODO items: beta\n"

    def test_todo_all_shows_empty_message(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo collapses blank and missing TODO.md files into one notice."""
        alpha_dir = mm_home_with_todos.parent / "alpha"
        (alpha_dir / "TODO.md").write_text("   \n\n  ")
        assert run_mm("todo") == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "2 projects have no TODO items: alpha, beta\n"

    def test_todo_single_project_shows_content(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo <project> shows that project's TODO.md."""
        assert run_mm("todo", "alpha") == 0
        captured = capsys.readouterr()
        assert captured.out.splitlines() == [
            "alpha\t1\t- Fix the widget",
            "alpha\t2\t- Refactor utils",
        ]
        assert captured.err == ""

    def test_todo_single_project_no_file(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo <project> with no TODO.md notices on stderr, exits 0."""
        assert run_mm("todo", "beta") == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "No TODO items in beta\n"

    def test_todo_unknown_project_exits_error(self, mm_home_with_todos: Path):
        """mm todo <unknown> exits with error (config error, not missing file)."""
        assert run_mm("todo", "nonexistent") == 1

    def test_todo_no_projects_configured(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo with no projects configured notices with a hint and exits 0."""
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")
        assert run_mm("todo") == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [
            "No projects configured",
            f"hint: add projects to {mm_home / 'config.toml'}",
        ]

    def test_given_bracketed_name_and_markdown_when_todo_runs_then_both_print_literally(
        self, mm_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "TODO.md").write_text("# Keep *Markdown*\n", encoding="utf-8")
        mm_home.mkdir(parents=True)
        write_config(
            mm_home,
            f'[projects."a[b]"]\npath = "{project}"\npackage_manager = "uv"\n',
        )

        assert run_mm("todo", "a[b]") == 0

        assert capsys.readouterr().out == "a[b]\t1\t# Keep *Markdown*\n"
