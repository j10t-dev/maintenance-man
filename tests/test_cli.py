from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from maintenance_man import __version__, cli
from maintenance_man.cli import app
from tests.conftest import run_mm


class TestHelp:
    def test_help_exits_zero(self):
        with pytest.raises(SystemExit) as exc_info:
            app(["--help"])
        assert exc_info.value.code == 0

    def test_help_contains_description(self, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit) as exc_info:
            app(["--help"])
        assert exc_info.value.code == 0
        assert "maintenance" in capsys.readouterr().out.lower()


class TestVersion:
    def test_version_exits_zero(self):
        with pytest.raises(SystemExit) as exc_info:
            app(["--version"])
        assert exc_info.value.code == 0

    def test_version_prints_version(self, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit) as exc_info:
            app(["--version"])
        assert exc_info.value.code == 0
        assert __version__ in capsys.readouterr().out


class TestInitCommand:
    def test_init_uses_redirected_home(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["init"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out.replace("\n", "")
        assert str(mm_home) in out
        assert (mm_home / "config.toml").is_file()

    def test_init_prints_bracketed_home_path_literally(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "[home]"
        output = StringIO()
        monkeypatch.setattr("maintenance_man.paths.MM_HOME", home)
        monkeypatch.setattr(
            cli, "console", Console(file=output, width=220, color_system=None)
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["init"])

        assert exc_info.value.code == 0
        assert str(home) in output.getvalue()


def test_fatal_prints_bracketed_plain_text_literally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=220, color_system=None)
    )

    with pytest.raises(SystemExit):
        cli._fatal("bad [projects.x]")

    assert "Error: bad [projects.x]" in output.getvalue()


def test_config_validation_error_keeps_pydantic_type_suffix(
    mm_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mm_home.mkdir(parents=True)
    (mm_home / "config.toml").write_text(
        '[projects.api]\npackage_manager = "uv"\n', encoding="utf-8"
    )

    assert run_mm("scan") == 1

    assert "[type=missing" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("deploy", "Add deploy_command to [projects.api] in ~/.mm/config.toml."),
        ("build", "Add build_command to [projects.api]"),
        ("test", "Add test_unit to [projects.api]"),
    ],
)
def test_missing_command_error_keeps_config_table_literal(
    mm_home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    expected: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    mm_home.mkdir(parents=True)
    (mm_home / "config.toml").write_text(
        f'[projects.api]\npath = "{project}"\npackage_manager = "uv"\n',
        encoding="utf-8",
    )

    assert run_mm(command, "api") == 1

    assert expected in " ".join(capsys.readouterr().out.split())


def test_deploy_check_hint_keeps_defaults_table_literal(
    mm_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mm_home.mkdir(parents=True)
    (mm_home / "config.toml").write_text("[defaults]\n", encoding="utf-8")

    assert run_mm("deploy", "--check") == 0

    assert "configured in [defaults]" in capsys.readouterr().out


class TestDeployCommand:
    def test_deploy_no_project_is_mass_mode(self, mm_home: Path):
        """Deploy with no project triggers mass mode (exits OK with no projects)."""
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"])
        assert exc_info.value.code == 0

    def test_deploy_unknown_project_exits_error(self, mm_home):
        """Deploy with unknown project exits with ERROR."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "project-alpha"])
        assert exc_info.value.code == 1


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
        (mm_home / "config.toml").write_text(
            f'[projects.alpha]\npath = "{alpha_dir}"\npackage_manager = "uv"\n\n'
            f'[projects.beta]\npath = "{beta_dir}"\npackage_manager = "uv"\n'
        )
        return mm_home

    def test_todo_all_shows_content(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo shows TODO.md content for projects that have one."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "alpha" in output
        assert "Fix the widget" in output

    def test_todo_all_shows_no_file_message(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo shows 'no TODO.md' for projects without the file."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "beta" in output
        assert "no TODO.md" in output

    def test_todo_all_shows_empty_message(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo shows 'empty' for projects with blank TODO.md."""
        alpha_dir = mm_home_with_todos.parent / "alpha"
        (alpha_dir / "TODO.md").write_text("   \n\n  ")
        with pytest.raises(SystemExit) as exc_info:
            app(["todo"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "alpha" in output
        assert "empty" in output

    def test_todo_single_project_shows_content(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo <project> shows that project's TODO.md."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo", "alpha"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "alpha" in output
        assert "Fix the widget" in output
        assert "beta" not in output

    def test_todo_single_project_no_file(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo <project> with no TODO.md logs missing file, exits 0."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo", "beta"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "no TODO.md" in output

    def test_todo_unknown_project_exits_error(self, mm_home_with_todos: Path):
        """mm todo <unknown> exits with error (config error, not missing file)."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo", "nonexistent"])
        assert exc_info.value.code == 1

    def test_todo_no_projects_configured(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo with no projects configured prints message and exits 0."""
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")
        with pytest.raises(SystemExit) as exc_info:
            app(["todo"])
        assert exc_info.value.code == 0
        assert "no projects" in capsys.readouterr().out.lower()

    def test_todo_prints_bracketed_panel_title_literally(
        self, mm_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "TODO.md").write_text("# Keep *Markdown*\n", encoding="utf-8")
        mm_home.mkdir(parents=True)
        (mm_home / "config.toml").write_text(
            f'[projects."a[b]"]\npath = "{project}"\npackage_manager = "uv"\n',
            encoding="utf-8",
        )

        assert run_mm("todo", "a[b]") == 0

        output = capsys.readouterr().out
        assert "a[b]" in output
        assert "Keep Markdown" in output
