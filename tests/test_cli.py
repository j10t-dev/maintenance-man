from pathlib import Path

import pytest

from maintenance_man import __version__
from maintenance_man.cli import app


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


class TestDeployCommand:
    def test_deploy_no_project_is_mass_mode(self, mm_home: Path):
        """Deploy with no project triggers mass mode (exits OK with no projects)."""
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
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
        (mm_home / "worktrees").mkdir()
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
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")
        with pytest.raises(SystemExit) as exc_info:
            app(["todo"])
        assert exc_info.value.code == 0
        assert "no projects" in capsys.readouterr().out.lower()
