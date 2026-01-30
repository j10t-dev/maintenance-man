from pathlib import Path

from typer.testing import CliRunner

from maintenance_man.cli import app

runner = CliRunner()


class TestListCommand:
    def test_list_no_projects(self, mm_home: Path):
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "no projects" in result.output.lower()

    def test_list_shows_projects(self, mm_home: Path):
        project_dir = mm_home.parent / "myproject"
        project_dir.mkdir()
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text(
            f'[projects.myapp]\npath = "{project_dir}"\npackage_manager = "bun"\n'
        )
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "myapp" in result.output
        assert "bun" in result.output
