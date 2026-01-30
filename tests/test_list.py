from pathlib import Path

import pytest

from maintenance_man.cli import app


class TestListCommand:
    def test_list_no_projects(self, mm_home: Path, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        assert "no projects" in capsys.readouterr().out.lower()

    def test_list_shows_projects(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        project_dir = mm_home.parent / "myproject"
        project_dir.mkdir()
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text(
            f'[projects.myapp]\npath = "{project_dir}"\npackage_manager = "bun"\n'
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "myapp" in output
        assert "bun" in output
