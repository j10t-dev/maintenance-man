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
