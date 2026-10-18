from pathlib import Path

import pytest

from maintenance_man.cli import ExitCode
from maintenance_man.vcs import RevisionError
from tests.support.cli import refuse_jj_commands, run_mm
from tests.support.projects import write_config
from tests.support.repository import configure_jj_projects, fail_repository_method


class TestSyncCommand:
    def test_exits_nonzero_on_typed_failure(
        self,
        mm_home_with_projects: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = configure_jj_projects(mm_home_with_projects, tmp_path)["vulnerable"]
        fail_repository_method(
            monkeypatch, path, "fetch", RevisionError("fetch failed")
        )

        assert run_mm("sync", "vulnerable") == ExitCode.SYNC_FAILED
        assert "fetch failed" in capsys.readouterr().err

    def test_reports_successful_action(
        self,
        mm_home_with_projects: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        configure_jj_projects(mm_home_with_projects, tmp_path)

        assert run_mm("sync", "vulnerable") == ExitCode.OK
        captured = capsys.readouterr()
        assert captured.out == "vulnerable\tsync\tunchanged\tmain\t-\t-\t-\n"
        assert captured.err == ""

    def test_no_configured_projects(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mm_home.mkdir(parents=True, exist_ok=True)
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")
        refuse_jj_commands(monkeypatch)

        assert run_mm("sync") == ExitCode.OK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [
            "No projects configured",
            f"hint: add projects to {mm_home / 'config.toml'}",
        ]

    def test_skips_nonexistent_path(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mm_home.mkdir(parents=True, exist_ok=True)
        missing_path = tmp_path / "does-not-exist"
        config_text = f"""\
[defaults]
min_version_age_days = 7

[projects.ghost]
path = "{missing_path}"
package_manager = "uv"
test_unit = "uv run pytest"
"""
        write_config(mm_home, config_text)
        refuse_jj_commands(monkeypatch)

        assert run_mm("sync") == ExitCode.SYNC_FAILED
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == (
            f"warning: ghost · path does not exist: {missing_path}\n"
        )
