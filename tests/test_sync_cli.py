from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man import cli
from maintenance_man.cli import ExitCode
from maintenance_man.config import load_config
from maintenance_man.vcs import RevisionError
from tests.conftest import configure_fake_vcs, run_mm, write_config
from tests.fake_vcs import FakeJjState


class TestSyncCommand:
    def test_exits_nonzero_on_typed_failure(
        self,
        mm_home_with_projects: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        state, _ = configure_fake_vcs(mm_home_with_projects, tmp_path, monkeypatch)
        path = load_config().projects["vulnerable"].path
        state.fail("fetch", error=RevisionError("fetch failed"), path=path)

        assert run_mm("sync", "vulnerable") == ExitCode.SYNC_FAILED
        assert "fetch failed" in capsys.readouterr().err

    def test_composes_once_without_extra_vcs_context(
        self,
        mm_home_with_projects: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state = FakeJjState()
        path = load_config().projects["vulnerable"].path
        state.seed_repository(path, files={"dep.txt": "version=1\n"})
        factory = MagicMock(return_value=state.services())
        monkeypatch.setattr(cli, "make_vcs_services", factory)

        assert run_mm("sync", "vulnerable") == ExitCode.OK
        factory.assert_called_once_with()
        assert not any(
            call.method in {"revision_bookmarks", "change_id"}
            for call in state.attempts
        )

    def test_reports_successful_action(
        self,
        mm_home_with_projects: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        configure_fake_vcs(mm_home_with_projects, tmp_path, monkeypatch)

        assert run_mm("sync", "vulnerable") == ExitCode.OK
        assert "vulnerable — already up to date" in capsys.readouterr().out

    def test_no_configured_projects(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mm_home.mkdir(parents=True, exist_ok=True)
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")
        factory = MagicMock()
        monkeypatch.setattr(cli, "make_vcs_services", factory)

        assert run_mm("sync") == ExitCode.OK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [
            "No projects configured",
            "hint: add projects to ~/.mm/config.toml",
        ]
        factory.assert_not_called()

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
        state = FakeJjState()
        monkeypatch.setattr(cli, "make_vcs_services", state.services)

        assert run_mm("sync") == ExitCode.SYNC_FAILED
        assert "ghost — path does not exist" in capsys.readouterr().out
        assert state.attempts == []
