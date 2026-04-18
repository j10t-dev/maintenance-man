from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import ExitCode, app
from maintenance_man.config import load_config


class TestSyncCommand:
    def test_syncs_all_projects_by_default(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_sync = MagicMock(return_value=(True, ""))
        monkeypatch.setattr("maintenance_man.cli.sync_main", mock_sync)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync"])

        assert exc_info.value.code == ExitCode.OK
        assert mock_sync.call_count == len(load_config().projects)

    def test_syncs_named_projects_only(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_sync = MagicMock(return_value=(True, ""))
        monkeypatch.setattr("maintenance_man.cli.sync_main", mock_sync)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync", "vulnerable", "clean"])

        assert exc_info.value.code == ExitCode.OK
        assert mock_sync.call_count == 2

    def test_exits_nonzero_on_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_sync = MagicMock(return_value=(False, "fetch failed"))
        monkeypatch.setattr("maintenance_man.cli.sync_main", mock_sync)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync", "vulnerable"])

        assert exc_info.value.code == ExitCode.SYNC_FAILED

    def test_continues_after_one_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # First call fails, second succeeds
        mock_sync = MagicMock(side_effect=[(False, "fetch failed"), (True, "")])
        monkeypatch.setattr("maintenance_man.cli.sync_main", mock_sync)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync", "vulnerable", "clean"])

        assert exc_info.value.code == ExitCode.SYNC_FAILED
        # Both projects were attempted despite the first failure
        assert mock_sync.call_count == 2

    def test_no_configured_projects(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")

        mock_sync = MagicMock(return_value=(True, ""))
        monkeypatch.setattr("maintenance_man.cli.sync_main", mock_sync)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync"])

        assert exc_info.value.code == ExitCode.OK
        mock_sync.assert_not_called()

    def test_skips_nonexistent_path(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
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
        (mm_home / "config.toml").write_text(config_text)

        mock_sync = MagicMock(return_value=(True, ""))
        monkeypatch.setattr("maintenance_man.cli.sync_main", mock_sync)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync"])

        assert exc_info.value.code == ExitCode.SYNC_FAILED
        mock_sync.assert_not_called()
