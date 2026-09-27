from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man import cli
from maintenance_man.cli import ExitCode, app
from maintenance_man.config import load_config
from maintenance_man.vcs import RevisionError
from tests.fake_vcs import FakeJjState


def _install_fake_services(monkeypatch: pytest.MonkeyPatch) -> FakeJjState:
    state = FakeJjState()
    seeded: set[Path] = set()
    for project in load_config().projects.values():
        path = project.path.resolve()
        if path not in seeded:
            state.seed_repository(path, files={"dep.txt": "version=1\n"})
            seeded.add(path)
    services = state.services()
    monkeypatch.setattr(cli, "make_vcs_services", lambda: services)
    return state


class TestSyncCommand:
    def test_syncs_all_projects_by_default(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state = _install_fake_services(monkeypatch)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync"])

        assert exc_info.value.code == ExitCode.OK
        assert sum(call.method == "fetch" for call in state.attempts) == len(
            load_config().projects
        )

    def test_syncs_named_projects_only(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state = _install_fake_services(monkeypatch)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync", "vulnerable", "clean"])

        assert exc_info.value.code == ExitCode.OK
        assert sum(call.method == "fetch" for call in state.attempts) == 2

    def test_exits_nonzero_on_typed_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        state = _install_fake_services(monkeypatch)
        path = load_config().projects["vulnerable"].path
        state.fail("fetch", error=RevisionError("fetch failed"), path=path)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync", "vulnerable"])

        assert exc_info.value.code == ExitCode.SYNC_FAILED
        assert "fetch failed" in capsys.readouterr().out

    def test_continues_after_one_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state = _install_fake_services(monkeypatch)
        path = load_config().projects["vulnerable"].path
        state.fail("fetch", error=RevisionError("fetch failed"), path=path)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync", "vulnerable", "clean"])

        assert exc_info.value.code == ExitCode.SYNC_FAILED
        assert sum(call.method == "fetch" for call in state.attempts) == 2

    def test_composes_once_without_extra_vcs_context(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state = FakeJjState()
        path = load_config().projects["vulnerable"].path
        state.seed_repository(path, files={"dep.txt": "version=1\n"})
        factory = MagicMock(return_value=state.services())
        monkeypatch.setattr(cli, "make_vcs_services", factory)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync", "vulnerable"])

        assert exc_info.value.code == ExitCode.OK
        factory.assert_called_once_with()
        assert not any(
            call.method in {"revision_bookmarks", "change_id"}
            for call in state.attempts
        )

    def test_reports_successful_action(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _install_fake_services(monkeypatch)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync", "vulnerable"])

        assert exc_info.value.code == ExitCode.OK
        assert "vulnerable — already up to date" in capsys.readouterr().out

    def test_no_configured_projects(
        self,
        mm_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "config.toml").write_text(
            "[defaults]\nmin_version_age_days = 7\n", encoding="utf-8"
        )
        factory = MagicMock()
        monkeypatch.setattr(cli, "make_vcs_services", factory)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync"])

        assert exc_info.value.code == ExitCode.OK
        factory.assert_not_called()

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
        (mm_home / "config.toml").write_text(config_text, encoding="utf-8")
        state = FakeJjState()
        monkeypatch.setattr(cli, "make_vcs_services", state.services)

        with pytest.raises(SystemExit) as exc_info:
            app(["sync"])

        assert exc_info.value.code == ExitCode.SYNC_FAILED
        assert state.attempts == []
