from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man import cli, paths
from maintenance_man.cli import ExitCode, app
from maintenance_man.deployer import BuildError
from maintenance_man.storage import load_activity
from maintenance_man.vcs import RevisionError
from tests.conftest import configure_fake_vcs, run_mm, write_config
from tests.fake_vcs import FakeJjState


@pytest.fixture
def _build_vcs(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> FakeJjState:
    state, _paths = configure_fake_vcs(mm_home_with_projects, tmp_path, monkeypatch)
    return state


def test_label_failure_does_not_block_persisted_build_activity(
    mm_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_path = tmp_path / "project"
    state = FakeJjState()
    state.seed_repository(project_path, files={"dep.txt": "version=1\n"})
    state.fail(
        "revision_bookmarks",
        error=RevisionError("label unavailable"),
        path=project_path,
    )
    write_config(
        mm_home,
        f'[projects.demo]\npath = "{project_path}"\npackage_manager = "uv"\n'
        'build_command = "build"\n',
    )
    monkeypatch.setattr(cli, "make_vcs_services", state.services)
    monkeypatch.setattr("maintenance_man.services.deploy.run_build", lambda *args: None)

    assert run_mm("build", "demo") == ExitCode.OK

    recorded = load_activity(paths.activity_path())["demo"].last_build
    assert recorded is not None
    assert recorded.success is True
    assert recorded.branch == "unknown"
    assert any(call.method == "revision_bookmarks" for call in state.attempts)


class TestBuildCommand:
    def test_no_build_config(
        self, mm_home_with_projects: Path, _build_vcs: FakeJjState
    ) -> None:
        """Error when project has no build_command configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "no-deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    def test_no_build_config_deploy_only_project(
        self, mm_home_with_projects: Path, _build_vcs: FakeJjState
    ) -> None:
        """Error when project has deploy_command but no build_command."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "deploy-only"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    @patch("maintenance_man.services.deploy.run_build")
    def test_successful_build(
        self,
        mock_build: MagicMock,
        mm_home_with_projects: Path,
        _build_vcs: FakeJjState,
    ) -> None:
        """Exit 0 on successful build."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_build.assert_called_once()
        assert any(call.method == "revision_bookmarks" for call in _build_vcs.attempts)

    @patch(
        "maintenance_man.services.deploy.run_build",
        side_effect=BuildError("build failed"),
    )
    def test_failed_build(
        self,
        mock_build: MagicMock,
        mm_home_with_projects: Path,
        _build_vcs: FakeJjState,
    ) -> None:
        """Exit BUILD_FAILED on build failure."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.BUILD_FAILED

    def test_unknown_project(
        self, mm_home_with_projects: Path, _build_vcs: FakeJjState
    ) -> None:
        """Error when project doesn't exist."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "nonexistent"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    @patch("maintenance_man.services.deploy.record_activity")
    @patch("maintenance_man.services.deploy.run_build")
    def test_successful_build_records_activity(
        self,
        mock_build: MagicMock,
        mock_record: MagicMock,
        mm_home_with_projects: Path,
        _build_vcs: FakeJjState,
    ) -> None:
        """Successful build records activity event."""
        with pytest.raises(SystemExit):
            app(["build", "deployable"], exit_on_error=False)
        mock_record.assert_called_once()
        _, kwargs = mock_record.call_args
        assert kwargs["success"] is True

    @patch("maintenance_man.services.deploy.record_activity")
    @patch(
        "maintenance_man.services.deploy.run_build",
        side_effect=BuildError("build failed"),
    )
    def test_failed_build_records_activity(
        self,
        mock_build: MagicMock,
        mock_record: MagicMock,
        mm_home_with_projects: Path,
        _build_vcs: FakeJjState,
    ) -> None:
        """Failed build still records activity event with success=False."""
        with pytest.raises(SystemExit):
            app(["build", "deployable"], exit_on_error=False)
        mock_record.assert_called_once()
        _, kwargs = mock_record.call_args
        assert kwargs["success"] is False
