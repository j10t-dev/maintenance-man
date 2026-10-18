from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man import output, paths
from maintenance_man.cli import ExitCode
from maintenance_man.deployer import BuildError
from maintenance_man.storage import load_activity
from maintenance_man.vcs import RevisionError
from tests.support.cli import run_mm
from tests.support.projects import write_config
from tests.support.repository import (
    configure_jj_projects,
    copy_jj_repository,
    fail_repository_method,
)


@pytest.fixture
def _build_repositories(mm_home_with_projects: Path, tmp_path: Path) -> dict[str, Path]:
    return configure_jj_projects(mm_home_with_projects, tmp_path)


def test_label_failure_does_not_block_persisted_build_activity(
    mm_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_path = copy_jj_repository(tmp_path / "project").path
    fail_repository_method(
        monkeypatch,
        project_path,
        "revision_bookmarks",
        RevisionError("label unavailable"),
    )
    write_config(
        mm_home,
        f'[projects.demo]\npath = "{project_path}"\npackage_manager = "uv"\n'
        'build_command = "build"\n',
    )
    monkeypatch.setattr(
        "maintenance_man.services.deploy.run_shell_command",
        lambda *args, **kwargs: None,
    )

    assert run_mm("build", "demo") == ExitCode.OK

    recorded = load_activity(paths.activity_path())["demo"].last_build
    assert recorded is not None
    assert recorded.success is True
    assert recorded.branch == "unknown"


class TestBuildCommand:
    def test_no_build_config(
        self, mm_home_with_projects: Path, _build_repositories: dict[str, Path]
    ) -> None:
        """Error when project has no build_command configured."""
        assert run_mm("build", "no-deploy") == ExitCode.ERROR

    def test_no_build_config_deploy_only_project(
        self, mm_home_with_projects: Path, _build_repositories: dict[str, Path]
    ) -> None:
        """Error when project has deploy_command but no build_command."""
        assert run_mm("build", "deploy-only") == ExitCode.ERROR

    @patch("maintenance_man.services.deploy.run_shell_command")
    def test_successful_build(
        self,
        mock_build: MagicMock,
        _build_repositories: dict[str, Path],
    ) -> None:
        """Exit 0 on successful build, recording the activity on main."""
        assert run_mm("build", "deployable") == ExitCode.OK
        mock_build.assert_called_once()
        recorded = load_activity(paths.activity_path())["deployable"].last_build
        assert recorded is not None
        assert recorded.success is True
        assert recorded.branch == "main"

    @patch(
        "maintenance_man.services.deploy.run_shell_command",
        side_effect=BuildError("build failed"),
    )
    def test_failed_build(
        self,
        mock_build: MagicMock,
        _build_repositories: dict[str, Path],
    ) -> None:
        """Exit BUILD_FAILED on build failure, still recording the activity."""
        assert run_mm("build", "deployable") == ExitCode.BUILD_FAILED
        recorded = load_activity(paths.activity_path())["deployable"].last_build
        assert recorded is not None
        assert recorded.success is False
        assert recorded.branch == "main"

    def test_unknown_project(
        self, mm_home_with_projects: Path, _build_repositories: dict[str, Path]
    ) -> None:
        """Error when project doesn't exist."""
        assert run_mm("build", "nonexistent") == ExitCode.ERROR

    @patch("maintenance_man.services.deploy.run_shell_command")
    def test_given_verbose_build_when_a_later_command_runs_then_verbosity_does_not_leak(
        self,
        mock_build: MagicMock,
        mm_home_with_projects: Path,
        _build_repositories: dict[str, Path],
    ) -> None:
        assert run_mm("build", "deployable", "--verbose") == ExitCode.OK
        assert output.is_verbose() is True

        assert run_mm("list") == ExitCode.OK
        assert output.is_verbose() is False

    @patch("maintenance_man.services.deploy.run_shell_command")
    def test_given_successful_build_when_piped_then_one_passed_record(
        self,
        mock_build: MagicMock,
        mm_home_with_projects: Path,
        _build_repositories: dict[str, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("build", "deployable") == ExitCode.OK

        captured = capsys.readouterr()
        assert captured.out == "deployable\tbuild\tpassed\tbuild\t-\t-\t-\n"
        assert captured.err == ""

    @patch(
        "maintenance_man.services.deploy.run_shell_command",
        side_effect=BuildError("Build for deployable failed (exit 2)"),
    )
    def test_given_failed_build_when_piped_then_failed_record_and_build_exit_code(
        self,
        mock_build: MagicMock,
        mm_home_with_projects: Path,
        _build_repositories: dict[str, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("build", "deployable") == ExitCode.BUILD_FAILED

        captured = capsys.readouterr()
        assert captured.out == (
            "deployable\tbuild\tfailed\tbuild\t-\t-\t"
            "Build for deployable failed (exit 2)\n"
        )
        assert captured.err == ""
