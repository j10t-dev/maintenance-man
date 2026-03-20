from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.cli import ExitCode, app
from maintenance_man.deployer import BuildError


class TestBuildCommand:
    def test_no_build_config(self, mm_home_with_projects: Path) -> None:
        """Error when project has no build_command configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "no-deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    def test_no_build_config_deploy_only_project(
        self, mm_home_with_projects: Path
    ) -> None:
        """Error when project has deploy_command but no build_command."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "deploy-only"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    @patch("maintenance_man.cli.run_build")
    def test_successful_build(
        self, mock_build: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """Exit 0 on successful build."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_build.assert_called_once()

    @patch("maintenance_man.cli.run_build", side_effect=BuildError("build failed"))
    def test_failed_build(
        self, mock_build: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """Exit BUILD_FAILED on build failure."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.BUILD_FAILED

    def test_unknown_project(self, mm_home_with_projects: Path) -> None:
        """Error when project doesn't exist."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "nonexistent"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR
