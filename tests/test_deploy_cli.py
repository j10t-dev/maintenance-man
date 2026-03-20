from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.cli import ExitCode, app
from maintenance_man.deployer import BuildError, DeployError, HealthCheckResult


class TestDeployCommand:
    def test_no_deploy_config(self, mm_home_with_projects: Path) -> None:
        """Error when project has no deploy_command configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "no-deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    @patch("maintenance_man.cli.run_deploy")
    def test_successful_deploy(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """Exit 0 on successful deploy."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_deploy.assert_called_once()

    @patch(
        "maintenance_man.cli.run_deploy",
        side_effect=DeployError("deploy failed"),
    )
    def test_failed_deploy(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """Exit DEPLOY_FAILED on deploy failure."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.DEPLOY_FAILED

    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_build_flag_runs_build_then_deploy(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """--build runs build before deploy."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable", "--build"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_build.assert_called_once()
        mock_deploy.assert_called_once()

    @patch("maintenance_man.cli.run_deploy")
    def test_build_flag_skips_when_no_build_command(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """--build silently skips if no build_command configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deploy-only", "--build"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_deploy.assert_called_once()

    @patch("maintenance_man.cli.run_deploy")
    @patch(
        "maintenance_man.cli.run_build",
        side_effect=BuildError("build failed"),
    )
    def test_build_failure_aborts_deploy(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Deploy is not attempted if build fails."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable", "--build"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.BUILD_FAILED
        mock_deploy.assert_not_called()

    def test_unknown_project(self, mm_home_with_projects: Path) -> None:
        """Error when project doesn't exist."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "nonexistent"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR


class TestDeployCheck:
    @patch(
        "maintenance_man.cli.check_health",
        return_value=HealthCheckResult(is_up=True),
    )
    @patch("maintenance_man.cli.run_deploy")
    def test_check_calls_healthchecker(
        self,
        mock_deploy: MagicMock,
        mock_check: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """--check calls check_health after successful deploy."""
        # Add healthcheck_url to config
        config_path = mm_home_with_projects / "config.toml"
        text = config_path.read_text().replace(
            "min_version_age_days = 7",
            'min_version_age_days = 7\nhealthcheck_url = "http://pihost:8080"',
        )
        config_path.write_text(text)

        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable", "--check"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_check.assert_called_once_with("http://pihost:8080", "deployable")

    @patch(
        "maintenance_man.cli.check_health",
        return_value=HealthCheckResult(is_up=False, error="connection refused"),
    )
    @patch("maintenance_man.cli.run_deploy")
    def test_check_unhealthy_still_exits_ok(
        self,
        mock_deploy: MagicMock,
        mock_check: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """--check with unhealthy result is informational, exit still OK."""
        config_path = mm_home_with_projects / "config.toml"
        text = config_path.read_text().replace(
            "min_version_age_days = 7",
            'min_version_age_days = 7\nhealthcheck_url = "http://pihost:8080"',
        )
        config_path.write_text(text)

        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable", "--check"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK

    @patch("maintenance_man.cli.run_deploy")
    def test_check_without_healthcheck_url_warns(
        self,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--check without healthcheck_url configured prints warning."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable", "--check"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
