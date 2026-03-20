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

    @patch("maintenance_man.cli.record_activity")
    @patch("maintenance_man.cli.run_deploy")
    def test_successful_deploy_records_activity(
        self,
        mock_deploy: MagicMock,
        mock_record: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Successful deploy records activity event."""
        with pytest.raises(SystemExit):
            app(["deploy", "deployable"], exit_on_error=False)
        mock_record.assert_called_once()
        _, kwargs = mock_record.call_args
        assert kwargs["success"] is True

    @patch("maintenance_man.cli.record_activity")
    @patch("maintenance_man.cli.run_deploy", side_effect=DeployError("deploy failed"))
    def test_failed_deploy_records_activity(
        self,
        mock_deploy: MagicMock,
        mock_record: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Failed deploy still records activity event with success=False."""
        with pytest.raises(SystemExit):
            app(["deploy", "deployable"], exit_on_error=False)
        mock_record.assert_called_once()
        _, kwargs = mock_record.call_args
        assert kwargs["success"] is False

    @patch("maintenance_man.cli.record_activity")
    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_deploy_with_build_records_both(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mock_record: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """--build records both build and deploy events."""
        with pytest.raises(SystemExit):
            app(["deploy", "deployable", "--build"], exit_on_error=False)
        assert mock_record.call_count == 2
        calls = mock_record.call_args_list
        # First call is build, second is deploy
        assert calls[0].args[2] == "build"
        assert calls[1].args[2] == "deploy"


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
        assert "--check: no healthcheck_url configured" in capsys.readouterr().out


class TestMassDeployCommand:
    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_deploys_all_projects_with_deploy_command(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Mass deploy runs build+deploy for all projects with deploy_command."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        # "deployable" has both build+deploy, "deploy-only" has deploy only
        assert mock_deploy.call_count == 2
        # Only "deployable" has build_command
        assert mock_build.call_count == 1

    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_skips_projects_without_deploy_command(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Projects without deploy_command are silently skipped."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        capsys.readouterr()
        deployed_projects = [
            call.args[0] for call in mock_deploy.call_args_list
        ]
        assert "no-deploy" not in deployed_projects
        assert "vulnerable" not in deployed_projects

    @patch(
        "maintenance_man.cli.run_deploy",
        side_effect=DeployError("deploy failed"),
    )
    @patch("maintenance_man.cli.run_build")
    def test_continues_after_deploy_failure(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Deploy failure on one project doesn't stop others."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.DEPLOY_FAILED
        assert mock_deploy.call_count == 2

    @patch("maintenance_man.cli.run_deploy")
    @patch(
        "maintenance_man.cli.run_build",
        side_effect=BuildError("build failed"),
    )
    def test_build_failure_skips_deploy_for_that_project(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Build failure skips deploy for that project but continues to next."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.DEPLOY_FAILED
        # "deployable" build fails => deploy skipped; "deploy-only" has no build => runs
        assert mock_deploy.call_count == 1

    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_prints_summary_table(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Mass deploy prints a summary table."""
        with pytest.raises(SystemExit):
            app(["deploy"], exit_on_error=False)
        output = capsys.readouterr().out
        assert "Deploy Summary" in output

    @patch(
        "maintenance_man.cli.check_health",
        return_value=HealthCheckResult(is_up=True),
    )
    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_check_flag_works_in_mass_mode(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mock_check: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--check runs health check for each deployed project."""
        config_path = mm_home_with_projects / "config.toml"
        text = config_path.read_text().replace(
            "min_version_age_days = 7",
            'min_version_age_days = 7\nhealthcheck_url = "http://pihost:8080"',
        )
        config_path.write_text(text)

        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "--check"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        assert mock_check.call_count == 2
        output = capsys.readouterr().out
        assert "Healthy: deploy-only is up" in output
        assert "Healthy: deployable is up" in output

    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_check_without_healthcheck_url_warns_in_mass_mode(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Mass deploy warns when --check is requested without healthcheck_url."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "--check"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        assert "--check: no healthcheck_url configured" in capsys.readouterr().out

    def test_no_projects_configured(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Mass deploy with no projects prints message and exits OK."""
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        assert "no projects" in capsys.readouterr().out.lower()
