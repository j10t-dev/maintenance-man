from dataclasses import dataclass
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from maintenance_man import cli, paths
from maintenance_man.cli import ExitCode, app
from maintenance_man.deployer import BuildError, DeployError, HealthCheckResult
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.events import (
    DeployStep,
    DeployStepFailed,
    DeployStepStarted,
    DeployStepSucceeded,
    Event,
    HealthChecked,
    HealthcheckUnconfigured,
    ProjectStarted,
)
from maintenance_man.services import deploy as deploy_service
from maintenance_man.storage import load_activity
from maintenance_man.vcs import RevisionError
from tests.conftest import configure_fake_vcs, run_mm, write_config
from tests.fake_vcs import FakeJjState


def test_deploy_summary_prints_bracketed_project_literal(capsys) -> None:
    cli._print_deploy_summary(
        [deploy_service.DeployResult("a[b]", build_status="pass", deploy_status="pass")]
    )

    assert "a[b]" in capsys.readouterr().out


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
@pytest.mark.parametrize(
    ("event", "single", "batch_text"),
    [
        (
            ProjectStarted("a[b]"),
            "",
            f"\n{'═' * 40}\na[b]\n{'═' * 40}\n",
        ),
        (
            DeployStepStarted("a[b]", DeployStep.BUILD),
            "Building a[b]\n\n",
            "  Building...\n",
        ),
        (
            DeployStepStarted("a[b]", DeployStep.DEPLOY),
            "Deploying a[b]\n\n",
            "  Deploying...\n",
        ),
        (
            DeployStepStarted("a[b]", DeployStep.HEALTH),
            "\nChecking health of a[b]...\n",
            "",
        ),
        (
            DeployStepSucceeded("a[b]", DeployStep.BUILD),
            "\nBuild succeeded.\n\n",
            "",
        ),
        (
            DeployStepSucceeded("a[b]", DeployStep.DEPLOY),
            "\nDeploy succeeded.\n",
            "",
        ),
        (
            DeployStepFailed("a[b]", DeployStep.BUILD, "bad [state]"),
            "Error: bad [state]\n",
            "  Build failed: bad [state]\n",
        ),
        (
            DeployStepFailed("a[b]", DeployStep.DEPLOY, "bad [state]"),
            "Error: bad [state]\n",
            "  Deploy failed: bad [state]\n",
        ),
        (
            HealthChecked("a[b]", True, None),
            "Healthy: a[b] is up\n",
            "  Healthy: a[b] is up\n",
        ),
        (
            HealthChecked("a[b]", False, "bad [state]"),
            "Warning: bad [state]\n",
            "  Warning: bad [state]\n",
        ),
        (
            HealthChecked("a[b]", False, None),
            "Warning: a[b] is not healthy\n",
            "  Warning: a[b] is not healthy\n",
        ),
        (
            HealthcheckUnconfigured(),
            "--check: no healthcheck_url configured in [defaults]\n",
            "--check: no healthcheck_url configured in [defaults]\n",
        ),
    ],
)
def test_deploy_event_renderer_preserves_text(
    monkeypatch: pytest.MonkeyPatch,
    event: Event,
    single: str,
    batch_text: str,
    batch: bool,
) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=220, color_system=None)
    )

    cli._Renderer(batch=batch)(event)

    assert output.getvalue() == (batch_text if batch else single)


@dataclass(frozen=True)
class _DeployVcs:
    state: FakeJjState
    paths: dict[str, Path]
    main_ids: dict[str, str]


@pytest.fixture
def _deploy_vcs(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> _DeployVcs:
    state, paths_by_name = configure_fake_vcs(
        mm_home_with_projects, tmp_path, monkeypatch
    )
    main_ids = {
        name: state.repository(path).resolve_revision(revision="main")
        for name, path in paths_by_name.items()
    }
    state.clear_calls()
    return _DeployVcs(state=state, paths=paths_by_name, main_ids=main_ids)


@pytest.mark.parametrize(
    "force, expected_code, expected_deploys, expected_commit",
    [
        (False, ExitCode.ERROR, 0, "absent"),
        (True, ExitCode.OK, 1, None),
    ],
)
def test_unresolved_main_deploy_gate_persists_no_invented_identity(
    mm_home,
    tmp_path,
    monkeypatch,
    force,
    expected_code,
    expected_deploys,
    expected_commit,
):
    project_path = tmp_path / "project"
    state = FakeJjState()
    state.seed_repository(project_path, files={"dep.txt": "version=1\n"})
    state.fail(
        "resolve_revision",
        error=RevisionError("main unavailable"),
        path=project_path,
    )
    write_config(
        mm_home,
        f'[projects.demo]\npath = "{project_path}"\npackage_manager = "uv"\n'
        'deploy_command = "deploy"\n',
    )
    monkeypatch.setattr(cli, "make_vcs_services", state.services)
    deployed: list[str] = []
    monkeypatch.setattr(
        deploy_service, "run_deploy", lambda name, *args: deployed.append(name)
    )

    argv = ["deploy", "demo"] + (["--force"] if force else [])
    assert run_mm(*argv) == expected_code

    assert deployed == (["demo"] if expected_deploys else [])
    assert any(call.method == "resolve_revision" for call in state.attempts)
    activity = load_activity(paths.activity_path())
    if expected_commit == "absent":
        assert "demo" not in activity
    else:
        assert activity["demo"].last_deploy is not None
        assert activity["demo"].last_deploy.commit_id is expected_commit


def test_deploy_saves_the_exact_main_identity_used_by_the_gate(
    mm_home, tmp_path, monkeypatch
):
    project_path = tmp_path / "project"
    state = FakeJjState()
    repo = state.seed_repository(project_path, files={"dep.txt": "version=1\n"})
    main_id = repo.resolve_revision(revision="main")
    write_config(
        mm_home,
        f'[projects.demo]\npath = "{project_path}"\npackage_manager = "uv"\n'
        'deploy_command = "deploy"\n',
    )
    monkeypatch.setattr(cli, "make_vcs_services", state.services)

    def deploy(*args):
        advanced = state.seed_commit(
            project_path,
            parent=main_id,
            files={"dep.txt": "version=2\n"},
            description="advanced during deployment",
        )
        state.seed_bookmark(project_path, bookmark="main", targets=(advanced,))

    monkeypatch.setattr(deploy_service, "run_deploy", deploy)

    assert run_mm("deploy", "demo") == ExitCode.OK

    event = load_activity(paths.activity_path())["demo"].last_deploy
    assert event is not None
    assert event.commit_id == main_id
    assert repo.resolve_revision(revision="main") != main_id
    assert any(call.method == "resolve_revision" for call in state.attempts)


def _activity(*, success: bool, commit_id: str | None) -> dict[str, ProjectActivity]:
    return {
        "app": ProjectActivity(
            last_deploy=ActivityEvent(
                timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                success=success,
                branch="main",
                commit_id=commit_id,
            )
        )
    }


@pytest.mark.parametrize(
    "argv, code, deployed",
    [
        (["deploy", "deploy-only"], ExitCode.ERROR, False),
        (["deploy"], ExitCode.OK, False),
        (["deploy", "deploy-only", "--force"], ExitCode.OK, True),
    ],
)
@patch("maintenance_man.services.deploy.record_activity")
@patch("maintenance_man.services.deploy.run_deploy")
def test_unresolved_repository_uses_the_existing_deploy_gate(
    mock_deploy,
    mock_record,
    mm_home_with_projects,
    _deploy_vcs,
    argv,
    code,
    deployed,
):
    path = _deploy_vcs.paths["deploy-only"]
    _deploy_vcs.state.fail(
        "resolve_revision", error=RevisionError("missing jj"), path=path
    )
    _deploy_vcs.state.fail(
        "resolve_revision", ordinal=2, error=RevisionError("missing jj"), path=path
    )
    with pytest.raises(SystemExit) as exc:
        app(argv, exit_on_error=False)
    assert exc.value.code == code
    assert mock_deploy.called is deployed
    if deployed:
        assert mock_record.call_args.kwargs["commit_id"] is None


class TestDeployCommand:
    @pytest.fixture(autouse=True)
    def _gate(self, _deploy_vcs: _DeployVcs) -> None:
        pass

    def test_no_deploy_config(self, mm_home_with_projects: Path) -> None:
        """Error when project has no deploy_command configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "no-deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    @patch("maintenance_man.services.deploy.run_deploy")
    def test_successful_deploy(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """Exit 0 on successful deploy."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_deploy.assert_called_once()

    @patch(
        "maintenance_man.services.deploy.run_deploy",
        side_effect=DeployError("deploy failed"),
    )
    def test_failed_deploy(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """Exit DEPLOY_FAILED on deploy failure."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.DEPLOY_FAILED

    @patch("maintenance_man.services.deploy.run_deploy")
    @patch("maintenance_man.services.deploy.run_build")
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

    @patch("maintenance_man.services.deploy.run_deploy")
    def test_build_flag_skips_when_no_build_command(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """--build silently skips if no build_command configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deploy-only", "--build"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_deploy.assert_called_once()

    @patch("maintenance_man.services.deploy.run_deploy")
    @patch(
        "maintenance_man.services.deploy.run_build",
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

    @patch("maintenance_man.services.deploy.record_activity")
    @patch("maintenance_man.services.deploy.run_deploy")
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

    @patch("maintenance_man.services.deploy.record_activity")
    @patch(
        "maintenance_man.services.deploy.run_deploy",
        side_effect=DeployError("deploy failed"),
    )
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

    @patch("maintenance_man.services.deploy.record_activity")
    @patch("maintenance_man.services.deploy.run_deploy")
    @patch("maintenance_man.services.deploy.run_build")
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
    @pytest.fixture(autouse=True)
    def _gate(self, _deploy_vcs: _DeployVcs) -> None:
        pass

    @patch(
        "maintenance_man.services.deploy.check_health",
        return_value=HealthCheckResult(is_up=True),
    )
    @patch("maintenance_man.services.deploy.run_deploy")
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
        "maintenance_man.services.deploy.check_health",
        return_value=HealthCheckResult(is_up=False, error="connection refused"),
    )
    @patch("maintenance_man.services.deploy.run_deploy")
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

    @pytest.mark.parametrize("healthcheck_line", [None, 'healthcheck_url = ""'])
    @patch("maintenance_man.services.deploy.check_health")
    @patch("maintenance_man.services.deploy.run_deploy")
    def test_check_without_healthcheck_url_warns(
        self,
        mock_deploy: MagicMock,
        mock_check: MagicMock,
        healthcheck_line: str | None,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--check without healthcheck_url configured prints warning."""
        if healthcheck_line is not None:
            config_path = mm_home_with_projects / "config.toml"
            config_path.write_text(
                config_path.read_text().replace(
                    "min_version_age_days = 7",
                    f"min_version_age_days = 7\n{healthcheck_line}",
                )
            )
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable", "--check"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        output = capsys.readouterr().out
        assert output.count("--check: no healthcheck_url configured") == 1
        mock_check.assert_not_called()

    @pytest.mark.parametrize(
        ("failure", "error", "expected_code"),
        [
            ("run_build", BuildError("build failed"), ExitCode.BUILD_FAILED),
            ("run_deploy", DeployError("deploy failed"), ExitCode.DEPLOY_FAILED),
        ],
    )
    def test_failed_deploy_with_check_has_no_health_hint(
        self,
        failure: str,
        error: BuildError | DeployError,
        expected_code: ExitCode,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(deploy_service, "run_build", lambda *args: None)
        monkeypatch.setattr(deploy_service, "run_deploy", lambda *args: None)

        def fail(*args) -> None:
            raise error

        monkeypatch.setattr(deploy_service, failure, fail)

        assert run_mm("deploy", "deployable", "--build", "--check") == expected_code
        output = capsys.readouterr().out
        assert str(error) in output
        assert "no healthcheck_url" not in output


class TestMassDeployCommand:
    @pytest.fixture(autouse=True)
    def _gate(self, _deploy_vcs: _DeployVcs) -> None:
        pass

    @patch("maintenance_man.services.deploy.run_deploy")
    @patch("maintenance_man.services.deploy.run_build")
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

    @patch("maintenance_man.services.deploy.run_deploy")
    @patch("maintenance_man.services.deploy.run_build")
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
        deployed_projects = [call.args[0] for call in mock_deploy.call_args_list]
        assert "no-deploy" not in deployed_projects
        assert "vulnerable" not in deployed_projects

    @patch(
        "maintenance_man.services.deploy.run_deploy",
        side_effect=DeployError("deploy failed"),
    )
    @patch("maintenance_man.services.deploy.run_build")
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

    @patch("maintenance_man.services.deploy.run_deploy")
    @patch(
        "maintenance_man.services.deploy.run_build",
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

    @patch("maintenance_man.services.deploy.run_deploy")
    @patch("maintenance_man.services.deploy.run_build")
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
        "maintenance_man.services.deploy.check_health",
        return_value=HealthCheckResult(is_up=True),
    )
    @patch("maintenance_man.services.deploy.run_deploy")
    @patch("maintenance_man.services.deploy.run_build")
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

    @pytest.mark.parametrize("healthcheck_line", [None, 'healthcheck_url = ""'])
    @patch("maintenance_man.services.deploy.check_health")
    @patch("maintenance_man.services.deploy.run_deploy")
    @patch("maintenance_man.services.deploy.run_build")
    def test_check_without_healthcheck_url_warns_in_mass_mode(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mock_check: MagicMock,
        healthcheck_line: str | None,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Mass deploy warns when --check is requested without healthcheck_url."""
        if healthcheck_line is not None:
            config_path = mm_home_with_projects / "config.toml"
            config_path.write_text(
                config_path.read_text().replace(
                    "min_version_age_days = 7",
                    f"min_version_age_days = 7\n{healthcheck_line}",
                )
            )
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "--check"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        output = capsys.readouterr().out
        assert output.count("--check: no healthcheck_url configured") == 1
        mock_check.assert_not_called()

    def test_no_projects_configured(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Mass deploy with no projects prints message and exits OK."""
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "scan-results").mkdir(exist_ok=True)
        (mm_home / "workspaces").mkdir(exist_ok=True)
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        assert "no projects" in capsys.readouterr().out.lower()


class TestDeployGateWiring:
    @pytest.fixture(autouse=True)
    def _vcs(self, _deploy_vcs: _DeployVcs) -> None:
        pass

    @patch("maintenance_man.services.deploy.run_deploy")
    def test_explicit_unchanged_skips_with_warning(
        self,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        _deploy_vcs: _DeployVcs,
    ) -> None:
        main_id = _deploy_vcs.main_ids["deploy-only"]
        monkeypatch.setattr(
            "maintenance_man.services.deploy.load_activity",
            lambda path: (
                _activity(success=True, commit_id="C")
                | {
                    "deploy-only": ProjectActivity(
                        last_deploy=ActivityEvent(
                            timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                            success=True,
                            branch="main",
                            commit_id=main_id,
                        )
                    )
                }
            ),
        )
        with pytest.raises(SystemExit) as exc:
            app(["deploy", "deploy-only"], exit_on_error=False)
        assert exc.value.code == ExitCode.OK
        mock_deploy.assert_not_called()
        assert "force" in capsys.readouterr().out.lower()

    @patch("maintenance_man.services.deploy.record_activity")
    @patch("maintenance_man.services.deploy.run_deploy")
    def test_explicit_unchanged_records_nothing(
        self,
        mock_deploy: MagicMock,
        mock_record: MagicMock,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        _deploy_vcs: _DeployVcs,
    ) -> None:
        main_id = _deploy_vcs.main_ids["deploy-only"]
        monkeypatch.setattr(
            "maintenance_man.services.deploy.load_activity",
            lambda path: {
                "deploy-only": ProjectActivity(
                    last_deploy=ActivityEvent(
                        timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                        success=True,
                        branch="main",
                        commit_id=main_id,
                    )
                )
            },
        )
        with pytest.raises(SystemExit):
            app(["deploy", "deploy-only"], exit_on_error=False)
        mock_record.assert_not_called()

    @patch("maintenance_man.services.deploy.record_activity")
    @patch("maintenance_man.services.deploy.run_deploy")
    def test_force_redeploys_unchanged_and_records_commit_id(
        self,
        mock_deploy: MagicMock,
        mock_record: MagicMock,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        _deploy_vcs: _DeployVcs,
    ) -> None:
        main_id = _deploy_vcs.main_ids["deploy-only"]
        monkeypatch.setattr(
            "maintenance_man.services.deploy.load_activity",
            lambda path: {
                "deploy-only": ProjectActivity(
                    last_deploy=ActivityEvent(
                        timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                        success=True,
                        branch="main",
                        commit_id=main_id,
                    )
                )
            },
        )
        with pytest.raises(SystemExit) as exc:
            app(["deploy", "deploy-only", "--force"], exit_on_error=False)
        assert exc.value.code == ExitCode.OK
        mock_deploy.assert_called_once()
        assert mock_record.call_args.kwargs["commit_id"] == main_id

    @patch("maintenance_man.services.deploy.run_deploy")
    def test_explicit_blocked_exits_error(
        self,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        _deploy_vcs: _DeployVcs,
    ) -> None:
        _deploy_vcs.state.fail(
            "resolve_revision",
            error=RevisionError("no main"),
            path=_deploy_vcs.paths["deploy-only"],
        )
        monkeypatch.setattr(
            "maintenance_man.services.deploy.load_activity", lambda path: {}
        )
        with pytest.raises(SystemExit) as exc:
            app(["deploy", "deploy-only"], exit_on_error=False)
        assert exc.value.code == ExitCode.ERROR
        mock_deploy.assert_not_called()

    @patch("maintenance_man.services.deploy.run_deploy")
    def test_batch_blocked_exits_ok(
        self,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        _deploy_vcs: _DeployVcs,
    ) -> None:
        path = _deploy_vcs.paths["deploy-only"]
        _deploy_vcs.state.fail(
            "resolve_revision", error=RevisionError("no main"), path=path
        )
        _deploy_vcs.state.fail(
            "resolve_revision", ordinal=2, error=RevisionError("no main"), path=path
        )
        monkeypatch.setattr(
            "maintenance_man.services.deploy.load_activity", lambda path: {}
        )
        with pytest.raises(SystemExit) as exc:
            app(["deploy"], exit_on_error=False)
        assert exc.value.code == ExitCode.OK
        mock_deploy.assert_not_called()

    @patch("maintenance_man.services.deploy.run_build")
    @patch("maintenance_man.services.deploy.run_deploy")
    def test_batch_skips_unchanged_deploys_changed(
        self,
        mock_deploy: MagicMock,
        mock_build: MagicMock,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        _deploy_vcs: _DeployVcs,
    ) -> None:
        main_id = _deploy_vcs.main_ids["deployable"]
        monkeypatch.setattr(
            "maintenance_man.services.deploy.load_activity",
            lambda path: {
                "deployable": ProjectActivity(
                    last_deploy=ActivityEvent(
                        timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                        success=True,
                        branch="main",
                        commit_id=main_id,
                    )
                )
            },
        )
        with pytest.raises(SystemExit) as exc:
            app(["deploy"], exit_on_error=False)
        assert exc.value.code == ExitCode.OK
        deployed = [c.args[0] for c in mock_deploy.call_args_list]
        assert "deployable" not in deployed
        assert "deploy-only" in deployed
        mock_build.assert_not_called()

    @patch(
        "maintenance_man.services.deploy.check_health",
        return_value=HealthCheckResult(is_up=True),
    )
    @patch("maintenance_man.services.deploy.run_build")
    @patch("maintenance_man.services.deploy.run_deploy")
    def test_check_not_run_for_skipped(
        self,
        mock_deploy: MagicMock,
        mock_build: MagicMock,
        mock_check: MagicMock,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        _deploy_vcs: _DeployVcs,
    ) -> None:
        config_path = mm_home_with_projects / "config.toml"
        config_path.write_text(
            config_path.read_text().replace(
                "min_version_age_days = 7",
                'min_version_age_days = 7\nhealthcheck_url = "http://h:8080"',
            )
        )
        main_id = _deploy_vcs.main_ids["deployable"]
        monkeypatch.setattr(
            "maintenance_man.services.deploy.load_activity",
            lambda path: {
                "deployable": ProjectActivity(
                    last_deploy=ActivityEvent(
                        timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                        success=True,
                        branch="main",
                        commit_id=main_id,
                    )
                ),
                "deploy-only": ProjectActivity(
                    last_deploy=ActivityEvent(
                        timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                        success=True,
                        branch="main",
                        commit_id=main_id,
                    )
                ),
            },
        )
        with pytest.raises(SystemExit):
            app(["deploy", "--check"], exit_on_error=False)
        mock_check.assert_not_called()

    @patch("maintenance_man.services.deploy.run_deploy")
    def test_loop_closes_real_activity(
        self,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Deploy once records the id; second run skips. The headline behaviour."""
        with pytest.raises(SystemExit):
            app(["deploy", "deploy-only"], exit_on_error=False)
        assert mock_deploy.call_count == 1
        with pytest.raises(SystemExit) as exc:
            app(["deploy", "deploy-only"], exit_on_error=False)
        assert exc.value.code == ExitCode.OK
        assert mock_deploy.call_count == 1
