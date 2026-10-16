from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man import cli, paths
from maintenance_man.cli import ExitCode
from maintenance_man.deployer import BuildError, DeployError, HealthCheckResult
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
        deploy_service,
        "run_live",
        lambda command, *args, **kwargs: deployed.append(command),
    )

    argv = ["deploy", "demo"] + (["--force"] if force else [])
    assert run_mm(*argv) == expected_code

    assert deployed == (["deploy"] if expected_deploys else [])
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

    def deploy(*args, **kwargs):
        advanced = state.seed_commit(
            project_path,
            parent=main_id,
            files={"dep.txt": "version=2\n"},
            description="advanced during deployment",
        )
        state.seed_bookmark(project_path, bookmark="main", targets=(advanced,))

    monkeypatch.setattr(deploy_service, "run_live", deploy)

    assert run_mm("deploy", "demo") == ExitCode.OK

    event = load_activity(paths.activity_path())["demo"].last_deploy
    assert event is not None
    assert event.commit_id == main_id
    assert repo.resolve_revision(revision="main") != main_id
    assert any(call.method == "resolve_revision" for call in state.attempts)


class TestDeployCommand:
    @pytest.fixture(autouse=True)
    def _gate(self, _deploy_vcs: _DeployVcs) -> None:
        pass

    def test_no_deploy_config(self, mm_home_with_projects: Path) -> None:
        """Error when project has no deploy_command configured."""
        assert run_mm("deploy", "no-deploy") == ExitCode.ERROR

    @patch("maintenance_man.services.deploy.run_live")
    def test_successful_deploy(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """Exit 0 on successful deploy."""
        assert run_mm("deploy", "deployable") == ExitCode.OK
        mock_deploy.assert_called_once()

    @patch(
        "maintenance_man.services.deploy.run_live",
        side_effect=DeployError("deploy failed"),
    )
    def test_failed_deploy(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """Exit DEPLOY_FAILED on deploy failure."""
        assert run_mm("deploy", "deployable") == ExitCode.DEPLOY_FAILED

    @patch("maintenance_man.services.deploy.run_live")
    def test_build_flag_runs_build_then_deploy(
        self,
        mock_run: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """--build runs build before deploy."""
        calls: list[str] = []
        mock_run.side_effect = lambda *args, **kwargs: calls.append(
            "build" if kwargs["error"] is BuildError else "deploy"
        )
        assert run_mm("deploy", "deployable", "--build") == ExitCode.OK
        assert mock_run.call_count == 2
        assert calls == ["build", "deploy"]

    @patch("maintenance_man.services.deploy.run_live")
    def test_build_flag_skips_when_no_build_command(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """--build silently skips if no build_command configured."""
        assert run_mm("deploy", "deploy-only", "--build") == ExitCode.OK
        mock_deploy.assert_called_once()

    @patch(
        "maintenance_man.services.deploy.run_live",
        side_effect=BuildError("build failed"),
    )
    def test_build_failure_aborts_deploy(
        self,
        mock_run: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Deploy is not attempted if build fails."""
        assert run_mm("deploy", "deployable", "--build") == ExitCode.BUILD_FAILED
        mock_run.assert_called_once()
        assert mock_run.call_args.kwargs["error"] is BuildError

    def test_unknown_project(self, mm_home_with_projects: Path) -> None:
        """Error when project doesn't exist."""
        assert run_mm("deploy", "nonexistent") == ExitCode.ERROR

    @patch("maintenance_man.services.deploy.run_live")
    def test_given_unchanged_deploy_when_run_then_exits_zero_with_force_hint(
        self,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("deploy", "deploy-only") == ExitCode.OK
        capsys.readouterr()

        assert run_mm("deploy", "deploy-only") == ExitCode.OK
        assert (
            "deploy-only unchanged since last deploy (use --force to redeploy)."
            in capsys.readouterr().out.splitlines()
        )


class TestDeployCheck:
    @pytest.fixture(autouse=True)
    def _gate(self, _deploy_vcs: _DeployVcs) -> None:
        pass

    @patch(
        "maintenance_man.services.deploy.check_health",
        return_value=HealthCheckResult(is_up=True),
    )
    @patch("maintenance_man.services.deploy.run_live")
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
        write_config(mm_home_with_projects, text)

        assert run_mm("deploy", "deployable", "--check") == ExitCode.OK
        mock_check.assert_called_once_with("http://pihost:8080", "deployable")

    @patch(
        "maintenance_man.services.deploy.check_health",
        return_value=HealthCheckResult(is_up=False, error="connection refused"),
    )
    @patch("maintenance_man.services.deploy.run_live")
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
        write_config(mm_home_with_projects, text)

        assert run_mm("deploy", "deployable", "--check") == ExitCode.OK
        mock_check.assert_called_once_with("http://pihost:8080", "deployable")

    @patch("maintenance_man.services.deploy.check_health")
    @patch("maintenance_man.services.deploy.run_live")
    def test_given_unconfigured_check_when_run_then_exits_zero_with_warning(
        self,
        mock_deploy: MagicMock,
        mock_check: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("deploy", "deployable", "--check") == ExitCode.OK
        assert (
            capsys.readouterr().out.count(
                "--check: no healthcheck_url configured in [defaults]"
            )
            == 1
        )

    @pytest.mark.parametrize(
        ("failure", "error", "expected_code"),
        [
            (BuildError, BuildError("build failed"), ExitCode.BUILD_FAILED),
            (DeployError, DeployError("deploy failed"), ExitCode.DEPLOY_FAILED),
        ],
    )
    def test_given_failed_checked_deploy_when_run_then_error_has_no_health_hint(
        self,
        failure: type[BuildError] | type[DeployError],
        error: BuildError | DeployError,
        expected_code: ExitCode,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        def run(*args, **kwargs) -> None:
            if kwargs["error"] is failure:
                raise error

        monkeypatch.setattr(deploy_service, "run_live", run)

        assert run_mm("deploy", "deployable", "--build", "--check") == expected_code
        output = capsys.readouterr().out
        assert str(error) in output
        assert "no healthcheck_url" not in output


def test_given_empty_project_name_when_deploy_then_runs_deploy_all_in_batch_mode(
    mm_home_with_projects: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(deploy_service, "run_live", lambda *a, **k: None)
    configure_fake_vcs(mm_home_with_projects, tmp_path, monkeypatch)

    code = run_mm("deploy", "")
    out = capsys.readouterr().out

    assert code == 0
    assert "Deploy Summary" in out
    assert "Deploying deployable" not in out


class TestMassDeployCommand:
    @pytest.fixture(autouse=True)
    def _gate(self, _deploy_vcs: _DeployVcs) -> None:
        pass

    @patch("maintenance_man.services.deploy.run_live")
    def test_deploys_all_projects_and_prints_summary(
        self,
        mock_run: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Mass deploy runs eligible projects and reports the combined result."""
        assert run_mm("deploy") == ExitCode.OK
        deploy_labels = [
            call.kwargs["label"]
            for call in mock_run.call_args_list
            if call.kwargs["error"] is DeployError
        ]
        assert deploy_labels == [
            "Deploy for deploy-only",
            "Deploy for deployable",
        ]
        assert (
            sum(call.kwargs["error"] is BuildError for call in mock_run.call_args_list)
            == 1
        )
        assert "Deploy Summary" in capsys.readouterr().out

    @patch("maintenance_man.services.deploy.run_live")
    def test_continues_after_deploy_failure(
        self,
        mock_run: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Deploy failure on one project doesn't stop others."""
        error = DeployError("deploy failed")

        def fail_deploy(*args, **kwargs):
            if kwargs["error"] is DeployError:
                raise error

        mock_run.side_effect = fail_deploy
        assert run_mm("deploy") == ExitCode.DEPLOY_FAILED
        assert (
            sum(call.kwargs["error"] is DeployError for call in mock_run.call_args_list)
            == 2
        )

    @patch(
        "maintenance_man.services.deploy.check_health",
        return_value=HealthCheckResult(is_up=True),
    )
    @patch("maintenance_man.services.deploy.run_live")
    def test_check_flag_works_in_mass_mode(
        self,
        mock_run: MagicMock,
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
        write_config(mm_home_with_projects, text)

        assert run_mm("deploy", "--check") == ExitCode.OK
        assert mock_check.call_count == 2
        output = capsys.readouterr().out
        assert "Healthy: deploy-only is up" in output
        assert "Healthy: deployable is up" in output

    @pytest.mark.parametrize("healthcheck_line", [None, 'healthcheck_url = ""'])
    @patch("maintenance_man.services.deploy.check_health")
    @patch("maintenance_man.services.deploy.run_live")
    def test_check_without_healthcheck_url_warns_in_mass_mode(
        self,
        mock_run: MagicMock,
        mock_check: MagicMock,
        healthcheck_line: str | None,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Mass deploy warns when --check is requested without healthcheck_url."""
        if healthcheck_line is not None:
            config_path = mm_home_with_projects / "config.toml"
            write_config(
                mm_home_with_projects,
                config_path.read_text().replace(
                    "min_version_age_days = 7",
                    f"min_version_age_days = 7\n{healthcheck_line}",
                ),
            )
        assert run_mm("deploy", "--check") == ExitCode.OK
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
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")
        assert run_mm("deploy") == ExitCode.OK
        assert "no projects" in capsys.readouterr().out.lower()
