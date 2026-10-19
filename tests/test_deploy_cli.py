from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from maintenance_man import cli, paths
from maintenance_man.cli import ExitCode
from maintenance_man.deployer import BuildError, DeployError, HealthCheckResult
from maintenance_man.services import deploy as deploy_service
from maintenance_man.storage import load_activity
from tests.support.cli import run_mm
from tests.support.projects import write_config
from tests.support.repository import (
    commit_to_main,
    configure_jj_projects,
    copy_jj_repository,
    write_file,
)


@pytest.mark.parametrize(
    ("results", "expected"),
    [
        ([], "No projects have deploy_command configured\n"),
        (
            [
                deploy_service.DeployResult("a", "passed", "passed"),
                deploy_service.DeployResult("b", "failed", "skipped"),
                deploy_service.DeployResult("c", "passed", "failed"),
                deploy_service.DeployResult("d", "skipped", "skipped"),
                deploy_service.DeployResult("e", "skipped", "unchanged"),
                deploy_service.DeployResult("f", "skipped", "blocked"),
                deploy_service.DeployResult("g", "skipped", "failed"),
            ],
            "1 passed · 3 failed · 1 blocked · 1 skipped · 1 unchanged\n",
        ),
        ([deploy_service.DeployResult("a", "passed", "passed")], "1 passed\n"),
    ],
    ids=["none", "every-status", "passed-only"],
)
def test_given_deploy_results_when_summarised_then_one_status_counts_per_project(
    capsys: pytest.CaptureFixture[str],
    results: list[deploy_service.DeployResult],
    expected: str,
) -> None:
    cli._print_deploy_summary(results)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == expected


def test_given_batch_deploy_with_failed_build_when_run_then_deploy_is_recorded_skipped(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    error = BuildError("Build for deployable failed (exit 2)")

    def run(*args, **kwargs) -> None:
        if kwargs["error"] is BuildError:
            raise error

    monkeypatch.setattr(deploy_service, "run_shell_command", run)
    configure_jj_projects(mm_home_with_projects, tmp_path)

    assert run_mm("deploy") == ExitCode.DEPLOY_FAILED

    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "deploy-only\tdeploy\tpassed\tdeploy\t-\t-\t-",
        "deployable\tbuild\tfailed\tbuild\t-\t-\tBuild for deployable failed (exit 2)",
        "deployable\tdeploy\tskipped\tdeploy\t-\t-\tbuild failed",
    ]
    assert captured.err == "1 passed · 1 failed\n"


def test_given_unusable_projects_when_batch_deploy_then_records_and_summary_agree(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        deploy_service, "run_shell_command", lambda *args, **kwargs: None
    )
    configure_jj_projects(mm_home_with_projects, tmp_path)
    config_path = mm_home_with_projects / "config.toml"
    missing = tmp_path / "missing"
    write_config(
        mm_home_with_projects,
        config_path.read_text()
        + f'\n[projects.ghost]\npath = "{missing}"\npackage_manager = "uv"\n'
        'deploy_command = "scripts/deploy.sh"\n'
        f'\n[projects.parked]\npath = "{tmp_path}"\npackage_manager = "uv"\n'
        'deploy_command = "scripts/deploy.sh"\ndeployable = false\n',
    )

    assert run_mm("deploy") == ExitCode.DEPLOY_FAILED

    captured = capsys.readouterr()
    assert captured.out.splitlines()[-2:] == [
        f"ghost\tdeploy\tfailed\tdeploy\t-\t-\tpath does not exist: {missing}",
        "parked\tdeploy\tskipped\tdeploy\t-\t-\tnot deployable",
    ]
    assert captured.err == "2 passed · 1 failed · 1 skipped\n"


@pytest.fixture
def _jj_projects(mm_home_with_projects: Path, tmp_path: Path) -> None:
    configure_jj_projects(mm_home_with_projects, tmp_path)


def test_deploy_saves_the_exact_main_identity_used_by_the_gate(
    mm_home, tmp_path, monkeypatch
):
    project_path = tmp_path / "project"
    repo = copy_jj_repository(project_path)
    main_id = repo.resolve_revision(revision="main")
    write_config(
        mm_home,
        f'[projects.demo]\npath = "{project_path}"\npackage_manager = "uv"\n'
        'deploy_command = "deploy"\n',
    )

    def deploy(*args, **kwargs):
        write_file(repo, "dep.txt", "version=2\n")
        commit_to_main(repo, "advanced during deployment")

    monkeypatch.setattr(deploy_service, "run_shell_command", deploy)

    assert run_mm("deploy", "demo") == ExitCode.OK

    event = load_activity(paths.activity_path())["demo"].last_deploy
    assert event is not None
    assert event.commit_id == main_id
    assert repo.resolve_revision(revision="main") != main_id


@pytest.mark.usefixtures("_jj_projects")
@pytest.mark.parametrize(
    ("argv", "failure", "expected_code", "expected_records"),
    [
        pytest.param(
            ("deploy", "no-deploy"), None, ExitCode.ERROR, [], id="no-deploy-command"
        ),
        pytest.param(
            ("deploy", "deployable"),
            None,
            ExitCode.OK,
            ["deployable\tdeploy\tpassed\tdeploy\t-\t-\t-"],
            id="deploy-passes",
        ),
        pytest.param(
            ("deploy", "deployable"),
            DeployError("deploy failed"),
            ExitCode.DEPLOY_FAILED,
            ["deployable\tdeploy\tfailed\tdeploy\t-\t-\tdeploy failed"],
            id="deploy-fails",
        ),
        pytest.param(
            ("deploy", "deployable", "--build"),
            None,
            ExitCode.OK,
            [
                "deployable\tbuild\tpassed\tbuild\t-\t-\t-",
                "deployable\tdeploy\tpassed\tdeploy\t-\t-\t-",
            ],
            id="build-then-deploy",
        ),
        pytest.param(
            ("deploy", "deploy-only", "--build"),
            None,
            ExitCode.OK,
            ["deploy-only\tdeploy\tpassed\tdeploy\t-\t-\t-"],
            id="build-flag-skips-a-project-without-build-command",
        ),
        pytest.param(
            ("deploy", "deployable", "--build"),
            BuildError("build failed"),
            ExitCode.BUILD_FAILED,
            [
                "deployable\tbuild\tfailed\tbuild\t-\t-\tbuild failed",
                "deployable\tdeploy\tskipped\tdeploy\t-\t-\tbuild failed",
            ],
            id="build-failure-aborts-deploy",
        ),
    ],
)
def test_given_deploy_arguments_when_run_then_records_follow_the_failing_step(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, ...],
    failure: BuildError | DeployError | None,
    expected_code: ExitCode,
    expected_records: list[str],
) -> None:
    def run(*args, **kwargs) -> None:
        if failure is not None and kwargs["error"] is type(failure):
            raise failure

    monkeypatch.setattr(deploy_service, "run_shell_command", run)

    assert run_mm(*argv) == expected_code
    assert capsys.readouterr().out.splitlines() == expected_records


@pytest.mark.usefixtures("_jj_projects")
class TestDeployCommand:
    @patch("maintenance_man.services.deploy.run_shell_command")
    def test_given_unchanged_deploy_when_run_then_exits_zero_with_force_hint(
        self,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("deploy", "deploy-only") == ExitCode.OK
        capsys.readouterr()

        assert run_mm("deploy", "deploy-only") == ExitCode.OK
        captured = capsys.readouterr()
        assert captured.out == (
            "deploy-only\tdeploy\tunchanged\tdeploy\t-\t-\t"
            "unchanged since last deploy · use --force to redeploy\n"
        )
        assert captured.err == ""


@pytest.mark.usefixtures("_jj_projects")
class TestDeployCheck:
    @pytest.mark.parametrize(
        ("health", "expected_record"),
        [
            pytest.param(
                HealthCheckResult(is_up=True),
                "deployable\thealth\tpassed\thealthcheck\t-\t-\t-",
                id="healthy",
            ),
            pytest.param(
                HealthCheckResult(is_up=False, error="connection refused"),
                "deployable\thealth\tfailed\thealthcheck\t-\t-\tconnection refused",
                id="unhealthy-is-informational",
            ),
        ],
    )
    def test_given_check_when_deployed_then_health_is_checked_and_exit_stays_ok(
        self,
        health: HealthCheckResult,
        expected_record: str,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        config_path = mm_home_with_projects / "config.toml"
        write_config(
            mm_home_with_projects,
            config_path.read_text().replace(
                "min_version_age_days = 7",
                'min_version_age_days = 7\nhealthcheck_url = "http://pihost:8080"',
            ),
        )
        check = MagicMock(return_value=health)
        monkeypatch.setattr(deploy_service, "check_health", check)
        monkeypatch.setattr(deploy_service, "run_shell_command", MagicMock())

        assert run_mm("deploy", "deployable", "--check") == ExitCode.OK

        check.assert_called_once_with("http://pihost:8080", "deployable")
        assert capsys.readouterr().out.splitlines()[-1] == expected_record

    @patch("maintenance_man.services.deploy.check_health")
    @patch("maintenance_man.services.deploy.run_shell_command")
    def test_given_unconfigured_check_when_run_then_exits_zero_with_warning(
        self,
        mock_deploy: MagicMock,
        mock_check: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert run_mm("deploy", "deployable", "--check") == ExitCode.OK
        captured = capsys.readouterr()
        assert (
            captured.err.count("--check: no healthcheck_url configured in [defaults]")
            == 1
        )
        assert "healthcheck_url" not in captured.out

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

        monkeypatch.setattr(deploy_service, "run_shell_command", run)

        assert run_mm("deploy", "deployable", "--build", "--check") == expected_code
        captured = capsys.readouterr()
        assert str(error) in captured.out
        assert "no healthcheck_url" not in captured.out + captured.err


def test_given_empty_project_name_when_deploy_then_runs_deploy_all_in_batch_mode(
    mm_home_with_projects: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.setattr(deploy_service, "run_shell_command", lambda *a, **k: None)
    configure_jj_projects(mm_home_with_projects, tmp_path)

    code = run_mm("deploy", "")
    captured = capsys.readouterr()

    assert code == 0
    assert captured.err == "2 passed\n"
    assert "deployable\tbuild\tpassed\tbuild\t-\t-\t-" in captured.out


@pytest.mark.usefixtures("_jj_projects")
class TestMassDeployCommand:
    @patch("maintenance_man.services.deploy.run_shell_command")
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

    @pytest.mark.parametrize("healthcheck_line", [None, 'healthcheck_url = ""'])
    @patch("maintenance_man.services.deploy.check_health")
    @patch("maintenance_man.services.deploy.run_shell_command")
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
        captured = capsys.readouterr()
        assert captured.err.splitlines() == [
            "--check: no healthcheck_url configured in [defaults]",
            "2 passed",
        ]
        assert "healthcheck_url" not in captured.out
        mock_check.assert_not_called()

    def test_given_check_when_batch_deployed_then_every_deploy_is_health_checked(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config_path = mm_home_with_projects / "config.toml"
        write_config(
            mm_home_with_projects,
            config_path.read_text().replace(
                "min_version_age_days = 7",
                'min_version_age_days = 7\nhealthcheck_url = "http://pihost:8080"',
            ),
        )
        check = MagicMock(return_value=HealthCheckResult(is_up=True))
        monkeypatch.setattr(deploy_service, "check_health", check)
        monkeypatch.setattr(deploy_service, "run_shell_command", MagicMock())

        assert run_mm("deploy", "--check") == ExitCode.OK

        assert check.call_args_list == [
            call("http://pihost:8080", "deploy-only"),
            call("http://pihost:8080", "deployable"),
        ]

    def test_no_projects_configured(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Mass deploy with no projects notices with a hint and exits OK."""
        mm_home.mkdir(parents=True, exist_ok=True)
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")
        assert run_mm("deploy") == ExitCode.OK
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [
            "No projects configured",
            f"hint: add projects to {mm_home / 'config.toml'}",
        ]
