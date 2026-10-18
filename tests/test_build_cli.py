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


@pytest.mark.parametrize(
    ("error", "expected_code", "expected_record", "expected_success"),
    [
        pytest.param(
            None,
            ExitCode.OK,
            "deployable\tbuild\tpassed\tbuild\t-\t-\t-\n",
            True,
            id="passed",
        ),
        pytest.param(
            BuildError("Build for deployable failed (exit 2)"),
            ExitCode.BUILD_FAILED,
            "deployable\tbuild\tfailed\tbuild\t-\t-\t"
            "Build for deployable failed (exit 2)\n",
            False,
            id="failed",
        ),
    ],
)
def test_given_build_outcome_when_run_then_record_exit_code_and_activity_agree(
    error: BuildError | None,
    expected_code: ExitCode,
    expected_record: str,
    expected_success: bool,
    mm_home_with_projects: Path,
    _build_repositories: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "maintenance_man.services.deploy.run_shell_command",
        MagicMock(side_effect=error),
    )

    assert run_mm("build", "deployable") == expected_code

    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (expected_record, "")
    recorded = load_activity(paths.activity_path())["deployable"].last_build
    assert recorded is not None
    assert (recorded.success, recorded.branch) == (expected_success, "main")


@patch("maintenance_man.services.deploy.run_shell_command")
def test_given_verbose_build_when_a_later_command_runs_then_verbosity_does_not_leak(
    mock_build: MagicMock,
    mm_home_with_projects: Path,
    _build_repositories: dict[str, Path],
) -> None:
    assert run_mm("build", "deployable", "--verbose") == ExitCode.OK
    assert output.is_verbose() is True

    assert run_mm("list") == ExitCode.OK
    assert output.is_verbose() is False
