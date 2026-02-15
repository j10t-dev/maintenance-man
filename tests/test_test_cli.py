from pathlib import Path
from unittest.mock import patch

import pytest

from maintenance_man.cli import ExitCode, app


class TestTestCommand:
    """Tests for `mm test <project>`."""

    def test_missing_test_config(self, mm_home_with_projects: Path) -> None:
        """Error when project has no test block configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["test", "no-tests"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    @patch("maintenance_man.cli.run_test_phases", return_value=(True, None))
    def test_all_phases_pass(self, mock_run, mm_home_with_projects: Path) -> None:
        """Exit 0 when all test phases pass."""
        with pytest.raises(SystemExit) as exc_info:
            app(["test", "vulnerable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_run.assert_called_once()

    @patch(
        "maintenance_man.cli.run_test_phases",
        return_value=(False, "integration"),
    )
    def test_phase_failure(self, mock_run, mm_home_with_projects: Path) -> None:
        """Exit TEST_FAILED when a phase fails."""
        with pytest.raises(SystemExit) as exc_info:
            app(["test", "vulnerable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.TEST_FAILED

    def test_unknown_project(self, mm_home_with_projects: Path) -> None:
        """Error when project name doesn't exist."""
        with pytest.raises(SystemExit) as exc_info:
            app(["test", "nonexistent"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR
