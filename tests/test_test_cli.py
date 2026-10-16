from pathlib import Path
from unittest.mock import patch

from maintenance_man.cli import ExitCode
from tests.conftest import run_mm


class TestTestCommand:
    """Tests for `mm test <project>`."""

    def test_missing_test_config(self, mm_home_with_projects: Path) -> None:
        """Error when project has no test block configured."""
        assert run_mm("test", "no-tests") == ExitCode.ERROR

    @patch("maintenance_man.cli.run_test_phases", return_value=None)
    def test_all_phases_pass(self, mock_run, mm_home_with_projects: Path) -> None:
        """Exit 0 when all test phases pass."""
        assert run_mm("test", "vulnerable") == ExitCode.OK
        mock_run.assert_called_once()

    @patch(
        "maintenance_man.cli.run_test_phases",
        return_value="integration",
    )
    def test_phase_failure(self, mock_run, mm_home_with_projects: Path) -> None:
        """Exit TEST_FAILED when a phase fails."""
        assert run_mm("test", "vulnerable") == ExitCode.TEST_FAILED

    def test_unknown_project(self, mm_home_with_projects: Path) -> None:
        """Error when project name doesn't exist."""
        assert run_mm("test", "nonexistent") == ExitCode.ERROR
