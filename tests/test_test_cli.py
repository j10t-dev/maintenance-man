from pathlib import Path
from unittest.mock import patch

import pytest

from maintenance_man.cli import ExitCode
from tests.support.cli import run_mm


class TestTestCommand:
    """Tests for `mm test <project>`."""

    def test_missing_test_config(self, mm_home_with_projects: Path) -> None:
        """Error when project has no test block configured."""
        assert run_mm("test", "no-tests") == ExitCode.ERROR

    def test_unknown_project(self, mm_home_with_projects: Path) -> None:
        """Error when project name doesn't exist."""
        assert run_mm("test", "nonexistent") == ExitCode.ERROR

    @pytest.mark.parametrize(
        ("failed_phase", "expected_code", "expected_record"),
        [
            (None, ExitCode.OK, "vulnerable\ttest\tpassed\ttests\t-\t-\t-\n"),
            (
                "unit",
                ExitCode.TEST_FAILED,
                "vulnerable\ttest\tfailed\ttests\t-\t-\tunit failed\n",
            ),
        ],
        ids=["passed", "failed"],
    )
    def test_given_test_phases_when_piped_then_one_outcome_record(
        self,
        failed_phase: str | None,
        expected_code: ExitCode,
        expected_record: str,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with patch("maintenance_man.cli.run_test_phases", return_value=failed_phase):
            assert run_mm("test", "vulnerable") == expected_code

        captured = capsys.readouterr()
        assert captured.out == expected_record
        assert captured.err == ""
