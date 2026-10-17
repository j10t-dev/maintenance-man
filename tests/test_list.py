from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from maintenance_man import cli
from maintenance_man.models.scan import (
    ScanResult,
    SecretFinding,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
)
from maintenance_man.output import relative_time
from maintenance_man.storage import record_activity
from tests.conftest import TerminalStream, run_mm, write_config

_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _write_scan_result(mm_home: Path, name: str, result: ScanResult) -> None:
    """Write a scan result JSON to the scan-results dir."""
    (mm_home / "scan-results" / f"{name}.json").write_text(
        result.model_dump_json(indent=2),
        encoding="utf-8",
    )


def _records(output: str) -> list[list[str]]:
    return [line.split("\t") for line in output.splitlines()]


@pytest.fixture()
def list_project_home(mm_home: Path) -> Path:
    """mm_home with a single 'myapp' project configured."""
    project_dir = mm_home.parent / "myproject"
    project_dir.mkdir()
    mm_home.mkdir(parents=True)
    (mm_home / "scan-results").mkdir()
    (mm_home / "workspaces").mkdir()
    write_config(
        mm_home, f'[projects.myapp]\npath = "{project_dir}"\npackage_manager = "uv"\n'
    )
    return mm_home


_VULN = VulnFinding(
    vuln_id="CVE-2024-0001",
    pkg_name="badpkg",
    installed_version="1.0.0",
    fixed_version="1.0.1",
    severity=Severity.HIGH,
    title="Bad vuln",
    description="desc",
    status="fixed",
)
_UPDATE = UpdateFinding(
    pkg_name="somepkg",
    installed_version="1.0.0",
    latest_version="2.0.0",
    semver_tier=SemverTier.MAJOR,
)
_SECRET = SecretFinding(
    file="secrets.env",
    rule_id="generic-api-key",
    title="API Key",
    severity=Severity.HIGH,
)


class TestRelativeTime:
    @pytest.mark.parametrize(
        ("delta", "expected"),
        [
            (timedelta(seconds=30), "just now"),
            (timedelta(minutes=5), "5m ago"),
            (timedelta(hours=1), "1h ago"),
            (timedelta(hours=3), "3h ago"),
            (timedelta(days=1), "1d ago"),
            (timedelta(days=14), "14d ago"),
        ],
        ids=["seconds", "minutes", "1hour", "hours", "1day", "days"],
    )
    def test_relative_time(self, delta: timedelta, expected: str):
        assert relative_time(_NOW - delta, _NOW) == expected


def test_given_wide_project_name_when_narrow_terminal_then_columns_drop_by_cell_width(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdout", TerminalStream())
    wide_name = "日本語プロジェクト"
    row = [wide_name, "uv", "0", "0", "0", "never", "-", "not deployable"]

    visible, dropped = cli._fit_columns(
        cli._OVERVIEW_HEADERS, [row], list(range(len(row)))
    )

    assert dropped == ["scanned"]
    assert visible == [0, 1, 2, 3, 4, 6, 7]


def test_given_long_last_column_when_terminal_is_narrow_then_it_is_not_capped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdout", TerminalStream())
    monkeypatch.setenv("COLUMNS", "84")
    row = ["api", "uv", "0", "0", "0", "never", "-", "failed " + "9" * 25]

    visible, dropped = cli._fit_columns(
        cli._OVERVIEW_HEADERS, [row], list(range(len(row)))
    )

    assert dropped == ["scanned"]
    assert visible == [0, 1, 2, 3, 4, 6, 7]


class TestListCommand:
    def test_list_no_projects(self, mm_home: Path, capsys: pytest.CaptureFixture[str]):
        assert run_mm("list") == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [
            "No projects configured",
            f"hint: add projects to {mm_home / 'config.toml'}",
        ]

    def test_list_shows_projects(
        self, list_project_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        assert run_mm("list") == 0
        assert [row[:2] for row in _records(capsys.readouterr().out)] == [
            ["myapp", "uv"]
        ]

    def test_st_alias_shows_projects(
        self, list_project_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        assert run_mm("st") == 0
        assert [row[:2] for row in _records(capsys.readouterr().out)] == [
            ["myapp", "uv"]
        ]

    def test_list_prints_bracketed_project_name_literally(
        self, mm_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project = tmp_path / "project"
        project.mkdir()
        mm_home.mkdir(parents=True)
        write_config(
            mm_home,
            f'[projects."a[b]"]\npath = "{project}"\npackage_manager = "uv"\n',
        )

        assert run_mm("list") == 0
        assert [row[0] for row in _records(capsys.readouterr().out)] == ["a[b]"]


class TestListFindings:
    def test_shows_never_for_unscanned_projects(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Projects without scan results have unknown counts and 'never' scanned."""
        assert run_mm("list") == 0
        (row,) = _records(capsys.readouterr().out)
        assert row[2:6] == ["-", "-", "-", "never"]

    def test_summary_shows_counts(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Summary view shows finding counts from saved scan results."""
        result = ScanResult(
            project="myapp",
            scanned_at=_NOW,
            trivy_target=".",
            vulnerabilities=[_VULN, _VULN],
            updates=[_UPDATE, _UPDATE, _UPDATE],
            secrets=[_SECRET],
        )
        _write_scan_result(list_project_home, "myapp", result)
        assert run_mm("list") == 0
        output = capsys.readouterr().out
        (row,) = _records(output)
        assert row[2:5] == ["2", "3", "1"]

    def test_corrupt_scan_results_skipped(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """A corrupt scan-results JSON should not crash mm list."""
        (list_project_home / "scan-results" / "myapp.json").write_text(
            "NOT VALID JSON",
            encoding="utf-8",
        )
        assert run_mm("list") == 0
        captured = capsys.readouterr()
        assert [row[:5] for row in _records(captured.out)] == [
            ["myapp", "uv", "-", "-", "-"]
        ]
        assert captured.err == "warning: corrupt scan results for myapp; skipped\n"

    @pytest.mark.parametrize(
        "expected_substring",
        ["CVE-2024-0001", "badpkg"],
        ids=["vuln_id", "pkg_name"],
    )
    def test_detail_shows_findings(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
        expected_substring: str,
    ):
        """--detail flag prints full findings (vuln IDs, package names)."""
        result = ScanResult(
            project="myapp",
            scanned_at=_NOW,
            trivy_target=".",
            vulnerabilities=[_VULN],
        )
        _write_scan_result(list_project_home, "myapp", result)
        assert run_mm("list", "--detail") == 0
        assert expected_substring in capsys.readouterr().out

    def test_detail_sorts_by_severity(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Findings are sorted CRITICAL > HIGH > LOW in detail output."""
        vulns = [
            VulnFinding(
                vuln_id="CVE-LOW",
                pkg_name="low-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.LOW,
                title="t",
                description="d",
                status="fixed",
            ),
            VulnFinding(
                vuln_id="CVE-CRIT",
                pkg_name="crit-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.CRITICAL,
                title="t",
                description="d",
                status="fixed",
            ),
            VulnFinding(
                vuln_id="CVE-HIGH",
                pkg_name="high-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.HIGH,
                title="t",
                description="d",
                status="fixed",
            ),
        ]
        result = ScanResult(
            project="myapp",
            scanned_at=_NOW,
            trivy_target=".",
            vulnerabilities=vulns,
        )
        _write_scan_result(list_project_home, "myapp", result)
        assert run_mm("list", "--detail") == 0
        output = capsys.readouterr().out
        crit_pos = output.index("CVE-CRIT")
        high_pos = output.index("CVE-HIGH")
        low_pos = output.index("CVE-LOW")
        assert crit_pos < high_pos < low_pos

    @pytest.mark.parametrize(
        ("severities", "vuln_ids", "expected_order"),
        [
            ((Severity.HIGH, Severity.HIGH), ("CVE-0001", "CVE-0002"), None),
            (
                (Severity.CRITICAL, Severity.HIGH),
                ("CVE-CRIT", "CVE-HIGH"),
                ("CVE-CRIT", "CVE-HIGH"),
            ),
        ],
        ids=["equal-severity", "mixed-severity"],
    )
    def test_detail_fix_marker_on_highest_version(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
        severities: tuple[Severity, Severity],
        vuln_ids: tuple[str, str],
        expected_order: tuple[str, str] | None,
    ):
        """'selected fix' marks the highest fix version for duplicate-package vulns."""
        vulns = [
            VulnFinding(
                vuln_id=vuln_ids[0],
                pkg_name="requests",
                installed_version="2.25.0",
                fixed_version="2.31.0",
                severity=severities[0],
                title="t",
                description="d",
                status="fixed",
            ),
            VulnFinding(
                vuln_id=vuln_ids[1],
                pkg_name="requests",
                installed_version="2.25.0",
                fixed_version="2.32.4",
                severity=severities[1],
                title="t",
                description="d",
                status="fixed",
            ),
        ]
        result = ScanResult(
            project="myapp",
            scanned_at=_NOW,
            trivy_target=".",
            vulnerabilities=vulns,
        )
        _write_scan_result(list_project_home, "myapp", result)
        assert run_mm("list", "--detail") == 0
        output = capsys.readouterr().out
        assert "2.32.4" in output
        lines_with_marker = [
            line for line in output.splitlines() if "selected fix" in line
        ]
        assert len(lines_with_marker) == 1
        assert "2.32.4" in lines_with_marker[0]
        if expected_order is not None:
            assert output.index(expected_order[0]) < output.index(expected_order[1])

    def test_detail_no_fix_marker_for_single_vuln_package(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Single-vuln packages should not get the 'selected fix' marker."""
        result = ScanResult(
            project="myapp",
            scanned_at=_NOW,
            trivy_target=".",
            vulnerabilities=[_VULN],
        )
        _write_scan_result(list_project_home, "myapp", result)
        assert run_mm("list", "--detail") == 0
        output = capsys.readouterr().out
        assert "selected fix" not in output


class TestListActivity:
    def test_shows_dash_when_never_built(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Projects with no activity pipe '-' for every build and deploy field."""
        assert run_mm("list") == 0
        (row,) = _records(capsys.readouterr().out)
        assert row[6:10] == ["-", "-", "-", "-"]

    def test_given_successful_build_when_listed_in_pipe_then_iso_time_and_passed_status(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Piped build activity carries an ISO timestamp and a status word."""
        activity_path = list_project_home / "activity.json"
        record_activity(activity_path, "myapp", "build", success=True, branch="main")
        assert run_mm("list") == 0
        (row,) = _records(capsys.readouterr().out)
        assert datetime.fromisoformat(row[6]).tzinfo is not None
        assert row[7] == "passed"

    def test_given_failed_build_when_listed_in_pipe_then_status_is_failed(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """A failed build is a status field, not a marker inside a timestamp."""
        activity_path = list_project_home / "activity.json"
        record_activity(activity_path, "myapp", "build", success=False, branch="main")
        assert run_mm("list") == 0
        (row,) = _records(capsys.readouterr().out)
        assert row[7] == "failed"

    def test_given_failed_build_when_listed_on_terminal_then_row_reads_failed_just_now(
        self,
        list_project_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """On a terminal a failed build reads 'failed just now'."""
        activity_path = list_project_home / "activity.json"
        record_activity(activity_path, "myapp", "build", success=False, branch="main")
        stream = TerminalStream()
        monkeypatch.setattr("sys.stdout", stream)
        monkeypatch.setenv("NO_COLOR", "1")
        assert run_mm("list") == 0
        assert "failed just now" in stream.getvalue()
