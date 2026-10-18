import json
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
)
from maintenance_man.output import relative_time
from maintenance_man.storage import record_activity, save_scan_results
from tests.support.cli import TerminalStream, run_mm
from tests.support.findings import make_vuln
from tests.support.projects import write_config

_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


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


_VULN = make_vuln(pkg_name="badpkg", title="Bad vuln")
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

    @pytest.mark.parametrize("command", ["list", "status", "st"])
    def test_list_shows_projects(
        self, list_project_home: Path, capsys: pytest.CaptureFixture[str], command: str
    ):
        assert run_mm(command) == 0
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


_COUNTS_SCAN = ScanResult(
    project="app",
    scanned_at=datetime(2026, 3, 20, tzinfo=UTC),
    trivy_target=".",
    vulnerabilities=[_VULN, _VULN],
    updates=[_UPDATE, _UPDATE, _UPDATE],
    secrets=[_SECRET],
)


def _build_activity(*, success: bool) -> str:
    event = {
        "timestamp": "2026-03-20T12:00:00+00:00",
        "success": success,
        "branch": "main",
    }
    return json.dumps({"app": {"last_build": event}})


@pytest.mark.parametrize(
    ("scan", "activity", "expected_record"),
    [
        pytest.param(None, None, "app\tuv\t-\t-\t-\tnever\t-\t-\t-\t-", id="unscanned"),
        pytest.param(
            _COUNTS_SCAN,
            None,
            "app\tuv\t2\t3\t1\t2026-03-20T00:00:00+00:00\t-\t-\t-\t-",
            id="counts",
        ),
        pytest.param(
            None,
            _build_activity(success=True),
            "app\tuv\t-\t-\t-\tnever\t2026-03-20T12:00:00+00:00\tpassed\t-\t-",
            id="built-passed",
        ),
        pytest.param(
            None,
            _build_activity(success=False),
            "app\tuv\t-\t-\t-\tnever\t2026-03-20T12:00:00+00:00\tfailed\t-\t-",
            id="built-failed",
        ),
    ],
)
def test_given_saved_state_when_listed_in_pipe_then_whole_record_matches(
    mm_home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    scan: ScanResult | None,
    activity: str | None,
    expected_record: str,
) -> None:
    write_config(
        mm_home,
        f'[projects.app]\npath = "{tmp_path / "app"}"\npackage_manager = "uv"\n',
    )
    if scan is not None:
        save_scan_results("app", scan)
    if activity is not None:
        (mm_home / "activity.json").write_text(activity, encoding="utf-8")

    assert run_mm("list") == 0
    assert capsys.readouterr().out == f"{expected_record}\n"


class TestListFindings:
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
        save_scan_results("myapp", result)
        assert run_mm("list", "--detail") == 0
        assert expected_substring in capsys.readouterr().out

    def test_detail_sorts_by_severity(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Findings are sorted CRITICAL > HIGH > LOW in detail output."""
        vulns = [
            make_vuln(vuln_id="CVE-LOW", pkg_name="low-pkg", severity=Severity.LOW),
            make_vuln(
                vuln_id="CVE-CRIT", pkg_name="crit-pkg", severity=Severity.CRITICAL
            ),
            make_vuln(vuln_id="CVE-HIGH", pkg_name="high-pkg"),
        ]
        result = ScanResult(
            project="myapp",
            scanned_at=_NOW,
            trivy_target=".",
            vulnerabilities=vulns,
        )
        save_scan_results("myapp", result)
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
            make_vuln(
                vuln_id=vuln_ids[0],
                pkg_name="requests",
                installed_version="2.25.0",
                fixed_version="2.31.0",
                severity=severities[0],
            ),
            make_vuln(
                vuln_id=vuln_ids[1],
                pkg_name="requests",
                installed_version="2.25.0",
                fixed_version="2.32.4",
                severity=severities[1],
            ),
        ]
        result = ScanResult(
            project="myapp",
            scanned_at=_NOW,
            trivy_target=".",
            vulnerabilities=vulns,
        )
        save_scan_results("myapp", result)
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
        save_scan_results("myapp", result)
        assert run_mm("list", "--detail") == 0
        output = capsys.readouterr().out
        assert "selected fix" not in output


class TestListActivity:
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
