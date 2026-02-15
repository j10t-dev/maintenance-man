import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from maintenance_man.cli import _relative_time, app
from maintenance_man.models.scan import (
    ScanResult,
    SecretFinding,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
)

_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def _write_scan_result(mm_home: Path, name: str, result: ScanResult) -> None:
    """Write a scan result JSON to the scan-results dir."""
    (mm_home / "scan-results" / f"{name}.json").write_text(
        result.model_dump_json(indent=2),
        encoding="utf-8",
    )


@pytest.fixture()
def list_project_home(mm_home: Path) -> Path:
    """mm_home with a single 'myapp' project configured."""
    project_dir = mm_home.parent / "myproject"
    project_dir.mkdir()
    mm_home.mkdir(parents=True)
    (mm_home / "scan-results").mkdir()
    (mm_home / "worktrees").mkdir()
    (mm_home / "config.toml").write_text(
        f'[projects.myapp]\npath = "{project_dir}"\npackage_manager = "uv"\n'
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
        assert _relative_time(_NOW - delta, _NOW) == expected


class TestListCommand:
    def test_list_no_projects(self, mm_home: Path, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        assert "no projects" in capsys.readouterr().out.lower()

    def test_list_shows_projects(
        self, list_project_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "myapp" in output
        assert "uv" in output


class TestListFindings:
    def test_shows_never_for_unscanned_projects(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Projects without scan results show 'never' in scanned column."""
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        # Look for the table having a Scanned column and a row with "never"
        assert "Scanned" in output
        # Match pattern: ends of table rows that should have "never" as last column
        assert re.search(r"\│\s+never\s+\│", output, re.IGNORECASE)

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
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "2" in output  # 2 actionable vulns
        assert "3" in output  # 3 updates

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
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "myapp" in output
        assert "Warning" in output

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
        with pytest.raises(SystemExit) as exc_info:
            app(["list", "--detail"])
        assert exc_info.value.code == 0
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
        with pytest.raises(SystemExit) as exc_info:
            app(["list", "--detail"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        crit_pos = output.index("CVE-CRIT")
        high_pos = output.index("CVE-HIGH")
        low_pos = output.index("CVE-LOW")
        assert crit_pos < high_pos < low_pos

    def test_detail_fix_marker_on_highest_version(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """'← fix' marks the highest fix version for duplicate-package vulns."""
        vulns = [
            VulnFinding(
                vuln_id="CVE-0001",
                pkg_name="requests",
                installed_version="2.25.0",
                fixed_version="2.31.0",
                severity=Severity.HIGH,
                title="t",
                description="d",
                status="fixed",
            ),
            VulnFinding(
                vuln_id="CVE-0002",
                pkg_name="requests",
                installed_version="2.25.0",
                fixed_version="2.32.4",
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
        with pytest.raises(SystemExit) as exc_info:
            app(["list", "--detail"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        # The marker should appear on the row with 2.32.4
        assert "2.32.4" in output
        # Find lines containing the marker
        lines_with_marker = [
            line for line in output.splitlines() if "\u2190 fix" in line
        ]
        assert len(lines_with_marker) == 1
        assert "2.32.4" in lines_with_marker[0]

    def test_detail_no_fix_marker_for_single_vuln_package(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Single-vuln packages should not get the '← fix' marker."""
        result = ScanResult(
            project="myapp",
            scanned_at=_NOW,
            trivy_target=".",
            vulnerabilities=[_VULN],
        )
        _write_scan_result(list_project_home, "myapp", result)
        with pytest.raises(SystemExit) as exc_info:
            app(["list", "--detail"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "\u2190 fix" not in output
