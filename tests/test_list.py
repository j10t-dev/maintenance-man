import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from maintenance_man.cli import ExitCode
from maintenance_man.models.scan import (
    ScanResult,
    SecretFinding,
    SemverTier,
    Severity,
    UpdateFinding,
)
from maintenance_man.output import relative_time
from maintenance_man.storage import record_activity, save_scan_results
from tests.support.cli import run_mm, terminal_stdout
from tests.support.findings import make_scan_result, make_vuln
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


@pytest.mark.parametrize(
    ("width", "expected_headers", "expected_hidden"),
    [
        (69, ["project", "vulns", "updates"], "hidden: type, scanned"),
        (70, ["project", "type", "vulns", "updates", "scanned"], None),
    ],
)
def test_given_terminal_width_when_listed_then_narrow_overview_names_hidden_columns(
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    width: int,
    expected_headers: list[str],
    expected_hidden: str | None,
) -> None:
    write_config(
        mm_home,
        f'[projects.api]\npath = "{tmp_path}"\npackage_manager = "uv"\n\n'
        f'[projects.web]\npath = "{tmp_path}"\npackage_manager = "bun"\n',
    )
    save_scan_results("api", make_scan_result())
    older = make_scan_result(vulns=[], updates=[])
    older.scanned_at = datetime.now(tz=UTC) - timedelta(days=2)
    save_scan_results("web", older)
    stream = terminal_stdout(monkeypatch, width=width)

    assert run_mm("list") == 0

    lines = stream.getvalue().splitlines()
    assert lines[1].split() == expected_headers
    if expected_hidden is None:
        assert "hidden:" not in lines[-1]
    else:
        assert lines[-1].endswith(expected_hidden)


class TestListCommand:
    @pytest.mark.parametrize("command", ["list", "status", "st"])
    def test_list_shows_projects(
        self, list_project_home: Path, capsys: pytest.CaptureFixture[str], command: str
    ):
        assert run_mm(command) == 0
        assert [row[:2] for row in _records(capsys.readouterr().out)] == [
            ["myapp", "uv"]
        ]


_COUNTS_SCAN = ScanResult(
    project_name="app",
    package_manager="uv",
    scanned_at=datetime(2026, 3, 20, tzinfo=UTC),
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
        results = list_project_home / "scan-results"
        results.mkdir()
        (results / "myapp.json").write_text("NOT VALID JSON", encoding="utf-8")
        assert run_mm("list") == 0
        captured = capsys.readouterr()
        assert [row[:5] for row in _records(captured.out)] == [
            ["myapp", "uv", "-", "-", "-"]
        ]
        assert captured.err == "warning: corrupt scan results for myapp; skipped\n"


_OLD_SHAPE_SCAN = (
    '{"project_name": "vulnerable", "package_manager": "uv", '
    '"scanned_at": "2026-01-15T12:00:00Z", '
    '"vulnerabilities": [], "updates": [], "secrets": [], "update_status": null}'
)


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(_OLD_SHAPE_SCAN, id="old-shape"),
        pytest.param("[]", id="not-an-object"),
        pytest.param(None, id="directory"),
    ],
)
def test_given_unusable_scan_file_when_listed_then_project_warns_and_list_succeeds(
    mm_home_with_projects: Path,
    capsys: pytest.CaptureFixture[str],
    content: str | None,
) -> None:
    path = mm_home_with_projects / "scan-results" / "vulnerable.json"
    if content is None:
        path.mkdir()
    else:
        path.write_text(content, encoding="utf-8")

    assert run_mm("list") == ExitCode.OK

    err = capsys.readouterr().err.splitlines()
    assert "warning: corrupt scan results for vulnerable; skipped" in err


def test_given_loader_bug_when_listing_then_it_propagates(
    mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(name):
        raise RuntimeError(name)

    monkeypatch.setattr("maintenance_man.cli.load_scan_results", explode)

    with pytest.raises(RuntimeError):
        run_mm("list")


def test_given_saved_findings_when_listed_with_detail_then_records_print(
    list_project_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = ScanResult(
        project_name="myapp",
        package_manager="uv",
        scanned_at=_NOW,
        vulnerabilities=[_VULN],
    )
    save_scan_results("myapp", result)

    assert run_mm("list", "--detail") == 0

    captured = capsys.readouterr()
    assert captured.out == (
        "myapp\tvuln\tbadpkg\t1.0.0\t1.0.1\tHIGH\tCVE-2024-0001\t-\tfixed\t-\n"
    )
    assert captured.err == ""


def test_given_clean_and_unscanned_projects_when_detail_listed_then_notices_name_them(
    mm_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_config(
        mm_home,
        f'[projects.clean]\npath = "{tmp_path}"\npackage_manager = "uv"\n\n'
        f'[projects.unscanned]\npath = "{tmp_path}"\npackage_manager = "uv"\n',
    )
    save_scan_results(
        "clean", ScanResult(project_name="clean", package_manager="uv", scanned_at=_NOW)
    )

    assert run_mm("list", "--detail") == 0

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "1 projects have no findings: clean",
        "1 projects have no saved scan: unscanned",
    ]


class TestListActivity:
    def test_given_failed_build_when_listed_on_terminal_then_row_reads_failed_just_now(
        self,
        list_project_home: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """On a terminal a failed build reads 'failed just now'."""
        activity_path = list_project_home / "activity.json"
        record_activity(activity_path, "myapp", "build", success=False, branch="main")
        stream = terminal_stdout(monkeypatch)
        assert run_mm("list") == 0
        assert "failed just now" in stream.getvalue()
