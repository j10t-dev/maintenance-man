from datetime import datetime, timezone
from pathlib import Path

import pytest

from maintenance_man.cli import ExitCode, _print_scan_result, _scan_exit_code, app
from maintenance_man.gradle import GradleError
from maintenance_man.models.scan import (
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
)
from tests.conftest import make_scan_result, make_update


def _make_vulnerable_result() -> ScanResult:
    return ScanResult(
        project="vulnerable",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="tests/fixtures/vulnerable-project",
        vulnerabilities=[
            VulnFinding(
                vuln_id="CVE-2024-0001",
                pkg_name="some-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.HIGH,
                title="Test vulnerability",
                description="A test vulnerability",
                status="fixed",
            ),
        ],
    )


def _make_clean_result() -> ScanResult:
    return ScanResult(
        project="clean",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="tests/fixtures/clean-project",
    )


def _make_updates_only_result() -> ScanResult:
    return ScanResult(
        project="outdated",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="tests/fixtures/clean-project",
        updates=[
            UpdateFinding(
                pkg_name="axios",
                installed_version="1.6.0",
                latest_version="1.7.2",
                semver_tier=SemverTier.MINOR,
            ),
        ],
    )


@pytest.fixture(autouse=True)
def _mock_trivy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent all CLI tests from calling real Trivy."""
    monkeypatch.setattr("maintenance_man.cli.check_trivy_available", lambda: None)
    monkeypatch.setattr("maintenance_man.cli.prune_stale_bookmarks", lambda _path: True)

    def _fake_scan(
        name: str, project_config: object, min_version_age_days: int = 7
    ) -> ScanResult:
        match name:
            case "vulnerable":
                return _make_vulnerable_result()
            case "clean":
                return _make_clean_result()
            case "outdated":
                return _make_updates_only_result()
            case "no-tests" | "deployable" | "deploy-only" | "no-deploy":
                return _make_clean_result()
            case _:
                raise FileNotFoundError(f"Unknown project: {name}")

    monkeypatch.setattr("maintenance_man.cli.scan_project", _fake_scan)


class TestScanSingleProject:
    def test_scan_project_with_vulns_exits_2(self, mm_home_with_projects: Path):
        """mm scan vulnerable — has vulns, should exit 2."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "vulnerable"])
        assert exc_info.value.code == 2

    def test_scan_project_with_vulns_shows_findings(
        self, mm_home_with_projects: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Output should contain vulnerability information."""
        with pytest.raises(SystemExit):
            app(["scan", "vulnerable"])
        output = capsys.readouterr().out
        assert "CVE-" in output or "vuln" in output.lower()

    def test_scan_clean_project_exits_0(self, mm_home_with_projects: Path):
        """mm scan clean — clean, should exit 0."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "clean"])
        assert exc_info.value.code == 0

    def test_scan_unknown_project_exits_1(self, mm_home_with_projects: Path):
        """mm scan nonexistent — should exit 1."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "nonexistent"])
        assert exc_info.value.code == 1


class TestScanAllProjects:
    def test_scan_all_exits_worst_case(self, mm_home_with_projects: Path):
        """mm scan (no args) — should exit 2 if any project has vulns."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan"])
        # vulnerable has vulns, so worst case is 2
        assert exc_info.value.code == 2


class TestScanUpdatesExitCodes:
    def test_scan_updates_only_exits_3(self, mm_home_with_projects: Path):
        """mm scan outdated — updates only, no vulns, should exit 3."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "outdated"])
        assert exc_info.value.code == 3

    def test_scan_updates_output_shows_update_rows(
        self, mm_home_with_projects: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Output should contain update information."""
        with pytest.raises(SystemExit):
            app(["scan", "outdated"])
        output = capsys.readouterr().out
        assert "UPDATE" in output or "update" in output.lower()
        assert "axios" in output

    def test_scan_clean_still_exits_0(self, mm_home_with_projects: Path):
        """Clean project (no vulns, no updates) still exits 0."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "clean"])
        assert exc_info.value.code == 0

    def test_scan_vulns_and_updates_exits_2(self, mm_home_with_projects: Path):
        """If project has both vulns and updates, exit 2 (vulns take precedence)."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "vulnerable"])
        assert exc_info.value.code == 2


class TestScanAllWithUpdates:
    def test_scan_all_updates_takes_precedence_over_clean(
        self, mm_home_with_projects: Path
    ):
        """mm scan (all) — worst case includes updates, but vulns override."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan"])
        # vulnerable has vulns → exit 2 takes precedence
        assert exc_info.value.code == 2


def test_blocked_gradle_candidates_are_shown_not_treated_as_clean(capsys):
    result = make_scan_result(
        vulns=[],
        updates=[
            make_update(
                pkg_name="ksp",
                installed_version="2.3.10",
                latest_version="2.3.12",
                blocked_reason=(
                    "no Maven Central publication date for "
                    "com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin "
                    "2.3.12"
                ),
                gradle_block_kind="age",
            )
        ],
    )

    _print_scan_result(result)
    out = capsys.readouterr().out

    assert "clean" not in out
    assert "ksp" in out
    assert "1 blocked" in out
    assert "no Maven Central publication date" in out


def test_blocked_update_candidates_still_exit_updates_found():
    """A ScanResult whose only update is blocked must still reach
    UPDATES_FOUND: has_updates counts blocked candidates (they stay in
    ``updates``), and that count is what drives the exit code — not whether
    any update happens to be eligible.
    """
    result = make_scan_result(
        vulns=[],
        updates=[
            make_update(
                pkg_name="ksp",
                installed_version="2.3.10",
                latest_version="2.3.12",
                blocked_reason="no Maven Central publication date",
                gradle_block_kind="age",
            )
        ],
    )

    assert result.has_updates is True
    assert _scan_exit_code(result.has_actionable_vulns, result.has_updates) == (
        ExitCode.UPDATES_FOUND
    )


def test_gradle_scan_failure_exits_error(mm_home_with_gradle, monkeypatch):
    monkeypatch.setattr("maintenance_man.cli.check_trivy_available", lambda: None)

    def _boom(name, proj_config, min_age_days):
        raise GradleError("./gradlew cyclonedxBom failed (exit 1): boom")

    monkeypatch.setattr("maintenance_man.cli._scan_one", _boom)

    with pytest.raises(SystemExit) as exc:
        app(["scan", "android"])

    assert exc.value.code == ExitCode.ERROR


def test_gradle_scan_failure_in_all_project_scan_exits_error_after_others(
    mm_home_with_gradle, monkeypatch, capsys
):
    monkeypatch.setattr("maintenance_man.cli.check_trivy_available", lambda: None)
    scanned: list[str] = []

    def _scan(name, proj_config, min_age_days):
        scanned.append(name)
        if proj_config.package_manager == "gradle":
            raise GradleError("boom")
        return make_scan_result(vulns=[], updates=[])

    monkeypatch.setattr("maintenance_man.cli._scan_one", _scan)

    with pytest.raises(SystemExit) as exc:
        app(["scan"])

    assert exc.value.code == ExitCode.ERROR
    assert "clean" in scanned or len(scanned) > 1
    assert "boom" in capsys.readouterr().out


@pytest.mark.parametrize("all_projects", [False, True])
@pytest.mark.parametrize("with_updates", [False, True])
@pytest.mark.parametrize("manager", ["gradle", "bun"])
@pytest.mark.parametrize("with_vulnerability", [False, True])
def test_scan_blocked_no_fix_vulnerability_exit(
    mm_home,
    tmp_path,
    monkeypatch,
    all_projects,
    with_updates,
    manager,
    with_vulnerability,
):
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "config.toml").write_text(
        f'[projects.sample]\npath = "{tmp_path}"\npackage_manager = "{manager}"\n'
    )
    result = make_scan_result(
        vulns=[
            VulnFinding(
                vuln_id="CVE-no-fix",
                pkg_name="unmapped",
                installed_version="1",
                fixed_version=None,
                severity=Severity.HIGH,
                title="No fix",
                description="No published fix",
                status="affected",
                blocked_reason="no fixed version",
                gradle_block_kind="mapping",
            )
        ]
        if with_vulnerability
        else [],
        updates=[
            make_update(blocked_reason="no publication date", gradle_block_kind="age")
        ]
        if with_updates
        else [],
    )
    assert not result.has_actionable_vulns
    monkeypatch.setattr("maintenance_man.cli.scan_project", lambda *args: result)
    with pytest.raises(SystemExit) as exc:
        app(["scan"] if all_projects else ["scan", "sample"])
    expected = (
        2 if manager == "gradle" and with_vulnerability else (3 if with_updates else 0)
    )
    assert exc.value.code == expected


def test_all_scan_real_wrapper_launch_error_preserves_results_and_scans_next(
    mm_home, gradle_project, monkeypatch
):
    from maintenance_man.gradle import GRADLE_INVENTORY_RELPATH
    from maintenance_man.scanner import scan_project

    monkeypatch.setattr("maintenance_man.cli.scan_project", scan_project)

    root = Path(gradle_project.path)
    (root / "gradlew").write_text("#!/definitely/missing/mm-interpreter\n")
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "config.toml").write_text(
        f'[projects.android]\npath = "{root}"\npackage_manager = "gradle"\n'
        f'[projects.remaining]\npath = "{root}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n"
    )
    results = mm_home / "scan-results"
    results.mkdir()
    (results / "android.json").write_bytes(b"previous scan results\n")
    monkeypatch.setattr("maintenance_man.cli.check_trivy_available", lambda: None)
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda *args: [])
    monkeypatch.setattr("maintenance_man.scanner._check_outdated", lambda *args: [])
    with pytest.raises(SystemExit) as exc:
        app(["scan"])
    assert exc.value.code == ExitCode.ERROR
    assert (results / "android.json").read_bytes() == b"previous scan results\n"
    assert (results / "remaining.json").is_file()
    assert not (root / GRADLE_INVENTORY_RELPATH).exists()


@pytest.mark.parametrize(
    "phase",
    ["inventory-mkdir", "inventory-marker", "inventory-cleanup", "report-cleanup"],
)
def test_all_scan_owned_filesystem_error_preserves_results_and_processes_remaining(
    mm_home, gradle_project, monkeypatch, phase
):
    import subprocess

    from maintenance_man.gradle import (
        GRADLE_INVENTORY_MARKER_RELPATH,
        GRADLE_INVENTORY_RELPATH,
        GRADLE_REPORT_MARKER_RELPATH,
        GRADLE_UPDATE_REPORT_RELPATH,
    )
    from maintenance_man.scanner import _check_outdated, scan_project
    from tests.conftest import GRADLE_FIXTURES

    monkeypatch.setattr("maintenance_man.cli.scan_project", scan_project)
    root = Path(gradle_project.path)
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "config.toml").write_text(
        f'[projects.android]\npath = "{root}"\npackage_manager = "gradle"\n'
        "scan_secrets = false\n"
        f'[projects.remaining]\npath = "{root}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n"
    )
    results = mm_home / "scan-results"
    results.mkdir()
    (results / "android.json").write_bytes(b"old result bytes")
    monkeypatch.setattr("maintenance_man.cli.check_trivy_available", lambda: None)
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda *args: [])
    monkeypatch.setattr(
        "maintenance_man.scanner._check_outdated",
        lambda name, project, *args: (
            []
            if project.package_manager == "uv"
            else _check_outdated(name, project, *args)
        ),
    )
    if phase == "inventory-mkdir":
        mkdir = Path.mkdir

        def fail(path, *args, **kwargs):
            if path == root / GRADLE_INVENTORY_RELPATH:
                raise PermissionError("mkdir denied")
            return mkdir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", fail)
    elif phase == "inventory-marker":
        write = Path.write_bytes

        def fail(path, content):
            if path == root / GRADLE_INVENTORY_MARKER_RELPATH:
                raise PermissionError("marker denied")
            return write(path, content)

        monkeypatch.setattr(Path, "write_bytes", fail)
    elif phase == "inventory-cleanup":

        def fail(*args, **kwargs):
            raise PermissionError("inventory cleanup denied")

        monkeypatch.setattr("maintenance_man.gradle.shutil.rmtree", fail)
    else:
        monkeypatch.setattr(
            "maintenance_man.scanner._run_gradle_vuln_scan", lambda *args: []
        )
        unlink = Path.unlink

        def fail(path, *args, **kwargs):
            if path == root / GRADLE_UPDATE_REPORT_RELPATH:
                raise PermissionError("cleanup denied")
            return unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail)
    commands = []

    def run(cmd, **kwargs):
        commands.append(cmd)
        if phase == "inventory-cleanup":
            from maintenance_man.gradle import GRADLE_INVENTORY_BOM_RELPATH

            if cmd[1] == "cyclonedxBom":
                (root / GRADLE_INVENTORY_BOM_RELPATH).write_bytes(
                    (GRADLE_FIXTURES / "bom.json").read_bytes()
                )
            else:
                assert cmd[:2] == ["trivy", "sbom"]
                return subprocess.CompletedProcess(
                    cmd, 0, stdout='{"Results": []}', stderr=""
                )
        else:
            assert phase == "report-cleanup"
            assert cmd[1] == "versionCatalogUpdate"
            (root / GRADLE_UPDATE_REPORT_RELPATH).write_bytes(
                (GRADLE_FIXTURES / "updates-clean.toml").read_bytes()
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(SystemExit) as exc:
        app(["scan"])
    assert exc.value.code == ExitCode.ERROR
    assert (results / "android.json").read_bytes() == b"old result bytes"
    assert (results / "remaining.json").is_file()
    if phase == "inventory-cleanup":
        assert (root / GRADLE_INVENTORY_MARKER_RELPATH).is_file()
    else:
        assert not (root / GRADLE_INVENTORY_RELPATH).exists()
    if phase == "report-cleanup":
        assert (root / GRADLE_REPORT_MARKER_RELPATH).is_file()
    elif phase != "inventory-cleanup":
        assert commands == []


@pytest.mark.parametrize(
    "failure",
    [
        "report-false",
        "trivy-root",
        "trivy-results",
        "trivy-row",
        "trivy-launch",
        "trivy-decode",
        "wrapper-decode",
    ],
)
def test_all_scan_malformed_gradle_output_preserves_results_and_continues(
    mm_home, gradle_project, monkeypatch, failure
):
    import json
    import subprocess

    from maintenance_man.gradle import (
        GRADLE_INVENTORY_BOM_RELPATH,
        GRADLE_INVENTORY_RELPATH,
        GRADLE_REPORT_MARKER_RELPATH,
        GRADLE_UPDATE_REPORT_RELPATH,
    )
    from maintenance_man.scanner import _check_outdated, scan_project
    from tests.conftest import GRADLE_FIXTURES

    root = Path(gradle_project.path)
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "config.toml").write_text(
        f'[projects.android]\npath = "{root}"\npackage_manager = "gradle"\n'
        "scan_secrets = false\n"
        f'[projects.remaining]\npath = "{root}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n"
    )
    results = mm_home / "scan-results"
    results.mkdir()
    (results / "android.json").write_bytes(b"old result bytes")
    monkeypatch.setattr("maintenance_man.cli.scan_project", scan_project)
    monkeypatch.setattr("maintenance_man.cli.check_trivy_available", lambda: None)
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda *args: [])
    monkeypatch.setattr(
        "maintenance_man.scanner._check_outdated",
        lambda name, project, *args: (
            []
            if project.package_manager == "uv"
            else _check_outdated(name, project, *args)
        ),
    )
    if failure == "report-false":
        monkeypatch.setattr(
            "maintenance_man.scanner._run_gradle_vuln_scan", lambda *args: []
        )

    def run(cmd, **kwargs):
        if cmd[1] == "cyclonedxBom":
            if failure == "wrapper-decode":
                raise UnicodeDecodeError("utf8", b"\xff", 0, 1, "invalid")
            (root / GRADLE_INVENTORY_BOM_RELPATH).write_bytes(
                (GRADLE_FIXTURES / "bom.json").read_bytes()
            )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[1] == "versionCatalogUpdate":
            assert failure == "report-false"
            (root / GRADLE_UPDATE_REPORT_RELPATH).write_text("libraries = false\n")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        assert cmd[:2] == ["trivy", "sbom"]
        if failure == "trivy-launch":
            raise FileNotFoundError("missing interpreter")
        if failure == "trivy-decode":
            raise UnicodeDecodeError("utf8", b"\xff", 0, 1, "invalid")
        payload = {
            "trivy-root": [],
            "trivy-results": {"Results": False},
            "trivy-row": {"Results": [None]},
        }[failure]
        return subprocess.CompletedProcess(
            cmd, 0, stdout=json.dumps(payload), stderr=""
        )

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(SystemExit) as exc:
        app(["scan"])
    assert exc.value.code == ExitCode.ERROR
    assert (results / "android.json").read_bytes() == b"old result bytes"
    assert (results / "remaining.json").is_file()
    assert not (root / GRADLE_INVENTORY_RELPATH).exists()
    assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
    assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()
