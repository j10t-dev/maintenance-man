import json
import shutil
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from unittest.mock import patch

import pytest

from maintenance_man.gradle import GRADLE_INVENTORY_BOM_RELPATH, GradleError
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
)
from maintenance_man.scanner import (
    TrivyNotFoundError,
    _check_outdated,
    _parse_uv_audit_vulns,
    check_trivy_available,
    scan_project,
)
from tests.conftest import GRADLE_FIXTURES, make_gradle_target, make_update, make_vuln

_OLD = datetime(2024, 1, 1, tzinfo=timezone.utc)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _make_project(
    path: str | Path, pm: Literal["bun", "uv", "mvn"] = "uv"
) -> ProjectConfig:
    return ProjectConfig(path=Path(path), package_manager=pm)


class TestUvAuditParsing:
    def test_parses_vulnerabilities(self):
        output = (
            "Found 1 known vulnerability and no adverse project statuses in "
            "1 package\n\n"
            "Vulnerabilities:\n\n"
            "setuptools 65.5.0 has 1 known vulnerability:\n\n"
            "- GHSA-r9hx-vwmv-q579: pypa/setuptools vulnerable to Regular "
            "Expression Denial of Service (ReDoS)\n\n"
            "  Fixed in: 65.5.1\n\n"
            "  Advisory information: https://nvd.nist.gov/vuln/detail/"
            "CVE-2022-40897\n"
        )

        vulns = _parse_uv_audit_vulns(output)

        assert len(vulns) == 1
        assert vulns[0].vuln_id == "GHSA-r9hx-vwmv-q579"
        assert vulns[0].pkg_name == "setuptools"
        assert vulns[0].installed_version == "65.5.0"
        assert vulns[0].fixed_version == "65.5.1"
        assert vulns[0].primary_url == "https://nvd.nist.gov/vuln/detail/CVE-2022-40897"

    def test_ignores_non_advisory_bullets_inside_package_section(self):
        output = """setuptools 65.5.0 has 1 known vulnerability:

- GHSA-r9hx-vwmv-q579: real vulnerability

- note: this is not another vulnerability

  Fixed in: 65.5.1
"""

        vulns = _parse_uv_audit_vulns(output)

        assert len(vulns) == 1
        assert vulns[0].vuln_id == "GHSA-r9hx-vwmv-q579"
        assert vulns[0].fixed_version == "65.5.1"


class TestCheckTrivyAvailable:
    def test_trivy_is_available(self):
        # Should not raise — trivy is installed on this machine
        check_trivy_available()

    def test_trivy_not_available(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("PATH", "/nonexistent")
        with pytest.raises(TrivyNotFoundError):
            check_trivy_available()


@pytest.mark.integration
class TestScanProject:
    def test_scan_project_with_vulns(self, scan_results_dir: Path):
        """Scan vulnerable fixture — known to have vulnerabilities."""
        project = _make_project(FIXTURES_DIR / "vulnerable-project")
        result = scan_project("vulnerable", project)

        assert isinstance(result, ScanResult)
        assert result.project == "vulnerable"
        assert result.scanned_at is not None
        assert len(result.vulnerabilities) > 0
        assert result.has_actionable_vulns is True

        # Structural checks on findings
        for v in result.vulnerabilities:
            assert v.vuln_id.startswith(("CVE-", "GHSA-", "PYSEC-"))
            assert v.pkg_name
            assert v.installed_version
            assert v.severity in Severity
            assert v.title
            assert v.status

    def test_scan_project_clean(self, scan_results_dir: Path):
        """Scan clean fixture — expected to have no vulnerabilities."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        result = scan_project("clean", project)

        assert isinstance(result, ScanResult)
        assert result.project == "clean"
        assert len(result.vulnerabilities) == 0
        assert result.has_actionable_vulns is False

    def test_scan_writes_results_file(self, scan_results_dir: Path):
        """Scan should write JSON results to scan-results dir."""
        project = _make_project(FIXTURES_DIR / "vulnerable-project")
        scan_project("vulnerable", project)

        results_file = scan_results_dir / "vulnerable.json"
        assert results_file.exists()

        data = json.loads(results_file.read_text())
        assert data["project"] == "vulnerable"
        assert "vulnerabilities" in data
        assert "secrets" in data

        # Round-trip: the JSON should deserialise back into a ScanResult
        reloaded = ScanResult.model_validate(data)
        assert reloaded.project == "vulnerable"

    def test_scan_nonexistent_path(self, scan_results_dir: Path):
        """Scan a path that doesn't exist — should raise."""
        project = _make_project("/nonexistent/path")
        with pytest.raises(FileNotFoundError):
            scan_project("ghost", project)


class TestScanProjectWithUpdates:
    def test_scan_includes_updates(self, scan_results_dir: Path):
        """When outdated check returns updates, they appear in ScanResult."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        fake_updates = [
            UpdateFinding(
                pkg_name="requests",
                installed_version="2.28.0",
                latest_version="2.31.0",
                semver_tier=SemverTier.MINOR,
            ),
        ]
        with (
            patch("maintenance_man.scanner.get_outdated", return_value=fake_updates),
            patch("maintenance_man.scanner.filter_by_age", return_value=fake_updates),
        ):
            result = scan_project("clean", project)

        assert result.has_updates is True
        assert len(result.updates) == 1
        assert result.updates[0].pkg_name == "requests"

    def test_scan_deduplicates_vuln_and_update(self, scan_results_dir: Path):
        """If a package is both a vuln and an update, only the vuln appears."""
        project = ProjectConfig(
            path=FIXTURES_DIR / "vulnerable-project",
            package_manager="uv",
            scan_secrets=False,
        )
        fake_updates = [
            UpdateFinding(
                pkg_name="cryptography",
                installed_version="42.0.0",
                latest_version="43.0.0",
                semver_tier=SemverTier.MAJOR,
            ),
            UpdateFinding(
                pkg_name="brand-new-pkg",
                installed_version="1.0.0",
                latest_version="2.0.0",
                semver_tier=SemverTier.MAJOR,
            ),
        ]
        audit = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout=(
                "Found 1 known vulnerability and no adverse project statuses in "
                "1 package\n\n"
                "Vulnerabilities:\n\n"
                "cryptography 42.0.0 has 1 known vulnerability:\n\n"
                "- GHSA-test: test vulnerability\n\n"
                "  Fixed in: 43.0.0\n"
            ),
            stderr="",
        )
        with (
            patch("maintenance_man.scanner.subprocess.run", return_value=audit),
            patch("maintenance_man.scanner.get_outdated", return_value=fake_updates),
            patch("maintenance_man.scanner.filter_by_age", return_value=fake_updates),
        ):
            result = scan_project("vulnerable", project)

        vuln_pkg_names = {v.pkg_name for v in result.vulnerabilities}
        update_pkg_names = {u.pkg_name for u in result.updates}
        assert "cryptography" in vuln_pkg_names
        assert "cryptography" not in update_pkg_names
        assert "brand-new-pkg" in update_pkg_names

    def test_scan_outdated_failure_does_not_crash(self, scan_results_dir: Path):
        """If the outdated check fails, scan still returns Trivy results."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        with patch(
            "maintenance_man.scanner.get_outdated",
            side_effect=Exception("bun not found"),
        ):
            result = scan_project("clean", project)

        assert isinstance(result, ScanResult)
        assert result.updates == []

    def test_scan_passes_min_version_age_days(self, scan_results_dir: Path):
        """min_version_age_days parameter is forwarded to filter_by_age."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        with (
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
            patch("maintenance_man.scanner.filter_by_age", return_value=[]) as mock_age,
        ):
            scan_project("clean", project, min_version_age_days=14)

        mock_age.assert_called_once()
        assert mock_age.call_args.kwargs["min_age_days"] == 14


class TestUvNativeScan:
    def test_uv_project_uses_uv_audit_locked_not_trivy_vulns(
        self, scan_results_dir: Path, tmp_path: Path
    ):
        project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)
        audit = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Found no known vulnerabilities", stderr=""
        )

        with (
            patch("maintenance_man.scanner.subprocess.run", return_value=audit) as run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            result = scan_project("test-proj", project)

        assert result.vulnerabilities == []
        assert result.secrets == []
        assert run.call_args.args[0] == ["uv", "audit", "--locked"]

    def test_uv_project_scans_secrets_when_enabled(
        self, scan_results_dir: Path, tmp_path: Path
    ):
        project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=True)
        audit = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Found no known vulnerabilities", stderr=""
        )
        trivy = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {
                    "Results": [
                        {
                            "Class": "secret",
                            "Target": "creds/example.json",
                            "Secrets": [
                                {
                                    "RuleID": "secret-rule",
                                    "Title": "Example secret",
                                    "Severity": "HIGH",
                                }
                            ],
                        }
                    ]
                }
            ),
            stderr="",
        )

        with (
            patch(
                "maintenance_man.scanner.subprocess.run", side_effect=[audit, trivy]
            ) as run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            result = scan_project("test-proj", project)

        assert result.vulnerabilities == []
        assert len(result.secrets) == 1
        assert result.secrets[0].file == "creds/example.json"
        assert run.call_args_list[0].args[0] == ["uv", "audit", "--locked"]
        assert run.call_args_list[1].args[0][4:6] == ["--scanners", "secret"]


class TestRunTrivyScanSkipDirs:
    def test_skip_dirs_appended_to_command(
        self, scan_results_dir: Path, tmp_path: Path
    ):
        """scan_skip_dirs entries are forwarded as --skip-dirs flags to trivy."""
        project = ProjectConfig(
            path=tmp_path,
            package_manager="bun",
            scan_skip_dirs=["tests/fixtures", "vendor"],
        )
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Results": []}', stderr=""
        )
        with (
            patch(
                "maintenance_man.scanner.subprocess.run",
                return_value=fake_result,
            ) as mock_run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            scan_project("test-proj", project)

        cmd = mock_run.call_args.args[0]
        assert cmd.count("--skip-dirs") == 2
        dirs_indices = [i for i, v in enumerate(cmd) if v == "--skip-dirs"]
        assert cmd[dirs_indices[0] + 1] == "tests/fixtures"
        assert cmd[dirs_indices[1] + 1] == "vendor"

    def test_no_skip_dirs_by_default(self, scan_results_dir: Path, tmp_path: Path):
        """Without scan_skip_dirs, no --skip-dirs flags are added."""
        project = ProjectConfig(path=tmp_path, package_manager="bun")
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Results": []}', stderr=""
        )
        with (
            patch(
                "maintenance_man.scanner.subprocess.run",
                return_value=fake_result,
            ) as mock_run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            scan_project("test-proj", project)

        cmd = mock_run.call_args.args[0]
        assert "--skip-dirs" not in cmd


def _gradle_scan(monkeypatch, findings, dates):
    monkeypatch.setattr(
        "maintenance_man.scanner.get_outdated", lambda project: findings
    )
    monkeypatch.setattr(
        "maintenance_man.dependency_age._get_maven_publish_date",
        lambda pkg, version: dates.get(pkg),
    )


def test_gradle_outdated_retains_blocked_candidates(
    gradle_project, monkeypatch, mm_home
):
    eligible = make_update(pkg_name="room", gradle_target=make_gradle_target())
    withheld = make_update(
        pkg_name="ksp",
        installed_version="2.3.10",
        latest_version="2.3.12",
        gradle_target=GradleUpdateTarget(
            version_ref="ksp",
            members=[
                GradleMember(
                    kind="plugin",
                    alias="ksp",
                    coordinate="com.google.devtools.ksp",
                    installed_version="2.3.10",
                )
            ],
            target_version="2.3.12",
        ),
    )
    _gradle_scan(
        monkeypatch,
        [eligible, withheld],
        {
            "androidx.room:room-runtime": _OLD,
            "androidx.room:room-compiler": _OLD,
            "androidx.room:room-testing": _OLD,
        },
    )
    result = _check_outdated("android", gradle_project, [], 7)

    names = {u.pkg_name: u for u in result}
    assert names["room"].blocked_reason is None
    assert names["room"].published_date == _OLD
    assert names["ksp"].gradle_block_kind == "age"
    assert names["ksp"].blocked_reason is not None
    assert "no Maven Central publication date" in names["ksp"].blocked_reason


def test_gradle_discovery_failure_is_not_swallowed(gradle_project, monkeypatch):
    def _boom(project):
        raise GradleError("versionCatalogUpdate failed (exit 1): boom")

    monkeypatch.setattr("maintenance_man.scanner.get_outdated", _boom)

    with pytest.raises(GradleError, match="versionCatalogUpdate failed"):
        _check_outdated("android", gradle_project, [], 7)


def test_gradle_update_findings_are_not_suppressed_by_vuln_package_names(
    gradle_project, monkeypatch
):
    finding = make_update(pkg_name="room", gradle_target=make_gradle_target())
    _gradle_scan(
        monkeypatch,
        [finding],
        {
            "androidx.room:room-runtime": _OLD,
            "androidx.room:room-compiler": _OLD,
            "androidx.room:room-testing": _OLD,
        },
    )
    vulns = [make_vuln(pkg_name="androidx.room:room-runtime")]

    result = _check_outdated("android", gradle_project, vulns, 7)

    assert [u.pkg_name for u in result] == ["room"]


def test_gradle_finding_without_target_or_reason_is_blocked_not_eligible(
    gradle_project, monkeypatch
):
    """A finding with neither a target nor a reason must not be presented as an
    eligible update with zero publication evidence.  This combination should
    not occur today, but the branch must fail closed if it ever does.
    """
    finding = make_update(pkg_name="mystery", latest_version="9.9.9")
    monkeypatch.setattr(
        "maintenance_man.scanner.get_outdated", lambda project: [finding]
    )

    result = _check_outdated("android", gradle_project, [], 7)

    assert len(result) == 1
    assert result[0].blocked_reason is not None
    assert result[0].gradle_block_kind == "age"
    assert "no catalogue target" in result[0].blocked_reason


def _yield_fixture_bom(project):
    @contextmanager
    def _generate(_project):
        bom = Path(project.path) / GRADLE_INVENTORY_BOM_RELPATH
        bom.parent.mkdir(parents=True, exist_ok=True)
        bom.write_text(
            (GRADLE_FIXTURES / "bom.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        try:
            yield bom
        finally:
            shutil.rmtree(bom.parent, ignore_errors=True)

    return _generate


def _trivy_sbom(monkeypatch, *, returncode: int = 0, stdout: str | None = None):
    payload = (
        stdout
        if stdout is not None
        else (GRADLE_FIXTURES / "trivy-sbom.json").read_text(encoding="utf-8")
    )

    def _run(cmd, **kwargs):
        assert cmd[:5] == ["trivy", "sbom", "--format", "json", "--scanners"]
        return subprocess.CompletedProcess(cmd, returncode, stdout=payload, stderr="")

    monkeypatch.setattr("maintenance_man.scanner.subprocess.run", _run)


def test_gradle_scan_maps_and_blocks_vulnerabilities(
    gradle_project, monkeypatch, mm_home
):
    def _run(cmd, **kwargs):
        bom = Path(gradle_project.path) / GRADLE_INVENTORY_BOM_RELPATH
        if cmd[1] == "cyclonedxBom":
            bom.write_bytes((GRADLE_FIXTURES / "bom.json").read_bytes())
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        assert cmd == [
            "trivy",
            "sbom",
            "--format",
            "json",
            "--scanners",
            "vuln",
            str(bom),
        ]
        assert bom.is_file()
        return subprocess.CompletedProcess(
            cmd, 0, stdout=(GRADLE_FIXTURES / "trivy-sbom.json").read_text(), stderr=""
        )

    monkeypatch.setattr(subprocess, "run", _run)
    monkeypatch.setattr(
        "maintenance_man.dependency_age._get_maven_publish_date",
        lambda pkg, version: _OLD,
    )
    monkeypatch.setattr("maintenance_man.scanner.get_outdated", lambda project: [])
    gradle_project = gradle_project.model_copy(update={"scan_secrets": False})

    result = scan_project("android", gradle_project, 7)
    by_id = {v.vuln_id: v for v in result.vulnerabilities}

    assert len(result.vulnerabilities) == 6
    assert by_id["CVE-2026-2222"].blocked_reason is None
    assert (gson_target := by_id["CVE-2026-2222"].gradle_target) is not None
    assert gson_target.members[0].alias == "gson"
    assert (room_target := by_id["CVE-2026-6666"].gradle_target) is not None
    assert room_target.version_ref == "room"
    assert by_id["CVE-2026-1111"].gradle_block_kind == "mapping"
    assert by_id["CVE-2026-3333"].gradle_block_kind == "mapping"
    assert by_id["CVE-2026-4444"].gradle_block_kind == "mapping"
    assert by_id["CVE-2026-5555"].gradle_block_kind == "conflict"
    assert all(v.actionable for v in result.vulnerabilities)
    persisted = ScanResult.model_validate_json(
        (mm_home / "scan-results" / "android.json").read_bytes()
    )
    assert persisted.vulnerabilities == result.vulnerabilities
    assert not (Path(gradle_project.path) / ".mm-gradle-inventory").exists()


def test_gradle_scan_error_leaves_previous_results_intact(
    gradle_project, monkeypatch, mm_home
):
    results_file = mm_home / "scan-results" / "android.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text('{"previous": true}', encoding="utf-8")

    def _boom(project):
        raise GradleError("./gradlew cyclonedxBom failed (exit 1): boom")

    monkeypatch.setattr("maintenance_man.scanner.generate_gradle_inventory", _boom)

    with pytest.raises(GradleError, match="cyclonedxBom failed"):
        scan_project("android", gradle_project, 7)

    assert results_file.read_text(encoding="utf-8") == '{"previous": true}'


@pytest.mark.parametrize(
    "payload, returncode",
    [
        (None, 0),
        ("{bad json", 0),
        ('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', 0),
        ("{}", 1),
    ],
)
def test_gradle_inventory_failure_preserves_previous_result_bytes(
    gradle_project, monkeypatch, mm_home, payload, returncode
):
    results_file = mm_home / "scan-results" / "android.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    previous = b'{"previous": true}\n'
    results_file.write_bytes(previous)

    def _run(cmd, **kwargs):
        assert cmd[1] == "cyclonedxBom"
        if payload is not None:
            (Path(kwargs["cwd"]) / GRADLE_INVENTORY_BOM_RELPATH).write_text(
                payload, encoding="utf-8"
            )
        return subprocess.CompletedProcess(cmd, returncode, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", _run)
    with pytest.raises(GradleError):
        scan_project("android", gradle_project, 7)
    assert results_file.read_bytes() == previous
    assert not (Path(gradle_project.path) / ".mm-gradle-inventory").exists()


def test_gradle_scan_runs_the_existing_secret_scan_when_enabled(
    gradle_project, monkeypatch, mm_home
):
    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_inventory",
        _yield_fixture_bom(gradle_project),
    )
    _trivy_sbom(monkeypatch, stdout='{"Results": []}')
    monkeypatch.setattr("maintenance_man.scanner.get_outdated", lambda project: [])
    secret_calls: list[Path] = []
    monkeypatch.setattr(
        "maintenance_man.scanner._run_trivy_secret_scan",
        lambda path, skip_dirs: (secret_calls.append(path), [])[1],
    )

    scan_project("android", gradle_project, 7)

    assert secret_calls == [Path(gradle_project.path)]


def test_gradle_inventory_cleanup_failure_preserves_previous_results(
    gradle_project, monkeypatch, mm_home
):
    results_file = mm_home / "scan-results" / "android.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    previous = b'{"previous": true}\n'
    results_file.write_bytes(previous)

    def _run(cmd, **kwargs):
        if cmd[1] == "cyclonedxBom":
            bom = Path(gradle_project.path) / GRADLE_INVENTORY_BOM_RELPATH
            bom.write_bytes((GRADLE_FIXTURES / "bom.json").read_bytes())
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout='{"Results": []}', stderr="")

    def _cannot_remove(*args, **kwargs):
        if not kwargs.get("ignore_errors"):
            raise PermissionError("cleanup denied")

    monkeypatch.setattr(subprocess, "run", _run)
    monkeypatch.setattr("maintenance_man.gradle.shutil.rmtree", _cannot_remove)
    monkeypatch.setattr("maintenance_man.scanner.get_outdated", lambda project: [])
    gradle_project = gradle_project.model_copy(update={"scan_secrets": False})
    with pytest.raises(GradleError, match="cleanup denied"):
        scan_project("android", gradle_project, 7)
    assert results_file.read_bytes() == previous


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"Results": False},
        {"Results": None},
        {"Results": ""},
        {"Results": 0},
        {"Results": [None]},
        {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": False}]},
    ],
)
def test_gradle_trivy_malformed_shape_is_scan_error(
    gradle_project, monkeypatch, payload
):
    from maintenance_man.scanner import TrivyScanError, _run_gradle_vuln_scan

    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_inventory",
        _yield_fixture_bom(gradle_project),
    )
    _trivy_sbom(monkeypatch, stdout=json.dumps(payload))
    with pytest.raises(TrivyScanError, match="Trivy"):
        _run_gradle_vuln_scan(gradle_project)
    assert not (Path(gradle_project.path) / ".mm-gradle-inventory").exists()


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError("interpreter missing"),
        PermissionError("launch denied"),
        UnicodeDecodeError("utf8", b"\xff", 0, 1, "invalid"),
    ],
)
def test_gradle_trivy_launch_or_decode_failure_is_scan_error(
    gradle_project, monkeypatch, failure
):
    from maintenance_man.scanner import TrivyScanError, _run_gradle_vuln_scan

    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_inventory",
        _yield_fixture_bom(gradle_project),
    )

    def run(*args, **kwargs):
        raise failure

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(TrivyScanError, match="Trivy"):
        _run_gradle_vuln_scan(gradle_project)
    assert not (Path(gradle_project.path) / ".mm-gradle-inventory").exists()


@pytest.mark.parametrize(
    "field, value",
    [
        ("VulnerabilityID", None),
        ("VulnerabilityID", ""),
        ("PkgName", 3),
        ("InstalledVersion", False),
        ("Severity", None),
        ("Severity", False),
        ("Severity", []),
        ("PublishedDate", 0),
        ("PublishedDate", {}),
        ("Title", None),
        ("Description", []),
        ("Status", False),
        ("FixedVersion", []),
        ("PrimaryURL", {}),
    ],
)
def test_gradle_trivy_invalid_consumed_vulnerability_field_is_scan_error(field, value):
    from maintenance_man.scanner import TrivyScanError, _parse_gradle_trivy_output

    row = {
        "VulnerabilityID": "CVE-example",
        "PkgName": "org.example:library",
        "InstalledVersion": "1",
    }
    row[field] = value
    with pytest.raises(TrivyScanError, match=field):
        _parse_gradle_trivy_output(
            json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [row]}]})
        )


@pytest.mark.parametrize("field", ["VulnerabilityID", "PkgName", "InstalledVersion"])
def test_gradle_trivy_missing_required_vulnerability_field_is_scan_error(field):
    from maintenance_man.scanner import TrivyScanError, _parse_gradle_trivy_output

    row = {
        "VulnerabilityID": "CVE-example",
        "PkgName": "org.example:library",
        "InstalledVersion": "1",
    }
    del row[field]
    with pytest.raises(TrivyScanError, match=field):
        _parse_gradle_trivy_output(
            json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [row]}]})
        )


@pytest.mark.parametrize(
    "result",
    [
        {"Class": False},
        {"Class": "lang-pkgs", "Vulnerabilities": ""},
        {"Class": "lang-pkgs", "Vulnerabilities": {}},
        {"Class": "lang-pkgs", "Vulnerabilities": [None]},
    ],
)
def test_gradle_trivy_invalid_result_or_row_container_is_scan_error(result):
    from maintenance_man.scanner import TrivyScanError, _parse_gradle_trivy_output

    with pytest.raises(TrivyScanError):
        _parse_gradle_trivy_output(json.dumps({"Results": [result]}))


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"Results": []},
        {"Results": [{"Class": "lang-pkgs"}]},
        {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": None}]},
    ],
)
def test_gradle_trivy_absent_optional_or_null_vulnerabilities_is_clean(payload):
    from maintenance_man.scanner import _parse_gradle_trivy_output

    assert _parse_gradle_trivy_output(json.dumps(payload)) == []


def test_gradle_trivy_unknown_severity_and_bad_string_date_keep_existing_semantics():
    from maintenance_man.scanner import _parse_gradle_trivy_output

    row = {
        "VulnerabilityID": "CVE-example",
        "PkgName": "org.example:library",
        "InstalledVersion": "1",
        "Severity": "new-severity",
        "PublishedDate": "bad-date",
        "FixedVersion": None,
        "PrimaryURL": None,
    }
    findings = _parse_gradle_trivy_output(
        json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [row]}]})
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.UNKNOWN
    assert findings[0].published_date is None
    assert findings[0].fixed_version is None
