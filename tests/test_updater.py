import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.models.config import PhaseTestConfig, ProjectConfig
from maintenance_man.models.scan import (
    BumpFinding,
    ScanResult,
    SemverTier,
    Severity,
    VulnFinding,
)
from maintenance_man.updater import (
    GraphiteNotFoundError,
    NoScanResultsError,
    RepoDirtyError,
    check_graphite_available,
    check_repo_clean,
    get_update_command,
    load_scan_results,
    process_bumps,
    process_vulns,
    run_test_phases,
    sort_bumps_by_risk,
)

# -- Fixtures --

VULN_FINDING = VulnFinding(
    vuln_id="CVE-2024-0001",
    pkg_name="some-pkg",
    installed_version="1.0.0",
    fixed_version="1.0.1",
    severity=Severity.HIGH,
    title="Test vuln",
    description="desc",
    status="fixed",
)

BUMP_PATCH = BumpFinding(
    pkg_name="pkg-a",
    installed_version="1.0.0",
    latest_version="1.0.1",
    semver_tier=SemverTier.PATCH,
)

BUMP_MINOR = BumpFinding(
    pkg_name="pkg-b",
    installed_version="1.0.0",
    latest_version="1.1.0",
    semver_tier=SemverTier.MINOR,
)

BUMP_MAJOR = BumpFinding(
    pkg_name="pkg-c",
    installed_version="1.0.0",
    latest_version="2.0.0",
    semver_tier=SemverTier.MAJOR,
)


@pytest.fixture()
def project_config(tmp_path: Path) -> ProjectConfig:
    return ProjectConfig(
        path=tmp_path,
        package_manager="bun",
        test=PhaseTestConfig(unit="bun test"),
    )


@pytest.fixture()
def scan_result() -> ScanResult:
    return ScanResult(
        project="myapp",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="/tmp/myapp",
        vulnerabilities=[VULN_FINDING],
        bumps=[BUMP_MAJOR, BUMP_PATCH, BUMP_MINOR],
    )


# -- check_graphite_available --

class TestCheckGraphiteAvailable:
    def test_gt_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "shutil.which",
            lambda cmd: "/usr/bin/gt" if cmd == "gt" else None,
        )
        check_graphite_available()  # should not raise

    def test_gt_not_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        with pytest.raises(GraphiteNotFoundError):
            check_graphite_available()


# -- check_repo_clean --

class TestCheckRepoClean:
    @patch("maintenance_man.updater.subprocess.run")
    def test_clean_repo(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        check_repo_clean(tmp_path)  # should not raise

    @patch("maintenance_man.updater.subprocess.run")
    def test_dirty_repo(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=" M src/file.py\n", stderr=""
        )
        with pytest.raises(RepoDirtyError):
            check_repo_clean(tmp_path)


# -- load_scan_results --

class TestLoadScanResults:
    def test_load_existing(self, scan_results_dir: Path):
        result = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
        )
        (scan_results_dir / "myapp.json").write_text(
            result.model_dump_json(indent=2), encoding="utf-8"
        )
        loaded = load_scan_results("myapp", scan_results_dir)
        assert loaded.project == "myapp"

    def test_load_missing(self, scan_results_dir: Path):
        with pytest.raises(NoScanResultsError):
            load_scan_results("nonexistent", scan_results_dir)


# -- get_update_command --

class TestGetUpdateCommand:
    def test_bun(self):
        cmd = get_update_command("bun", "axios", "1.7.0")
        assert cmd == ["bun", "add", "axios@1.7.0"]

    def test_uv(self):
        cmd = get_update_command("uv", "requests", "2.32.0")
        assert cmd == ["uv", "add", "requests==2.32.0"]

    def test_mvn(self):
        cmds = get_update_command("mvn", "org.example:lib", "3.0.0")
        assert cmds == [
            "mvn", "versions:use-dep-version",
            "-Dincludes=org.example:lib",
            "-DdepVersion=3.0.0",
        ]


# -- run_test_phases --

class TestRunTestPhases:
    @patch("maintenance_man.updater.subprocess.run")
    def test_all_green(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        tc = PhaseTestConfig(
            unit="bun test",
            integration="bun run test:integration",
        )
        passed, failed_phase = run_test_phases(tc, tmp_path)
        assert passed is True
        assert failed_phase is None
        assert mock_run.call_count == 2

    @patch("maintenance_man.updater.subprocess.run")
    def test_unit_fails(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="FAIL", stderr=""
        )
        tc = PhaseTestConfig(unit="bun test")
        passed, failed_phase = run_test_phases(tc, tmp_path)
        assert passed is False
        assert failed_phase == "unit"
        assert mock_run.call_count == 1

    @patch("maintenance_man.updater.subprocess.run")
    def test_integration_fails(self, mock_run: MagicMock, tmp_path: Path):
        def side_effect(*args, **kwargs):
            cmd_str = " ".join(args[0])
            if "integration" in cmd_str:
                return subprocess.CompletedProcess(
                    args=[], returncode=1, stdout="", stderr=""
                )
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )

        mock_run.side_effect = side_effect
        tc = PhaseTestConfig(unit="bun test", integration="bun run test:integration")
        passed, failed_phase = run_test_phases(tc, tmp_path)
        assert passed is False
        assert failed_phase == "integration"

    @patch("maintenance_man.updater.subprocess.run")
    def test_skips_unconfigured_phases(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        tc = PhaseTestConfig(unit="bun test")  # no integration or component
        passed, _ = run_test_phases(tc, tmp_path)
        assert passed is True
        assert mock_run.call_count == 1  # only unit


# -- sort_bumps_by_risk --

class TestSortBumpsByRisk:
    def test_sorts_patch_minor_major(self):
        bumps = [BUMP_MAJOR, BUMP_PATCH, BUMP_MINOR]
        sorted_b = sort_bumps_by_risk(bumps)
        assert [b.semver_tier for b in sorted_b] == [
            SemverTier.PATCH,
            SemverTier.MINOR,
            SemverTier.MAJOR,
        ]

    def test_empty_list(self):
        assert sort_bumps_by_risk([]) == []

    def test_single_bump(self):
        result = sort_bumps_by_risk([BUMP_MINOR])
        assert len(result) == 1
        assert result[0].semver_tier == SemverTier.MINOR


# -- process_vulns --

class TestProcessVulns:
    @patch("maintenance_man.updater._gt_checkout_main")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_single_vuln_passes(
        self, mock_test, mock_apply, mock_gt, mock_checkout,
        project_config: ProjectConfig,
    ):
        results = process_vulns([VULN_FINDING], project_config)
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].kind == "vuln"

    @patch("maintenance_man.updater._gt_checkout_main")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch(
        "maintenance_man.updater.run_test_phases",
        return_value=(False, "unit"),
    )
    def test_vuln_test_fails_continues(
        self, mock_test, mock_apply, mock_gt, mock_checkout,
        project_config: ProjectConfig,
    ):
        vuln2 = VULN_FINDING.model_copy(
            update={"vuln_id": "CVE-2024-0002", "pkg_name": "other-pkg"}
        )
        results = process_vulns([VULN_FINDING, vuln2], project_config)
        assert len(results) == 2
        assert results[0].passed is False
        assert results[1].passed is False  # both fail, but both attempted
        assert mock_apply.call_count == 2  # both were attempted

    @patch("maintenance_man.updater._gt_checkout_main")
    @patch("maintenance_man.updater._apply_update", return_value=False)
    def test_vuln_apply_fails(
        self, mock_apply, mock_checkout, project_config: ProjectConfig,
    ):
        results = process_vulns([VULN_FINDING], project_config)
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].failed_phase == "apply"


# -- process_bumps --

class TestProcessBumps:
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_all_bumps_pass(
        self, mock_test, mock_apply, mock_gt, project_config: ProjectConfig,
    ):
        bumps = [BUMP_MAJOR, BUMP_PATCH, BUMP_MINOR]
        results = process_bumps(bumps, project_config)
        # All 3 pass, sorted as patch -> minor -> major
        assert len(results) == 3
        assert all(r.passed for r in results)
        # Verify sort order via call order
        names = [r.pkg_name for r in results]
        assert names == ["pkg-a", "pkg-b", "pkg-c"]  # patch, minor, major

    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases")
    def test_bump_failure_stops_stack(
        self, mock_test, mock_apply, mock_gt, project_config: ProjectConfig,
    ):
        # Patch passes, minor fails
        mock_test.side_effect = [(True, None), (False, "unit")]
        bumps = [BUMP_PATCH, BUMP_MINOR, BUMP_MAJOR]
        results = process_bumps(bumps, project_config)

        assert len(results) == 3
        assert results[0].passed is True  # patch passed
        assert results[1].passed is False  # minor failed
        assert results[1].failed_phase == "unit"
        assert results[2].skipped is True  # major skipped

    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_empty_bumps(
        self, mock_test, mock_apply, mock_gt, project_config: ProjectConfig,
    ):
        results = process_bumps([], project_config)
        assert results == []
