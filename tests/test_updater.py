import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import ANY, MagicMock

import pytest

from maintenance_man.models.config import PhaseTestConfig, ProjectConfig
from maintenance_man.models.scan import (
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
)
from maintenance_man.updater import (
    NoScanResultsError,
    _consolidate_vulns,
    _highest_fix_version,
    get_update_command,
    load_scan_results,
    process_updates,
    process_vulns,
    run_test_phases,
    save_scan_results,
    sort_updates_by_risk,
)

# -- Factory helpers --


def make_vuln(**overrides) -> VulnFinding:
    defaults = dict(
        vuln_id="CVE-2024-0001",
        pkg_name="some-pkg",
        installed_version="1.0.0",
        fixed_version="1.0.1",
        severity=Severity.HIGH,
        title="Test vuln",
        description="desc",
        status="fixed",
    )
    return VulnFinding(**(defaults | overrides))


def make_update(tier: SemverTier = SemverTier.PATCH, **overrides) -> UpdateFinding:
    tier_defaults = {
        SemverTier.PATCH: ("pkg-a", "1.0.0", "1.0.1"),
        SemverTier.MINOR: ("pkg-b", "1.0.0", "1.1.0"),
        SemverTier.MAJOR: ("pkg-c", "1.0.0", "2.0.0"),
    }
    name, installed, latest = tier_defaults.get(tier, ("pkg-x", "1.0.0", "2.0.0"))
    defaults = dict(
        pkg_name=name,
        installed_version=installed,
        latest_version=latest,
        semver_tier=tier,
    )
    return UpdateFinding(**(defaults | overrides))


# -- Fixtures --


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
        vulnerabilities=[make_vuln()],
        updates=[
            make_update(SemverTier.MAJOR),
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ],
    )


@pytest.fixture()
def mock_vcs(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Mock all VCS and updater subprocess calls."""
    mocks = {}
    for name, default in [
        ("submit_stack", (True, "")),
        ("gt_checkout", True),
        ("gt_create", True),
        ("gt_delete", True),
        ("_apply_update", True),
        ("run_test_phases", (True, None)),
    ]:
        mock = MagicMock(return_value=default)
        monkeypatch.setattr(f"maintenance_man.updater.{name}", mock)
        mocks[name] = mock
    return mocks


# -- save_scan_results --


class TestSaveScanResults:
    def test_writes_json_to_disk(self, scan_results_dir: Path, scan_result: ScanResult):
        save_scan_results("myapp", scan_results_dir, scan_result)
        import json

        data = json.loads((scan_results_dir / "myapp.json").read_text(encoding="utf-8"))
        assert data["project"] == "myapp"

    def test_preserves_update_status(self, scan_results_dir: Path):
        result = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            updates=[
                UpdateFinding(
                    pkg_name="pkg-a",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    semver_tier=SemverTier.PATCH,
                    update_status=UpdateStatus.COMPLETED,
                ),
            ],
        )
        save_scan_results("myapp", scan_results_dir, result)
        import json

        data = json.loads((scan_results_dir / "myapp.json").read_text(encoding="utf-8"))
        assert data["updates"][0]["update_status"] == "completed"


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
        with pytest.raises(NoScanResultsError, match="nonexistent"):
            load_scan_results("nonexistent", scan_results_dir)


# -- get_update_command --


class TestGetUpdateCommand:
    @pytest.mark.parametrize(
        ("manager", "pkg", "version", "expected"),
        [
            pytest.param(
                "bun", "axios", "1.7.0", ["bun", "add", "axios@1.7.0"], id="bun"
            ),
            pytest.param(
                "uv",
                "requests",
                "2.32.0",
                ["uv", "add", "requests==2.32.0"],
                id="uv",
            ),
            pytest.param(
                "mvn",
                "org.example:lib",
                "3.0.0",
                [
                    "mvn",
                    "versions:use-dep-version",
                    "-Dincludes=org.example:lib",
                    "-DdepVersion=3.0.0",
                ],
                id="mvn",
            ),
        ],
    )
    def test_get_update_command(self, manager, pkg, version, expected):
        assert get_update_command(manager, pkg, version) == expected


# -- run_test_phases --


class TestRunTestPhases:
    def test_all_green(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
        )
        monkeypatch.setattr("maintenance_man.updater.subprocess.run", mock_run)
        tc = PhaseTestConfig(
            unit="bun test",
            integration="bun run test:integration",
        )
        passed, failed_phase = run_test_phases(tc, tmp_path)
        assert passed is True
        assert failed_phase is None
        assert mock_run.call_count == 2

    def test_unit_fails(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=1, stdout="FAIL", stderr=""
            )
        )
        monkeypatch.setattr("maintenance_man.updater.subprocess.run", mock_run)
        tc = PhaseTestConfig(unit="bun test")
        passed, failed_phase = run_test_phases(tc, tmp_path)
        assert passed is False
        assert failed_phase == "unit"
        assert mock_run.call_count == 1

    def test_integration_fails(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        def side_effect(*args, **kwargs):
            cmd_str = " ".join(args[0])
            if "integration" in cmd_str:
                return subprocess.CompletedProcess(
                    args=[], returncode=1, stdout="", stderr=""
                )
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )

        mock_run = MagicMock(side_effect=side_effect)
        monkeypatch.setattr("maintenance_man.updater.subprocess.run", mock_run)
        tc = PhaseTestConfig(unit="bun test", integration="bun run test:integration")
        passed, failed_phase = run_test_phases(tc, tmp_path)
        assert passed is False
        assert failed_phase == "integration"

    def test_skips_unconfigured_phases(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
        )
        monkeypatch.setattr("maintenance_man.updater.subprocess.run", mock_run)
        tc = PhaseTestConfig(unit="bun test")  # no integration or component
        passed, _ = run_test_phases(tc, tmp_path)
        assert passed is True
        assert mock_run.call_count == 1  # only unit


# -- sort_updates_by_risk --


class TestSortUpdatesByRisk:
    def test_sorts_patch_minor_major(self):
        updates = [
            make_update(SemverTier.MAJOR),
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]
        sorted_u = sort_updates_by_risk(updates)
        assert [u.semver_tier for u in sorted_u] == [
            SemverTier.PATCH,
            SemverTier.MINOR,
            SemverTier.MAJOR,
        ]

    def test_empty_list(self):
        assert sort_updates_by_risk([]) == []

    def test_single_update(self):
        result = sort_updates_by_risk([make_update(SemverTier.MINOR)])
        assert len(result) == 1
        assert result[0].semver_tier == SemverTier.MINOR


# -- _highest_fix_version --


class TestHighestFixVersion:
    def test_picks_highest_semver(self):
        vulns = [
            make_vuln(fixed_version="2.31.0"),
            make_vuln(fixed_version="2.32.4"),
            make_vuln(fixed_version="2.32.0"),
        ]
        assert _highest_fix_version(vulns) == "2.32.4"

    def test_single_vuln(self):
        assert _highest_fix_version([make_vuln(fixed_version="1.0.1")]) == "1.0.1"

    def test_invalid_version_ignored(self):
        vulns = [
            make_vuln(fixed_version="not-a-version"),
            make_vuln(fixed_version="2.0.0"),
        ]
        assert _highest_fix_version(vulns) == "2.0.0"

    def test_invalid_version_order_independent(self):
        vulns = [
            make_vuln(fixed_version="2.0.0"),
            make_vuln(fixed_version="not-a-version"),
        ]
        assert _highest_fix_version(vulns) == "2.0.0"


# -- _consolidate_vulns --


class TestConsolidateVulns:
    def test_same_package_consolidated(self):
        vulns = [
            make_vuln(
                vuln_id="CVE-2023-32681",
                pkg_name="requests",
                fixed_version="2.31.0",
            ),
            make_vuln(
                vuln_id="CVE-2024-35195",
                pkg_name="requests",
                fixed_version="2.32.0",
            ),
            make_vuln(
                vuln_id="CVE-2024-47081",
                pkg_name="requests",
                fixed_version="2.32.4",
            ),
        ]
        result = _consolidate_vulns(vulns)
        assert len(result) == 1
        assert result[0].pkg_name == "requests"
        assert result[0].target_version == "2.32.4"
        assert "CVE-2023-32681" in result[0].detail
        assert "CVE-2024-35195" in result[0].detail
        assert "CVE-2024-47081" in result[0].detail

    def test_different_packages_not_consolidated(self):
        vulns = [
            make_vuln(vuln_id="CVE-0001", pkg_name="pkg-a", fixed_version="1.0.1"),
            make_vuln(vuln_id="CVE-0002", pkg_name="pkg-b", fixed_version="2.0.1"),
        ]
        result = _consolidate_vulns(vulns)
        assert len(result) == 2
        assert result[0].pkg_name == "pkg-a"
        assert result[1].pkg_name == "pkg-b"

    def test_status_fanout_to_originals(self):
        v1 = make_vuln(vuln_id="CVE-0001", pkg_name="pkg", fixed_version="1.0.1")
        v2 = make_vuln(vuln_id="CVE-0002", pkg_name="pkg", fixed_version="1.0.2")
        consolidated = _consolidate_vulns([v1, v2])
        consolidated[0].update_status = UpdateStatus.COMPLETED
        assert v1.update_status == UpdateStatus.COMPLETED
        assert v2.update_status == UpdateStatus.COMPLETED

    def test_empty_list(self):
        assert _consolidate_vulns([]) == []


# -- process_vulns --


class TestProcessVulns:
    def test_single_vuln_passes(
        self, mock_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        results = process_vulns([make_vuln()], project_config)
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].kind == "vuln"
        mock_vcs["submit_stack"].assert_called_once()

    def test_vuln_test_fails_continues(
        self, mock_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_vcs["run_test_phases"].return_value = (False, "unit")
        vuln2 = make_vuln(vuln_id="CVE-2024-0002", pkg_name="other-pkg")
        results = process_vulns([make_vuln(), vuln2], project_config)
        assert len(results) == 2
        assert results[0].passed is False
        assert results[1].passed is False
        assert mock_vcs["_apply_update"].call_count == 2
        assert mock_vcs["gt_delete"].call_count == 2  # both failed branches deleted

    def test_vuln_apply_fails(
        self, mock_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_vcs["_apply_update"].return_value = False
        results = process_vulns([make_vuln()], project_config)
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].failed_phase == "apply"

    def test_submit_failure_marks_findings_failed(
        self,
        mock_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
    ):
        mock_vcs["submit_stack"].return_value = (False, "")
        mock_save = MagicMock()
        monkeypatch.setattr("maintenance_man.updater.save_scan_results", mock_save)
        vuln = make_vuln()
        scan = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            vulnerabilities=[vuln],
            secrets=[],
            updates=[],
        )
        results = process_vulns(
            [vuln],
            project_config,
            scan_result=scan,
            project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert results[0].passed is False
        assert results[0].failed_phase == "submit"
        assert vuln.update_status == UpdateStatus.FAILED
        mock_save.assert_called()

    def test_duplicate_package_vulns_consolidated(
        self, mock_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        """Multiple CVEs for the same package → one _apply_update call."""
        v1 = make_vuln(
            vuln_id="CVE-0001", pkg_name="requests", fixed_version="2.31.0"
        )
        v2 = make_vuln(
            vuln_id="CVE-0002", pkg_name="requests", fixed_version="2.32.4"
        )
        v3 = make_vuln(
            vuln_id="CVE-0003", pkg_name="requests", fixed_version="2.32.0"
        )
        results = process_vulns([v1, v2, v3], project_config)
        assert len(results) == 1
        assert results[0].passed is True
        mock_vcs["_apply_update"].assert_called_once()
        # Highest version used
        call_args = mock_vcs["_apply_update"].call_args
        assert call_args[0][2] == "2.32.4"
        # All originals get status
        assert v1.update_status == UpdateStatus.COMPLETED
        assert v2.update_status == UpdateStatus.COMPLETED
        assert v3.update_status == UpdateStatus.COMPLETED

    def test_duplicate_package_vulns_failure_fans_out(
        self, mock_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        """When consolidated vuln fails, all originals are marked FAILED."""
        mock_vcs["_apply_update"].return_value = False
        v1 = make_vuln(
            vuln_id="CVE-0001", pkg_name="requests", fixed_version="2.31.0"
        )
        v2 = make_vuln(
            vuln_id="CVE-0002", pkg_name="requests", fixed_version="2.32.4"
        )
        results = process_vulns([v1, v2], project_config)
        assert len(results) == 1
        assert results[0].passed is False
        assert v1.update_status == UpdateStatus.FAILED
        assert v2.update_status == UpdateStatus.FAILED


# -- process_updates --


class TestProcessUpdates:
    def test_all_updates_pass(
        self, mock_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        updates = [
            make_update(SemverTier.MAJOR),
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]
        results = process_updates(updates, project_config)
        # All 3 pass, sorted as patch -> minor -> major
        assert len(results) == 3
        assert all(r.passed for r in results)
        # Verify sort order via call order
        names = [r.pkg_name for r in results]
        assert names == ["pkg-a", "pkg-b", "pkg-c"]  # patch, minor, major
        # Stack submitted from tip (last passing = pkg-c), then return to main
        mock_vcs["gt_checkout"].assert_any_call("bump/pkg-c", ANY)
        mock_vcs["gt_checkout"].assert_any_call("main", ANY)
        mock_vcs["submit_stack"].assert_called_once()

    def test_update_failure_skips_and_continues(
        self, mock_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        # Patch passes, minor fails, major passes
        mock_vcs["run_test_phases"].side_effect = [
            (True, None),
            (False, "unit"),
            (True, None),
        ]
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
            make_update(SemverTier.MAJOR),
        ]
        results = process_updates(updates, project_config)

        assert len(results) == 3
        assert results[0].passed is True  # patch passed
        assert results[1].passed is False  # minor failed
        assert results[1].failed_phase == "unit"
        assert results[2].passed is True  # major still attempted and passed
        mock_vcs["gt_delete"].assert_called_once()  # failed branch deleted
        # Stack submitted from tip (last passing = pkg-c / major)
        mock_vcs["gt_checkout"].assert_any_call("bump/pkg-c", ANY)
        mock_vcs["submit_stack"].assert_called_once()

    def test_empty_updates(
        self, mock_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        results = process_updates([], project_config)
        assert results == []
        mock_vcs["gt_checkout"].assert_called_once_with("main", ANY)

    def test_submit_failure_marks_findings_failed(
        self,
        mock_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
    ):
        mock_vcs["submit_stack"].return_value = (False, "")
        mock_save = MagicMock()
        monkeypatch.setattr("maintenance_man.updater.save_scan_results", mock_save)
        upd = make_update(SemverTier.PATCH)
        scan = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            vulnerabilities=[],
            secrets=[],
            updates=[upd],
        )
        results = process_updates(
            [upd],
            project_config,
            scan_result=scan,
            project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert results[0].passed is False
        assert results[0].failed_phase == "submit"
        assert upd.update_status == UpdateStatus.FAILED
        mock_save.assert_called()


# -- status tracking --


class TestStatusTracking:
    def test_vuln_pass_sets_completed(
        self,
        mock_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
        scan_result: ScanResult,
    ):
        mock_save = MagicMock()
        monkeypatch.setattr("maintenance_man.updater.save_scan_results", mock_save)
        process_vulns(
            scan_result.vulnerabilities,
            project_config,
            scan_result=scan_result,
            project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.COMPLETED
        mock_save.assert_called()

    def test_update_fail_sets_failed(
        self,
        mock_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
        scan_result: ScanResult,
    ):
        mock_vcs["run_test_phases"].return_value = (False, "unit")
        mock_save = MagicMock()
        monkeypatch.setattr("maintenance_man.updater.save_scan_results", mock_save)
        process_updates(
            scan_result.updates,
            project_config,
            scan_result=scan_result,
            project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        statuses = [u.update_status for u in scan_result.updates]
        assert UpdateStatus.FAILED in statuses
        mock_save.assert_called()

    def test_started_set_before_processing(
        self,
        mock_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
        scan_result: ScanResult,
    ):
        """Verify 'started' is set before test execution."""
        mock_save = MagicMock()
        monkeypatch.setattr("maintenance_man.updater.save_scan_results", mock_save)

        statuses_during_test = []

        def capture_status(*args, **kwargs):
            # Capture update statuses at the time tests run
            statuses_during_test.extend([u.update_status for u in scan_result.updates])
            return (True, None)

        mock_vcs["run_test_phases"].side_effect = capture_status
        process_updates(
            scan_result.updates[:1],
            project_config,
            scan_result=scan_result,
            project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert UpdateStatus.STARTED in statuses_during_test
