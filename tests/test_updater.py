import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

import pytest

from maintenance_man.models.config import PhaseTestConfig, ProjectConfig
from maintenance_man.models.scan import (
    UpdateFinding,
    ScanResult,
    SemverTier,
    Severity,
    UpdateStatus,
    VulnFinding,
)
from maintenance_man.updater import (
    GraphiteNotFoundError,
    NoScanResultsError,
    RepoDirtyError,
    _branch_slug,
    check_graphite_available,
    check_repo_clean,
    get_current_branch,
    get_update_command,
    load_scan_results,
    process_updates,
    process_vulns,
    run_test_phases,
    save_scan_results,
    sort_updates_by_risk,
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

UPDATE_PATCH = UpdateFinding(
    pkg_name="pkg-a",
    installed_version="1.0.0",
    latest_version="1.0.1",
    semver_tier=SemverTier.PATCH,
)

UPDATE_MINOR = UpdateFinding(
    pkg_name="pkg-b",
    installed_version="1.0.0",
    latest_version="1.1.0",
    semver_tier=SemverTier.MINOR,
)

UPDATE_MAJOR = UpdateFinding(
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
        vulnerabilities=[VULN_FINDING.model_copy()],
        updates=[
            UPDATE_MAJOR.model_copy(),
            UPDATE_PATCH.model_copy(),
            UPDATE_MINOR.model_copy(),
        ],
    )


# -- save_scan_results --

class TestSaveScanResults:
    def test_writes_json_to_disk(self, scan_results_dir: Path, scan_result: ScanResult):
        save_scan_results("myapp", scan_results_dir, scan_result)
        import json
        data = json.loads(
            (scan_results_dir / "myapp.json").read_text(encoding="utf-8")
        )
        assert data["project"] == "myapp"

    def test_preserves_update_status(self, scan_results_dir: Path):
        from maintenance_man.models.scan import UpdateStatus
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
        data = json.loads(
            (scan_results_dir / "myapp.json").read_text(encoding="utf-8")
        )
        assert data["updates"][0]["update_status"] == "completed"


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


# -- sort_updates_by_risk --

class TestSortUpdatesByRisk:
    def test_sorts_patch_minor_major(self):
        updates = [UPDATE_MAJOR, UPDATE_PATCH, UPDATE_MINOR]
        sorted_u = sort_updates_by_risk(updates)
        assert [u.semver_tier for u in sorted_u] == [
            SemverTier.PATCH,
            SemverTier.MINOR,
            SemverTier.MAJOR,
        ]

    def test_empty_list(self):
        assert sort_updates_by_risk([]) == []

    def test_single_update(self):
        result = sort_updates_by_risk([UPDATE_MINOR])
        assert len(result) == 1
        assert result[0].semver_tier == SemverTier.MINOR


# -- _branch_slug --

class TestBranchSlug:
    def test_plain_name(self):
        assert _branch_slug("express") == "express"

    def test_scoped_npm(self):
        assert _branch_slug("@types/bun") == "types-bun"

    def test_deeply_scoped(self):
        assert _branch_slug("@babel/preset-env") == "babel-preset-env"

    def test_no_at_no_slash(self):
        assert _branch_slug("lodash") == "lodash"


# -- process_vulns --

class TestProcessVulns:
    @patch("maintenance_man.updater.submit_stack", return_value=(True, ""))
    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_single_vuln_passes(
        self, mock_test, mock_apply, mock_gt, mock_co, mock_submit,
        project_config: ProjectConfig,
    ):
        results = process_vulns(
            [VULN_FINDING.model_copy()], project_config,
        )
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].kind == "vuln"
        mock_submit.assert_called_once()

    @patch("maintenance_man.updater._gt_delete")
    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch(
        "maintenance_man.updater.run_test_phases",
        return_value=(False, "unit"),
    )
    def test_vuln_test_fails_continues(
        self, mock_test, mock_apply, mock_gt, mock_checkout, mock_delete,
        project_config: ProjectConfig,
    ):
        vuln2 = VULN_FINDING.model_copy(
            update={"vuln_id": "CVE-2024-0002", "pkg_name": "other-pkg"}
        )
        results = process_vulns(
            [VULN_FINDING.model_copy(), vuln2], project_config,
        )
        assert len(results) == 2
        assert results[0].passed is False
        assert results[1].passed is False
        assert mock_apply.call_count == 2
        assert mock_delete.call_count == 2  # both failed branches deleted

    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=False)
    def test_vuln_apply_fails(
        self, mock_apply, mock_checkout, project_config: ProjectConfig,
    ):
        results = process_vulns(
            [VULN_FINDING.model_copy()], project_config,
        )
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].failed_phase == "apply"

    @patch("maintenance_man.updater.save_scan_results")
    @patch("maintenance_man.updater.submit_stack", return_value=(False, ""))
    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_submit_failure_marks_findings_failed(
        self, mock_test, mock_apply, mock_gt, mock_co, mock_submit,
        mock_save, project_config: ProjectConfig,
    ):
        vuln = VULN_FINDING.model_copy()
        scan = ScanResult(
            project="myapp", scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            vulnerabilities=[vuln], secrets=[], updates=[],
        )
        results = process_vulns(
            [vuln], project_config,
            scan_result=scan, project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert results[0].passed is False
        assert results[0].failed_phase == "submit"
        assert vuln.update_status == UpdateStatus.FAILED
        mock_save.assert_called()


# -- process_updates --

class TestProcessUpdates:
    @patch("maintenance_man.updater.submit_stack", return_value=(True, ""))
    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_all_updates_pass(
        self, mock_test, mock_apply, mock_gt, mock_co, mock_submit,
        project_config: ProjectConfig,
    ):
        updates = [
            UPDATE_MAJOR.model_copy(),
            UPDATE_PATCH.model_copy(),
            UPDATE_MINOR.model_copy(),
        ]
        results = process_updates(updates, project_config)
        # All 3 pass, sorted as patch -> minor -> major
        assert len(results) == 3
        assert all(r.passed for r in results)
        # Verify sort order via call order
        names = [r.pkg_name for r in results]
        assert names == ["pkg-a", "pkg-b", "pkg-c"]  # patch, minor, major
        # Stack submitted from tip (last passing = pkg-c), then return to main
        mock_co.assert_any_call("bump/pkg-c", ANY)
        mock_co.assert_any_call("main", ANY)
        mock_submit.assert_called_once()

    @patch("maintenance_man.updater.submit_stack", return_value=(True, ""))
    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_delete")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases")
    def test_update_failure_skips_and_continues(
        self, mock_test, mock_apply, mock_gt, mock_delete, mock_co,
        mock_submit,
        project_config: ProjectConfig,
    ):
        # Patch passes, minor fails, major passes
        mock_test.side_effect = [(True, None), (False, "unit"), (True, None)]
        updates = [
            UPDATE_PATCH.model_copy(),
            UPDATE_MINOR.model_copy(),
            UPDATE_MAJOR.model_copy(),
        ]
        results = process_updates(updates, project_config)

        assert len(results) == 3
        assert results[0].passed is True   # patch passed
        assert results[1].passed is False  # minor failed
        assert results[1].failed_phase == "unit"
        assert results[2].passed is True   # major still attempted and passed
        mock_delete.assert_called_once()  # failed branch deleted
        # Stack submitted from tip (last passing = pkg-c / major)
        mock_co.assert_any_call("bump/pkg-c", ANY)
        mock_submit.assert_called_once()

    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_empty_updates(
        self, mock_test, mock_apply, mock_gt, mock_checkout,
        project_config: ProjectConfig,
    ):
        results = process_updates([], project_config)
        assert results == []
        mock_checkout.assert_called_once_with("main", ANY)

    @patch("maintenance_man.updater.save_scan_results")
    @patch("maintenance_man.updater.submit_stack", return_value=(False, ""))
    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_submit_failure_marks_findings_failed(
        self, mock_test, mock_apply, mock_gt, mock_co, mock_submit,
        mock_save, project_config: ProjectConfig,
    ):
        upd = UPDATE_PATCH.model_copy()
        scan = ScanResult(
            project="myapp", scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            vulnerabilities=[], secrets=[], updates=[upd],
        )
        results = process_updates(
            [upd], project_config,
            scan_result=scan, project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert results[0].passed is False
        assert results[0].failed_phase == "submit"
        assert upd.update_status == UpdateStatus.FAILED
        mock_save.assert_called()


# -- status tracking --

class TestStatusTracking:
    @patch("maintenance_man.updater.save_scan_results")
    @patch("maintenance_man.updater.submit_stack", return_value=(True, ""))
    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_vuln_pass_sets_completed(
        self, mock_test, mock_apply, mock_gt, mock_co, mock_submit,
        mock_save,
        project_config: ProjectConfig, scan_result: ScanResult,
    ):
        from maintenance_man.models.scan import UpdateStatus
        process_vulns(
            scan_result.vulnerabilities, project_config,
            scan_result=scan_result, project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.COMPLETED
        mock_save.assert_called()

    @patch("maintenance_man.updater.save_scan_results")
    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_delete")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(False, "unit"))
    def test_update_fail_sets_failed(
        self, mock_test, mock_apply, mock_gt, mock_delete,
        mock_checkout, mock_save,
        project_config: ProjectConfig, scan_result: ScanResult,
    ):
        from maintenance_man.models.scan import UpdateStatus
        process_updates(
            scan_result.updates, project_config,
            scan_result=scan_result, project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        statuses = [u.update_status for u in scan_result.updates]
        assert UpdateStatus.FAILED in statuses
        mock_save.assert_called()

    @patch("maintenance_man.updater.save_scan_results")
    @patch("maintenance_man.updater.submit_stack", return_value=(True, ""))
    @patch("maintenance_man.updater._gt_checkout", return_value=True)
    @patch("maintenance_man.updater._gt_delete")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases")
    def test_started_set_before_processing(
        self, mock_test, mock_apply, mock_gt, mock_delete, mock_co,
        mock_submit, mock_save,
        project_config: ProjectConfig, scan_result: ScanResult,
    ):
        """Verify 'started' is set before test execution."""
        from maintenance_man.models.scan import UpdateStatus

        statuses_during_test = []

        def capture_status(*args, **kwargs):
            # Capture update statuses at the time tests run
            statuses_during_test.extend(
                [u.update_status for u in scan_result.updates]
            )
            return (True, None)

        mock_test.side_effect = capture_status
        process_updates(
            scan_result.updates[:1], project_config,
            scan_result=scan_result, project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert UpdateStatus.STARTED in statuses_during_test


# -- get_current_branch --

class TestGetCurrentBranch:
    @patch("maintenance_man.updater.subprocess.run")
    def test_returns_branch_name(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="bump/pkg-a\n", stderr=""
        )
        assert get_current_branch(tmp_path) == "bump/pkg-a"

    @patch("maintenance_man.updater.subprocess.run")
    def test_strips_whitespace(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="  fix/some-pkg  \n", stderr=""
        )
        assert get_current_branch(tmp_path) == "fix/some-pkg"


class TestSyncGraphite:
    @patch("maintenance_man.updater.subprocess.run")
    def test_deletes_merged_branches(self, mock_run: MagicMock, tmp_path: Path):
        from maintenance_man.updater import sync_graphite

        def side_effect(cmd, **kwargs):
            if cmd[0] == "gt" and cmd[1] == "sync":
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="", stderr=""
                )
            if cmd[0] == "gh" and "--state" in cmd:
                state = cmd[cmd.index("--state") + 1]
                if state == "merged":
                    return subprocess.CompletedProcess(
                        args=cmd, returncode=0,
                        stdout="bump/click\nbump/tornado\n", stderr=""
                    )
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="", stderr=""
                )
            if cmd[0] == "git" and "branch" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0,
                    stdout="main\nbump/click\nbump/tornado\nbump/new-pkg\n",
                    stderr=""
                )
            if cmd[0] == "gt" and cmd[1] == "delete":
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="", stderr=""
                )
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr=""
            )

        mock_run.side_effect = side_effect
        assert sync_graphite(tmp_path) is True

        # Should delete bump/click and bump/tornado but NOT bump/new-pkg
        delete_calls = [
            c for c in mock_run.call_args_list
            if c[0][0][0] == "gt" and c[0][0][1] == "delete"
        ]
        deleted = {c[0][0][3] for c in delete_calls}
        assert deleted == {"bump/click", "bump/tornado"}

    @patch("maintenance_man.updater.subprocess.run")
    def test_handles_gh_failure_gracefully(
        self, mock_run: MagicMock, tmp_path: Path,
    ):
        from maintenance_man.updater import sync_graphite

        def side_effect(cmd, **kwargs):
            if cmd[0] == "gt" and cmd[1] == "sync":
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="", stderr=""
                )
            if cmd[0] == "gh":
                return subprocess.CompletedProcess(
                    args=cmd, returncode=1, stdout="", stderr="auth error"
                )
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr=""
            )

        mock_run.side_effect = side_effect
        assert sync_graphite(tmp_path) is True
