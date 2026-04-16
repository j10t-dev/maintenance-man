import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.models.config import ProjectConfig
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
    _apply_update,
    _get_uv_update_command,
    consolidate_vulns,
    get_update_commands,
    highest_fix_version,
    load_scan_results,
    process_findings,
    process_updates,
    process_vulns,
    remove_completed_findings,
    run_test_phases,
    save_scan_results,
    sort_updates_by_risk,
)
from maintenance_man.uv_dependencies import UvDependencyError, UvDependencyLocation

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
        test_unit="bun test",
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
def mock_local_vcs(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Mock VCS and updater calls for single-branch update processing."""
    mocks = {}
    for name, default in [
        ("git_commit_all", True),
        ("_apply_update", True),
        ("run_test_phases", (True, None)),
    ]:
        mock = MagicMock(return_value=default)
        monkeypatch.setattr(f"maintenance_man.updater.{name}", mock)
        mocks[name] = mock
    mock_discard = MagicMock()
    monkeypatch.setattr("maintenance_man.updater.discard_changes", mock_discard)
    mocks["discard_changes"] = mock_discard
    return mocks


@pytest.fixture()
def mock_resolve_vcs(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Mock VCS and updater calls for single-branch resolve processing."""
    mocks = {}
    for name, default in [
        ("git_commit_all", True),
        ("_apply_update", True),
        ("run_test_phases", (True, None)),
        ("discard_changes", None),
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


# -- get_update_commands --


class TestGetUpdateCommands:
    def test_uv_runtime_dependency(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests>=2.28"]\n', encoding="utf-8"
        )

        assert get_update_commands("uv", "requests", "2.33.1", tmp_path) == [
            ["uv", "add", "requests==2.33.1"]
        ]

    def test_uv_dev_dependency_group(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = []\n\n"
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0"]\n',
            encoding="utf-8",
        )

        assert get_update_commands("uv", "pytest", "9.0.3", tmp_path) == [
            ["uv", "add", "--group", "dev", "pytest==9.0.3"]
        ]

    def test_uv_custom_dependency_group(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = []\n\n"
            "[dependency-groups]\n"
            'lint = ["ruff>=0.9.0"]\n',
            encoding="utf-8",
        )

        assert get_update_commands("uv", "ruff", "0.13.0", tmp_path) == [
            ["uv", "add", "--group", "lint", "ruff==0.13.0"]
        ]

    def test_uv_optional_dependency_is_not_supported(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = []\n\n"
            "[project.optional-dependencies]\n"
            'cli = ["rich>=14.0"]\n',
            encoding="utf-8",
        )

        with pytest.raises(
            UvDependencyError,
            match=(
                "Package reported as direct dependency but no matching declaration "
                "was found in pyproject.toml: rich"
            ),
        ):
            get_update_commands("uv", "rich", "14.3.3", tmp_path)

    def test_uv_runtime_and_group_dependency(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["pytest>=8.0"]\n\n'
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0"]\n',
            encoding="utf-8",
        )

        assert get_update_commands("uv", "pytest", "9.0.3", tmp_path) == [
            ["uv", "add", "pytest==9.0.3"],
            ["uv", "add", "--group", "dev", "pytest==9.0.3"],
        ]

    def test_uv_missing_declaration_site_raises(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests>=2.28"]\n', encoding="utf-8"
        )

        with pytest.raises(
            UvDependencyError,
            match=(
                "Package reported as direct dependency but no matching declaration "
                "was found in pyproject.toml: pytest"
            ),
        ):
            get_update_commands("uv", "pytest", "9.0.3", tmp_path)

    @pytest.mark.parametrize(
        ("manager", "pkg", "version", "expected"),
        [
            pytest.param(
                "bun",
                "axios",
                "1.7.0",
                [["bun", "add", "axios@1.7.0"]],
                id="bun",
            ),
            pytest.param(
                "mvn",
                "org.example:lib",
                "3.0.0",
                [
                    [
                        "mvn",
                        "versions:use-dep-version",
                        "-Dincludes=org.example:lib",
                        "-DdepVersion=3.0.0",
                    ]
                ],
                id="mvn",
            ),
        ],
    )
    def test_non_uv_managers_unchanged(
        self, tmp_path: Path, manager, pkg, version, expected
    ):
        assert get_update_commands(manager, pkg, version, tmp_path) == expected

    def test_uv_group_command_requires_group_name(self):
        with pytest.raises(
            UvDependencyError,
            match="group dependency location missing",
        ):
            _get_uv_update_command(
                "pytest",
                "9.0.3",
                UvDependencyLocation(kind="group"),
            )


class TestApplyUpdate:
    def test_uv_runs_all_matching_commands_in_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["pytest>=8.0"]\n\n'
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0"]\n'
            'lint = ["pytest>=8.0"]\n',
            encoding="utf-8",
        )
        monkeypatch.setattr("maintenance_man.updater._project_env", lambda: {})
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
        )
        monkeypatch.setattr("maintenance_man.updater.subprocess.run", mock_run)

        assert _apply_update("uv", "pytest", "9.0.3", tmp_path) is True
        assert [call.args[0] for call in mock_run.call_args_list] == [
            ["uv", "add", "pytest==9.0.3"],
            ["uv", "add", "--group", "dev", "pytest==9.0.3"],
            ["uv", "add", "--group", "lint", "pytest==9.0.3"],
        ]

    def test_uv_stops_on_first_failing_command(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["pytest>=8.0"]\n\n'
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0"]\n'
            'lint = ["pytest>=8.0"]\n',
            encoding="utf-8",
        )
        monkeypatch.setattr("maintenance_man.updater._project_env", lambda: {})
        mock_run = MagicMock(
            side_effect=[
                subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                ),
                subprocess.CompletedProcess(
                    args=[], returncode=1, stdout="", stderr="boom"
                ),
                subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="", stderr=""
                ),
            ]
        )
        monkeypatch.setattr("maintenance_man.updater.subprocess.run", mock_run)

        assert _apply_update("uv", "pytest", "9.0.3", tmp_path) is False
        assert mock_run.call_count == 2
        assert "uv add --group dev pytest==9.0.3" in capsys.readouterr().out

    def test_uv_pyproject_read_failure_is_apply_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        monkeypatch.setattr("maintenance_man.updater._project_env", lambda: {})
        mock_run = MagicMock()
        monkeypatch.setattr("maintenance_man.updater.subprocess.run", mock_run)

        assert _apply_update("uv", "pytest", "9.0.3", tmp_path) is False
        assert mock_run.call_count == 0
        assert "Failed to read" in capsys.readouterr().out


# -- run_test_phases --


class TestRunTestPhases:
    def test_all_green(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
        )
        monkeypatch.setattr("maintenance_man.updater.subprocess.run", mock_run)
        tc = ProjectConfig(
            path=tmp_path,
            package_manager="bun",
            test_unit="bun test",
            test_integration="bun run test:integration",
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
        tc = ProjectConfig(path=tmp_path, package_manager="bun", test_unit="bun test")
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
        tc = ProjectConfig(
            path=tmp_path,
            package_manager="bun",
            test_unit="bun test",
            test_integration="bun run test:integration",
        )
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
        tc = ProjectConfig(
            path=tmp_path, package_manager="bun", test_unit="bun test"
        )  # no integration or component
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


# -- highest_fix_version --


class TestHighestFixVersion:
    def test_picks_highest_semver(self):
        vulns = [
            make_vuln(fixed_version="2.31.0"),
            make_vuln(fixed_version="2.32.4"),
            make_vuln(fixed_version="2.32.0"),
        ]
        assert highest_fix_version(vulns) == "2.32.4"

    def test_single_vuln(self):
        assert highest_fix_version([make_vuln(fixed_version="1.0.1")]) == "1.0.1"

    def test_invalid_version_ignored(self):
        vulns = [
            make_vuln(fixed_version="not-a-version"),
            make_vuln(fixed_version="2.0.0"),
        ]
        assert highest_fix_version(vulns) == "2.0.0"

    def test_invalid_version_order_independent(self):
        vulns = [
            make_vuln(fixed_version="2.0.0"),
            make_vuln(fixed_version="not-a-version"),
        ]
        assert highest_fix_version(vulns) == "2.0.0"


# -- consolidate_vulns --


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
        result = consolidate_vulns(vulns)
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
        result = consolidate_vulns(vulns)
        assert len(result) == 2
        assert result[0].pkg_name == "pkg-a"
        assert result[1].pkg_name == "pkg-b"

    def test_status_fanout_to_originals(self):
        v1 = make_vuln(vuln_id="CVE-0001", pkg_name="pkg", fixed_version="1.0.1")
        v2 = make_vuln(vuln_id="CVE-0002", pkg_name="pkg", fixed_version="1.0.2")
        consolidated = consolidate_vulns([v1, v2])
        consolidated[0].update_status = UpdateStatus.COMPLETED
        assert v1.update_status == UpdateStatus.COMPLETED
        assert v2.update_status == UpdateStatus.COMPLETED

    def test_lifecycle_fanout_to_originals(self):
        v1 = make_vuln(vuln_id="CVE-0001", pkg_name="pkg", fixed_version="1.0.1")
        v2 = make_vuln(vuln_id="CVE-0002", pkg_name="pkg", fixed_version="1.0.2")
        consolidated = consolidate_vulns([v1, v2])

        consolidated[0].update_status = UpdateStatus.READY
        consolidated[0].failed_phase = "unit"
        consolidated[0].flow = "resolve"

        assert v1.update_status == UpdateStatus.READY
        assert v2.update_status == UpdateStatus.READY
        assert v1.failed_phase == "unit"
        assert v2.failed_phase == "unit"
        assert v1.flow == "resolve"
        assert v2.flow == "resolve"

    def test_initial_lifecycle_state_normalises_across_group(self):
        v1 = make_vuln(vuln_id="CVE-0001", pkg_name="pkg", fixed_version="1.0.1")
        v2 = make_vuln(
            vuln_id="CVE-0002",
            pkg_name="pkg",
            fixed_version="1.0.2",
            update_status=UpdateStatus.FAILED,
            failed_phase="unit",
            flow="resolve",
        )

        consolidated = consolidate_vulns([v1, v2])

        assert consolidated[0].update_status == UpdateStatus.FAILED
        assert consolidated[0].failed_phase == "unit"
        assert consolidated[0].flow == "resolve"
        assert v1.update_status == UpdateStatus.FAILED
        assert v1.failed_phase == "unit"
        assert v1.flow == "resolve"
        assert v2.update_status == UpdateStatus.FAILED
        assert v2.failed_phase == "unit"
        assert v2.flow == "resolve"

    def test_empty_list(self):
        assert consolidate_vulns([]) == []


# -- remove_completed_findings --


class TestRemoveCompletedFindings:
    def test_removes_completed_vulns_and_updates(self):
        vulns = [
            make_vuln(vuln_id="CVE-1", update_status=UpdateStatus.COMPLETED),
            make_vuln(vuln_id="CVE-2", update_status=UpdateStatus.FAILED),
            make_vuln(vuln_id="CVE-3", update_status=None),
        ]
        updates = [
            make_update(SemverTier.PATCH, update_status=UpdateStatus.COMPLETED),
            make_update(SemverTier.MINOR, update_status=UpdateStatus.FAILED),
        ]
        scan = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            vulnerabilities=vulns,
            updates=updates,
        )

        remove_completed_findings(scan)

        assert len(scan.vulnerabilities) == 2
        assert all(
            v.update_status != UpdateStatus.COMPLETED for v in scan.vulnerabilities
        )
        assert len(scan.updates) == 1
        assert scan.updates[0].update_status == UpdateStatus.FAILED

    def test_no_completed_is_noop(self):
        scan = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            updates=[make_update(SemverTier.PATCH, update_status=UpdateStatus.FAILED)],
        )

        remove_completed_findings(scan)

        assert len(scan.updates) == 1


# -- process_findings (on_failure="continue") --


class TestProcessFindingsLocal:
    def test_success_sets_ready_and_update_flow(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        update = make_update(SemverTier.PATCH)

        results = process_findings([update], project_config, flow="update")

        assert len(results) == 1
        assert results[0].passed is True
        assert update.update_status == UpdateStatus.READY
        assert update.failed_phase is None
        assert update.flow == "update"

    def test_already_applied_sets_ready_and_update_flow(
        self,
        mock_local_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
    ):
        mock_has_changes = MagicMock(return_value=False)
        monkeypatch.setattr(
            "maintenance_man.updater.git_has_changes",
            mock_has_changes,
            raising=False,
        )
        update = make_update(SemverTier.PATCH)

        results = process_findings([update], project_config, flow="update")

        assert len(results) == 1
        assert results[0].passed is True
        assert update.update_status == UpdateStatus.READY
        assert update.failed_phase is None
        assert update.flow == "update"
        mock_local_vcs["git_commit_all"].assert_not_called()

    def test_failure_sets_failed_and_active_flow(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_local_vcs["run_test_phases"].return_value = (False, "unit")
        update = make_update(SemverTier.PATCH)

        results = process_findings([update], project_config, flow="update")

        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].failed_phase == "unit"
        assert update.update_status == UpdateStatus.FAILED
        assert update.failed_phase == "unit"
        assert update.flow == "update"

    def test_all_pass(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]

        results = process_findings(updates, project_config, flow="update")

        assert len(results) == 2
        assert all(r.passed for r in results)
        assert mock_local_vcs["_apply_update"].call_count == 2
        assert mock_local_vcs["run_test_phases"].call_count == 2
        assert mock_local_vcs["git_commit_all"].call_count == 2
        mock_local_vcs["discard_changes"].assert_not_called()

    def test_failure_discards_and_continues(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_local_vcs["run_test_phases"].side_effect = [
            (True, None),
            (False, "unit"),
            (True, None),
        ]
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
            make_update(SemverTier.MAJOR),
        ]

        results = process_findings(updates, project_config, flow="update")

        assert len(results) == 3
        assert results[0].passed is True
        assert results[1].passed is False
        assert results[2].passed is True
        mock_local_vcs["discard_changes"].assert_called_once()
        assert mock_local_vcs["git_commit_all"].call_count == 2

    def test_apply_failure_continues(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_local_vcs["_apply_update"].side_effect = [False, True]
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]

        results = process_findings(updates, project_config, flow="update")

        assert len(results) == 2
        assert results[0].passed is False
        assert results[0].failed_phase == "apply"
        assert results[1].passed is True

    def test_no_test_config_treats_update_as_pass(
        self, mock_local_vcs: dict[str, MagicMock], tmp_path: Path
    ):
        project_config = ProjectConfig(path=tmp_path, package_manager="bun")

        results = process_findings(
            [make_update(SemverTier.PATCH)],
            project_config,
            flow="update",
        )

        assert len(results) == 1
        assert results[0].passed is True
        mock_local_vcs["run_test_phases"].assert_not_called()
        mock_local_vcs["git_commit_all"].assert_called_once()

    def test_commit_failure_marks_finding_failed_and_continues(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_local_vcs["git_commit_all"].side_effect = [False, True]
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]

        results = process_findings(updates, project_config, flow="update")

        assert len(results) == 2
        assert results[0].passed is False
        assert results[0].failed_phase == "commit"
        assert results[1].passed is True

    def test_noop_update_without_changes_counts_as_pass(
        self,
        mock_local_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
    ):
        mock_local_vcs["git_commit_all"].return_value = False
        mock_has_changes = MagicMock(return_value=False)
        monkeypatch.setattr(
            "maintenance_man.updater.git_has_changes",
            mock_has_changes,
            raising=False,
        )
        update = make_update(SemverTier.PATCH)

        results = process_findings([update], project_config, flow="update")

        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].failed_phase is None
        assert update.update_status == UpdateStatus.READY
        mock_local_vcs["git_commit_all"].assert_not_called()

    def test_status_tracking(
        self,
        mock_local_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
    ):
        mock_local_vcs["run_test_phases"].side_effect = [
            (True, None),
            (False, "unit"),
        ]
        mock_save = MagicMock()
        monkeypatch.setattr("maintenance_man.updater.save_scan_results", mock_save)
        upd_pass = make_update(SemverTier.PATCH)
        upd_fail = make_update(SemverTier.MINOR)
        scan = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            updates=[upd_pass, upd_fail],
        )

        process_findings(
            [upd_pass, upd_fail],
            project_config,
            flow="update",
            scan_result=scan,
            project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )

        assert upd_pass.update_status == UpdateStatus.READY
        assert upd_fail.update_status == UpdateStatus.FAILED
        mock_save.assert_called()

    def test_empty_findings(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        results = process_findings([], project_config, flow="update")
        assert results == []


# -- process_findings (on_failure="stop") --


class TestProcessFindingsResolve:
    def test_success_sets_ready_and_resolve_flow(
        self, mock_resolve_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        update = make_update(SemverTier.PATCH)

        results = process_findings(
            [update],
            project_config,
            flow="resolve",
            on_failure="stop",
        )

        assert len(results) == 1
        assert results[0].passed is True
        assert update.update_status == UpdateStatus.READY
        assert update.failed_phase is None
        assert update.flow == "resolve"

    def test_failure_sets_failed_and_resolve_flow(
        self, mock_resolve_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_resolve_vcs["_apply_update"].return_value = False
        update = make_update(SemverTier.PATCH)

        results = process_findings(
            [update],
            project_config,
            flow="resolve",
            on_failure="stop",
        )

        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].failed_phase == "apply"
        assert update.update_status == UpdateStatus.FAILED
        assert update.failed_phase == "apply"
        assert update.flow == "resolve"

    def test_all_pass(
        self, mock_resolve_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]

        results = process_findings(
            updates,
            project_config,
            flow="resolve",
            on_failure="stop",
        )

        assert len(results) == 2
        assert all(r.passed for r in results)
        assert mock_resolve_vcs["_apply_update"].call_count == 2
        assert mock_resolve_vcs["git_commit_all"].call_count == 2
        assert mock_resolve_vcs["run_test_phases"].call_count == 2

    def test_failure_stops_and_preserves_branch_state(
        self, mock_resolve_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_resolve_vcs["run_test_phases"].side_effect = [
            (True, None),
            (False, "unit"),
        ]
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
            make_update(SemverTier.MAJOR),
        ]

        results = process_findings(
            updates,
            project_config,
            flow="resolve",
            on_failure="stop",
        )

        assert len(results) == 2
        assert results[0].passed is True
        assert results[1].passed is False
        assert results[1].failed_phase == "unit"
        assert mock_resolve_vcs["_apply_update"].call_count == 2
        assert mock_resolve_vcs["git_commit_all"].call_count == 1
        mock_resolve_vcs["discard_changes"].assert_not_called()

    def test_no_test_config_treats_update_as_pass(
        self, mock_resolve_vcs: dict[str, MagicMock], tmp_path: Path
    ):
        project_config = ProjectConfig(path=tmp_path, package_manager="bun")

        results = process_findings(
            [make_update(SemverTier.PATCH)],
            project_config,
            flow="resolve",
            on_failure="stop",
        )

        assert len(results) == 1
        assert results[0].passed is True
        mock_resolve_vcs["run_test_phases"].assert_not_called()

    def test_status_tracking(
        self,
        mock_resolve_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
    ):
        mock_resolve_vcs["run_test_phases"].side_effect = [
            (False, "unit"),
        ]
        mock_save = MagicMock()
        monkeypatch.setattr("maintenance_man.updater.save_scan_results", mock_save)
        upd_fail = make_update(SemverTier.PATCH, update_status=UpdateStatus.FAILED)
        scan = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            updates=[upd_fail],
        )

        process_findings(
            [upd_fail],
            project_config,
            flow="resolve",
            scan_result=scan,
            project_name="myapp",
            results_dir=Path("/tmp/fake"),
            on_failure="stop",
        )

        assert upd_fail.update_status == UpdateStatus.FAILED
        mock_save.assert_called()

    def test_noop_update_without_changes_counts_as_pass(
        self,
        mock_resolve_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
    ):
        mock_resolve_vcs["git_commit_all"].return_value = False
        mock_has_changes = MagicMock(return_value=False)
        monkeypatch.setattr(
            "maintenance_man.updater.git_has_changes",
            mock_has_changes,
            raising=False,
        )
        update = make_update(SemverTier.PATCH)

        results = process_findings(
            [update],
            project_config,
            flow="resolve",
            on_failure="stop",
        )

        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].failed_phase is None
        assert update.update_status == UpdateStatus.READY
        mock_resolve_vcs["git_commit_all"].assert_not_called()


# -- process_vulns / process_updates --


class TestProcessVulnsLocal:
    def test_consolidates_and_processes(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        v1 = make_vuln(vuln_id="CVE-0001", pkg_name="requests", fixed_version="2.31.0")
        v2 = make_vuln(vuln_id="CVE-0002", pkg_name="requests", fixed_version="2.32.4")

        results = process_vulns([v1, v2], project_config, flow="update")

        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].kind == "vuln"


class TestProcessUpdatesLocal:
    def test_sorts_by_risk(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        updates = [
            make_update(SemverTier.MAJOR),
            make_update(SemverTier.PATCH),
        ]

        results = process_updates(updates, project_config, flow="update")

        assert len(results) == 2
        assert results[0].pkg_name == "pkg-a"
        assert results[1].pkg_name == "pkg-c"
