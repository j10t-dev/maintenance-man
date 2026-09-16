import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GradleError,
    validate_gradle_target,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    Workflow,
)
from maintenance_man.updater import (
    GradleFinding,
    NoScanResultsError,
    _apply_update,
    _get_uv_update_command,
    consolidate_vulns,
    get_update_commands,
    highest_fix_version,
    load_scan_results,
    prepare_gradle_findings,
    process_findings,
    process_updates,
    process_vulns,
    remove_completed_findings,
    run_test_phases,
    save_scan_results,
    sort_updates_by_risk,
)
from maintenance_man.uv_dependencies import (
    UvDependencyError,
    UvDependencyLocation,
    get_uv_dependency_locations,
)
from tests.conftest import make_gradle_target, make_scan_result

# -- Factory helpers --


def make_vuln(**overrides: Any) -> VulnFinding:
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
    return VulnFinding(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_update(tier: SemverTier = SemverTier.PATCH, **overrides: Any) -> UpdateFinding:
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
    return UpdateFinding(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


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
    """Mock VCS and updater calls for single-bookmark update processing."""
    mocks = {}
    for name, default in [
        ("commit_current_change", True),
        ("current_change_has_changes", True),
        ("create_or_reset_bookmark", True),
        ("_apply_update", True),
        ("run_test_phases", (True, None)),
    ]:
        mock = MagicMock(return_value=default)
        monkeypatch.setattr(f"maintenance_man.updater.{name}", mock)
        mocks[name] = mock
    mock_discard = MagicMock()
    monkeypatch.setattr("maintenance_man.updater.discard_current_change", mock_discard)
    mocks["discard_current_change"] = mock_discard
    return mocks


@pytest.fixture()
def mock_resolve_vcs(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Mock VCS and updater calls for single-bookmark resolve processing."""
    mocks = {}
    for name, default in [
        ("commit_current_change", True),
        ("current_change_has_changes", True),
        ("create_or_reset_bookmark", True),
        ("_apply_update", True),
        ("run_test_phases", (True, None)),
        ("discard_current_change", None),
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

    def test_uv_optional_dependency_uses_lock_upgrade(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = []\n\n"
            "[project.optional-dependencies]\n"
            'cli = ["rich>=14.0"]\n',
            encoding="utf-8",
        )

        assert get_update_commands("uv", "rich", "14.3.3", tmp_path) == [
            ["uv", "lock", "--upgrade-package", "rich"]
        ]

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

    def test_uv_missing_declaration_uses_lock_upgrade(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests>=2.28"]\n', encoding="utf-8"
        )

        assert get_update_commands("uv", "urllib3", "2.7.0", tmp_path) == [
            ["uv", "lock", "--upgrade-package", "urllib3"]
        ]

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

    def test_uv_transitive_location_emits_lock_upgrade_command(self):
        assert _get_uv_update_command(
            "urllib3", "2.7.0", UvDependencyLocation(kind="transitive")
        ) == ["uv", "lock", "--upgrade-package", "urllib3"]


class TestGetUvDependencyLocations:
    def test_returns_transitive_when_package_not_in_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests>=2.28"]\n', encoding="utf-8"
        )

        result = get_uv_dependency_locations(tmp_path, "urllib3")
        assert result == [UvDependencyLocation(kind="transitive")]

    def test_returns_transitive_for_optional_dependency(self, tmp_path: Path):
        # project.optional-dependencies are intentionally not scanned for direct deps;
        # packages declared only there fall through to the transitive path.
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = []\n\n"
            "[project.optional-dependencies]\n"
            'cli = ["rich>=14.0"]\n',
            encoding="utf-8",
        )

        result = get_uv_dependency_locations(tmp_path, "rich")
        assert result == [UvDependencyLocation(kind="transitive")]


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
        consolidated[0].flow = Workflow.RESOLVE

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

        results = process_findings([update], project_config, flow=Workflow.UPDATE)

        assert len(results) == 1
        assert results[0].passed is True
        assert update.update_status == UpdateStatus.READY
        assert update.failed_phase is None
        assert update.flow == "update"

    def test_success_moves_update_bookmark_to_finished_commit(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        update = make_update(SemverTier.PATCH)

        process_findings([update], project_config, flow=Workflow.UPDATE)

        mock_local_vcs["commit_current_change"].assert_called_once()
        mock_local_vcs["create_or_reset_bookmark"].assert_called_once_with(
            "mm/update-dependencies",
            project_config.path,
            "@-",
        )

    def test_already_applied_sets_ready_and_update_flow(
        self,
        mock_local_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
    ):
        mock_has_changes = MagicMock(return_value=False)
        monkeypatch.setattr(
            "maintenance_man.updater.current_change_has_changes",
            mock_has_changes,
            raising=False,
        )
        update = make_update(SemverTier.PATCH)

        results = process_findings([update], project_config, flow=Workflow.UPDATE)

        assert len(results) == 1
        assert results[0].passed is True
        assert update.update_status == UpdateStatus.READY
        assert update.failed_phase is None
        assert update.flow == "update"
        mock_local_vcs["commit_current_change"].assert_not_called()

    def test_failure_sets_failed_and_active_flow(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_local_vcs["run_test_phases"].return_value = (False, "unit")
        update = make_update(SemverTier.PATCH)

        results = process_findings([update], project_config, flow=Workflow.UPDATE)

        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].failed_phase == "unit"
        assert update.update_status == UpdateStatus.FAILED
        assert update.failed_phase == "unit"
        assert update.flow == "update"

    def test_failure_discards_current_change_and_continues(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_local_vcs["run_test_phases"].return_value = (False, "unit")
        update = make_update(SemverTier.PATCH)

        results = process_findings([update], project_config, flow=Workflow.UPDATE)

        assert results[0].passed is False
        mock_local_vcs["discard_current_change"].assert_called_once_with(
            project_config.path
        )

    def test_all_pass(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]

        results = process_findings(updates, project_config, flow=Workflow.UPDATE)

        assert len(results) == 2
        assert all(r.passed for r in results)
        assert mock_local_vcs["_apply_update"].call_count == 2
        assert mock_local_vcs["run_test_phases"].call_count == 2
        assert mock_local_vcs["commit_current_change"].call_count == 2
        mock_local_vcs["discard_current_change"].assert_not_called()

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

        results = process_findings(updates, project_config, flow=Workflow.UPDATE)

        assert len(results) == 3
        assert results[0].passed is True
        assert results[1].passed is False
        assert results[2].passed is True
        mock_local_vcs["discard_current_change"].assert_called_once()
        assert mock_local_vcs["commit_current_change"].call_count == 2

    def test_apply_failure_continues(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_local_vcs["_apply_update"].side_effect = [False, True]
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]

        results = process_findings(updates, project_config, flow=Workflow.UPDATE)

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
            flow=Workflow.UPDATE,
        )

        assert len(results) == 1
        assert results[0].passed is True
        mock_local_vcs["run_test_phases"].assert_not_called()
        mock_local_vcs["commit_current_change"].assert_called_once()

    def test_commit_failure_marks_finding_failed_and_continues(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_local_vcs["commit_current_change"].side_effect = [False, True]
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]

        results = process_findings(updates, project_config, flow=Workflow.UPDATE)

        assert len(results) == 2
        assert results[0].passed is False
        assert results[0].failed_phase == "commit"
        assert results[1].passed is True

    def test_bookmark_advancement_failure_stops_after_successful_commit(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_local_vcs["create_or_reset_bookmark"].return_value = False
        updates = [
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]

        results = process_findings(updates, project_config, flow=Workflow.UPDATE)

        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].failed_phase == "commit"
        mock_local_vcs["commit_current_change"].assert_called_once()
        mock_local_vcs["_apply_update"].assert_called_once()
        mock_local_vcs["discard_current_change"].assert_not_called()

    def test_noop_update_without_changes_counts_as_pass(
        self,
        mock_local_vcs: dict[str, MagicMock],
        monkeypatch: pytest.MonkeyPatch,
        project_config: ProjectConfig,
    ):
        mock_local_vcs["commit_current_change"].return_value = False
        mock_has_changes = MagicMock(return_value=False)
        monkeypatch.setattr(
            "maintenance_man.updater.current_change_has_changes",
            mock_has_changes,
            raising=False,
        )
        update = make_update(SemverTier.PATCH)

        results = process_findings([update], project_config, flow=Workflow.UPDATE)

        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].failed_phase is None
        assert update.update_status == UpdateStatus.READY
        mock_local_vcs["commit_current_change"].assert_not_called()

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
            flow=Workflow.UPDATE,
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
        results = process_findings([], project_config, flow=Workflow.UPDATE)
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
            flow=Workflow.RESOLVE,
            on_failure="stop",
        )

        assert len(results) == 1
        assert results[0].passed is True
        assert update.update_status == UpdateStatus.READY
        assert update.failed_phase is None
        assert update.flow == "resolve"

    def test_success_moves_resolve_bookmark_to_finished_commit(
        self, mock_resolve_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        update = make_update(SemverTier.PATCH)

        process_findings(
            [update],
            project_config,
            flow=Workflow.RESOLVE,
            on_failure="stop",
        )

        mock_resolve_vcs["create_or_reset_bookmark"].assert_called_once_with(
            "mm/resolve-dependencies",
            project_config.path,
            "@-",
        )

    def test_failure_sets_failed_and_resolve_flow(
        self, mock_resolve_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        mock_resolve_vcs["_apply_update"].return_value = False
        update = make_update(SemverTier.PATCH)

        results = process_findings(
            [update],
            project_config,
            flow=Workflow.RESOLVE,
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
            flow=Workflow.RESOLVE,
            on_failure="stop",
        )

        assert len(results) == 2
        assert all(r.passed for r in results)
        assert mock_resolve_vcs["_apply_update"].call_count == 2
        assert mock_resolve_vcs["commit_current_change"].call_count == 2
        assert mock_resolve_vcs["run_test_phases"].call_count == 2

    def test_failure_stops_and_preserves_change_state(
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
            flow=Workflow.RESOLVE,
            on_failure="stop",
        )

        assert len(results) == 2
        assert results[0].passed is True
        assert results[1].passed is False
        assert results[1].failed_phase == "unit"
        assert mock_resolve_vcs["_apply_update"].call_count == 2
        assert mock_resolve_vcs["commit_current_change"].call_count == 1
        mock_resolve_vcs["discard_current_change"].assert_not_called()

    def test_no_test_config_treats_update_as_pass(
        self, mock_resolve_vcs: dict[str, MagicMock], tmp_path: Path
    ):
        project_config = ProjectConfig(path=tmp_path, package_manager="bun")

        results = process_findings(
            [make_update(SemverTier.PATCH)],
            project_config,
            flow=Workflow.RESOLVE,
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
            flow=Workflow.RESOLVE,
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
        mock_resolve_vcs["commit_current_change"].return_value = False
        mock_has_changes = MagicMock(return_value=False)
        monkeypatch.setattr(
            "maintenance_man.updater.current_change_has_changes",
            mock_has_changes,
            raising=False,
        )
        update = make_update(SemverTier.PATCH)

        results = process_findings(
            [update],
            project_config,
            flow=Workflow.RESOLVE,
            on_failure="stop",
        )

        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].failed_phase is None
        assert update.update_status == UpdateStatus.READY
        mock_resolve_vcs["commit_current_change"].assert_not_called()


# -- process_vulns / process_updates --


class TestProcessVulnsLocal:
    def test_consolidates_and_processes(
        self, mock_local_vcs: dict[str, MagicMock], project_config: ProjectConfig
    ):
        v1 = make_vuln(vuln_id="CVE-0001", pkg_name="requests", fixed_version="2.31.0")
        v2 = make_vuln(vuln_id="CVE-0002", pkg_name="requests", fixed_version="2.32.4")

        results = process_vulns([v1, v2], project_config, flow=Workflow.UPDATE)

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

        results = process_updates(updates, project_config, flow=Workflow.UPDATE)

        assert len(results) == 2
        assert results[0].pkg_name == "pkg-a"
        assert results[1].pkg_name == "pkg-c"


def _room_scan_result():
    """One advisory and two update findings, all owned by the 'room' reference."""
    target = make_gradle_target()
    return make_scan_result(
        vulns=[
            make_vuln(
                vuln_id="CVE-2026-6666",
                pkg_name="androidx.room:room-compiler",
                installed_version="2.8.4",
                fixed_version="2.8.5",
                gradle_target=target,
            )
        ],
        updates=[
            make_update(
                pkg_name="room",
                installed_version="2.8.4",
                latest_version="2.8.5",
                gradle_target=target,
            ),
            make_update(
                pkg_name="com.google.code.gson:gson",
                installed_version="2.11.0",
                latest_version="2.12.0",
                gradle_target=GradleUpdateTarget(
                    members=[
                        GradleMember(
                            kind="library",
                            alias="gson",
                            coordinate="com.google.code.gson:gson",
                            installed_version="2.11.0",
                        )
                    ],
                    target_version="2.12.0",
                ),
            ),
        ],
    )


@pytest.fixture()
def old_dates(monkeypatch):
    monkeypatch.setattr(
        "maintenance_man.dependency_age._get_maven_publish_date",
        lambda pkg, version: datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


class TestPrepareGradleFindings:
    def test_cross_kind_group_becomes_one_vulnerability_proxy(
        self, gradle_project, old_dates
    ):
        scan_result = _room_scan_result()

        prepared = prepare_gradle_findings(scan_result, gradle_project, 7)

        rooms = [p for p in prepared if p.pkg_name == "room"]
        assert len(prepared) == 2
        assert len(rooms) == 1
        assert rooms[0].kind == "vuln"
        assert rooms[0].target_version == "2.8.5"
        assert "CVE-2026-6666" in rooms[0].detail
        assert len(rooms[0]._originals) == 2

    def test_conflicting_target_versions_block_the_group(
        self, gradle_project, old_dates
    ):
        scan_result = _room_scan_result()
        scan_result.updates[0].gradle_target = make_gradle_target(
            target_version="2.9.0"
        )
        scan_result.updates[0].latest_version = "2.9.0"

        prepared = prepare_gradle_findings(scan_result, gradle_project, 7)

        assert [p.pkg_name for p in prepared] == ["com.google.code.gson:gson"]
        assert scan_result.vulnerabilities[0].gradle_block_kind == "conflict"
        assert scan_result.updates[0].gradle_block_kind == "conflict"
        assert (reason := scan_result.updates[0].blocked_reason) is not None
        assert "conflicting target versions" in reason

    def test_age_block_clears_on_a_later_invocation(self, gradle_project, monkeypatch):
        scan_result = _room_scan_result()
        scan_result.updates[0].blocked_reason = "was too young"
        scan_result.updates[0].gradle_block_kind = "age"
        monkeypatch.setattr(
            "maintenance_man.dependency_age._get_maven_publish_date",
            lambda pkg, version: datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

        prepared = prepare_gradle_findings(scan_result, gradle_project, 7)

        assert "room" in {p.pkg_name for p in prepared}
        assert scan_result.updates[0].blocked_reason is None
        assert scan_result.updates[0].gradle_block_kind is None

    def test_structural_block_survives_without_a_fresh_scan(
        self, gradle_project, old_dates
    ):
        scan_result = _room_scan_result()
        scan_result.updates[1].gradle_target = None
        scan_result.updates[1].blocked_reason = "rich version"
        scan_result.updates[1].gradle_block_kind = "mapping"

        prepared = prepare_gradle_findings(scan_result, gradle_project, 7)

        assert [p.pkg_name for p in prepared] == ["room"]
        assert scan_result.updates[1].gradle_block_kind == "mapping"

    def test_missing_target_metadata_asks_for_a_rescan(self, gradle_project, old_dates):
        scan_result = make_scan_result(
            vulns=[], updates=[make_update(pkg_name="room", gradle_target=None)]
        )

        assert prepare_gradle_findings(scan_result, gradle_project, 7) == []
        assert scan_result.updates[0].gradle_block_kind == "stale"
        assert (reason := scan_result.updates[0].blocked_reason) is not None
        assert "mm scan" in reason

    def test_completed_and_ready_groups_are_not_reapplied(
        self, gradle_project, old_dates
    ):
        scan_result = _room_scan_result()
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.updates[0].update_status = UpdateStatus.READY

        prepared = prepare_gradle_findings(scan_result, gradle_project, 7)

        assert [p.pkg_name for p in prepared] == ["com.google.code.gson:gson"]

    def test_a_ready_group_on_an_applied_catalogue_is_not_marked_stale(
        self, gradle_project, old_dates
    ):
        catalogue = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        catalogue.write_text(
            catalogue.read_text(encoding="utf-8").replace(
                'room = "2.8.4"', 'room = "2.8.5"'
            ),
            encoding="utf-8",
        )
        scan_result = _room_scan_result()
        scan_result.vulnerabilities[0].update_status = UpdateStatus.READY
        scan_result.updates[0].update_status = UpdateStatus.READY

        prepared = prepare_gradle_findings(scan_result, gradle_project, 7)

        assert [p.pkg_name for p in prepared] == ["com.google.code.gson:gson"]
        assert scan_result.vulnerabilities[0].blocked_reason is None
        assert scan_result.updates[0].blocked_reason is None

    def test_inconsistent_lifecycle_within_a_group_is_stale(
        self, gradle_project, old_dates
    ):
        scan_result = _room_scan_result()
        scan_result.vulnerabilities[0].update_status = UpdateStatus.FAILED

        prepared = prepare_gradle_findings(scan_result, gradle_project, 7)

        assert [p.pkg_name for p in prepared] == ["com.google.code.gson:gson"]
        assert scan_result.updates[0].gradle_block_kind == "stale"

    def test_age_block_is_not_a_failed_status(self, gradle_project, monkeypatch):
        scan_result = _room_scan_result()
        monkeypatch.setattr(
            "maintenance_man.dependency_age._get_maven_publish_date",
            lambda pkg, version: None,
        )

        assert prepare_gradle_findings(scan_result, gradle_project, 7) == []
        for finding in (*scan_result.vulnerabilities, *scan_result.updates):
            assert finding.gradle_block_kind == "age"
            assert finding.update_status is None
            assert finding.failed_phase is None
            assert finding.flow is None


class TestProcessGradleFindings:
    def test_one_group_produces_one_apply_one_test_run_and_one_commit(
        self, gradle_project, old_dates, monkeypatch
    ):
        applies: list[GradleUpdateTarget] = []
        commits: list[str] = []
        tests: list[int] = []
        monkeypatch.setattr(
            "maintenance_man.updater.apply_gradle_update",
            lambda project, target: applies.append(target) or None,
        )
        monkeypatch.setattr(
            "maintenance_man.updater.run_test_phases",
            lambda cfg, path: (tests.append(1), (True, None))[1],
        )
        monkeypatch.setattr(
            "maintenance_man.updater.current_change_has_changes", lambda path: True
        )
        monkeypatch.setattr(
            "maintenance_man.updater.commit_current_change",
            lambda path, msg: commits.append(msg) or True,
        )
        monkeypatch.setattr(
            "maintenance_man.updater.create_or_reset_bookmark", lambda b, p, r: True
        )
        scan_result = _room_scan_result()
        prepared = [
            p
            for p in prepare_gradle_findings(scan_result, gradle_project, 7)
            if p.pkg_name == "room"
        ]

        results = process_findings(
            prepared, gradle_project, flow=Workflow.UPDATE, minimum_age_days=7
        )

        assert len(applies) == 1
        assert [m.alias for m in applies[0].members] == [
            "room-runtime",
            "room-compiler",
            "room-testing",
        ]
        assert tests == [1]
        assert commits == ["fix: upgrade room 2.8.4 -> 2.8.5 for CVE-2026-6666"]
        assert [r.passed for r in results] == [True]
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.READY
        assert scan_result.updates[0].update_status == UpdateStatus.READY

    def test_a_block_found_before_mutation_never_tests_or_commits(
        self, gradle_project, monkeypatch
    ):
        monkeypatch.setattr(
            "maintenance_man.updater.apply_gradle_update",
            lambda project, target: pytest.fail("blocked work must not apply"),
        )
        monkeypatch.setattr(
            "maintenance_man.updater.run_test_phases",
            lambda cfg, path: pytest.fail("blocked work must not test"),
        )
        monkeypatch.setattr(
            "maintenance_man.updater.commit_current_change",
            lambda path, msg: pytest.fail("blocked work must not commit"),
        )
        monkeypatch.setattr(
            "maintenance_man.dependency_age._get_maven_publish_date",
            lambda pkg, version: None,
        )
        catalogue = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        before = catalogue.read_bytes()
        finding = GradleFinding(
            pkg_name="room",
            installed_version="2.8.4",
            target=make_gradle_target(),
            kind="update",
            _detail="minor",
            _originals=[
                make_update(pkg_name="room", gradle_target=make_gradle_target())
            ],
        )

        results = process_findings(
            [finding], gradle_project, flow=Workflow.UPDATE, minimum_age_days=7
        )

        assert catalogue.read_bytes() == before
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].failed_phase is None
        assert results[0].blocked_reason is not None
        assert "no Maven Central publication date" in results[0].blocked_reason
        assert finding.update_status is None
        assert finding._originals[0].gradle_block_kind == "age"

    def test_apply_error_fans_failure_out_to_every_original(
        self, gradle_project, old_dates, monkeypatch
    ):
        discarded: list[Path] = []

        def _boom(project, target):
            raise GradleError("./gradlew versionCatalogApplyUpdates failed (exit 1)")

        monkeypatch.setattr("maintenance_man.updater.apply_gradle_update", _boom)
        monkeypatch.setattr(
            "maintenance_man.updater.discard_current_change",
            lambda path: discarded.append(path) or True,
        )
        scan_result = _room_scan_result()
        prepared = [
            p
            for p in prepare_gradle_findings(scan_result, gradle_project, 7)
            if p.pkg_name == "room"
        ]

        results = process_findings(
            prepared, gradle_project, flow=Workflow.UPDATE, minimum_age_days=7
        )

        assert [r.failed_phase for r in results] == ["apply"]
        assert len(discarded) == 1
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.FAILED
        assert scan_result.updates[0].update_status == UpdateStatus.FAILED
        assert scan_result.updates[0].failed_phase == "apply"

    def test_resolve_preserves_the_change_on_apply_error(
        self, gradle_project, old_dates, monkeypatch
    ):
        monkeypatch.setattr(
            "maintenance_man.updater.apply_gradle_update",
            lambda project, target: (_ for _ in ()).throw(GradleError("boom")),
        )
        monkeypatch.setattr(
            "maintenance_man.updater.discard_current_change",
            lambda path: pytest.fail("resolve must preserve the change"),
        )
        scan_result = _room_scan_result()
        prepared = [
            p
            for p in prepare_gradle_findings(scan_result, gradle_project, 7)
            if p.pkg_name == "room"
        ]

        results = process_findings(
            prepared,
            gradle_project,
            flow=Workflow.RESOLVE,
            on_failure="stop",
            minimum_age_days=7,
        )

        assert [r.failed_phase for r in results] == ["apply"]


def test_get_update_commands_refuses_gradle(tmp_path):
    with pytest.raises(ValueError, match="Gradle"):
        get_update_commands("gradle", "room", "2.8.5", tmp_path)


def test_get_update_commands_refusal_records_a_failure_not_a_crash(tmp_path):
    """Unreachable by design; it must still degrade, not unwind the flow."""
    assert _apply_update("gradle", "room", "2.8.5", tmp_path) is False


def test_a_test_phase_timeout_is_recorded_as_a_failed_phase(
    project_config, monkeypatch
):
    def _timeout(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 600)

    monkeypatch.setattr(subprocess, "run", _timeout)

    assert run_test_phases(project_config, Path(project_config.path)) == (False, "unit")


def test_an_uncommitted_catalogue_edit_blocks_with_a_workspace_hint(
    gradle_project, tmp_path
):
    target = make_gradle_target()
    catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        catalogue.read_text(encoding="utf-8").replace(
            'room = "2.8.4"', 'room = "2.8.6"'
        ),
        encoding="utf-8",
    )

    block = validate_gradle_target(gradle_project, target)

    assert block is not None and block.kind == "stale"
    assert "update workspace" in block.reason


def test_historical_vulnerability_requires_recorded_metadata(gradle_project, old_dates):
    scan = _room_scan_result()
    scan.vulnerabilities[0].gradle_target = None
    prepare_gradle_findings(scan, gradle_project, 7)
    assert scan.vulnerabilities[0].gradle_block_kind == "stale"
    assert scan.vulnerabilities[0].blocked_reason is not None
    assert "mm scan" in scan.vulnerabilities[0].blocked_reason


def test_historical_vulnerability_drift_is_not_reconstructed(gradle_project, old_dates):
    scan = _room_scan_result()
    scan.vulnerabilities[0].gradle_target = make_gradle_target()
    scan.updates = []
    catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        catalogue.read_text().replace('room = "2.8.4"', 'room = "2.8.9"')
    )
    assert prepare_gradle_findings(scan, gradle_project, 7) == []
    assert scan.vulnerabilities[0].gradle_block_kind == "stale"


def test_empty_historical_update_blocks_in_preparation(gradle_project, old_dates):
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(gradle_target=make_gradle_target(version_ref=None, members=[]))
        ],
    )
    assert prepare_gradle_findings(scan, gradle_project, 7) == []
    assert scan.updates[0].gradle_block_kind == "stale"


def test_shared_group_rejects_inconsistent_historical_members(
    gradle_project, old_dates
):
    scan = _room_scan_result()
    scan.updates[0].gradle_target = make_gradle_target(
        members=make_gradle_target().members[:1]
    )
    assert [p.pkg_name for p in prepare_gradle_findings(scan, gradle_project, 7)] == [
        "com.google.code.gson:gson"
    ]
    assert scan.updates[0].gradle_block_kind == "stale"
    assert scan.vulnerabilities[0].gradle_block_kind == "stale"


def test_repeated_preparation_preserves_cross_kind_conflict(gradle_project, old_dates):
    scan = _room_scan_result()
    scan.updates[0].gradle_target = make_gradle_target(target_version="2.9.0")
    scan.updates[0].latest_version = "2.9.0"
    for _ in range(2):
        assert [
            p.pkg_name for p in prepare_gradle_findings(scan, gradle_project, 7)
        ] == ["com.google.code.gson:gson"]
        for original in (scan.vulnerabilities[0], scan.updates[0]):
            assert original.gradle_block_kind == "conflict"
            assert original.blocked_reason is not None
            assert "conflicting target versions" in original.blocked_reason


def test_three_room_originals_use_real_adapter_and_one_test_sequence(
    gradle_project, old_dates, monkeypatch
):
    scan = _room_scan_result()
    scan.updates[1] = make_update(
        pkg_name="room",
        installed_version="2.8.4",
        latest_version="2.8.5",
        gradle_target=make_gradle_target(),
    )
    root = Path(gradle_project.path)
    catalogue = root / GRADLE_CATALOGUE_RELPATH
    calls: list[list[str]] = []
    reports: list[str] = []
    commits: list[str] = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        assert Path(kwargs["cwd"]) == root
        if cmd[1] == "versionCatalogApplyUpdates":
            from maintenance_man.gradle import GRADLE_UPDATE_REPORT_RELPATH

            reports.append((root / GRADLE_UPDATE_REPORT_RELPATH).read_text())
            catalogue.write_text(
                catalogue.read_text().replace('room = "2.8.4"', 'room = "2.8.5"')
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(
        "maintenance_man.updater.current_change_has_changes", lambda path: True
    )
    monkeypatch.setattr(
        "maintenance_man.updater.commit_current_change",
        lambda path, msg: commits.append(msg) or True,
    )
    monkeypatch.setattr(
        "maintenance_man.updater.create_or_reset_bookmark", lambda b, p, r: True
    )
    prepared = prepare_gradle_findings(scan, gradle_project, 7)
    assert len(prepared) == 1
    assert len(prepared[0]._originals) == 3
    results = process_findings(
        prepared, gradle_project, flow=Workflow.UPDATE, minimum_age_days=7
    )
    assert [cmd[1:] for cmd in calls] == [
        ["versionCatalogApplyUpdates", "--no-daemon", "--console=plain"],
        ["test"],
    ]
    assert len(reports) == 1
    assert reports[0].splitlines() == [
        "[libraries]",
        '"room-runtime" = "androidx.room:room-runtime:2.8.5"',
        '"room-compiler" = "androidx.room:room-compiler:2.8.5"',
        '"room-testing" = "androidx.room:room-testing:2.8.5"',
    ]
    assert 'room = "2.8.5"' in catalogue.read_text()
    assert commits == ["fix: upgrade room 2.8.4 -> 2.8.5 for CVE-2026-6666"]
    assert [r.passed for r in results] == [True]
    for original in (*scan.vulnerabilities, *scan.updates):
        assert original.update_status == UpdateStatus.READY
        assert original.flow == Workflow.UPDATE
        assert original.failed_phase is None


@pytest.mark.parametrize(
    "target,expected", [(None, "stale"), (make_gradle_target(), "mapping")]
)
def test_nonactionable_gradle_advisory_is_rechecked(gradle_project, target, expected):
    finding = make_vuln(
        pkg_name="androidx.room:room-runtime",
        installed_version="2.8.4",
        fixed_version=None,
        gradle_target=target,
    )
    scan = make_scan_result(vulns=[finding], updates=[])
    assert prepare_gradle_findings(scan, gradle_project, 0) == []
    assert finding.gradle_block_kind == expected
    assert finding.blocked_reason


@pytest.mark.parametrize(
    "fixture",
    ["updates-conflict.toml", "updates-incomplete.toml", "updates-unmatched.toml"],
)
def test_real_discovery_structural_block_withholds_cross_kind_group(
    gradle_project, old_dates, monkeypatch, fixture
):
    from maintenance_man.gradle import (
        GRADLE_UPDATE_REPORT_RELPATH,
        discover_gradle_updates,
    )
    from tests.conftest import GRADLE_FIXTURES

    def run(cmd, **kwargs):
        (Path(kwargs["cwd"]) / GRADLE_UPDATE_REPORT_RELPATH).write_bytes(
            (GRADLE_FIXTURES / fixture).read_bytes()
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    scan = _room_scan_result()
    independent = scan.updates[1]
    scan.updates = discover_gradle_updates(gradle_project) + [independent]
    for _ in range(2):
        assert [
            p.pkg_name for p in prepare_gradle_findings(scan, gradle_project, 7)
        ] == ["com.google.code.gson:gson"]
        assert scan.vulnerabilities[0].gradle_block_kind == (
            "mapping" if fixture == "updates-unmatched.toml" else "conflict"
        )
        assert scan.vulnerabilities[0].blocked_reason


def test_known_structural_ref_survives_malformed_recorded_members(
    gradle_project, old_dates
):
    scan = _room_scan_result()
    scan.updates[0].gradle_block_kind = "conflict"
    scan.updates[0].blocked_reason = "incomplete proposal requires fresh scan"
    scan.updates[0].gradle_target.members = []
    assert [p.pkg_name for p in prepare_gradle_findings(scan, gradle_project, 7)] == [
        "com.google.code.gson:gson"
    ]
    assert scan.vulnerabilities[0].gradle_block_kind == "conflict"
    assert scan.updates[0].blocked_reason == "incomplete proposal requires fresh scan"


@pytest.mark.parametrize("inventory_state", ["marked", "unmarked", "cleanup-error"])
def test_real_application_reclaims_owned_inventory_before_tests_and_commit(
    gradle_project, old_dates, monkeypatch, inventory_state
):
    from maintenance_man.gradle import (
        GRADLE_INVENTORY_MARKER_RELPATH,
        GRADLE_INVENTORY_RELPATH,
        GRADLE_REPORT_MARKER_RELPATH,
        GRADLE_UPDATE_REPORT_RELPATH,
    )

    root = Path(gradle_project.path)
    catalogue = root / GRADLE_CATALOGUE_RELPATH
    inventory = root / GRADLE_INVENTORY_RELPATH
    inventory.mkdir()
    (inventory / "bom.json").write_bytes(b"inventory bytes")
    if inventory_state != "unmarked":
        (root / GRADLE_INVENTORY_MARKER_RELPATH).write_bytes(b"")
    (root / GRADLE_UPDATE_REPORT_RELPATH).write_bytes(b"leftover generated report")
    (root / GRADLE_REPORT_MARKER_RELPATH).write_bytes(b"")
    scan = _room_scan_result()
    scan.updates = scan.updates[:1]
    effects = []
    commands = []

    def clear():
        assert not inventory.exists()
        assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
        assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()

    def run(cmd, **kwargs):
        assert cmd[1] == "versionCatalogApplyUpdates"
        assert not inventory.exists()
        commands.append(cmd)
        catalogue.write_text(
            catalogue.read_text().replace('room = "2.8.4"', 'room = "2.8.5"')
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def tests(*args):
        clear()
        effects.append("tests")
        return True, None

    def dirty(*args):
        clear()
        effects.append("dirty")
        return True

    def commit(*args):
        clear()
        effects.append("commit")
        return True

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("maintenance_man.updater.run_test_phases", tests)
    monkeypatch.setattr("maintenance_man.updater.current_change_has_changes", dirty)
    monkeypatch.setattr("maintenance_man.updater.commit_current_change", commit)
    monkeypatch.setattr(
        "maintenance_man.updater.create_or_reset_bookmark", lambda *args: True
    )
    monkeypatch.setattr(
        "maintenance_man.updater.discard_current_change",
        lambda *args: pytest.fail("stop-on-failure must not discard"),
    )
    if inventory_state == "cleanup-error":

        def fail(*args, **kwargs):
            raise PermissionError("cannot reclaim inventory")

        monkeypatch.setattr("maintenance_man.gradle.shutil.rmtree", fail)
    prepared = prepare_gradle_findings(scan, gradle_project, 7)
    results = process_findings(
        prepared,
        gradle_project,
        flow=Workflow.RESOLVE,
        on_failure="stop",
        minimum_age_days=7,
    )
    if inventory_state == "marked":
        assert [r.passed for r in results] == [True]
        assert effects == ["tests", "dirty", "commit"]
        assert len(commands) == 1
        clear()
    else:
        assert [r.passed for r in results] == [False]
        assert results[0].failed_phase == "apply"
        assert commands == []
        assert effects == []
        assert (inventory / "bom.json").read_bytes() == b"inventory bytes"
        assert 'room = "2.8.4"' in catalogue.read_text()


@pytest.mark.parametrize("complete", [False, True])
def test_real_same_alias_library_plugin_proposals_withhold_cross_kind_group_on_retry(
    gradle_project, old_dates, monkeypatch, complete
):
    from maintenance_man.gradle import (
        GRADLE_UPDATE_REPORT_RELPATH,
        discover_gradle_updates,
        resolve_gradle_vulnerability_target,
    )

    root = Path(gradle_project.path)
    (root / GRADLE_CATALOGUE_RELPATH).write_text(
        '[versions]\nshared = "1.0.0"\n'
        '[libraries]\nsame = { module = "org.example:library", '
        'version.ref = "shared" }\n'
        '[plugins]\nsame = { id = "org.example.plugin", version.ref = "shared" }\n'
    )
    report = '[libraries]\nsame = "org.example:library:1.0.1"\n'
    if complete:
        report += '[plugins]\nsame = "org.example.plugin:1.0.1"\n'

    def run(cmd, **kwargs):
        assert cmd[1] == "versionCatalogUpdate"
        (Path(kwargs["cwd"]) / GRADLE_UPDATE_REPORT_RELPATH).write_text(report)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    vuln = make_vuln(
        pkg_name="org.example:library", installed_version="1.0.0", fixed_version="1.0.1"
    )
    target = resolve_gradle_vulnerability_target(gradle_project, vuln)
    assert isinstance(target, GradleUpdateTarget)
    vuln.gradle_target = target
    scan = make_scan_result(
        vulns=[vuln], updates=discover_gradle_updates(gradle_project)
    )
    for _ in range(2):
        prepared = prepare_gradle_findings(scan, gradle_project, 7)
        if complete:
            assert len(prepared) == 1
            assert prepared[0].kind == "vuln"
            assert prepared[0].target_version == "1.0.1"
        else:
            assert prepared == []
            assert all(
                f.gradle_block_kind == "conflict"
                for f in (*scan.vulnerabilities, *scan.updates)
            )
            assert all(
                f.blocked_reason and "plugin same" in f.blocked_reason
                for f in (*scan.vulnerabilities, *scan.updates)
            )


def _actual_inline_sibling_scan(project, *, malformed_first=False, defect="duplicate"):
    from maintenance_man.gradle import (
        build_update_findings,
        parse_catalogue,
        parse_update_report,
        resolve_gradle_vulnerability_target,
    )

    root = Path(project.path)
    catalogue = root / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        "[libraries]\n"
        'gson-json = { module = "com.google.code.gson:gson", version = "2.11.0" }\n'
        'other = { module = "org.example:other", version = "1.0.0" }\n'
        '[plugins]\ngson-json = { id = "org.example.plugin", version = "1.0.0" }\n'
    )
    report = root / "test-proposals.toml"
    report.write_text(
        '[libraries]\ngson-json = "com.google.code.gson:gson:2.12.0"\n'
        'other = "org.example:other:1.0.1"\n'
        '[plugins]\ngson-json = "org.example.plugin:1.0.1"\n'
    )
    updates = build_update_findings(
        parse_catalogue(catalogue), parse_update_report(report)
    )
    report.unlink()
    update = next(u for u in updates if u.pkg_name == "com.google.code.gson:gson")
    assert update.gradle_target is not None
    malformed = update.model_copy(deep=True)
    assert malformed.gradle_target is not None
    malformed.gradle_target.members[0].alias = "gson_json"
    if defect == "duplicate":
        malformed.gradle_target.members.append(
            malformed.gradle_target.members[0].model_copy(update={"alias": "gson.json"})
        )
    elif defect == "coordinate":
        malformed.gradle_target.members[0].coordinate = ""
    elif defect == "history":
        malformed.gradle_target.members[0].installed_version = ""
    elif defect == "version":
        malformed.gradle_target.target_version = ""
    vuln = make_vuln(
        pkg_name="com.google.code.gson:gson",
        installed_version="2.11.0",
        fixed_version="2.12.0",
    )
    target = resolve_gradle_vulnerability_target(project, vuln)
    assert isinstance(target, GradleUpdateTarget)
    vuln.gradle_target = target
    scan = make_scan_result(
        vulns=[vuln],
        updates=[malformed, *updates] if malformed_first else [*updates, malformed],
    )
    return scan


@pytest.mark.parametrize("malformed_first", [False, True])
def test_actual_inline_duplicate_member_withholds_all_cross_kind_siblings_on_retry(
    gradle_project, old_dates, malformed_first
):
    scan = _actual_inline_sibling_scan(gradle_project, malformed_first=malformed_first)
    for _ in range(2):
        prepared = prepare_gradle_findings(scan, gradle_project, 7)
        assert {p.pkg_name for p in prepared} == {
            "org.example:other",
            "org.example.plugin",
        }
        linked = [
            scan.vulnerabilities[0],
            *(u for u in scan.updates if u.pkg_name == "com.google.code.gson:gson"),
        ]
        assert all(f.gradle_block_kind == "stale" for f in linked)
        assert all(
            f.blocked_reason and "inline Gradle target" in f.blocked_reason
            for f in linked
        )


@pytest.mark.parametrize("defect", ["coordinate", "history", "version"])
def test_known_inline_identity_withholds_malformed_metadata_cross_kind_siblings(
    gradle_project, old_dates, defect
):
    scan = _actual_inline_sibling_scan(gradle_project, defect=defect)
    for _ in range(2):
        assert {
            p.pkg_name for p in prepare_gradle_findings(scan, gradle_project, 7)
        } == {"org.example:other", "org.example.plugin"}
        assert scan.vulnerabilities[0].gradle_block_kind == "stale"


@pytest.mark.parametrize("malformed_first", [False, True])
@pytest.mark.parametrize(
    "second_pkg, independent_pkg",
    [
        ("org.example.plugin", "org.example:other"),
        ("org.example:other", "org.example.plugin"),
    ],
)
def test_malformed_inline_multiple_known_keys_only_fan_out_as_blockers(
    gradle_project, old_dates, malformed_first, second_pkg, independent_pkg
):
    scan = _actual_inline_sibling_scan(gradle_project, malformed_first=malformed_first)
    malformed = next(
        u for u in scan.updates if u.gradle_target and len(u.gradle_target.members) == 2
    )
    second = next(u for u in scan.updates if u.pkg_name == second_pkg)
    malformed.gradle_target.members[1] = second.gradle_target.members[0].model_copy()
    for _ in range(2):
        assert [
            p.pkg_name for p in prepare_gradle_findings(scan, gradle_project, 7)
        ] == [independent_pkg]
        assert second.gradle_block_kind == "stale"
        assert scan.vulnerabilities[0].gradle_block_kind == "stale"


@pytest.mark.parametrize("aliases", [[], [""], ["unsafe\n"]])
def test_inline_unknown_alias_identity_never_invents_package_linkage(
    gradle_project, old_dates, aliases
):
    scan = _actual_inline_sibling_scan(gradle_project)
    malformed = scan.updates[-1]
    member = malformed.gradle_target.members[0]
    malformed.gradle_target.members = [
        member.model_copy(update={"alias": alias}) for alias in aliases
    ]
    prepared = prepare_gradle_findings(scan, gradle_project, 7)
    assert {p.pkg_name for p in prepared} == {
        "com.google.code.gson:gson",
        "org.example:other",
        "org.example.plugin",
    }
    assert malformed.gradle_block_kind == "stale"
    assert malformed.blocked_reason and "mm scan" in malformed.blocked_reason


@pytest.mark.parametrize("malformed_first", [False, True])
def test_inline_target_proxy_replacement_cannot_erase_recorded_blockers(
    gradle_project, malformed_first
):
    from maintenance_man.updater import gradle_groups_from_targets

    scan = _actual_inline_sibling_scan(gradle_project)
    malformed = scan.updates[-1]
    valid = scan.vulnerabilities[0]
    findings = [malformed, valid] if malformed_first else [valid, malformed]
    assert gradle_groups_from_targets(findings) == []
    assert malformed.gradle_block_kind == "stale"
    assert valid.gradle_block_kind == "stale"


def test_inline_sibling_lifecycle_inconsistency_blocks_group_and_preserves_failure(
    gradle_project, old_dates
):
    scan = _actual_inline_sibling_scan(gradle_project, defect="coordinate")
    malformed = scan.updates[-1]
    malformed.update_status = UpdateStatus.FAILED
    malformed.failed_phase = "unit"
    malformed.flow = Workflow.RESOLVE
    for _ in range(2):
        assert {
            p.pkg_name for p in prepare_gradle_findings(scan, gradle_project, 7)
        } == {"org.example:other", "org.example.plugin"}
        assert scan.vulnerabilities[0].gradle_block_kind == "stale"
        assert malformed.update_status == UpdateStatus.FAILED
        assert malformed.failed_phase == "unit"
        assert malformed.flow == Workflow.RESOLVE


@pytest.mark.parametrize("status", [None, UpdateStatus.READY, UpdateStatus.FAILED])
@pytest.mark.parametrize("mismatch_first", [False, True])
@pytest.mark.parametrize("preparation", [False, True])
def test_ordinary_update_installed_history_mismatch_blocks_recorded_group(
    gradle_project, old_dates, status, mismatch_first, preparation
):
    from maintenance_man.updater import gradle_groups_from_targets

    scan = _room_scan_result()
    scan.vulnerabilities = []
    valid = scan.updates[0]
    valid.update_status = status
    valid.flow = Workflow.RESOLVE if status else None
    valid.failed_phase = "unit" if status == UpdateStatus.FAILED else None
    mismatch = valid.model_copy(deep=True)
    mismatch.installed_version = "9.0.0"
    independent = scan.updates[1]
    scan.updates = (
        [mismatch, valid, independent]
        if mismatch_first
        else [valid, mismatch, independent]
    )
    groups = (
        prepare_gradle_findings(scan, gradle_project, 7)
        if preparation
        else gradle_groups_from_targets(scan.updates)
    )
    assert [g.pkg_name for g in groups] == ["com.google.code.gson:gson"]
    assert all(u.gradle_block_kind == "stale" for u in [valid, mismatch])
    assert all(
        u.blocked_reason and "installed" in u.blocked_reason for u in [valid, mismatch]
    )
    assert valid.update_status == status
    assert mismatch.update_status == status


@pytest.mark.parametrize("status", [None, UpdateStatus.READY, UpdateStatus.FAILED])
@pytest.mark.parametrize("preparation", [False, True])
def test_matching_ordinary_installed_history_preserves_valid_lifecycle_group(
    gradle_project, old_dates, status, preparation
):
    from maintenance_man.updater import gradle_groups_from_targets

    scan = _room_scan_result()
    scan.vulnerabilities = []
    valid = scan.updates[0]
    valid.update_status = status
    valid.flow = Workflow.RESOLVE if status else None
    valid.failed_phase = "unit" if status == UpdateStatus.FAILED else None
    scan.updates.insert(1, valid.model_copy(deep=True))
    groups = (
        prepare_gradle_findings(scan, gradle_project, 7)
        if preparation
        else gradle_groups_from_targets(scan.updates)
    )
    expected = (
        {"com.google.code.gson:gson"}
        if preparation and status == UpdateStatus.READY
        else {"room", "com.google.code.gson:gson"}
    )
    assert {g.pkg_name for g in groups} == expected
    assert all(u.gradle_block_kind is None for u in scan.updates)
    assert valid.update_status == status


@pytest.mark.parametrize("preparation", [False, True])
def test_actual_structural_block_inert_history_preserves_original_block_kind(
    gradle_project, old_dates, preparation
):
    from maintenance_man.gradle import (
        build_update_findings,
        parse_catalogue,
        parse_update_report,
    )
    from maintenance_man.updater import gradle_groups_from_targets
    from tests.conftest import GRADLE_FIXTURES

    scan = _room_scan_result()
    independent = scan.updates[1]
    scan.updates = build_update_findings(
        parse_catalogue(Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH),
        parse_update_report(GRADLE_FIXTURES / "updates-conflict.toml"),
    ) + [independent]
    blocked = next(u for u in scan.updates if u.pkg_name == "room")
    assert blocked.installed_version == "unknown"
    reason = blocked.blocked_reason
    groups = (
        prepare_gradle_findings(scan, gradle_project, 7)
        if preparation
        else gradle_groups_from_targets([*scan.vulnerabilities, *scan.updates])
    )
    assert [g.pkg_name for g in groups] == ["com.google.code.gson:gson"]
    assert blocked.gradle_block_kind == "conflict"
    assert blocked.blocked_reason == reason
    assert scan.vulnerabilities[0].gradle_block_kind == "conflict"


@pytest.mark.parametrize("preparation", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_vulnerability_only_mixed_shared_installed_history_blocks_before_proxy(
    gradle_project, old_dates, preparation, reverse
):
    from maintenance_man.updater import gradle_groups_from_targets

    scan = _room_scan_result()
    scan.updates = scan.updates[1:]
    vuln = scan.vulnerabilities[0]
    assert vuln.gradle_target is not None
    vuln.gradle_target.members[0].installed_version = "9.9.9"
    if reverse:
        vuln.gradle_target.members.reverse()
    vuln.update_status = UpdateStatus.FAILED
    vuln.failed_phase = "unit"
    vuln.flow = Workflow.RESOLVE
    for _ in range(2):
        groups = (
            prepare_gradle_findings(scan, gradle_project, 7)
            if preparation
            else gradle_groups_from_targets([*scan.vulnerabilities, *scan.updates])
        )
        assert [g.pkg_name for g in groups] == ["com.google.code.gson:gson"]
        assert vuln.gradle_block_kind == "stale"
        assert vuln.blocked_reason and "installed" in vuln.blocked_reason
        assert vuln.update_status == UpdateStatus.FAILED
        assert vuln.failed_phase == "unit"
        assert vuln.flow == Workflow.RESOLVE


@pytest.mark.parametrize("preparation", [False, True])
def test_structural_vulnerability_block_precedes_mixed_shared_history(
    gradle_project, old_dates, preparation
):
    from maintenance_man.updater import gradle_groups_from_targets

    scan = _room_scan_result()
    scan.updates = scan.updates[1:]
    vuln = scan.vulnerabilities[0]
    assert vuln.gradle_target is not None
    vuln.gradle_target.members[0].installed_version = "9.9.9"
    vuln.gradle_block_kind = "mapping"
    vuln.blocked_reason = "recorded mapping requires fresh scan"
    groups = (
        prepare_gradle_findings(scan, gradle_project, 7)
        if preparation
        else gradle_groups_from_targets([*scan.vulnerabilities, *scan.updates])
    )
    assert [g.pkg_name for g in groups] == ["com.google.code.gson:gson"]
    assert vuln.gradle_block_kind == "mapping"
    assert vuln.blocked_reason == "recorded mapping requires fresh scan"
