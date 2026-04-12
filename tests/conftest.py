from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.models.scan import (
    MaintenanceFlow,
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
)
from maintenance_man.updater import UpdateResult

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def mm_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect MM_HOME to a temp directory (not yet created on disk)."""
    home = tmp_path / ".mm"
    monkeypatch.setattr("maintenance_man.config.MM_HOME", home)
    return home


@pytest.fixture()
def mm_home_with_projects(mm_home: Path) -> Path:
    """MM_HOME populated with directory structure and real project config."""
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "scan-results").mkdir(exist_ok=True)
    (mm_home / "worktrees").mkdir(exist_ok=True)

    vuln_path = FIXTURES_DIR / "vulnerable-project"
    clean_path = FIXTURES_DIR / "clean-project"

    config_text = f"""\
[defaults]
min_version_age_days = 7

[projects.vulnerable]
path = "{vuln_path}"
package_manager = "uv"
test_unit = "uv run pytest"

[projects.clean]
path = "{clean_path}"
package_manager = "uv"
test_unit = "uv run pytest"

[projects.outdated]
path = "{clean_path}"
package_manager = "bun"
test_unit = "bun test"

[projects.no-tests]
path = "{clean_path}"
package_manager = "uv"

[projects.deployable]
path = "{clean_path}"
package_manager = "bun"
build_command = "scripts/build.sh"
deploy_command = "scripts/deploy.sh"
test_unit = "bun test"

[projects.deploy-only]
path = "{clean_path}"
package_manager = "uv"
deploy_command = "scripts/deploy.sh"
test_unit = "uv run pytest"

[projects.no-deploy]
path = "{clean_path}"
package_manager = "uv"
test_unit = "uv run pytest"
"""
    (mm_home / "config.toml").write_text(config_text)
    return mm_home


@pytest.fixture()
def scan_results_dir(mm_home: Path) -> Path:
    """MM_HOME with scan-results directory (no config file needed)."""
    mm_home.mkdir(parents=True, exist_ok=True)
    d = mm_home / "scan-results"
    d.mkdir(exist_ok=True)
    return d


@pytest.fixture()
def make_scan_result():
    def _make(
        *,
        vuln_status: UpdateStatus | None = None,
        vuln_flow: MaintenanceFlow | str | None = None,
        update_status: UpdateStatus | None = None,
        update_flow: MaintenanceFlow | str | None = None,
        include_vuln: bool = True,
        include_update: bool = True,
    ) -> ScanResult:
        vulnerabilities = []
        if include_vuln:
            vulnerabilities.append(
                VulnFinding(
                    vuln_id="CVE-2024-0001",
                    pkg_name="some-pkg",
                    installed_version="1.0.0",
                    fixed_version="1.0.1",
                    severity=Severity.HIGH,
                    title="Test vuln",
                    description="desc",
                    status="fixed",
                    update_status=vuln_status,
                    flow=vuln_flow,
                )
            )

        updates = []
        if include_update:
            updates.append(
                UpdateFinding(
                    pkg_name="pkg-a",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    semver_tier=SemverTier.PATCH,
                    update_status=update_status,
                    flow=update_flow,
                )
            )

        return ScanResult(
            project="vulnerable",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="tests/fixtures/vulnerable-project",
            vulnerabilities=vulnerabilities,
            updates=updates,
        )

    return _make


@pytest.fixture()
def make_failed_resolve_scan_result():
    def _make() -> ScanResult:
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
                    title="Test vuln",
                    description="desc",
                    status="fixed",
                    update_status=UpdateStatus.FAILED,
                    flow=MaintenanceFlow.RESOLVE,
                ),
                VulnFinding(
                    vuln_id="CVE-2024-0002",
                    pkg_name="other-pkg",
                    installed_version="1.0.0",
                    fixed_version="1.0.2",
                    severity=Severity.MEDIUM,
                    title="Other vuln",
                    description="desc",
                    status="fixed",
                    update_status=UpdateStatus.COMPLETED,
                ),
            ],
            updates=[
                UpdateFinding(
                    pkg_name="pkg-a",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    semver_tier=SemverTier.PATCH,
                    update_status=UpdateStatus.FAILED,
                    flow=MaintenanceFlow.RESOLVE,
                ),
                UpdateFinding(
                    pkg_name="pkg-b",
                    installed_version="1.0.0",
                    latest_version="1.1.0",
                    semver_tier=SemverTier.MINOR,
                    update_status=UpdateStatus.COMPLETED,
                ),
            ],
        )

    return _make


@pytest.fixture()
def make_pass_side_effect():
    def _make(
        *,
        flow: MaintenanceFlow,
        kind: str | None = None,
    ):
        def _result_kind(finding: UpdateFinding | VulnFinding) -> str:
            return "update" if isinstance(finding, UpdateFinding) else "vuln"

        def _inner(findings, *_args, **_kwargs):
            for finding in findings:
                finding.update_status = UpdateStatus.READY
                finding.failed_phase = None
                finding.flow = flow
            return [
                UpdateResult(
                    pkg_name=f.pkg_name,
                    kind=kind or _result_kind(f),
                    passed=True,
                )
                for f in findings
            ]

        return _inner

    return _make


@pytest.fixture()
def mock_update_cli_deps(
    monkeypatch: pytest.MonkeyPatch,
    make_scan_result,
    make_pass_side_effect,
):
    monkeypatch.setattr("maintenance_man.cli.check_repo_clean", lambda p: None)
    monkeypatch.setattr("maintenance_man.cli.ensure_on_main", lambda p: True)
    monkeypatch.setattr("maintenance_man.cli.sync_graphite", lambda p: True)
    monkeypatch.setattr(
        "maintenance_man.cli.create_worktree",
        lambda p, wt, branch="main", detach=True: True,
    )
    monkeypatch.setattr("maintenance_man.cli.remove_worktree", lambda p, wt: None)
    monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: False)
    monkeypatch.setattr("maintenance_man.cli.git_create_branch", lambda b, p: True)
    monkeypatch.setattr("maintenance_man.cli.git_checkout", lambda b, p: True)
    monkeypatch.setattr("maintenance_man.cli.git_merge_fast_forward", lambda b, p: True)
    monkeypatch.setattr("maintenance_man.cli.git_delete_branch", lambda b, p: True)
    monkeypatch.setattr(
        "maintenance_man.cli.git_replace_branch", lambda b, base, p: True
    )
    monkeypatch.setattr(
        "maintenance_man.cli.load_scan_results",
        lambda name, d: make_scan_result(),
    )

    mock_vulns = MagicMock(
        side_effect=make_pass_side_effect(
            flow=MaintenanceFlow.UPDATE,
            kind="vuln",
        )
    )
    mock_updates = MagicMock(
        side_effect=make_pass_side_effect(
            flow=MaintenanceFlow.UPDATE,
            kind="update",
        )
    )
    monkeypatch.setattr("maintenance_man.cli.process_vulns_local", mock_vulns)
    monkeypatch.setattr("maintenance_man.cli.process_updates_local", mock_updates)
    monkeypatch.setattr(
        "maintenance_man.cli.remove_completed_findings", lambda scan: None
    )
    monkeypatch.setattr("maintenance_man.cli.save_scan_results", lambda *args: None)
    return {
        "process_vulns_local": mock_vulns,
        "process_updates_local": mock_updates,
    }


@pytest.fixture()
def mock_resolve_cli_deps(
    monkeypatch: pytest.MonkeyPatch,
    make_failed_resolve_scan_result,
    make_pass_side_effect,
):
    monkeypatch.setattr("maintenance_man.cli.check_graphite_available", lambda: None)
    monkeypatch.setattr("maintenance_man.cli.sync_graphite", lambda p: True)
    monkeypatch.setattr("maintenance_man.cli.check_repo_clean", lambda p: None)
    monkeypatch.setattr("maintenance_man.cli.ensure_on_main", lambda p: True)
    monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: False)
    monkeypatch.setattr("maintenance_man.cli.git_create_branch", lambda b, p: True)
    monkeypatch.setattr("maintenance_man.cli.git_checkout", lambda b, p: True)
    monkeypatch.setattr(
        "maintenance_man.cli.git_replace_branch", lambda b, base, p: True
    )
    monkeypatch.setattr(
        "maintenance_man.cli.get_current_branch",
        lambda p: "mm/resolve-dependencies",
    )
    monkeypatch.setattr(
        "maintenance_man.cli.run_test_phases",
        lambda cfg, p: (True, None),
    )
    mock_process = MagicMock(
        side_effect=make_pass_side_effect(flow=MaintenanceFlow.RESOLVE)
    )
    monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)
    monkeypatch.setattr(
        "maintenance_man.cli.submit_stack",
        MagicMock(return_value=(True, "submitted")),
    )
    monkeypatch.setattr(
        "maintenance_man.cli.remove_completed_findings", lambda scan: None
    )
    monkeypatch.setattr("maintenance_man.cli.save_scan_results", lambda *args: None)
    monkeypatch.setattr(
        "maintenance_man.cli.load_scan_results",
        lambda name, d: make_failed_resolve_scan_result(),
    )
    return {"process_findings": mock_process}
