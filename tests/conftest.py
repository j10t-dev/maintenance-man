from datetime import datetime, timezone
from pathlib import Path

import pytest

from maintenance_man.models.scan import (
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_vuln(**overrides: object) -> VulnFinding:
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


def make_update(**overrides: object) -> UpdateFinding:
    defaults = dict(
        pkg_name="pkg-a",
        installed_version="1.0.0",
        latest_version="1.0.1",
        semver_tier=SemverTier.PATCH,
    )
    return UpdateFinding(**(defaults | overrides))


def make_scan_result(
    vulns: list[VulnFinding] | None = None,
    updates: list[UpdateFinding] | None = None,
) -> ScanResult:
    return ScanResult(
        project="vulnerable",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="tests/fixtures/vulnerable-project",
        vulnerabilities=vulns if vulns is not None else [make_vuln()],
        updates=updates if updates is not None else [make_update()],
    )


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
    (mm_home / "workspaces").mkdir(exist_ok=True)

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
def mock_update_cli_deps(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Patch all update-CLI boundaries so tests focus on orchestration.

    Returns a dict holding the live scan_result object (key: ``scan_result``)
    so individual tests can mutate lifecycle state before ``app(...)`` runs.
    """
    scan_result = make_scan_result()
    state: dict[str, object] = {"scan_result": scan_result}

    monkeypatch.setattr("maintenance_man.cli.check_gh_available", lambda: None)
    monkeypatch.setattr("maintenance_man.cli.check_jj_available", lambda: None)
    monkeypatch.setattr(
        "maintenance_man.cli.load_scan_results",
        lambda name, d: state["scan_result"],
    )
    monkeypatch.setattr(
        "maintenance_man.cli.save_scan_results",
        lambda name, d, sr: None,
    )
    monkeypatch.setattr("maintenance_man.cli.prune_stale_bookmarks", lambda p: True)
    monkeypatch.setattr("maintenance_man.cli.ensure_main_bookmark", lambda p: True)
    monkeypatch.setattr(
        "maintenance_man.cli.create_workspace",
        lambda repo_path, project, revision: True,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.remove_workspace",
        lambda repo_path, project: None,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.workspace_path_for_project",
        lambda project: Path("/tmp/mm-workspaces") / project,
    )
    monkeypatch.setattr("maintenance_man.cli.bookmark_exists", lambda b, p: False)
    monkeypatch.setattr(
        "maintenance_man.cli.create_or_reset_bookmark",
        lambda b, p, r: True,
    )
    monkeypatch.setattr(
        "maintenance_man.cli.promote_bookmark_to_main",
        lambda p, b: True,
    )
    monkeypatch.setattr("maintenance_man.cli.delete_bookmark", lambda b, p: True)
    monkeypatch.setattr("maintenance_man.cli.edit_new_change", lambda p, r: True)
    return state
