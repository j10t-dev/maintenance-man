import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from maintenance_man.gradle import (
    GRADLE_INVENTORY_BOM_RELPATH,
    GRADLE_INVENTORY_MARKER_RELPATH,
    GRADLE_INVENTORY_RELPATH,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
)


@pytest.fixture(autouse=True)
def _tools_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve CLI and scanner tool requirements without the host PATH."""

    def found(name: str, hint: str) -> Path:
        return Path("/usr/bin") / name

    monkeypatch.setattr("maintenance_man.cli.require_tool", found)
    monkeypatch.setattr("maintenance_man.scanner.require_tool", found)


FIXTURES_DIR = Path(__file__).parent / "fixtures"
GRADLE_FIXTURES = FIXTURES_DIR / "gradle"

_GRADLEW_STUB = "#!/bin/sh\nexit 0\n"

FIXTURE = GRADLE_FIXTURES / "resolution" / "empty.json"


def report_payload():
    return json.loads(FIXTURE.read_text())


def fixture_runner(root, args, *, label):
    assert args[0] == "mmGradleReport"
    assert "--rerun-tasks" in args and "--no-build-cache" in args
    owned = root / GRADLE_INVENTORY_RELPATH
    assert (root / GRADLE_INVENTORY_MARKER_RELPATH).is_file()
    assert (owned / "gradle-report.gradle").read_text().startswith("import ")
    (root / GRADLE_INVENTORY_BOM_RELPATH).write_text(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"group":"g","name":"a","version":"1.0","purl":"pkg:maven/g/a@1.0"}]}'
    )
    value = report_payload()
    value["scopes"][0]["components"].append(
        {
            "id": "a",
            "kind": "module",
            "module": {"group": "g", "artifact": "a", "version": "1.0"},
            "variants": ["runtime"],
        }
    )
    value["scopes"][0]["edges"].append(
        {"source": "root", "target": "a", "requested": "g:a:1.0", "constraint": False}
    )
    value["catalogue_digest"] = hashlib.sha256(
        (root / "gradle/libs.versions.toml").read_bytes()
    ).hexdigest()
    (owned / "report.json").write_text(json.dumps(value))
    return subprocess.CompletedProcess(args, 0, "", "")


def make_vuln(**overrides: Any) -> VulnFinding:
    defaults = {
        "vuln_id": "CVE-2024-0001",
        "pkg_name": "some-pkg",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
        "severity": Severity.HIGH,
        "title": "Test vuln",
        "description": "desc",
        "status": "fixed",
    }
    return VulnFinding(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_update(**overrides: Any) -> UpdateFinding:
    defaults = {
        "pkg_name": "pkg-a",
        "installed_version": "1.0.0",
        "latest_version": "1.0.1",
        "semver_tier": SemverTier.PATCH,
    }
    return UpdateFinding(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_scan_result(
    vulns: list[VulnFinding] | None = None,
    updates: list[UpdateFinding] | None = None,
) -> ScanResult:
    return ScanResult(
        project="vulnerable",
        scanned_at=datetime.now(tz=UTC),
        trivy_target="tests/fixtures/vulnerable-project",
        vulnerabilities=vulns if vulns is not None else [make_vuln()],
        updates=updates if updates is not None else [make_update()],
    )


@pytest.fixture()
def mm_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect MM_HOME to a temp directory (not yet created on disk)."""
    home = tmp_path / ".mm"
    monkeypatch.setattr("maintenance_man.paths.MM_HOME", home)
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
    monkeypatch.setattr(
        "maintenance_man.cli.refresh_working_copy_from_main", lambda p: True
    )
    monkeypatch.setattr("maintenance_man.cli.edit_new_change", lambda p, r: True)
    return state


def make_gradle_member(**overrides: Any) -> GradleMember:
    defaults = {
        "kind": "library",
        "alias": "room-runtime",
        "coordinate": "androidx.room:room-runtime",
        "installed_version": "2.8.4",
    }
    return GradleMember(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_gradle_target(**overrides: Any) -> GradleUpdateTarget:
    defaults = {
        "version_ref": "room",
        "members": [
            make_gradle_member(
                alias="room-runtime", coordinate="androidx.room:room-runtime"
            ),
            make_gradle_member(
                alias="room-compiler", coordinate="androidx.room:room-compiler"
            ),
            make_gradle_member(
                alias="room-testing", coordinate="androidx.room:room-testing"
            ),
        ],
        "target_version": "2.8.5",
    }
    return GradleUpdateTarget(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


@pytest.fixture()
def gradle_project(tmp_path: Path) -> ProjectConfig:
    """A real on-disk Gradle project with an executable wrapper substitute."""
    root = tmp_path / "gradle-project"
    (root / "gradle").mkdir(parents=True)
    (root / "gradle" / "libs.versions.toml").write_text(
        (GRADLE_FIXTURES / "libs.versions.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    wrapper = root / "gradlew"
    wrapper.write_text(_GRADLEW_STUB, encoding="utf-8")
    wrapper.chmod(0o755)
    return ProjectConfig(
        path=root, package_manager="gradle", test_unit="./gradlew test"
    )


@pytest.fixture()
def mm_home_with_gradle(
    mm_home_with_projects: Path, gradle_project: ProjectConfig
) -> Path:
    config_path = mm_home_with_projects / "config.toml"
    config_path.write_text(
        config_path.read_text()
        + f'\n[projects.android]\npath = "{gradle_project.path}"\n'
        f'package_manager = "gradle"\ntest_unit = "./gradlew testDebugUnitTest"\n'
    )
    return mm_home_with_projects


def set_maven_dates(
    monkeypatch: pytest.MonkeyPatch, *, undated: set[str], days_old: int = 900
) -> None:
    """Substitute Maven Central lookups with controlled, relative publication dates.

    Coordinates in *undated* have no evidence at all; every other coordinate was
    published *days_old* days ago.  The date is relative to now so an age
    threshold in a test means what it says regardless of the current date.
    """
    published = datetime.now(UTC) - timedelta(days=days_old)
    monkeypatch.setattr(
        "maintenance_man.dependency_age._get_maven_publish_date",
        lambda pkg, version: None if pkg in undated else published,
    )
