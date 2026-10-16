import dataclasses
import hashlib
import json
import subprocess
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from maintenance_man import cli
from maintenance_man.cli import app
from maintenance_man.config import load_config
from maintenance_man.gradle import (
    GRADLE_INVENTORY_BOM_RELPATH,
    GRADLE_INVENTORY_MARKER_RELPATH,
    GRADLE_INVENTORY_RELPATH,
)
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.config import MmConfig, ProjectConfig
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
from maintenance_man.package_managers import PackageManagerOps, package_manager_ops
from maintenance_man.process import ToolNotFoundError
from maintenance_man.storage import save_scan_results
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeFindingProcessor


@dataclasses.dataclass
class FakeClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


def completed(
    argv: str | list[str] | tuple[str, ...] = (),
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def make_project(path: Path, **overrides: Any) -> ProjectConfig:
    return ProjectConfig.model_validate(
        {"path": path, "package_manager": "uv"} | overrides
    )


def make_config(**overrides: Any) -> MmConfig:
    return MmConfig.model_validate({"projects": {}} | overrides)


def write_config(home: Path, text: str, *, filename: str = "config.toml") -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / filename
    path.write_text(text, encoding="utf-8")
    return path


def run_mm(*argv: str) -> int:
    try:
        result = app(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    assert result is None
    return 0


def configure_fake_vcs(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[FakeJjState, dict[str, Path]]:
    config_path = home / "config.toml"
    configured = load_config(config_path)
    replacements: dict[Path, Path] = {}
    state = FakeJjState()
    for project in configured.projects.values():
        if project.path in replacements:
            continue
        target = tmp_path / "repositories" / f"repo-{len(replacements)}"
        replacements[project.path] = target
        state.seed_repository(target, files={"dep.txt": "version=1\n"})
    text = config_path.read_text(encoding="utf-8")
    for source, target in replacements.items():
        text = text.replace(str(source), str(target))
    write_config(home, text)
    paths_by_name = {
        name: replacements[project.path]
        for name, project in configured.projects.items()
    }
    monkeypatch.setattr("maintenance_man.cli.make_vcs_services", state.services)
    return state, paths_by_name


_TERMINAL_OVERRIDES = ("FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE")


@pytest.fixture(autouse=True)
def _plain_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render CLI output as plain 80-column text whatever terminal runs the suite.

    The CLI console is built at import, during collection, so it has already
    read the invoking environment. Replace it with one that is never treated
    as a terminal, and clear the overrides so child processes are plain too.
    """
    for name in _TERMINAL_OVERRIDES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "console", Console(force_terminal=False, width=80))


@pytest.fixture(autouse=True)
def _tools_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve CLI and scanner tool requirements without the host PATH."""

    def found(name: str, hint: str) -> Path:
        return Path("/usr/bin") / name

    monkeypatch.setattr("maintenance_man.vcs_workflow.require_tool", found)
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
    return completed(tuple(args))


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


def make_update(tier: SemverTier = SemverTier.PATCH, **overrides: Any) -> UpdateFinding:
    name, installed, latest = {
        SemverTier.PATCH: ("pkg-a", "1.0.0", "1.0.1"),
        SemverTier.MINOR: ("pkg-b", "1.0.0", "1.1.0"),
        SemverTier.MAJOR: ("pkg-c", "1.0.0", "2.0.0"),
    }.get(tier, ("pkg-x", "1.0.0", "2.0.0"))
    defaults = {
        "pkg_name": name,
        "installed_version": installed,
        "latest_version": latest,
        "semver_tier": tier,
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


def make_activity(
    *, success: bool, commit_id: str | None
) -> dict[str, ProjectActivity]:
    return {
        "app": ProjectActivity(
            last_deploy=ActivityEvent(
                timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                success=success,
                branch="main",
                commit_id=commit_id,
            )
        )
    }


def missing_tool(tool: str) -> Callable[[str, str], Path]:
    def require(name: str, hint: str) -> Path:
        if name == tool:
            msg = f"{name} is not installed or not on PATH. {hint}"
            raise ToolNotFoundError(msg)
        return Path("/usr/bin") / name

    return require


def seed_project(
    tmp_path: Path,
    name: str,
    scan: ScanResult,
    *,
    test_unit: str | None = "pytest",
) -> tuple[FakeJjState, ProjectConfig]:
    project = make_project(tmp_path / name, test_unit=test_unit)
    state = FakeJjState()
    state.seed_repository(project.path, files={"dep.txt": "version=1\n"})
    state.register_files(
        project.path,
        "mm-fixture-some-pkg.txt",
        "mm-fixture-pkg-a.txt",
        "mm-fixture-pkg-b.txt",
    )
    scan.project = name
    save_scan_results(name, scan)
    return state, project


@pytest.fixture(autouse=True)
def _isolated_mm_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every test gets its own mm home; nothing reaches the real ~/.mm."""
    home = tmp_path / ".mm"
    monkeypatch.setattr("maintenance_man.paths.MM_HOME", home)
    return home


@pytest.fixture()
def mm_home(_isolated_mm_home: Path) -> Path:
    """Return the per-test MM_HOME without creating it."""
    return _isolated_mm_home


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
    write_config(mm_home, config_text)
    return mm_home


@pytest.fixture()
def scan_results_dir(mm_home: Path) -> Path:
    """MM_HOME with scan-results directory (no config file needed)."""
    mm_home.mkdir(parents=True, exist_ok=True)
    d = mm_home / "scan-results"
    d.mkdir(exist_ok=True)
    return d


@dataclasses.dataclass(frozen=True, slots=True)
class CliDeps:
    vcs_state: FakeJjState
    scan_result: ScanResult
    project_paths: dict[str, Path]
    save_scan: Callable[[], None]


def cli_deps(
    flow: Workflow,
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> CliDeps:
    if flow is Workflow.UPDATE:
        scan_result = make_scan_result()
        fixture_files = (
            "mm-fixture-some-pkg.txt",
            "mm-fixture-pkg-a.txt",
            "mm-fixture-pkg-b.txt",
            "mm-fixture-pkg-c.txt",
        )
        outcomes = {
            "some-pkg": (True, None),
            "pkg-a": (True, None),
            "pkg-b": (True, None),
            "pkg-c": (True, None),
        }
        processor_path = "maintenance_man.services.update.process_findings"
    else:
        scan_result = make_scan_result(
            vulns=[
                make_vuln(
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                    failed_phase="unit",
                ),
            ],
            updates=[
                make_update(
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                    failed_phase="unit",
                ),
            ],
        )
        fixture_files = ("mm-fixture-some-pkg.txt", "mm-fixture-pkg-a.txt")
        outcomes = {"some-pkg": (True, None), "pkg-a": (True, None)}
        processor_path = "maintenance_man.services.resolve.process_findings"

    vcs_state, project_paths = configure_fake_vcs(mm_home, tmp_path, monkeypatch)
    for project_path in set(project_paths.values()):
        vcs_state.register_files(project_path, *fixture_files)

    if flow is Workflow.RESOLVE:
        vcs_state.repository(project_paths["vulnerable"]).set_bookmark(
            bookmark="mm/resolve-dependencies", revision="@-"
        )

    def save_scan() -> None:
        save_scan_results("vulnerable", scan_result)

    save_scan()
    for project_name in project_paths:
        if project_name == "vulnerable":
            continue
        project_scan = deepcopy(scan_result)
        project_scan.project = project_name
        save_scan_results(project_name, project_scan)
    monkeypatch.setattr(processor_path, FakeFindingProcessor(outcomes))
    return CliDeps(vcs_state, scan_result, project_paths, save_scan)


@pytest.fixture()
def mock_update_cli_deps(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> CliDeps:
    return cli_deps(Workflow.UPDATE, mm_home_with_projects, tmp_path, monkeypatch)


@pytest.fixture()
def mock_resolve_cli_deps(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> CliDeps:
    return cli_deps(Workflow.RESOLVE, mm_home_with_projects, tmp_path, monkeypatch)


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
    write_config(
        mm_home_with_projects,
        config_path.read_text()
        + f'\n[projects.android]\npath = "{gradle_project.path}"\n'
        f'package_manager = "gradle"\ntest_unit = "./gradlew testDebugUnitTest"\n',
    )
    return mm_home_with_projects


def ops_with_outdated(
    outdated: Callable[[ProjectConfig], list[UpdateFinding]],
) -> Callable[[str], PackageManagerOps]:
    """Return a scanner table lookup whose entries use *outdated* instead."""

    def lookup(name: str) -> PackageManagerOps:
        return dataclasses.replace(package_manager_ops(name), outdated=outdated)

    return lookup
