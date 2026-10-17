"""Pytest fixture registration and per-test environment isolation."""

from pathlib import Path

import pytest

from maintenance_man import output
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    Workflow,
)
from tests.support.cli import CliDeps, cli_deps
from tests.support.gradle import GRADLE_FIXTURES
from tests.support.projects import FIXTURES_DIR, write_config
from tests.support.repository import (
    RepositoryCase,
    fake_repository_case,
    real_repository_case,
)


@pytest.fixture(autouse=True)
def _plain_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts in pipe mode at 80 columns with no colour overrides."""
    for name in ("FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setenv("TERM", "dumb")
    output.reset_invocation_output(verbose=False)


@pytest.fixture(autouse=True)
def _tools_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve CLI and scanner tool requirements without the host PATH."""

    def found(name: str, hint: str) -> Path:
        return Path("/usr/bin") / name

    monkeypatch.setattr("maintenance_man.vcs_workflow.require_tool", found)
    monkeypatch.setattr("maintenance_man.scanner.require_tool", found)


_GRADLEW_STUB = "#!/bin/sh\nexit 0\n"


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
    results_dir = mm_home / "scan-results"
    results_dir.mkdir(exist_ok=True)
    return results_dir


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


@pytest.fixture(params=["fake", pytest.param("real", marks=pytest.mark.integration)])
def repository_case(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> RepositoryCase:
    return (
        fake_repository_case(tmp_path)
        if request.param == "fake"
        else real_repository_case(tmp_path, monkeypatch)
    )
