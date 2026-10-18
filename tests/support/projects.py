"""Project configuration, saved scans and activity defaults for tests."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from maintenance_man.gradle import GRADLE_CATALOGUE_RELPATH
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.scan import (
    ScanResult,
)
from maintenance_man.storage import save_scan_results
from maintenance_man.vcs import JjRepository
from tests.support.findings import make_gradle_target, make_scan_result, make_update
from tests.support.repository import commit_to_main, copy_jj_repository, write_file


def make_project(path: Path, **overrides: Any) -> ProjectConfig:
    """Build a uv project; callers supply the settings their scenario exercises."""
    return ProjectConfig.model_validate(
        {"path": path, "package_manager": "uv"} | overrides
    )


def make_config(**overrides: Any) -> MmConfig:
    """Build an empty configuration unless the scenario supplies projects."""
    return MmConfig.model_validate({"projects": {}} | overrides)


def write_config(home: Path, text: str, *, filename: str = "config.toml") -> Path:
    """Write configuration text under the supplied test home."""
    home.mkdir(parents=True, exist_ok=True)
    path = home / filename
    path.write_text(text, encoding="utf-8")
    return path


def make_activity(
    *, success: bool, commit_id: str | None
) -> dict[str, ProjectActivity]:
    """Build one recorded deployment for the app project."""
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


def seed_project(
    tmp_path: Path,
    name: str,
    scan: ScanResult,
    *,
    test_unit: str | None = "pytest",
) -> tuple[JjRepository, ProjectConfig]:
    """Copy a jj repository and persist the supplied scan under its project name."""
    project = make_project(tmp_path / name, test_unit=test_unit)
    repo = copy_jj_repository(project.path)
    scan.project = name
    save_scan_results(name, scan)
    return repo, project


def seed_gradle_project(tmp_path: Path, name: str, **overrides: Any) -> ProjectConfig:
    """Copy a jj repository holding a Gradle project and save one shared update."""
    project = make_project(
        tmp_path / name,
        package_manager="gradle",
        test_unit="./gradlew test",
        **overrides,
    )
    catalogue = (FIXTURES_DIR / "gradle" / "libs.versions.toml").read_text(
        encoding="utf-8"
    )
    repo = copy_jj_repository(project.path)
    write_file(repo, "gradlew", "#!/bin/sh\nexit 0\n")
    write_file(repo, GRADLE_CATALOGUE_RELPATH, catalogue)
    commit_to_main(repo, "gradle project")
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(pkg_name="room", gradle_target=make_gradle_target())],
    )
    scan.project = name
    save_scan_results(name, scan)
    return project


FIXTURES_DIR = Path(__file__).parents[1] / "fixtures"
