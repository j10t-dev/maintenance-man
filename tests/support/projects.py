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
from tests.fake_vcs import FakeJjState
from tests.support.findings import make_gradle_target, make_scan_result, make_update


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
) -> tuple[FakeJjState, ProjectConfig]:
    """Create a fake repository and persist the supplied scan under its project name."""
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


def seed_gradle_project(
    tmp_path: Path, state: FakeJjState, name: str, **overrides: Any
) -> ProjectConfig:
    """Create a fake Gradle repository and save one shared-catalogue update."""
    project = make_project(
        tmp_path / name,
        package_manager="gradle",
        test_unit="./gradlew test",
        **overrides,
    )
    catalogue = (FIXTURES_DIR / "gradle" / "libs.versions.toml").read_text(
        encoding="utf-8"
    )
    state.seed_repository(
        project.path,
        files={"gradlew": "#!/bin/sh\nexit 0\n", GRADLE_CATALOGUE_RELPATH: catalogue},
    )
    scan = make_scan_result(
        vulns=[],
        updates=[make_update(pkg_name="room", gradle_target=make_gradle_target())],
    )
    scan.project = name
    save_scan_results(name, scan)
    return project


FIXTURES_DIR = Path(__file__).parents[1] / "fixtures"
