"""Project configuration, saved scans and activity defaults for tests."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.scan import (
    ScanResult,
)
from maintenance_man.storage import save_scan_results
from tests.fake_vcs import FakeJjState


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


FIXTURES_DIR = Path(__file__).parents[1] / "fixtures"
