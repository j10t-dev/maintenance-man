from pathlib import Path

import pytest


@pytest.fixture()
def mm_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect MM_HOME to a temp directory (not yet created on disk)."""
    home = tmp_path / ".mm"
    monkeypatch.setattr("maintenance_man.config.MM_HOME", home)
    monkeypatch.setattr("maintenance_man.scanner.MM_HOME", home)
    return home


@pytest.fixture()
def mm_home_with_projects(mm_home: Path) -> Path:
    """MM_HOME populated with directory structure and real project config."""
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "scan-results").mkdir(exist_ok=True)
    (mm_home / "worktrees").mkdir(exist_ok=True)

    config_text = """\
[defaults]
min_version_age_days = 7

[projects.feetfax]
path = "/home/glykon/dev/feetfax"
package_manager = "bun"

[projects.lifts]
path = "/home/glykon/dev/lifts"
package_manager = "uv"
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
