from pathlib import Path

import pytest

from maintenance_man.config import (
    ConfigError,
    ProjectNotFoundError,
    UnknownProjectError,
    ensure_mm_home,
    load_config,
    resolve_project,
)
from tests.support.projects import write_config


class TestEnsureMmHome:
    def test_creates_home_and_skeleton_config(self, mm_home: Path):
        assert not mm_home.exists()
        ensure_mm_home()
        assert [path.name for path in mm_home.iterdir()] == ["config.toml"]

    def test_does_not_overwrite_existing_config(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        config_path = mm_home / "config.toml"
        write_config(mm_home, "[defaults]\nmin_version_age_days = 30\n")
        ensure_mm_home()
        text = config_path.read_text()
        assert "30" in text


class TestLoadConfig:
    @pytest.mark.parametrize(
        ("text", "custom_path", "expected_days"),
        [
            pytest.param(
                "[defaults]\nmin_version_age_days = 14\n", False, 14, id="home"
            ),
            pytest.param(
                "[defaults]\nmin_version_age_days = 42\n", True, 42, id="custom-path"
            ),
            pytest.param("", False, 7, id="omitted-defaults-fall-back-to-seven"),
        ],
    )
    def test_given_config_file_when_loaded_then_min_version_age_comes_from_it(
        self,
        mm_home: Path,
        tmp_path: Path,
        text: str,
        custom_path: bool,
        expected_days: int,
    ):
        if custom_path:
            config_file = write_config(tmp_path, text, filename="custom-config.toml")
            config = load_config(config_path=config_file)
        else:
            write_config(mm_home, text)
            config = load_config()
        assert config.defaults.min_version_age_days == expected_days

    def test_loads_skeleton_config_on_first_run(self, mm_home: Path):
        """First run: directory doesn't exist, gets auto-created, skeleton loads."""
        config = load_config()
        assert config.defaults.min_version_age_days == 7
        assert config.projects == {}

    @pytest.mark.parametrize(
        "text",
        ["[defaults]\nbogus_key = true\n", '[settings]\nfoo = "bar"\n'],
        ids=["unknown-defaults-key", "unknown-top-level-key"],
    )
    def test_invalid_config_raises_config_error(self, mm_home: Path, text: str):
        write_config(mm_home, text)
        with pytest.raises(ConfigError):
            load_config()

    def test_custom_path_does_not_create_mm_home(self, mm_home: Path):
        """Using a custom config path should not create ~/.mm/."""
        config_file = write_config(
            mm_home.parent, "[defaults]\n", filename="custom-config.toml"
        )
        load_config(config_path=config_file)
        assert not mm_home.exists()

    def test_custom_path_file_not_found(self, tmp_path: Path):
        """Missing custom config file raises ConfigError."""
        with pytest.raises(ConfigError):
            load_config(config_path=tmp_path / "nonexistent.toml")

    @pytest.mark.parametrize(
        "relative",
        [
            pytest.param(True, id="relative-resolves-against-the-config-directory"),
            pytest.param(False, id="absolute-is-unchanged"),
        ],
    )
    def test_given_project_path_when_loaded_then_it_resolves_against_config_dir(
        self, tmp_path: Path, relative: bool
    ):
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)
        configured = "projects/myapp" if relative else str(project_dir)
        config_file = write_config(
            tmp_path,
            f'[projects.myapp]\npath = "{configured}"\npackage_manager = "bun"\n',
        )
        config = load_config(config_path=config_file)
        assert config.projects["myapp"].path == project_dir


class TestResolveProject:
    def test_unknown_project_raises_project_not_found(self, mm_home: Path):
        write_config(mm_home, "[defaults]\n")
        config = load_config()
        with pytest.raises(UnknownProjectError):
            resolve_project(config, "nonexistent")

    def test_missing_path_raises_project_not_found(self, mm_home: Path):
        write_config(
            mm_home,
            '[projects.myapp]\npath = "/nonexistent/path"\npackage_manager = "bun"\n',
        )
        config = load_config()
        with pytest.raises(ProjectNotFoundError) as raised:
            resolve_project(config, "myapp")
        assert not isinstance(raised.value, UnknownProjectError)
