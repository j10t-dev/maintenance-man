import tomllib
from pathlib import Path

import pytest
from pydantic import ValidationError

from maintenance_man.config import (
    ConfigError,
    ProjectNotFoundError,
    UnknownProjectError,
    ensure_mm_home,
    load_config,
    resolve_project,
)
from maintenance_man.models.config import DefaultsConfig, MmConfig
from tests.support.projects import write_config


class TestDefaultsConfig:
    def test_defaults_rejects_unknown_keys(self):
        with pytest.raises(ValidationError, match="extra_field"):
            DefaultsConfig(extra_field="bad")  # type: ignore[call-arg]  # ty:ignore[unknown-argument]


class TestMmConfig:
    def test_toml_missing_defaults_uses_fallback(self, tmp_path: Path):
        """If [defaults] is omitted from TOML, fallback values are used."""
        toml_str = f"""
[projects.myapp]
path = "{tmp_path}"
package_manager = "mvn"
"""
        raw = tomllib.loads(toml_str)
        config = MmConfig(**raw)
        assert config.defaults.min_version_age_days == 7

    def test_toml_unknown_top_level_key_rejected(self):
        toml_str = """
[settings]
foo = "bar"
"""
        raw = tomllib.loads(toml_str)
        with pytest.raises(ValidationError, match="settings"):
            MmConfig(**raw)


class TestEnsureMmHome:
    def test_creates_directory_structure(self, mm_home: Path):
        assert not mm_home.exists()
        ensure_mm_home()
        assert mm_home.is_dir()
        assert (mm_home / "scan-results").is_dir()
        assert (mm_home / "workspaces").is_dir()
        assert (mm_home / "config.toml").is_file()

    def test_idempotent(self, mm_home: Path):
        ensure_mm_home()
        ensure_mm_home()  # should not raise
        assert mm_home.is_dir()

    def test_skeleton_config_is_valid_toml(self, mm_home: Path):
        ensure_mm_home()
        text = (mm_home / "config.toml").read_text()
        # Should parse without error (comments are valid TOML)
        raw = tomllib.loads(text)
        # Should validate through MmConfig
        config = MmConfig(**raw)
        assert config.defaults.min_version_age_days == 7

    def test_does_not_overwrite_existing_config(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        config_path = mm_home / "config.toml"
        write_config(mm_home, "[defaults]\nmin_version_age_days = 30\n")
        ensure_mm_home()
        text = config_path.read_text()
        assert "30" in text


class TestLoadConfig:
    def test_loads_valid_config(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(mm_home, "[defaults]\nmin_version_age_days = 14\n")
        config = load_config()
        assert config.defaults.min_version_age_days == 14

    def test_loads_skeleton_config_on_first_run(self, mm_home: Path):
        """First run: directory doesn't exist, gets auto-created, skeleton loads."""
        config = load_config()
        assert config.defaults.min_version_age_days == 7
        assert config.projects == {}

    def test_invalid_config_raises_config_error(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        write_config(mm_home, "[defaults]\nbogus_key = true\n")
        with pytest.raises(ConfigError):
            load_config()

    def test_loads_from_custom_path(self, tmp_path: Path):
        """load_config(config_path=...) reads from the given file."""
        config_file = write_config(
            tmp_path,
            "[defaults]\nmin_version_age_days = 42\n",
            filename="custom-config.toml",
        )
        config = load_config(config_path=config_file)
        assert config.defaults.min_version_age_days == 42

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

    def test_resolves_relative_project_paths(self, tmp_path: Path):
        """Relative project paths resolve against config file's parent dir."""
        project_dir = tmp_path / "projects" / "myapp"
        project_dir.mkdir(parents=True)
        config_file = write_config(
            tmp_path,
            '[projects.myapp]\npath = "projects/myapp"\npackage_manager = "bun"\n',
        )
        config = load_config(config_path=config_file)
        assert config.projects["myapp"].path == project_dir

    def test_absolute_paths_unchanged(self, tmp_path: Path):
        """Absolute project paths are not modified during resolution."""
        project_dir = tmp_path / "myapp"
        project_dir.mkdir()
        config_file = write_config(
            tmp_path,
            f'[projects.myapp]\npath = "{project_dir}"\npackage_manager = "bun"\n',
        )
        config = load_config(config_path=config_file)
        assert config.projects["myapp"].path == project_dir


class TestResolveProject:
    def test_resolves_existing_project(self, mm_home: Path):
        project_dir = mm_home.parent / "myproject"
        project_dir.mkdir()
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(
            mm_home,
            f'[projects.myapp]\npath = "{project_dir}"\npackage_manager = "bun"\n',
        )
        config = load_config()
        proj = resolve_project(config, "myapp")
        assert proj.package_manager == "bun"

    def test_unknown_project_raises_project_not_found(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(mm_home, "[defaults]\n")
        config = load_config()
        with pytest.raises(UnknownProjectError):
            resolve_project(config, "nonexistent")

    def test_missing_path_raises_project_not_found(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(
            mm_home,
            '[projects.myapp]\npath = "/nonexistent/path"\npackage_manager = "bun"\n',
        )
        config = load_config()
        with pytest.raises(ProjectNotFoundError) as raised:
            resolve_project(config, "myapp")
        assert not isinstance(raised.value, UnknownProjectError)
