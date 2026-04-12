import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import SemverTier
from maintenance_man.outdated import (
    OutdatedCheckError,
    _get_uv_direct_dep_names,
    _normalise_pkg_name,
    bun_outdated,
    classify_semver,
    get_outdated,
    mvn_outdated,
    uv_outdated,
)


def _make_project(pm: str, path: str = "/tmp/fake") -> ProjectConfig:
    return ProjectConfig(path=Path(path), package_manager=pm)


class TestClassifySemver:
    def test_patch_update(self):
        assert classify_semver("1.2.3", "1.2.4") == SemverTier.PATCH

    def test_minor_update(self):
        assert classify_semver("1.2.3", "1.3.0") == SemverTier.MINOR

    def test_major_update(self):
        assert classify_semver("1.2.3", "2.0.0") == SemverTier.MAJOR

    def test_major_update_no_reset(self):
        assert classify_semver("1.2.3", "2.1.0") == SemverTier.MAJOR

    def test_same_version(self):
        assert classify_semver("1.2.3", "1.2.3") == SemverTier.UNKNOWN

    def test_non_semver_input(self):
        assert classify_semver("abc", "def") == SemverTier.UNKNOWN

    def test_two_part_version(self):
        assert classify_semver("1.2", "1.3") == SemverTier.MINOR

    def test_four_part_version(self):
        assert classify_semver("1.2.3.4", "1.2.4.0") == SemverTier.PATCH


class TestNormalisePkgName:
    def test_lowercase(self):
        assert _normalise_pkg_name("Requests") == "requests"

    def test_underscores_to_hyphens(self):
        assert _normalise_pkg_name("pydantic_core") == "pydantic-core"

    def test_dots_to_hyphens(self):
        assert _normalise_pkg_name("zope.interface") == "zope-interface"

    def test_consecutive_separators(self):
        assert _normalise_pkg_name("Foo-_.Bar") == "foo-bar"

    def test_already_normalised(self):
        assert _normalise_pkg_name("rich") == "rich"


class TestGetUvDirectDepNames:
    def test_extracts_from_dependencies_and_groups(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            'dependencies = ["requests>=2.28", "Flask==3.0.0"]\n'
            "\n"
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0", "ruff>=0.9.0"]\n'
        )
        names = _get_uv_direct_dep_names(tmp_path)
        assert names == {"requests", "flask", "pytest", "ruff"}

    def test_normalises_names(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\ndependencies = ["pydantic_core>=2.0", "Zope.Interface"]\n'
        )
        names = _get_uv_direct_dep_names(tmp_path)
        assert names == {"pydantic-core", "zope-interface"}

    def test_skips_non_string_group_entries(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            'dependencies = ["requests>=2.28"]\n'
            "\n"
            "[dependency-groups]\n"
            'all = [{include-group = "dev"}, "extra-pkg>=1.0"]\n'
        )
        names = _get_uv_direct_dep_names(tmp_path)
        assert names == {"requests", "extra-pkg"}

    def test_empty_dependencies(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\ndependencies = []\n")
        names = _get_uv_direct_dep_names(tmp_path)
        assert names == set()

    def test_no_dependency_groups(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["rich>=14.0"]\n')
        names = _get_uv_direct_dep_names(tmp_path)
        assert names == {"rich"}

    def test_missing_pyproject_raises(self, tmp_path):
        with pytest.raises(OutdatedCheckError, match="Failed to read"):
            _get_uv_direct_dep_names(tmp_path)


class TestUvOutdated:
    def test_parses_json_output(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\ndependencies = ["requests>=2.28", "flask>=2.0"]\n'
        )

        fake_json = json.dumps(
            [
                {
                    "name": "requests",
                    "version": "2.28.0",
                    "latest_version": "2.31.0",
                    "latest_filetype": "wheel",
                },
                {
                    "name": "flask",
                    "version": "2.3.0",
                    "latest_version": "3.0.0",
                    "latest_filetype": "wheel",
                },
            ]
        )
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=fake_json, stderr=""
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = uv_outdated(project)

        assert len(updates) == 2
        assert updates[0].pkg_name == "requests"
        assert updates[0].installed_version == "2.28.0"
        assert updates[0].latest_version == "2.31.0"
        assert updates[0].semver_tier == SemverTier.MINOR
        assert updates[1].semver_tier == SemverTier.MAJOR

    def test_empty_output(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\ndependencies = []\n")

        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="[]", stderr=""
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = uv_outdated(project)

        assert updates == []

    def test_command_failure_raises(self, tmp_path):
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            with pytest.raises(OutdatedCheckError):
                uv_outdated(project)

    def test_excludes_transitive_deps(self, tmp_path):
        """uv_outdated should only return direct dependencies from pyproject.toml."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            '[project]\ndependencies = ["pydantic>=2.0", "rich>=14.0"]\n'
        )

        fake_json = json.dumps(
            [
                {
                    "name": "pydantic",
                    "version": "2.12.5",
                    "latest_version": "2.13.0",
                },
                {
                    "name": "pydantic-core",
                    "version": "2.41.5",
                    "latest_version": "2.42.0",
                },
                {
                    "name": "rich",
                    "version": "14.3.1",
                    "latest_version": "14.3.3",
                },
            ]
        )
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=fake_json, stderr=""
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = uv_outdated(project)

        pkg_names = [u.pkg_name for u in updates]
        assert "pydantic" in pkg_names
        assert "rich" in pkg_names
        assert "pydantic-core" not in pkg_names


class TestBunOutdated:
    def test_parses_table_output(self):
        fake_output = (
            "| Package    | Current | Update  | Latest  |\n"
            "|------------|---------|---------|---------|  \n"
            "| lodash     | 4.17.20 | 4.17.21 | 4.17.21 |\n"
            "| express    | 4.18.0  | 4.18.3  | 5.0.0   |\n"
        )
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=fake_output, stderr=""
        )
        project = _make_project("bun")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = bun_outdated(project)

        assert len(updates) == 2
        assert updates[0].pkg_name == "lodash"
        assert updates[0].installed_version == "4.17.20"
        assert updates[0].latest_version == "4.17.21"
        assert updates[0].semver_tier == SemverTier.PATCH
        assert updates[1].pkg_name == "express"
        assert updates[1].latest_version == "5.0.0"
        assert updates[1].semver_tier == SemverTier.MAJOR

    def test_strips_peer_and_dev_qualifiers(self):
        fake_output = (
            "| Package           | Current | Update | Latest |\n"
            "|-------------------|---------|--------|--------|\n"
            "| typescript (peer) | 5.9.3   | 6.0.2  | 6.0.2  |\n"
            "| eslint (dev)      | 8.0.0   | 9.0.0  | 9.0.0  |\n"
        )
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=fake_output, stderr=""
        )
        project = _make_project("bun")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = bun_outdated(project)

        assert len(updates) == 2
        assert updates[0].pkg_name == "typescript"
        assert updates[1].pkg_name == "eslint"

    def test_empty_output(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        project = _make_project("bun")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = bun_outdated(project)

        assert updates == []

    def test_command_failure_raises(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        project = _make_project("bun")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            with pytest.raises(OutdatedCheckError):
                bun_outdated(project)


class TestMvnOutdated:
    def test_parses_text_output(self):
        fake_output = (
            "[INFO] The following dependencies in Dependencies have newer versions:\n"
            "[INFO]   org.apache.commons:commons-lang3 ......... 3.10 -> 3.14.0\n"
            "[INFO]   org.slf4j:slf4j-api .................. 2.0.9 -> 2.0.16\n"
            "[INFO] \n"
        )
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=fake_output, stderr=""
        )
        project = _make_project("mvn")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = mvn_outdated(project)

        assert len(updates) == 2
        assert updates[0].pkg_name == "org.apache.commons:commons-lang3"
        assert updates[0].installed_version == "3.10"
        assert updates[0].latest_version == "3.14.0"
        assert updates[0].semver_tier == SemverTier.MINOR
        assert updates[1].pkg_name == "org.slf4j:slf4j-api"

    def test_no_updates_available(self):
        fake_output = "[INFO] No dependencies in Dependencies have newer versions.\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=fake_output, stderr=""
        )
        project = _make_project("mvn")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = mvn_outdated(project)

        assert updates == []

    def test_command_failure_raises(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="BUILD FAILURE"
        )
        project = _make_project("mvn")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            with pytest.raises(OutdatedCheckError):
                mvn_outdated(project)


class TestGetOutdated:
    def test_dispatches_to_bun(self):
        project = _make_project("bun")
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = get_outdated(project)
        assert updates == []

    def test_dispatches_to_uv(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\ndependencies = []\n")

        project = ProjectConfig(path=tmp_path, package_manager="uv")
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="[]", stderr=""
        )
        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = get_outdated(project)
        assert updates == []

    def test_dispatches_to_mvn(self):
        project = _make_project("mvn")
        fake_output = "[INFO] No dependencies in Dependencies have newer versions.\n"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=fake_output, stderr=""
        )
        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            updates = get_outdated(project)
        assert updates == []

    def test_unsupported_manager_raises(self):
        project = _make_project("bun")
        # Bypass Pydantic validation to test the guard
        object.__setattr__(project, "package_manager", "npm")
        with pytest.raises(OutdatedCheckError):
            get_outdated(project)
