import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import SemverTier
from maintenance_man.outdated import (
    OutdatedCheckError,
    classify_semver,
    get_outdated,
)


def _make_project(pm: str, path: str = "/tmp/fake") -> ProjectConfig:
    return ProjectConfig(path=Path(path), package_manager=pm)


class TestClassifySemver:
    def test_patch_bump(self):
        assert classify_semver("1.2.3", "1.2.4") == SemverTier.PATCH

    def test_minor_bump(self):
        assert classify_semver("1.2.3", "1.3.0") == SemverTier.MINOR

    def test_major_bump(self):
        assert classify_semver("1.2.3", "2.0.0") == SemverTier.MAJOR

    def test_major_bump_no_reset(self):
        assert classify_semver("1.2.3", "2.1.0") == SemverTier.MAJOR

    def test_same_version(self):
        assert classify_semver("1.2.3", "1.2.3") == SemverTier.UNKNOWN

    def test_non_semver_input(self):
        assert classify_semver("abc", "def") == SemverTier.UNKNOWN

    def test_two_part_version(self):
        assert classify_semver("1.2", "1.3") == SemverTier.MINOR

    def test_four_part_version(self):
        assert classify_semver("1.2.3.4", "1.2.4.0") == SemverTier.PATCH


class TestUvOutdated:
    def test_parses_json_output(self):
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
        project = _make_project("uv")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            from maintenance_man.outdated import uv_outdated

            updates = uv_outdated(project)

        assert len(updates) == 2
        assert updates[0].pkg_name == "requests"
        assert updates[0].installed_version == "2.28.0"
        assert updates[0].latest_version == "2.31.0"
        assert updates[0].semver_tier == SemverTier.MINOR
        assert updates[1].semver_tier == SemverTier.MAJOR

    def test_empty_output(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="[]", stderr=""
        )
        project = _make_project("uv")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            from maintenance_man.outdated import uv_outdated

            updates = uv_outdated(project)

        assert updates == []

    def test_command_failure_raises(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        project = _make_project("uv")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            from maintenance_man.outdated import uv_outdated

            with pytest.raises(OutdatedCheckError):
                uv_outdated(project)


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
            from maintenance_man.outdated import bun_outdated

            updates = bun_outdated(project)

        assert len(updates) == 2
        assert updates[0].pkg_name == "lodash"
        assert updates[0].installed_version == "4.17.20"
        assert updates[0].latest_version == "4.17.21"
        assert updates[0].semver_tier == SemverTier.PATCH
        assert updates[1].pkg_name == "express"
        assert updates[1].latest_version == "5.0.0"
        assert updates[1].semver_tier == SemverTier.MAJOR

    def test_empty_output(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        project = _make_project("bun")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            from maintenance_man.outdated import bun_outdated

            updates = bun_outdated(project)

        assert updates == []

    def test_command_failure_raises(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        project = _make_project("bun")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            from maintenance_man.outdated import bun_outdated

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
            from maintenance_man.outdated import mvn_outdated

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
            from maintenance_man.outdated import mvn_outdated

            updates = mvn_outdated(project)

        assert updates == []

    def test_command_failure_raises(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="BUILD FAILURE"
        )
        project = _make_project("mvn")

        with patch("maintenance_man.outdated.subprocess.run", return_value=completed):
            from maintenance_man.outdated import mvn_outdated

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

    def test_dispatches_to_uv(self):
        project = _make_project("uv")
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
