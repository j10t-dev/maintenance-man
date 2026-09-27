import json
import os
import subprocess
from pathlib import Path
from typing import Literal
from unittest.mock import patch

import pytest

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import SemverTier
from maintenance_man.outdated import (
    OutdatedCheckError,
    _get_uv_direct_dep_names,
    bun_outdated,
    classify_semver,
    mvn_outdated,
    uv_outdated,
)
from maintenance_man.uv_dependencies import normalise_pkg_name


def _make_project(
    pm: Literal["bun", "uv", "mvn", "gradle"], path: str = "/tmp/fake"
) -> ProjectConfig:
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
        assert normalise_pkg_name("Requests") == "requests"

    def test_underscores_to_hyphens(self):
        assert normalise_pkg_name("pydantic_core") == "pydantic-core"

    def test_dots_to_hyphens(self):
        assert normalise_pkg_name("zope.interface") == "zope-interface"

    def test_consecutive_separators(self):
        assert normalise_pkg_name("Foo-_.Bar") == "foo-bar"

    def test_already_normalised(self):
        assert normalise_pkg_name("rich") == "rich"


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

    def test_excludes_optional_dependencies(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            'dependencies = ["requests>=2.28"]\n'
            "\n"
            "[project.optional-dependencies]\n"
            'cli = ["rich>=14.0"]\n'
            'docs = ["mkdocs-material>=9.0"]\n'
        )
        names = _get_uv_direct_dep_names(tmp_path)
        assert names == {"requests"}

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
    def test_syncs_environment_before_checking_outdated(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["requests==2.31.0"]\n')
        sync_completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        list_completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="[]", stderr=""
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with patch(
            "maintenance_man.process.subprocess.run",
            side_effect=[sync_completed, list_completed],
        ) as run:
            updates = uv_outdated(project)

        assert updates == []
        assert run.call_args_list[0].args[0] == ["uv", "sync", "--locked"]
        assert run.call_args_list[1].args[0][:5] == [
            "uv",
            "pip",
            "list",
            "--outdated",
            "--format",
        ]

    def test_sync_failure_raises(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["requests==2.31.0"]\n')
        failed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="lock stale"
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with (
            patch("maintenance_man.process.subprocess.run", return_value=failed),
            pytest.raises(OutdatedCheckError, match="uv sync --locked"),
        ):
            uv_outdated(project)

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
        sync_completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        list_completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=fake_json, stderr=""
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with patch(
            "maintenance_man.process.subprocess.run",
            side_effect=[sync_completed, list_completed],
        ):
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

        sync_completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        list_completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="[]", stderr=""
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with patch(
            "maintenance_man.process.subprocess.run",
            side_effect=[sync_completed, list_completed],
        ):
            updates = uv_outdated(project)

        assert updates == []

    def test_command_failure_raises(self, tmp_path):
        sync_completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        list_failed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with (
            patch(
                "maintenance_man.process.subprocess.run",
                side_effect=[sync_completed, list_failed],
            ),
            pytest.raises(OutdatedCheckError, match="uv pip list --outdated"),
        ):
            uv_outdated(project)

    @pytest.mark.parametrize(
        "payload",
        [
            '{"name": "a"}',
            '"text"',
            "[1]",
            '[{"version": "1.0", "latest_version": "2.0"}]',
            '[{"name": "a", "version": 1, "latest_version": "2.0"}]',
            '[{"name": "a", "version": "1.0"}]',
        ],
    )
    def test_uv_outdated_rejects_wrongly_shaped_output(
        self, tmp_path, monkeypatch, payload
    ):
        monkeypatch.setattr(
            "maintenance_man.outdated.get_uv_direct_dep_names", lambda path: {"a"}
        )
        monkeypatch.setattr(
            "maintenance_man.process.subprocess.run",
            lambda cmd, **kwargs: subprocess.CompletedProcess(
                cmd, 0, payload if cmd[1] == "pip" else "", ""
            ),
        )
        with pytest.raises(OutdatedCheckError, match="Unexpected uv output"):
            uv_outdated(ProjectConfig(path=tmp_path, package_manager="uv"))

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
        sync_completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        list_completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=fake_json, stderr=""
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        with patch(
            "maintenance_man.process.subprocess.run",
            side_effect=[sync_completed, list_completed],
        ):
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

        with patch("maintenance_man.process.subprocess.run", return_value=completed):
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

        with patch("maintenance_man.process.subprocess.run", return_value=completed):
            updates = bun_outdated(project)

        assert len(updates) == 2
        assert updates[0].pkg_name == "typescript"
        assert updates[1].pkg_name == "eslint"

    def test_empty_output(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        project = _make_project("bun")

        with patch("maintenance_man.process.subprocess.run", return_value=completed):
            updates = bun_outdated(project)

        assert updates == []

    def test_disables_progress_output_to_avoid_bun_resolving_hangs(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        project = _make_project("bun")

        with patch(
            "maintenance_man.process.subprocess.run", return_value=completed
        ) as run:
            bun_outdated(project)

        assert run.call_args.args[0] == ["bun", "outdated", "--no-progress"]

    def test_command_failure_raises(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        project = _make_project("bun")

        with (
            patch("maintenance_man.process.subprocess.run", return_value=completed),
            pytest.raises(OutdatedCheckError),
        ):
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

        with patch("maintenance_man.process.subprocess.run", return_value=completed):
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

        with patch("maintenance_man.process.subprocess.run", return_value=completed):
            updates = mvn_outdated(project)

        assert updates == []

    def test_command_failure_raises(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="BUILD FAILURE"
        )
        project = _make_project("mvn")

        with (
            patch("maintenance_man.process.subprocess.run", return_value=completed),
            pytest.raises(OutdatedCheckError),
        ):
            mvn_outdated(project)


def test_uv_outdated_commands_run_without_the_host_virtualenv(tmp_path, monkeypatch):
    monkeypatch.setenv("VIRTUAL_ENV", "/host/venv")
    monkeypatch.setenv("PATH", os.pathsep.join(["/host/venv/bin", "/usr/bin"]))
    monkeypatch.setattr(
        "maintenance_man.outdated.get_uv_direct_dep_names", lambda path: set()
    )
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, "[]", "")

    monkeypatch.setattr("maintenance_man.process.subprocess.run", run)
    assert uv_outdated(ProjectConfig(path=tmp_path, package_manager="uv")) == []
    assert [cmd[:3] for cmd, _ in calls] == [
        ["uv", "sync", "--locked"],
        ["uv", "pip", "list"],
    ]
    for _, kwargs in calls:
        assert "VIRTUAL_ENV" not in kwargs["env"]
        assert "/host/venv/bin" not in kwargs["env"]["PATH"].split(os.pathsep)
        assert kwargs["stdin"] is subprocess.DEVNULL


@pytest.mark.parametrize(
    "raised",
    [
        FileNotFoundError(2, "No such file or directory", "uv"),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    ],
)
def test_outdated_execution_failure_is_an_outdated_check_error(
    tmp_path, monkeypatch, raised
):
    def run(cmd, **kwargs):
        raise raised

    monkeypatch.setattr("maintenance_man.process.subprocess.run", run)
    with pytest.raises(
        OutdatedCheckError, match=r"^Could not run uv sync --locked in "
    ):
        uv_outdated(ProjectConfig(path=tmp_path, package_manager="uv"))
