import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import SemverTier
from maintenance_man.outdated import (
    OutdatedCheckError,
    _get_uv_direct_dep_names,
    bun_outdated,
    mvn_outdated,
    uv_outdated,
)
from tests.conftest import completed, make_project
from tests.fakes import FakeCommands


def _fake_commands(
    project: ProjectConfig,
    *results: subprocess.CompletedProcess[str] | BaseException,
) -> FakeCommands:
    commands = FakeCommands()
    command_lines = {
        "uv": (
            ("uv", "sync", "--locked"),
            ("uv", "pip", "list", "--outdated", "--format", "json"),
        ),
        "bun": (("bun", "outdated", "--no-progress"),),
        "mvn": (
            (
                "mvn",
                "versions:display-dependency-updates",
                "-DprocessDependencyManagement=false",
            ),
        ),
    }[project.package_manager]
    for index, result in enumerate(results):
        commands.add(command_lines[index], cwd=project.path, result=result)
    return commands


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
        sync_result = completed([], returncode=0, stdout="", stderr="")
        list_result = completed([], returncode=0, stdout="[]", stderr="")
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        commands = _fake_commands(project, sync_result, list_result)
        with patch("maintenance_man.outdated.run_captured", commands):
            updates = uv_outdated(project)

        assert updates == []
        assert [call[0] for call in commands.calls] == [
            ("uv", "sync", "--locked"),
            ("uv", "pip", "list", "--outdated", "--format", "json"),
        ]

    def test_sync_failure_raises(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["requests==2.31.0"]\n')
        failed = OutdatedCheckError("uv sync --locked failed (exit 1): lock stale")
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        commands = _fake_commands(project, failed)
        with (
            patch("maintenance_man.outdated.run_captured", commands),
            pytest.raises(OutdatedCheckError, match="uv sync --locked"),
        ):
            uv_outdated(project)
        ((argv, cwd, kwargs),) = commands.calls
        assert argv == ("uv", "sync", "--locked")
        assert cwd == project.path
        assert kwargs == {
            "timeout": 300,
            "label": "uv sync --locked",
            "error": OutdatedCheckError,
        }

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
        sync_result = completed([], returncode=0, stdout="", stderr="")
        list_result = completed([], returncode=0, stdout=fake_json, stderr="")
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        commands = _fake_commands(project, sync_result, list_result)
        with patch("maintenance_man.outdated.run_captured", commands):
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

        sync_result = completed([], returncode=0, stdout="", stderr="")
        list_result = completed([], returncode=0, stdout="[]", stderr="")
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        commands = _fake_commands(project, sync_result, list_result)
        with patch("maintenance_man.outdated.run_captured", commands):
            updates = uv_outdated(project)

        assert updates == []

    def test_command_failure_raises(self, tmp_path):
        sync_result = completed([], returncode=0, stdout="", stderr="")
        list_failed = OutdatedCheckError(
            "uv pip list --outdated failed (exit 1): error"
        )
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        commands = _fake_commands(project, sync_result, list_failed)
        with (
            patch("maintenance_man.outdated.run_captured", commands),
            pytest.raises(OutdatedCheckError, match="uv pip list --outdated"),
        ):
            uv_outdated(project)
        _, (argv, cwd, kwargs) = commands.calls
        assert argv == ("uv", "pip", "list", "--outdated", "--format", "json")
        assert cwd == project.path
        assert kwargs == {
            "timeout": 120,
            "label": "uv pip list --outdated",
            "error": OutdatedCheckError,
        }

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
        project = make_project(tmp_path, package_manager="uv")
        commands = _fake_commands(
            project,
            completed(),
            completed(stdout=payload),
        )
        monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)
        with pytest.raises(OutdatedCheckError, match="Unexpected uv output"):
            uv_outdated(project)

    def test_given_empty_latest_version_when_uv_outdated_runs_then_row_is_skipped(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            "maintenance_man.outdated.get_uv_direct_dep_names", lambda path: {"a"}
        )
        project = make_project(tmp_path, package_manager="uv")
        commands = _fake_commands(
            project,
            completed(),
            completed(
                stdout='[{"name":"a","version":"1.0","latest_version":"","Extra":1}]'
            ),
        )
        monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)

        updates = uv_outdated(project)

        assert updates == []

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
        sync_result = completed([], returncode=0, stdout="", stderr="")
        list_result = completed([], returncode=0, stdout=fake_json, stderr="")
        project = ProjectConfig(path=tmp_path, package_manager="uv")

        commands = _fake_commands(project, sync_result, list_result)
        with patch("maintenance_man.outdated.run_captured", commands):
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
        result = completed([], returncode=0, stdout=fake_output, stderr="")
        project = make_project(Path("/tmp/fake"), package_manager="bun")

        with patch(
            "maintenance_man.outdated.run_captured", _fake_commands(project, result)
        ):
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
        result = completed([], returncode=0, stdout=fake_output, stderr="")
        project = make_project(Path("/tmp/fake"), package_manager="bun")

        with patch(
            "maintenance_man.outdated.run_captured", _fake_commands(project, result)
        ):
            updates = bun_outdated(project)

        assert len(updates) == 2
        assert updates[0].pkg_name == "typescript"
        assert updates[1].pkg_name == "eslint"

    def test_empty_output_disables_progress(self):
        result = completed([], returncode=0, stdout="", stderr="")
        project = make_project(Path("/tmp/fake"), package_manager="bun")

        commands = _fake_commands(project, result)
        with patch("maintenance_man.outdated.run_captured", commands):
            updates = bun_outdated(project)

        assert updates == []
        assert commands.calls[0][0] == ("bun", "outdated", "--no-progress")

    def test_command_failure_raises(self):
        result = completed([], returncode=1, stdout="", stderr="error")
        project = make_project(Path("/tmp/fake"), package_manager="bun")

        with (
            patch(
                "maintenance_man.outdated.run_captured", _fake_commands(project, result)
            ),
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
        result = completed([], returncode=0, stdout=fake_output, stderr="")
        project = make_project(Path("/tmp/fake"), package_manager="mvn")

        with patch(
            "maintenance_man.outdated.run_captured", _fake_commands(project, result)
        ):
            updates = mvn_outdated(project)

        assert len(updates) == 2
        assert updates[0].pkg_name == "org.apache.commons:commons-lang3"
        assert updates[0].installed_version == "3.10"
        assert updates[0].latest_version == "3.14.0"
        assert updates[0].semver_tier == SemverTier.MINOR
        assert updates[1].pkg_name == "org.slf4j:slf4j-api"

    def test_no_updates_available(self):
        fake_output = "[INFO] No dependencies in Dependencies have newer versions.\n"
        result = completed([], returncode=0, stdout=fake_output, stderr="")
        project = make_project(Path("/tmp/fake"), package_manager="mvn")

        with patch(
            "maintenance_man.outdated.run_captured", _fake_commands(project, result)
        ):
            updates = mvn_outdated(project)

        assert updates == []

    def test_command_failure_raises(self):
        result = OutdatedCheckError(
            "mvn versions:display-dependency-updates failed (exit 1): BUILD FAILURE"
        )
        project = make_project(Path("/tmp/fake"), package_manager="mvn")
        commands = _fake_commands(project, result)

        with (
            patch("maintenance_man.outdated.run_captured", commands),
            pytest.raises(OutdatedCheckError),
        ):
            mvn_outdated(project)
        ((argv, cwd, kwargs),) = commands.calls
        assert argv == (
            "mvn",
            "versions:display-dependency-updates",
            "-DprocessDependencyManagement=false",
        )
        assert cwd == project.path
        assert kwargs == {
            "timeout": 300,
            "label": "mvn versions:display-dependency-updates",
            "error": OutdatedCheckError,
        }


def test_given_uv_project_when_checking_outdated_then_command_contract_is_delegated(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("VIRTUAL_ENV", "/host/venv")
    monkeypatch.setenv("PATH", os.pathsep.join(["/host/venv/bin", "/usr/bin"]))
    monkeypatch.setattr(
        "maintenance_man.outdated.get_uv_direct_dep_names", lambda path: set()
    )
    project = make_project(tmp_path, package_manager="uv")
    commands = _fake_commands(project, completed(), completed(stdout="[]"))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)

    assert uv_outdated(project) == []
    assert [cmd[:3] for cmd, _, _ in commands.calls] == [
        ("uv", "sync", "--locked"),
        ("uv", "pip", "list"),
    ]
    assert [kwargs for _, _, kwargs in commands.calls] == [
        {
            "timeout": 300,
            "label": "uv sync --locked",
            "error": OutdatedCheckError,
        },
        {
            "timeout": 120,
            "label": "uv pip list --outdated",
            "error": OutdatedCheckError,
        },
    ]


@pytest.mark.parametrize(
    "raised",
    [
        FileNotFoundError(2, "No such file or directory", "uv"),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    ],
)
def test_given_command_execution_failure_when_checking_outdated_then_error_is_requested(
    tmp_path, monkeypatch, raised
):
    project = make_project(tmp_path, package_manager="uv")
    error = OutdatedCheckError(
        f"Could not run uv sync --locked in {tmp_path}: {raised}"
    )
    error.__cause__ = raised
    commands = _fake_commands(project, error)
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)
    with pytest.raises(
        OutdatedCheckError, match=r"^Could not run uv sync --locked in "
    ):
        uv_outdated(project)
    ((argv, cwd, kwargs),) = commands.calls
    assert argv == ("uv", "sync", "--locked")
    assert cwd == project.path
    assert kwargs == {
        "timeout": 300,
        "label": "uv sync --locked",
        "error": OutdatedCheckError,
    }
