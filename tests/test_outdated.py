import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import SemverTier, UpdateFinding
from maintenance_man.outdated import (
    OutdatedCheckError,
    bun_outdated,
    mvn_outdated,
    uv_outdated,
)
from maintenance_man.uv_dependencies import get_uv_direct_dep_names
from tests.fakes import FakeCommands
from tests.support.process import completed
from tests.support.projects import make_project


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


@pytest.mark.parametrize(
    ("pyproject", "expected"),
    [
        (
            "[project]\n"
            'dependencies = ["requests>=2.28", "Flask==3.0.0"]\n'
            "\n"
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0", "ruff>=0.9.0"]\n',
            {"requests", "flask", "pytest", "ruff"},
        ),
        (
            '[project]\ndependencies = ["pydantic_core>=2.0", "Zope.Interface"]\n',
            {"pydantic-core", "zope-interface"},
        ),
        (
            "[project]\n"
            'dependencies = ["requests>=2.28"]\n'
            "\n"
            "[dependency-groups]\n"
            'all = [{include-group = "dev"}, "extra-pkg>=1.0"]\n',
            {"requests", "extra-pkg"},
        ),
        (
            "[project]\n"
            'dependencies = ["requests>=2.28"]\n'
            "\n"
            "[project.optional-dependencies]\n"
            'cli = ["rich>=14.0"]\n'
            'docs = ["mkdocs-material>=9.0"]\n',
            {"requests"},
        ),
        ("[project]\ndependencies = []\n", set()),
        ('[project]\ndependencies = ["rich>=14.0"]\n', {"rich"}),
    ],
    ids=[
        "runtime-and-groups",
        "normalised",
        "non-string-group-entry",
        "optional-excluded",
        "empty",
        "no-groups",
    ],
)
def test_given_pyproject_when_direct_names_read_then_declared_names_are_normalised(
    tmp_path, pyproject, expected
):
    (tmp_path / "pyproject.toml").write_text(pyproject)

    assert get_uv_direct_dep_names(tmp_path) == expected


def test_given_missing_pyproject_when_uv_outdated_runs_then_outdated_check_error(
    tmp_path, monkeypatch
):
    project = make_project(tmp_path, package_manager="uv")
    commands = _fake_commands(project, completed(), completed(stdout="[]"))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)

    with pytest.raises(OutdatedCheckError, match="Failed to read"):
        uv_outdated(project)


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


@pytest.mark.parametrize(
    ("manager", "stdout", "expected"),
    [
        (
            "bun",
            "| Package    | Current | Update  | Latest  |\n"
            "|------------|---------|---------|---------|  \n"
            "| lodash     | 4.17.20 | 4.17.21 | 4.17.21 |\n"
            "| express    | 4.18.0  | 4.18.3  | 5.0.0   |\n",
            [
                UpdateFinding(
                    pkg_name="lodash",
                    installed_version="4.17.20",
                    latest_version="4.17.21",
                    semver_tier=SemverTier.PATCH,
                ),
                UpdateFinding(
                    pkg_name="express",
                    installed_version="4.18.0",
                    latest_version="5.0.0",
                    semver_tier=SemverTier.MAJOR,
                ),
            ],
        ),
        (
            "bun",
            "| Package           | Current | Update | Latest |\n"
            "|-------------------|---------|--------|--------|\n"
            "| typescript (peer) | 5.9.3   | 6.0.2  | 6.0.2  |\n"
            "| eslint (dev)      | 8.0.0   | 9.0.0  | 9.0.0  |\n",
            [
                UpdateFinding(
                    pkg_name="typescript",
                    installed_version="5.9.3",
                    latest_version="6.0.2",
                    semver_tier=SemverTier.MAJOR,
                ),
                UpdateFinding(
                    pkg_name="eslint",
                    installed_version="8.0.0",
                    latest_version="9.0.0",
                    semver_tier=SemverTier.MAJOR,
                ),
            ],
        ),
        (
            "mvn",
            "[INFO] The following dependencies in Dependencies have newer versions:\n"
            "[INFO]   org.apache.commons:commons-lang3 ......... 3.10 -> 3.14.0\n"
            "[INFO]   org.slf4j:slf4j-api .................. 2.0.9 -> 2.0.16\n"
            "[INFO] \n",
            [
                UpdateFinding(
                    pkg_name="org.apache.commons:commons-lang3",
                    installed_version="3.10",
                    latest_version="3.14.0",
                    semver_tier=SemverTier.MINOR,
                ),
                UpdateFinding(
                    pkg_name="org.slf4j:slf4j-api",
                    installed_version="2.0.9",
                    latest_version="2.0.16",
                    semver_tier=SemverTier.PATCH,
                ),
            ],
        ),
        (
            "mvn",
            "[INFO] No dependencies in Dependencies have newer versions.\n",
            [],
        ),
    ],
    ids=["bun-table", "bun-qualifiers", "mvn-updates", "mvn-none"],
)
def test_given_outdated_output_when_parsed_then_findings_match(
    manager, stdout, expected
):
    project = make_project(Path("/tmp/fake"), package_manager=manager)
    outdated = {"bun": bun_outdated, "mvn": mvn_outdated}[manager]

    with patch(
        "maintenance_man.outdated.run_captured",
        _fake_commands(project, completed(stdout=stdout)),
    ):
        assert outdated(project) == expected
