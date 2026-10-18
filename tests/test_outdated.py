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


def _finding(name: str, installed: str, latest: str, tier: SemverTier):
    return UpdateFinding(
        pkg_name=name,
        installed_version=installed,
        latest_version=latest,
        semver_tier=tier,
    )


@pytest.mark.parametrize(
    ("pyproject", "rows", "expected"),
    [
        pytest.param(
            '[project]\ndependencies = ["requests==2.31.0"]\n', [], [], id="no-rows"
        ),
        pytest.param(
            '[project]\ndependencies = ["requests>=2.28", "flask>=2.0"]\n',
            [
                {"name": "requests", "version": "2.28.0", "latest_version": "2.31.0"},
                {"name": "flask", "version": "2.3.0", "latest_version": "3.0.0"},
            ],
            [
                _finding("requests", "2.28.0", "2.31.0", SemverTier.MINOR),
                _finding("flask", "2.3.0", "3.0.0", SemverTier.MAJOR),
            ],
            id="direct-rows",
        ),
        pytest.param("[project]\ndependencies = []\n", [], [], id="no-dependencies"),
        pytest.param(
            '[project]\ndependencies = ["a"]\n',
            [{"name": "a", "version": "1.0", "latest_version": "", "Extra": 1}],
            [],
            id="empty-latest-version",
        ),
        pytest.param(
            '[project]\ndependencies = ["pydantic>=2.0", "rich>=14.0"]\n',
            [
                {"name": "pydantic", "version": "2.12.5", "latest_version": "2.13.0"},
                {
                    "name": "pydantic-core",
                    "version": "2.41.5",
                    "latest_version": "2.42.0",
                },
                {"name": "rich", "version": "14.3.1", "latest_version": "14.3.3"},
            ],
            [
                _finding("pydantic", "2.12.5", "2.13.0", SemverTier.MINOR),
                _finding("rich", "14.3.1", "14.3.3", SemverTier.PATCH),
            ],
            id="transitive-excluded",
        ),
    ],
)
def test_given_outdated_rows_when_uv_outdated_runs_then_direct_updates_are_returned(
    tmp_path, monkeypatch, pyproject, rows, expected
):
    (tmp_path / "pyproject.toml").write_text(pyproject)
    project = make_project(tmp_path, package_manager="uv")
    commands = _fake_commands(project, completed(), completed(stdout=json.dumps(rows)))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)

    updates = uv_outdated(project)

    assert updates == expected
    assert commands.calls == [
        (
            ("uv", "sync", "--locked"),
            tmp_path,
            {"timeout": 300, "label": "uv sync --locked", "error": OutdatedCheckError},
        ),
        (
            ("uv", "pip", "list", "--outdated", "--format", "json"),
            tmp_path,
            {
                "timeout": 120,
                "label": "uv pip list --outdated",
                "error": OutdatedCheckError,
            },
        ),
    ]


def test_given_wrongly_shaped_uv_output_when_uv_outdated_runs_then_outdated_check_error(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "maintenance_man.outdated.get_uv_direct_dep_names", lambda path: {"a"}
    )
    project = make_project(tmp_path, package_manager="uv")
    commands = _fake_commands(project, completed(), completed(stdout='[{"name": "a"}]'))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)

    with pytest.raises(OutdatedCheckError, match="Unexpected uv output"):
        uv_outdated(project)


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


@pytest.mark.parametrize(
    ("manager", "stdout", "expected", "expected_call"),
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
            (
                ("bun", "outdated", "--no-progress"),
                Path("/tmp/fake"),
                {
                    "timeout": 120,
                    "label": "bun outdated",
                    "error": OutdatedCheckError,
                    "ok_codes": None,
                },
            ),
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
            (
                ("bun", "outdated", "--no-progress"),
                Path("/tmp/fake"),
                {
                    "timeout": 120,
                    "label": "bun outdated",
                    "error": OutdatedCheckError,
                    "ok_codes": None,
                },
            ),
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
            (
                (
                    "mvn",
                    "versions:display-dependency-updates",
                    "-DprocessDependencyManagement=false",
                ),
                Path("/tmp/fake"),
                {
                    "timeout": 300,
                    "label": "mvn versions:display-dependency-updates",
                    "error": OutdatedCheckError,
                },
            ),
        ),
        (
            "mvn",
            "[INFO] No dependencies in Dependencies have newer versions.\n",
            [],
            (
                (
                    "mvn",
                    "versions:display-dependency-updates",
                    "-DprocessDependencyManagement=false",
                ),
                Path("/tmp/fake"),
                {
                    "timeout": 300,
                    "label": "mvn versions:display-dependency-updates",
                    "error": OutdatedCheckError,
                },
            ),
        ),
    ],
    ids=["bun-table", "bun-qualifiers", "mvn-updates", "mvn-none"],
)
def test_given_outdated_output_when_parsed_then_findings_match(
    manager, stdout, expected, expected_call, monkeypatch
):
    project = make_project(Path("/tmp/fake"), package_manager=manager)
    outdated = {"bun": bun_outdated, "mvn": mvn_outdated}[manager]
    commands = _fake_commands(project, completed(stdout=stdout))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)

    assert outdated(project) == expected
    assert commands.calls == [expected_call]
