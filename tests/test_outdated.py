import json
import subprocess

import pytest

from maintenance_man.bun_dependencies import BunDependencyError
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
                "-B",
                "-ntp",
                "-Dstyle.color=never",
                "versions:display-dependency-updates",
                "-DprocessDependencyManagement=false",
                "-Dversions.outputLineWidth=1000",
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


_BUN_LINE_ERROR = "bun outdated: unrecognised output line: "
_BUN_BANNER = "bun outdated v1.4.2 (744846f84)\n"
_BUN_TABLE = (
    "bun outdated v1.4.2 (744846f84)\n"
    "|---------------------------------------|\n"
    "| Package   | Current | Update | Latest |\n"
    "|-----------|---------|--------|--------|\n"
    "| is-number | 6.0.0   | 6.0.0  | 7.0.0  |\n"
    "|---------------------------------------|\n"
)
_BUN_ROW = "| is-number | 6.0.0   | 6.0.0  | 7.0.0  |"
# Captured from bun 1.4.2: a separator follows every row but the last.
_BUN_ROW_SEPARATOR = "|-----------------------|---------|--------|--------|"
_BUN_TWO_ROWS = (
    "bun outdated v1.4.2 (744846f84)\n"
    "|---------------------------------------------------|\n"
    "| Package               | Current | Update | Latest |\n"
    f"{_BUN_ROW_SEPARATOR}\n"
    "| commander             | 15.0.0  | 15.0.0 | 15.1.0 |\n"
    f"{_BUN_ROW_SEPARATOR}\n"
    "| @oxlint/plugins (dev) | 1.82.0  | 1.82.0 | 1.93.0 |\n"
    "|---------------------------------------------------|\n"
)


def _bun_lookup(expected_path, value):
    def lookup(project_path):
        assert project_path == expected_path
        if value is None:
            pytest.fail("bun dependency lookup called")
        if isinstance(value, Exception):
            raise value
        return value

    return lookup


def _run_bun_outdated(tmp_path, monkeypatch, stdout, declared, resolved, stderr=""):
    monkeypatch.setattr(
        "maintenance_man.outdated.registry_declared_bun_names",
        _bun_lookup(tmp_path, declared),
    )
    monkeypatch.setattr(
        "maintenance_man.outdated.resolved_bun_versions",
        _bun_lookup(tmp_path, resolved),
    )
    project = make_project(tmp_path, package_manager="bun")
    commands = _fake_commands(project, completed(stdout=stdout, stderr=stderr))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)
    return bun_outdated(project), commands


@pytest.mark.parametrize(
    ("stdout", "declared", "resolved", "expected"),
    [
        pytest.param(_BUN_BANNER, None, None, [], id="banner-only"),
        pytest.param(
            _BUN_TABLE,
            {"is-number"},
            {"is-number": "6.0.0"},
            [_finding("is-number", "6.0.0", "7.0.0", SemverTier.MAJOR)],
            id="declared-row",
        ),
        pytest.param(_BUN_TABLE, set(), {}, [], id="undeclared-row"),
        pytest.param(
            _BUN_TABLE.replace(_BUN_ROW, "| eslint (dev) | 9.0.0 | 9.0.0 | 9.1.0 |"),
            {"eslint"},
            {"eslint": "9.0.0"},
            [_finding("eslint", "9.0.0", "9.1.0", SemverTier.MINOR)],
            id="dev-suffix",
        ),
        pytest.param(
            _BUN_TWO_ROWS,
            {"commander", "@oxlint/plugins"},
            {"commander": "15.0.0", "@oxlint/plugins": "1.82.0"},
            [
                _finding("commander", "15.0.0", "15.1.0", SemverTier.MINOR),
                _finding("@oxlint/plugins", "1.82.0", "1.93.0", SemverTier.MINOR),
            ],
            id="separator-between-rows",
        ),
    ],
)
def test_given_bun_report_when_bun_outdated_runs_then_declared_updates_are_returned(
    tmp_path, monkeypatch, stdout, declared, resolved, expected
):
    updates, commands = _run_bun_outdated(
        tmp_path, monkeypatch, stdout, declared, resolved
    )

    assert updates == expected
    assert commands.calls == [
        (
            ("bun", "outdated", "--no-progress"),
            tmp_path,
            {"timeout": 120, "label": "bun outdated", "error": OutdatedCheckError},
        )
    ]


@pytest.mark.parametrize(
    ("stdout", "stderr", "declared", "resolved", "message"),
    [
        pytest.param(
            _BUN_BANNER,
            "warn: something\n",
            None,
            None,
            "bun outdated: unexpected standard error: 'warn: something'",
            id="standard-error",
        ),
        pytest.param(
            "",
            "",
            None,
            None,
            "bun outdated: unrecognised output: no banner",
            id="empty",
        ),
        pytest.param(
            _BUN_TABLE,
            "",
            {"is-number"},
            {"is-number": "6.0.1"},
            "bun outdated: is-number is at 6.0.0, but bun pm ls resolves 6.0.1",
            id="resolved-differs",
        ),
        pytest.param(
            _BUN_TABLE,
            "",
            {"is-number"},
            {},
            "bun outdated: is-number is at 6.0.0, but bun pm ls resolves nothing",
            id="unresolved",
        ),
        pytest.param(
            _BUN_BANNER + "┌───────────┬─────────┬────────┬────────┐\n"
            "│ Package   │ Current │ Update │ Latest │\n"
            "├───────────┼─────────┼────────┼────────┤\n"
            "│ is-number │ 6.0.0   │ 6.0.0  │ 7.0.0  │\n"
            "└───────────┴─────────┴────────┴────────┘\n",
            "",
            None,
            None,
            _BUN_LINE_ERROR + repr("┌───────────┬─────────┬────────┬────────┐"),
            id="box-drawing",
        ),
        pytest.param(
            "\x1b[1mbun outdated\x1b[0m v1.4.2\n",
            "",
            None,
            None,
            _BUN_LINE_ERROR + repr("\x1b[1mbun outdated\x1b[0m v1.4.2"),
            id="ansi-banner",
        ),
        pytest.param(
            _BUN_TABLE.replace("| Package ", "| Name "),
            "",
            None,
            None,
            _BUN_LINE_ERROR + repr("| Name   | Current | Update | Latest |"),
            id="wrong-header",
        ),
        pytest.param(
            _BUN_TABLE.replace(_BUN_ROW, "| is-number | 6.0.0 |"),
            "",
            None,
            None,
            _BUN_LINE_ERROR + repr("| is-number | 6.0.0 |"),
            id="short-row",
        ),
        pytest.param(
            _BUN_TABLE.replace(_BUN_ROW, "|           | 6.0.0   | 6.0.0  | 7.0.0  |"),
            "",
            None,
            None,
            _BUN_LINE_ERROR + repr("|           | 6.0.0   | 6.0.0  | 7.0.0  |"),
            id="empty-package-cell",
        ),
        pytest.param(
            _BUN_TABLE.replace(_BUN_ROW, "| is-number |         | 6.0.0  | 7.0.0  |"),
            "",
            None,
            None,
            _BUN_LINE_ERROR + repr("| is-number |         | 6.0.0  | 7.0.0  |"),
            id="empty-current-cell",
        ),
        pytest.param(
            _BUN_TABLE.replace(_BUN_ROW, "| is-number | 6.0.0   | 6.0.0  |        |"),
            "",
            None,
            None,
            _BUN_LINE_ERROR + repr("| is-number | 6.0.0   | 6.0.0  |        |"),
            id="empty-latest-cell",
        ),
        pytest.param(
            _BUN_BANNER + "|---------------------------------------|\n"
            "| Package   | Current | Update | Latest |\n"
            "|-----------|---------|--------|--------|\n",
            "",
            None,
            None,
            "bun outdated: unrecognised output: table shorter than five lines",
            id="header-without-row",
        ),
        pytest.param(
            _BUN_BANNER + "|---------------------------------------|\n"
            f"{_BUN_ROW}\n"
            "|---------------------------------------|\n",
            "",
            None,
            None,
            "bun outdated: unrecognised output: table shorter than five lines",
            id="row-without-header",
        ),
        pytest.param(
            _BUN_TWO_ROWS.replace(f"{_BUN_ROW_SEPARATOR}\n| @oxlint", "| @oxlint"),
            "",
            None,
            None,
            _BUN_LINE_ERROR
            + repr("| @oxlint/plugins (dev) | 1.82.0  | 1.82.0 | 1.93.0 |"),
            id="rows-without-separator",
        ),
        pytest.param(
            _BUN_TWO_ROWS.replace(
                "| 1.93.0 |\n", f"| 1.93.0 |\n{_BUN_ROW_SEPARATOR}\n"
            ),
            "",
            None,
            None,
            _BUN_LINE_ERROR + repr(_BUN_ROW_SEPARATOR),
            id="separator-after-last-row",
        ),
        pytest.param(
            _BUN_TABLE + "1 update available\n",
            "",
            None,
            None,
            _BUN_LINE_ERROR + repr("1 update available"),
            id="trailing-line",
        ),
        pytest.param(
            _BUN_TABLE,
            "",
            BunDependencyError("Failed to read package.json: gone"),
            None,
            "Failed to read package.json: gone",
            id="manifest-error",
        ),
    ],
)
def test_given_unrecognised_bun_report_when_bun_outdated_runs_then_outdated_check_error(
    tmp_path, monkeypatch, stdout, stderr, declared, resolved, message
):
    with pytest.raises(OutdatedCheckError) as caught:
        _run_bun_outdated(tmp_path, monkeypatch, stdout, declared, resolved, stderr)

    assert str(caught.value) == message


_MVN_HEADER = (
    "[INFO] --- versions:2.25.1:display-dependency-updates (default-cli) @ child ---\n"
)
_MVN_MULTI_MODULE = (
    "[INFO] ----------------------------< probe:parent >----------------------------\n"
    "[INFO] Building parent 1                                                  [1/2]\n"
    "[INFO]   from pom.xml\n"
    "[INFO] --------------------------------[ pom ]---------------------------------\n"
    "[INFO] \n"
    "[INFO] --- versions:2.25.1:display-dependency-updates (default-cli) @ parent ---\n"
    "[INFO] \n"
    "[INFO] ----------------------------< probe:child >-----------------------------\n"
    "[INFO] Building child 1                                                   [2/2]\n"
    "[INFO]   from child/pom.xml\n"
    "[INFO] --------------------------------[ jar ]---------------------------------\n"
    "[INFO] \n"
    "[INFO] --- versions:2.25.1:display-dependency-updates (default-cli) @ child ---\n"
    "[INFO] The following dependencies in Dependencies have newer versions:\n"
    "[INFO]   org.slf4j:slf4j-api ........ 2.0.0 -> 2.1.0-alpha1\n"
    "[INFO] \n"
    "[INFO] ------------------------------------------------------------------------\n"
    "[INFO] Reactor Summary for parent 1:\n"
)
_MVN_SECTION = "[INFO] The following dependencies in Dependencies have newer versions:"
_MVN_ROW = "[INFO]   org.slf4j:slf4j-api ........ 2.0.0 -> 2.1.0-alpha1"
_MVN_RULE = (
    "[INFO] ------------------------------------------------------------------------"
)
_MVN_ERROR = "mvn versions:display-dependency-updates: unrecognised output"
_SLF4J_FINDING = _finding(
    "org.slf4j:slf4j-api", "2.0.0", "2.1.0-alpha1", SemverTier.MINOR
)


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        pytest.param(_MVN_MULTI_MODULE, [_SLF4J_FINDING], id="multi-module"),
        pytest.param(
            _MVN_HEADER + f"{_MVN_SECTION}\n{_MVN_ROW}\n[INFO] \n"
            f"{_MVN_RULE}\n[INFO] BUILD SUCCESS\n",
            [_SLF4J_FINDING],
            id="single-module",
        ),
        pytest.param(
            _MVN_HEADER
            + "[INFO] No dependencies in Dependencies have newer versions.\n[INFO] \n",
            [],
            id="no-updates",
        ),
        pytest.param(
            _MVN_HEADER
            + "[INFO] The following dependencies in Plugin Dependencies have newer"
            " versions:\n"
            "[INFO]   org.a:b .... 1.0 -> 2.0\n"
            "[INFO] \n",
            [],
            id="other-section",
        ),
        pytest.param(_MVN_HEADER, [], id="header-only"),
    ],
)
def test_given_maven_report_when_mvn_outdated_runs_then_dependency_updates_are_returned(
    tmp_path, monkeypatch, stdout, expected
):
    project = make_project(tmp_path, package_manager="mvn")
    commands = _fake_commands(project, completed(stdout=stdout))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)

    assert mvn_outdated(project) == expected
    assert commands.calls == [
        (
            (
                "mvn",
                "-B",
                "-ntp",
                "-Dstyle.color=never",
                "versions:display-dependency-updates",
                "-DprocessDependencyManagement=false",
                "-Dversions.outputLineWidth=1000",
            ),
            tmp_path,
            {
                "timeout": 300,
                "label": "mvn versions:display-dependency-updates",
                "error": OutdatedCheckError,
            },
        )
    ]


_OTHER_EXECUTION = "[INFO] --- other:1.0:report (default-cli) @ child ---"


@pytest.mark.parametrize(
    ("stdout", "quoted"),
    [
        pytest.param(
            _MVN_HEADER + f"{_MVN_SECTION}\n[INFO] \n",
            _MVN_SECTION,
            id="section-without-row",
        ),
        pytest.param(
            _MVN_HEADER + f"{_MVN_SECTION}\n", _MVN_SECTION, id="section-at-end"
        ),
        pytest.param(
            _MVN_HEADER + f"{_MVN_SECTION}\n{_MVN_ROW}\n[INFO] something else\n",
            "[INFO] something else",
            id="unknown-line-after-row",
        ),
        pytest.param(
            _MVN_HEADER + "[INFO] Checking for updates\n",
            "[INFO] Checking for updates",
            id="unknown-info-line",
        ),
        pytest.param(
            _MVN_HEADER + "[WARNING] The POM is invalid\n",
            "[WARNING] The POM is invalid",
            id="warning-line",
        ),
        pytest.param(
            _MVN_HEADER + f"[INFO] \n{_MVN_ROW}\n", _MVN_ROW, id="row-without-section"
        ),
        pytest.param(
            _MVN_HEADER + f"{_MVN_SECTION}\n{_MVN_ROW}\n[INFO] \n"
            f"{_OTHER_EXECUTION}\n{_MVN_SECTION}\n{_MVN_ROW}\n",
            _MVN_SECTION,
            id="section-in-other-execution",
        ),
        pytest.param(
            _MVN_HEADER.removeprefix("[INFO] ") + f"{_MVN_SECTION}\n{_MVN_ROW}\n",
            _MVN_SECTION,
            id="unprefixed-header",
        ),
        pytest.param(
            _MVN_HEADER + "--- end ---\n", "--- end ---", id="unprefixed-rule"
        ),
    ],
)
def test_given_unrecognised_maven_line_when_mvn_outdated_runs_then_it_is_quoted(
    tmp_path, monkeypatch, stdout, quoted
):
    project = make_project(tmp_path, package_manager="mvn")
    commands = _fake_commands(project, completed(stdout=stdout))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)

    with pytest.raises(OutdatedCheckError) as caught:
        mvn_outdated(project)

    assert str(caught.value) == f"{_MVN_ERROR} line: {quoted!r}"


def test_given_no_maven_execution_when_mvn_outdated_runs_then_outdated_check_error(
    tmp_path, monkeypatch
):
    project = make_project(tmp_path, package_manager="mvn")
    commands = _fake_commands(project, completed(stdout="[INFO] BUILD SUCCESS\n"))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)

    with pytest.raises(OutdatedCheckError) as caught:
        mvn_outdated(project)

    assert str(caught.value) == f"{_MVN_ERROR}: no display-dependency-updates execution"
