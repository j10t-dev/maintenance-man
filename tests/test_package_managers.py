from pathlib import Path
from typing import cast, get_args

import pytest

from maintenance_man.models.config import ProjectConfig
from maintenance_man.outdated import bun_outdated, mvn_outdated, uv_outdated
from maintenance_man.package_managers import (
    PACKAGE_MANAGERS,
    PackageManagerOps,
    UnsupportedPackageManagerError,
    UpdateCommandError,
    package_manager_ops,
)


def test_table_covers_every_configurable_manager_except_gradle():
    annotation = ProjectConfig.model_fields["package_manager"].annotation
    assert set(PACKAGE_MANAGERS) == set(get_args(annotation)) - {"gradle"}


def test_table_is_read_only():
    with pytest.raises(TypeError):
        cast("dict[str, PackageManagerOps]", PACKAGE_MANAGERS)["pip"] = (
            PACKAGE_MANAGERS["uv"]
        )


@pytest.mark.parametrize(
    ("name", "source", "outdated", "publication"),
    [
        ("bun", "trivy", bun_outdated, "npm"),
        ("uv", "uv-audit", uv_outdated, "pypi"),
        ("mvn", "trivy", mvn_outdated, "central"),
    ],
)
def test_entry_scan_operations(name, source, outdated, publication):
    ops = package_manager_ops(name)
    assert ops.vulnerability_source == source
    assert ops.outdated is outdated
    assert ops.publication_source == publication


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("gradle", "Gradle updates are applied through the Gradle adapter"),
        ("npm", "Unsupported package manager: npm"),
    ],
)
def test_managers_outside_the_table_are_unsupported(name, message):
    with pytest.raises(UnsupportedPackageManagerError, match=message):
        package_manager_ops(name)


def test_bun_update_refuses_a_workspace_without_a_manifest(tmp_path: Path):
    with pytest.raises(UpdateCommandError, match=r"package.json"):
        package_manager_ops("bun").update_commands("zod", "4.6.5", tmp_path)


@pytest.mark.parametrize(
    ("pyproject_text", "pkg", "version", "expected_commands"),
    [
        (
            '[project]\ndependencies = ["requests>=2.28"]\n',
            "requests",
            "2.33.1",
            [["uv", "add", "requests==2.33.1"]],
        ),
        (
            "[project]\ndependencies = []\n\n"
            '[dependency-groups]\ndev = ["pytest>=8.0"]\n',
            "pytest",
            "9.0.3",
            [["uv", "add", "--group", "dev", "pytest==9.0.3"]],
        ),
        (
            "[project]\ndependencies = []\n\n"
            '[dependency-groups]\nlint = ["ruff>=0.9.0"]\n',
            "ruff",
            "0.13.0",
            [["uv", "add", "--group", "lint", "ruff==0.13.0"]],
        ),
        (
            "[project]\ndependencies = []\n\n"
            '[project.optional-dependencies]\ncli = ["rich>=14.0"]\n',
            "rich",
            "14.3.3",
            [["uv", "lock", "--upgrade-package", "rich"]],
        ),
        (
            '[project]\ndependencies = ["pytest>=8.0"]\n\n'
            '[dependency-groups]\ndev = ["pytest>=8.0"]\n',
            "pytest",
            "9.0.3",
            [
                ["uv", "add", "pytest==9.0.3"],
                ["uv", "add", "--group", "dev", "pytest==9.0.3"],
            ],
        ),
        (
            '[project]\ndependencies = ["requests>=2.28"]\n',
            "urllib3",
            "2.7.0",
            [["uv", "lock", "--upgrade-package", "urllib3"]],
        ),
    ],
)
def test_given_uv_declaration_when_commands_built_then_matching_commands_returned(
    tmp_path: Path, pyproject_text, pkg, version, expected_commands
):
    (tmp_path / "pyproject.toml").write_text(pyproject_text, encoding="utf-8")

    commands = package_manager_ops("uv").update_commands(pkg, version, tmp_path)

    assert commands == expected_commands


def test_given_bun_dependency_when_update_commands_are_built_then_bun_add_is_returned(
    tmp_path: Path,
):
    (tmp_path / "package.json").write_text('{"dependencies":{"axios":"1.6.0"}}')

    commands = package_manager_ops("bun").update_commands("axios", "1.7.0", tmp_path)

    assert commands == [["bun", "add", "axios@1.7.0"]]


def test_given_maven_dependency_when_commands_built_then_versions_commands_returned(
    tmp_path: Path,
):
    commands = package_manager_ops("mvn").update_commands(
        "org.example:lib", "3.0.0", tmp_path
    )

    assert commands == [
        [
            "mvn",
            "versions:use-dep-version",
            "-Dincludes=org.example:lib",
            "-DdepVersion=3.0.0",
        ],
        ["mvn", "versions:commit"],
    ]


def test_given_unreadable_pyproject_when_uv_commands_built_then_error_raised(
    tmp_path: Path,
):
    with pytest.raises(UpdateCommandError, match="Failed to read"):
        package_manager_ops("uv").update_commands("pytest", "9.0.3", tmp_path)
