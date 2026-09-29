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
    _uv_update_command,
    package_manager_ops,
)
from maintenance_man.uv_dependencies import UvDependencyLocation


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
    assert not (tmp_path / "package.json").exists()


class TestUpdateCommands:
    def test_uv_runtime_dependency(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests>=2.28"]\n', encoding="utf-8"
        )

        assert package_manager_ops("uv").update_commands(
            "requests", "2.33.1", tmp_path
        ) == [["uv", "add", "requests==2.33.1"]]

    def test_uv_dev_dependency_group(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = []\n\n"
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0"]\n',
            encoding="utf-8",
        )

        assert package_manager_ops("uv").update_commands(
            "pytest", "9.0.3", tmp_path
        ) == [["uv", "add", "--group", "dev", "pytest==9.0.3"]]

    def test_uv_custom_dependency_group(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = []\n\n"
            "[dependency-groups]\n"
            'lint = ["ruff>=0.9.0"]\n',
            encoding="utf-8",
        )

        assert package_manager_ops("uv").update_commands(
            "ruff", "0.13.0", tmp_path
        ) == [["uv", "add", "--group", "lint", "ruff==0.13.0"]]

    def test_uv_optional_dependency_uses_lock_upgrade(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = []\n\n"
            "[project.optional-dependencies]\n"
            'cli = ["rich>=14.0"]\n',
            encoding="utf-8",
        )

        assert package_manager_ops("uv").update_commands(
            "rich", "14.3.3", tmp_path
        ) == [["uv", "lock", "--upgrade-package", "rich"]]

    def test_uv_runtime_and_group_dependency(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["pytest>=8.0"]\n\n'
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0"]\n',
            encoding="utf-8",
        )

        assert package_manager_ops("uv").update_commands(
            "pytest", "9.0.3", tmp_path
        ) == [
            ["uv", "add", "pytest==9.0.3"],
            ["uv", "add", "--group", "dev", "pytest==9.0.3"],
        ]

    def test_uv_missing_declaration_uses_lock_upgrade(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests>=2.28"]\n', encoding="utf-8"
        )

        assert package_manager_ops("uv").update_commands(
            "urllib3", "2.7.0", tmp_path
        ) == [["uv", "lock", "--upgrade-package", "urllib3"]]

    @pytest.mark.parametrize(
        ("manager", "pkg", "version", "expected"),
        [
            pytest.param(
                "bun",
                "axios",
                "1.7.0",
                [["bun", "add", "axios@1.7.0"]],
                id="bun",
            ),
            pytest.param(
                "mvn",
                "org.example:lib",
                "3.0.0",
                [
                    [
                        "mvn",
                        "versions:use-dep-version",
                        "-Dincludes=org.example:lib",
                        "-DdepVersion=3.0.0",
                    ],
                    ["mvn", "versions:commit"],
                ],
                id="mvn",
            ),
        ],
    )
    def test_bun_and_mvn_commands(
        self, tmp_path: Path, manager, pkg, version, expected
    ):
        if manager == "bun":
            (tmp_path / "package.json").write_text('{"dependencies":{"axios":"1.6.0"}}')
        assert (
            package_manager_ops(manager).update_commands(pkg, version, tmp_path)
            == expected
        )

    def test_uv_group_command_requires_group_name(self):
        with pytest.raises(
            UpdateCommandError,
            match="group dependency location missing",
        ):
            _uv_update_command(
                "pytest",
                "9.0.3",
                UvDependencyLocation(kind="group"),
            )

    def test_uv_unreadable_pyproject_is_an_update_command_error(self, tmp_path):
        with pytest.raises(UpdateCommandError, match="Failed to read"):
            package_manager_ops("uv").update_commands("pytest", "9.0.3", tmp_path)
