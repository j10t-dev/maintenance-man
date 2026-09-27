import subprocess
from datetime import UTC, datetime
from typing import cast, get_args

import pytest

from maintenance_man import dependency_age
from maintenance_man.models.config import ProjectConfig
from maintenance_man.outdated import bun_outdated, mvn_outdated, uv_outdated
from maintenance_man.package_managers import (
    PACKAGE_MANAGERS,
    PackageManagerOps,
    UnsupportedPackageManagerError,
    package_manager_ops,
)

_OLD = datetime(2024, 1, 1, tzinfo=UTC)


def test_table_covers_every_configurable_manager_except_gradle():
    annotation = ProjectConfig.model_fields["package_manager"].annotation
    assert set(PACKAGE_MANAGERS) == set(get_args(annotation)) - {"gradle"}


def test_table_is_read_only():
    with pytest.raises(TypeError):
        cast("dict[str, PackageManagerOps]", PACKAGE_MANAGERS)["pip"] = (
            PACKAGE_MANAGERS["uv"]
        )


@pytest.mark.parametrize(
    ("name", "source", "outdated"),
    [
        ("bun", "trivy", bun_outdated),
        ("uv", "uv-audit", uv_outdated),
        ("mvn", "trivy", mvn_outdated),
    ],
)
def test_entry_scan_operations(name, source, outdated):
    ops = package_manager_ops(name)
    assert ops.vulnerability_source == source
    assert ops.outdated is outdated


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


def test_bun_publish_date_runs_bun_info_in_the_project(tmp_path, monkeypatch):
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs["cwd"]))
        return subprocess.CompletedProcess(
            cmd, 0, "zod@4.0.0 | MIT\nPublished: 2024-01-02T03:04:05Z\n", ""
        )

    monkeypatch.setattr("maintenance_man.process.subprocess.run", run)
    published = package_manager_ops("bun").publish_date("zod", "4.0.0", tmp_path)
    assert published == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert calls == [(["bun", "info", "zod@4.0.0"], tmp_path)]


@pytest.mark.parametrize(
    ("name", "lookup"),
    [("uv", "get_pypi_publish_date"), ("mvn", "get_maven_publish_date")],
)
def test_registry_publish_dates_receive_package_and_version(
    tmp_path, monkeypatch, name, lookup
):
    seen = []

    def fake(pkg, version):
        seen.append((pkg, version))
        return _OLD

    monkeypatch.setattr(dependency_age, lookup, fake)
    assert package_manager_ops(name).publish_date("g:a", "1.0", tmp_path) == _OLD
    assert seen == [("g:a", "1.0")]
