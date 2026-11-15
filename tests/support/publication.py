"""Publication fixtures shared by the dependency-age and scanner tests."""

import json
from collections.abc import Sequence
from pathlib import Path

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import RepositoryDeclaration, ResolutionReport
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    SemverTier,
    UpdateFinding,
)
from tests.support.findings import make_update
from tests.support.gradle import make_resolution_report

DEFAULT_GRADLE_MEMBER_SPECS = (("library", "one", "g:one"),)
DEFAULT_GRADLE_REPOSITORY_SPECS = (
    ("library", "https://repo.maven.apache.org/maven2"),
    ("library", "https://dl.google.com/dl/android/maven2"),
)


def scan_age_inputs(
    tmp_path: Path,
    *,
    member_specs=DEFAULT_GRADLE_MEMBER_SPECS,
    repository_specs=DEFAULT_GRADLE_REPOSITORY_SPECS,
) -> tuple[UpdateFinding, ProjectConfig, ResolutionReport]:
    """A Gradle update with its project and a report declaring the repositories."""
    target = GradleUpdateTarget(
        version_ref="shared",
        target_version="2",
        members=[
            GradleMember(
                kind=kind,
                alias=alias,
                coordinate=coordinate,
                installed_version="1",
            )
            for kind, alias, coordinate in member_specs
        ],
    )
    update = make_update(
        SemverTier.MINOR, pkg_name="shared", latest_version="2"
    ).model_copy(update={"gradle_target": target})
    project = ProjectConfig(
        path=tmp_path,
        package_manager="gradle",
        gradle_repository_routing="standard-public",
    )
    report = make_resolution_report(
        scopes={},
        repositories=[
            RepositoryDeclaration(project_path=":", domain=domain, url=url)
            for domain, url in repository_specs
        ],
    )
    return update, project, report


def pypi_body(
    name: str = "pkg",
    version: str = "1.0",
    uploads: Sequence[object] = ("2025-12-31T00:00:00Z",),
) -> bytes:
    """A PyPI release document uploaded at each of *uploads*."""
    return json.dumps(
        {
            "info": {"name": name, "version": version},
            "urls": [{"upload_time_iso_8601": value} for value in uploads],
        }
    ).encode()
