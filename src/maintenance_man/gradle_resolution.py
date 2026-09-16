"""Structured Gradle resolution and catalogue ownership; no lifecycle state."""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    Catalogue,
    GradleError,
    _validate_inventory,
    owned_gradle_inventory,
    run_gradle,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    CompleteResolution,
    IncompleteResolution,
    ResolutionOutcome,
    ResolutionReport,
)


def parse_resolution_report(text: str) -> ResolutionOutcome:
    try:
        report = ResolutionReport.model_validate_json(text)
        if not re.fullmatch(r"[0-9a-f]{64}", report.catalogue_digest):
            raise ValueError("invalid catalogue digest")
        for scope in report.selected_scopes:
            if not scope.project_path.startswith(":") or not scope.configuration:
                raise ValueError("invalid scope identity")
        for repository in report.repositories:
            if repository.url is not None:
                url = urlsplit(repository.url)
                if url.username or url.password or url.query or url.fragment:
                    raise ValueError(
                        "repository report contains private or ambiguous URL"
                    )
        for scope in report.scopes:
            for component in scope.components:
                if not component.id:
                    raise ValueError("empty component ID")
                if component.module is not None:
                    if any(
                        not value or re.search(r"[\s:/\\]", value)
                        for value in (
                            component.module.group,
                            component.module.artifact,
                            component.module.version,
                        )
                    ):
                        raise ValueError("invalid Maven identity")
    except (ValidationError, ValueError) as exc:
        raise GradleError(f"Malformed Gradle resolution report: {exc}") from exc
    reasons = list(report.selection_errors)
    actual = {scope.scope for scope in report.scopes}
    reasons.extend(
        f"Missing selected scope: {scope}"
        for scope in report.selected_scopes
        if scope not in actual
    )
    reasons.extend(
        f"{scope.scope}: {message}"
        for scope in report.scopes
        for message in scope.unresolved
    )
    if reasons:
        return IncompleteResolution(report=report, reasons=tuple(reasons))
    return CompleteResolution(report=report)


def _script(directory: Path) -> Path:
    script = directory / "gradle-report.gradle"
    script.write_bytes(
        files("maintenance_man.resources").joinpath("gradle-report.gradle").read_bytes()
    )
    return script


@contextmanager
def generate_gradle_report(
    project: ProjectConfig,
) -> Iterator[tuple[Path, ResolutionOutcome]]:
    root = Path(project.path)
    before = hashlib.sha256((root / GRADLE_CATALOGUE_RELPATH).read_bytes()).hexdigest()
    with owned_gradle_inventory(project) as directory:
        try:
            script = _script(directory)
            report_started = time.monotonic()
            run_gradle(
                root,
                [
                    "mmGradleReport",
                    "--init-script",
                    str(script),
                    "--no-daemon",
                    "--console=plain",
                    "--rerun-tasks",
                    "--no-build-cache",
                ],
                label="mmGradleReport",
            )
            logging.getLogger(__name__).info(
                "Gradle graph/inventory %.3fs", time.monotonic() - report_started
            )
            bom = directory / "bom.json"
            report_path = directory / "report.json"
            if bom.is_symlink() or report_path.is_symlink():
                raise GradleError("Gradle report output is a symlink")
            _validate_inventory(bom)
            outcome = parse_resolution_report(report_path.read_text(encoding="utf-8"))
            after = hashlib.sha256(
                (root / GRADLE_CATALOGUE_RELPATH).read_bytes()
            ).hexdigest()
            if before != after or outcome.report.catalogue_digest != before:
                raise GradleError("Catalogue changed during report generation")
            yield bom, outcome
        except (OSError, UnicodeError) as exc:
            raise GradleError(f"Could not capture Gradle resolution: {exc}") from exc


def collect_gradle_resolution(
    project: ProjectConfig, catalogue: Catalogue
) -> ResolutionOutcome:
    # The caller's catalogue participates in selection; digest validation binds
    # this report to the source file. No graph is reconstructed from TOML.
    with generate_gradle_report(project) as (_, outcome):
        return outcome
