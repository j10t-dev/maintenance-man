import time
from collections.abc import Sequence
from dataclasses import dataclass

from maintenance_man.config import ordered_unique_project_names
from maintenance_man.gradle import GradleError
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.events import (
    Emit,
    OperationFailed,
    Outcome,
    ScanReported,
    SyncCompleted,
)
from maintenance_man.models.scan import ScanResult
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.process import ToolNotFoundError
from maintenance_man.scanner import ScanError, scan_project
from maintenance_man.services import report_missing_path
from maintenance_man.vcs import JjRepository, RevisionError
from maintenance_man.vcs_workflow import sync_main

SCAN_ERRORS = (
    ScanError,
    GradleError,
    OutdatedCheckError,
    ToolNotFoundError,
)


@dataclass(frozen=True, slots=True)
class ScanSummary:
    has_vulns: bool
    has_updates: bool
    had_error: bool = False
    clean: tuple[str, ...] = ()


def scan_one(
    project_name: str,
    project: ProjectConfig,
    *,
    minimum_age_days: int,
    emit: Emit,
) -> ScanResult:
    started = time.monotonic()
    result = scan_project(project_name, project, minimum_age_days)
    emit(ScanReported(result, time.monotonic() - started))
    return result


def scan_all(cfg: MmConfig, *, emit: Emit) -> ScanSummary:
    results: list[ScanResult] = []
    clean: list[str] = []
    had_error = False
    for project_name, project in cfg.projects.items():
        if report_missing_path(project_name, project, emit=emit):
            had_error = True
            continue
        try:
            result = scan_one(
                project_name,
                project,
                minimum_age_days=cfg.defaults.min_version_age_days,
                emit=emit,
            )
        except SCAN_ERRORS as exc:
            emit(OperationFailed("scan", project_name, str(exc)))
            had_error = True
            continue
        results.append(result)
        if not result.has_findings:
            clean.append(project_name)
    return ScanSummary(
        any(result.has_actionable_vulns for result in results),
        any(result.updates for result in results),
        had_error,
        tuple(clean),
    )


def sync_projects(
    cfg: MmConfig,
    project_names: Sequence[str],
    *,
    emit: Emit,
) -> Outcome:
    targets = ordered_unique_project_names(cfg, project_names) or sorted(cfg.projects)
    failed = False
    for project_name in targets:
        project = cfg.projects[project_name]
        if report_missing_path(project_name, project, emit=emit):
            failed = True
            continue
        try:
            action = sync_main(repo=JjRepository(project.path))
        except RevisionError as exc:
            emit(OperationFailed("sync", project_name, str(exc)))
            failed = True
        else:
            emit(SyncCompleted(project_name, action.value))
    return Outcome.FAILED if failed else Outcome.SUCCEEDED
