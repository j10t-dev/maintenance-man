from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass

from maintenance_man.config import validate_project_names
from maintenance_man.github import CodeHostError
from maintenance_man.gradle import GradleError
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.events import (
    Emit,
    Operation,
    OperationFailed,
    Outcome,
    ProjectSkipped,
    ScanReported,
    SkipReason,
    SyncCompleted,
)
from maintenance_man.models.scan import ScanResult
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.process import ToolNotFoundError
from maintenance_man.scanner import ScanError, scan_project
from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import (
    VcsServices,
    prune_stale_bookmarks,
    require_vcs_tools,
    sync_main,
)

SCAN_ERRORS = (
    ScanError,
    GradleError,
    RevisionError,
    OutdatedCheckError,
    ToolNotFoundError,
)


@dataclass(frozen=True, slots=True)
class ScanSummary:
    has_vulns: bool
    has_updates: bool
    had_error: bool = False

    @classmethod
    def of(cls, result: ScanResult) -> ScanSummary:
        return cls(
            has_vulns=result.has_actionable_vulns,
            has_updates=result.has_updates,
        )


def scan_one(
    name: str,
    project: ProjectConfig,
    *,
    minimum_age_days: int,
    vcs: VcsServices,
    emit: Emit,
) -> ScanResult:
    try:
        require_vcs_tools()
        prune_stale_bookmarks(
            repo=vcs.repository(project.path), host=vcs.code_host(project.path)
        )
    except (ToolNotFoundError, RevisionError, CodeHostError) as exc:
        emit(OperationFailed(Operation.REMOTE_SYNC, name, str(exc)))

    started = time.monotonic()
    result = scan_project(name, project, minimum_age_days, vcs=vcs)
    emit(ScanReported(result, time.monotonic() - started))
    return result


def scan_all(cfg: MmConfig, *, vcs: VcsServices, emit: Emit) -> ScanSummary:
    summary = ScanSummary(False, False)
    for name, project in cfg.projects.items():
        if not project.path.exists():
            emit(ProjectSkipped(name, SkipReason.PATH_MISSING, str(project.path)))
            continue
        try:
            result = scan_one(
                name,
                project,
                minimum_age_days=cfg.defaults.min_version_age_days,
                vcs=vcs,
                emit=emit,
            )
        except SCAN_ERRORS as exc:
            emit(OperationFailed(Operation.SCAN, name, str(exc)))
            summary = ScanSummary(summary.has_vulns, summary.has_updates, True)
            continue
        summary = ScanSummary(
            summary.has_vulns or result.has_actionable_vulns,
            summary.has_updates or result.has_updates,
            summary.had_error,
        )
    return summary


def sync_projects(
    cfg: MmConfig,
    names: Sequence[str],
    *,
    vcs: VcsServices,
    emit: Emit,
) -> Outcome:
    targets = validate_project_names(cfg, names) or sorted(cfg.projects)
    failed = False
    for name in targets:
        project = cfg.projects[name]
        if not project.path.exists():
            emit(ProjectSkipped(name, SkipReason.PATH_MISSING, str(project.path)))
            failed = True
            continue
        try:
            action = sync_main(repo=vcs.repository(project.path))
        except RevisionError as exc:
            emit(OperationFailed(Operation.SYNC, name, str(exc)))
            failed = True
        else:
            emit(SyncCompleted(name, action.value))
    return Outcome.FAILED if failed else Outcome.SUCCEEDED
