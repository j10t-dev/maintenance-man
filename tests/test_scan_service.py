from pathlib import Path

import pytest

from maintenance_man.config import ProjectNotFoundError
from maintenance_man.gradle import GradleError
from maintenance_man.models.events import (
    OperationFailed,
    Outcome,
    ProjectSkipped,
    ScanReported,
    SkipReason,
    SyncCompleted,
)
from maintenance_man.scanner import ScanError
from maintenance_man.services import scan as scan_service
from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import SyncAction
from tests.fakes import RecordingEmit
from tests.support.findings import make_scan_result
from tests.support.projects import make_config, make_project


def test_scan_all_continues_after_failure_and_summarises_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = {}
    for name in ("first", "second", "third", "fourth"):
        path = tmp_path / name
        path.mkdir()
        projects[name] = make_project(path)
    cfg = make_config(projects=projects)
    first = make_scan_result(updates=[])
    first.project = "first"
    third = make_scan_result(vulns=[], updates=[])
    third.project = "third"

    def fake_scan(name, project, minimum_age_days):
        del project, minimum_age_days
        if name == "second":
            msg = "boom"
            raise ScanError(msg)
        if name == "fourth":
            msg = "gradle boom"
            raise GradleError(msg)
        return {"first": first, "third": third}[name]

    monkeypatch.setattr(scan_service, "scan_project", fake_scan)
    ticks = iter([1.0, 1.25, 2.0, 3.0, 3.5, 4.0])
    monkeypatch.setattr(scan_service.time, "monotonic", lambda: next(ticks))
    recorded = RecordingEmit()

    summary = scan_service.scan_all(cfg, emit=recorded)

    assert recorded.events == [
        ScanReported(first, 0.25),
        OperationFailed("scan", "second", "boom"),
        ScanReported(third, 0.5),
        OperationFailed("scan", "fourth", "gradle boom"),
    ]
    assert summary == scan_service.ScanSummary(
        has_vulns=True, has_updates=False, had_error=True, clean=("third",)
    )


def test_scan_all_skips_missing_path_without_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    cfg = make_config(projects={"ghost": make_project(missing)})
    recorded = RecordingEmit()

    summary = scan_service.scan_all(cfg, emit=recorded)

    assert recorded.events == [
        ProjectSkipped("ghost", SkipReason.PATH_MISSING, str(missing))
    ]
    assert summary == scan_service.ScanSummary(False, False, False)


def test_sync_projects_deduplicates_names_and_emits_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = {name: tmp_path / name for name in ("a", "b")}
    for path in paths.values():
        path.mkdir()
    cfg = make_config(
        projects={name: make_project(path) for name, path in paths.items()}
    )
    monkeypatch.setattr(scan_service, "sync_main", lambda *, repo: SyncAction.UNCHANGED)
    recorded = RecordingEmit()

    outcome = scan_service.sync_projects(cfg, ["b", "a", "b"], emit=recorded)

    assert outcome is Outcome.SUCCEEDED
    assert recorded.events == [
        SyncCompleted("b", "already up to date"),
        SyncCompleted("a", "already up to date"),
    ]


def test_sync_projects_reports_revision_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a"
    path.mkdir()
    cfg = make_config(projects={"a": make_project(path)})
    monkeypatch.setattr(
        scan_service,
        "sync_main",
        lambda **kwargs: (_ for _ in ()).throw(RevisionError("offline")),
    )
    recorded = RecordingEmit()

    outcome = scan_service.sync_projects(cfg, ["a"], emit=recorded)

    assert outcome is Outcome.FAILED
    assert recorded.events == [OperationFailed("sync", "a", "offline")]


def test_sync_projects_missing_path_is_failure(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    cfg = make_config(projects={"ghost": make_project(missing)})
    recorded = RecordingEmit()

    outcome = scan_service.sync_projects(cfg, [], emit=recorded)

    assert outcome is Outcome.FAILED
    assert recorded.events == [
        ProjectSkipped("ghost", SkipReason.PATH_MISSING, str(missing))
    ]


def test_sync_projects_rejects_unknown_name(tmp_path: Path) -> None:
    path = tmp_path / "a"
    path.mkdir()
    cfg = make_config(projects={"a": make_project(path)})

    with pytest.raises(ProjectNotFoundError, match="Unknown project 'missing'"):
        scan_service.sync_projects(cfg, ["missing"], emit=RecordingEmit())
