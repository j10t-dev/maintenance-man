from __future__ import annotations

from pathlib import Path

import pytest

from maintenance_man.config import ProjectNotFoundError
from maintenance_man.models.events import (
    Operation,
    OperationFailed,
    Outcome,
    ProjectSkipped,
    ScanReported,
    SkipReason,
    SyncCompleted,
)
from maintenance_man.models.scan import Severity, VulnFinding
from maintenance_man.scanner import ScanError
from maintenance_man.services import scan as scan_service
from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import SyncAction, VcsServices
from tests.conftest import make_config, make_project, make_scan_result
from tests.fake_vcs import FakeJjState
from tests.fakes import RecordingEmit


def _services(*paths: Path) -> VcsServices:
    state = FakeJjState()
    for path in paths:
        state.seed_repository(path, files={"dep.txt": "version=1\n"})
    return state.services()


def test_scan_all_continues_after_failure_and_summarises_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = {}
    for name in ("first", "second", "third"):
        path = tmp_path / name
        path.mkdir()
        projects[name] = make_project(path)
    cfg = make_config(projects=projects)
    first = make_scan_result(updates=[])
    first.project = "first"
    third = make_scan_result(vulns=[], updates=[])
    third.project = "third"

    def fake_scan(name, project, minimum_age_days, *, vcs):
        del project, minimum_age_days, vcs
        if name == "second":
            msg = "boom"
            raise ScanError(msg)
        return {"first": first, "third": third}[name]

    monkeypatch.setattr(scan_service, "require_vcs_tools", lambda: None)
    monkeypatch.setattr(scan_service, "prune_stale_bookmarks", lambda **kwargs: None)
    monkeypatch.setattr(scan_service, "scan_project", fake_scan)
    ticks = iter([1.0, 1.25, 2.0, 3.0, 3.5])
    monkeypatch.setattr(scan_service.time, "monotonic", lambda: next(ticks))
    recorded = RecordingEmit()

    summary = scan_service.scan_all(
        cfg,
        vcs=_services(*(project.path for project in projects.values())),
        emit=recorded,
    )

    assert recorded.events == [
        ScanReported(first, 0.25),
        OperationFailed(Operation.SCAN, "second", "boom"),
        ScanReported(third, 0.5),
    ]
    assert summary == scan_service.ScanSummary(
        has_vulns=True, has_updates=False, had_error=True
    )


def test_scan_all_skips_missing_path_without_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    cfg = make_config(projects={"ghost": make_project(missing)})
    recorded = RecordingEmit()

    summary = scan_service.scan_all(cfg, vcs=_services(), emit=recorded)

    assert recorded.events == [
        ProjectSkipped("ghost", SkipReason.PATH_MISSING, str(missing))
    ]
    assert summary == scan_service.ScanSummary(False, False, False)


def test_scan_one_reports_remote_sync_failure_then_scans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "project"
    path.mkdir()
    result = make_scan_result(vulns=[], updates=[])
    result.project = "demo"
    monkeypatch.setattr(scan_service, "require_vcs_tools", lambda: None)
    monkeypatch.setattr(
        scan_service,
        "prune_stale_bookmarks",
        lambda **kwargs: (_ for _ in ()).throw(RevisionError("offline")),
    )
    monkeypatch.setattr(scan_service, "scan_project", lambda *args, **kwargs: result)
    ticks = iter([1.0, 1.5])
    monkeypatch.setattr(scan_service.time, "monotonic", lambda: next(ticks))
    recorded = RecordingEmit()

    actual = scan_service.scan_one(
        "demo",
        make_project(path),
        minimum_age_days=7,
        vcs=_services(path),
        emit=recorded,
    )

    assert actual is result
    assert recorded.events == [
        OperationFailed(Operation.REMOTE_SYNC, "demo", "offline"),
        ScanReported(result, 0.5),
    ]


def test_scan_summary_ignores_blocked_vulnerability_without_fix() -> None:
    result = make_scan_result(
        vulns=[
            VulnFinding(
                vuln_id="CVE-no-fix",
                pkg_name="blocked",
                installed_version="1",
                fixed_version=None,
                severity=Severity.HIGH,
                title="No fix",
                description="No published fix",
                status="affected",
                blocked_reason="no fixed version",
            )
        ],
        updates=[],
    )

    assert scan_service.ScanSummary.of(result) == scan_service.ScanSummary(False, False)


def test_sync_projects_deduplicates_names_and_emits_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = {name: tmp_path / name for name in ("a", "b")}
    for path in paths.values():
        path.mkdir()
    cfg = make_config(
        projects={name: make_project(path) for name, path in paths.items()}
    )
    synced: list[Path] = []

    def fake_sync(*, repo):
        synced.append(repo.path)
        return SyncAction.UNCHANGED

    monkeypatch.setattr(scan_service, "sync_main", fake_sync)
    recorded = RecordingEmit()

    outcome = scan_service.sync_projects(
        cfg, ["b", "a", "b"], vcs=_services(*paths.values()), emit=recorded
    )

    assert outcome is Outcome.SUCCEEDED
    assert synced == [paths["b"], paths["a"]]
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

    outcome = scan_service.sync_projects(cfg, ["a"], vcs=_services(path), emit=recorded)

    assert outcome is Outcome.FAILED
    assert recorded.events == [OperationFailed(Operation.SYNC, "a", "offline")]


def test_sync_projects_missing_path_is_failure(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    cfg = make_config(projects={"ghost": make_project(missing)})
    recorded = RecordingEmit()

    outcome = scan_service.sync_projects(cfg, [], vcs=_services(), emit=recorded)

    assert outcome is Outcome.FAILED
    assert recorded.events == [
        ProjectSkipped("ghost", SkipReason.PATH_MISSING, str(missing))
    ]


def test_sync_projects_rejects_unknown_name(tmp_path: Path) -> None:
    path = tmp_path / "a"
    path.mkdir()
    cfg = make_config(projects={"a": make_project(path)})

    with pytest.raises(ProjectNotFoundError, match="Unknown project 'missing'"):
        scan_service.sync_projects(
            cfg, ["missing"], vcs=_services(), emit=RecordingEmit()
        )
