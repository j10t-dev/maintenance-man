"""Update and resolve lifecycles against real jj in disposable repositories."""

import shutil
from pathlib import Path

import pytest

from maintenance_man import updater, vcs_workflow
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import Operation, OperationFailed, Outcome
from maintenance_man.models.scan import UpdateStatus, Workflow
from maintenance_man.services import resolve as resolve_service
from maintenance_man.services import update as update_service
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs_workflow import VcsServices
from tests.fakes import RecordingEmit
from tests.support.findings import make_scan_result, make_update
from tests.support.projects import make_config, make_project
from tests.support.repository import (
    MANAGED,
    RepositoryCase,
    real_repository_case,
    run_jj,
)

FAILS_B = "test ! -e deps/pkg-b || test -e repair.txt"
RESOLVE_BOOKMARK = "mm/resolve-dependencies"


@pytest.fixture(autouse=True)
def _jj_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JJ_USER", "MM Tests")
    monkeypatch.setenv("JJ_EMAIL", "mm@example.invalid")


@pytest.fixture
def applied(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record each `bun add <pkg>@<version>`; write deps/<pkg> holding the version."""
    packages: list[str] = []

    def run(command: list[str], cwd: Path, **_: object) -> None:
        assert command[:2] == ["bun", "add"]
        package, version = command[2].rsplit("@", 1)
        packages.append(package)
        (Path(cwd) / "deps").mkdir(exist_ok=True)
        (Path(cwd) / "deps" / package).write_text(version, encoding="utf-8")

    monkeypatch.setattr(updater, "run_logged", run)
    return packages


def test_given_b_failing_when_updated_then_a_and_c_stay_pending_retry_applies_b(
    tmp_path: Path, applied: list[str]
) -> None:
    case, project = _bun_project(tmp_path, "api", FAILS_B)
    path = case.repo.path
    main_before = case.repo.resolve_revision(revision="main")

    first = _update(case, project)

    assert first.outcome is Outcome.FAILED
    assert [row.update_status for row in load_scan_results("api").updates] == [
        UpdateStatus.READY,
        UpdateStatus.FAILED,
        UpdateStatus.READY,
    ]
    assert case.repo.resolve_revision(revision="main") == main_before
    assert {"deps/pkg-a", "deps/pkg-c"} <= _files(path, MANAGED)
    assert "deps/pkg-b" not in _files(path, MANAGED)

    second = _update(case, project.model_copy(update={"test_unit": "true"}))

    assert second.outcome is Outcome.SUCCEEDED
    assert applied == ["pkg-a", "pkg-b", "pkg-c", "pkg-b"]
    assert case.repo.is_ancestor(ancestor=main_before, descendant="main")
    assert {"deps/pkg-a", "deps/pkg-b", "deps/pkg-c"} <= _files(path, "main")
    assert load_scan_results("api").updates == []
    assert not case.repo.bookmark_exists(bookmark=MANAGED)
    assert (path / "deps" / "pkg-b").is_file()


def test_given_main_moved_sideways_when_promoting_then_work_stays_pending_until_rebased(
    tmp_path: Path, applied: list[str]
) -> None:
    case, project = _bun_project(tmp_path, "api", FAILS_B)
    path = case.repo.path
    passing = project.model_copy(update={"test_unit": "true"})
    _update(case, project)
    assert run_jj(path, "new", "main").returncode == 0
    unrelated = case.commit_file("unrelated.txt", "x\n", "unrelated")
    case.repo.set_bookmark(bookmark="main", revision=unrelated)
    emit = RecordingEmit()

    second = _update(case, passing, emit)

    assert second.outcome is Outcome.FAILED
    failures = emit.of_type(OperationFailed)
    assert [event.operation for event in failures] == [Operation.PROMOTE]
    assert failures[0].error.endswith(
        f" · rebase with jj rebase -b {MANAGED} -d main, then rerun"
    )
    assert [row.update_status for row in load_scan_results("api").updates] == [
        UpdateStatus.READY
    ] * 3
    assert case.repo.resolve_revision(revision="main") == unrelated

    rebased = run_jj(path, "rebase", "-b", MANAGED, "-d", "main")
    assert rebased.returncode == 0, rebased.stderr
    applications = list(applied)

    third = _update(case, passing)

    assert third.outcome is Outcome.SUCCEEDED
    assert applied == applications
    assert {"unrelated.txt", "deps/pkg-a", "deps/pkg-b", "deps/pkg-c"} <= _files(
        path, "main"
    )


def test_given_pending_stack_when_resolve_takes_over_and_repairs_then_main_gets_all(
    tmp_path: Path, applied: list[str]
) -> None:
    case, project = _bun_project(tmp_path, "api", FAILS_B)
    path = case.repo.path
    _update(case, project)
    update_tip = case.repo.resolve_revision(revision=MANAGED)

    paused = _resolve(case, project, continue_=False)

    assert paused is Outcome.FAILED
    assert [
        (row.flow, row.update_status) for row in load_scan_results("api").updates
    ] == [
        (Workflow.RESOLVE, UpdateStatus.READY),
        (Workflow.RESOLVE, UpdateStatus.FAILED),
        (Workflow.RESOLVE, UpdateStatus.READY),
    ]
    assert case.repo.resolve_revision(revision=RESOLVE_BOOKMARK) == update_tip
    assert not case.repo.bookmark_exists(bookmark=MANAGED)
    assert (path / "deps" / "pkg-b").is_file()

    (path / "repair.txt").write_text("repaired\n", encoding="utf-8")
    committed = run_jj(path, "commit", "-m", "repair pkg-b")
    assert committed.returncode == 0, committed.stderr
    applications = list(applied)

    finished = _resolve(case, project, continue_=True)

    assert finished is Outcome.SUCCEEDED
    assert applied == applications == ["pkg-a", "pkg-b", "pkg-c", "pkg-b"]
    assert {"deps/pkg-a", "deps/pkg-b", "deps/pkg-c", "repair.txt"} <= _files(
        path, "main"
    )
    assert case.repo.is_ancestor(ancestor=update_tip, descendant="main")
    assert load_scan_results("api").findings == ()
    assert not case.repo.bookmark_exists(bookmark=MANAGED)
    assert not case.repo.bookmark_exists(bookmark=RESOLVE_BOOKMARK)


def test_given_cleanup_failure_when_batch_updated_then_next_project_promotes(
    tmp_path: Path, applied: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cases = {
        name: _bun_project(tmp_path, name, "true", packages="a")
        for name in ("api", "web")
    }
    real_rmtree = shutil.rmtree

    def rmtree(target: Path) -> None:
        if Path(target).name == "api" and Path(target).exists():
            msg = "device busy"
            raise OSError(msg)
        real_rmtree(target)

    monkeypatch.setattr(vcs_workflow.shutil, "rmtree", rmtree)
    emit = RecordingEmit()

    batch = update_service.update_projects(
        make_config(projects={name: project for name, (_, project) in cases.items()}),
        ["api", "web"],
        vcs=VcsServices(repository=cases["api"][0].bind),
        emit=emit,
    )

    assert [item.project for item in batch.projects] == ["api", "web"]
    assert [item.outcome for item in batch.projects] == [
        Outcome.FAILED,
        Outcome.SUCCEEDED,
    ]
    for case, _ in cases.values():
        assert "deps/pkg-a" in _files(case.repo.path, "main")
    assert [
        event.operation
        for event in emit.of_type(OperationFailed)
        if event.project == "api"
    ] == [Operation.WORKSPACE_CLEANUP]


def _bun_project(
    tmp_path: Path, name: str, test_unit: str, packages: str = "abc"
) -> tuple[RepositoryCase, ProjectConfig]:
    (tmp_path / name).mkdir()
    case = real_repository_case(tmp_path / name)
    case.commit_file("package.json", "{}\n", "add manifest")
    case.repo.set_bookmark(bookmark="main", revision="@-")
    scan = make_scan_result(
        vulns=[], updates=[make_update(pkg_name=f"pkg-{x}") for x in packages]
    )
    scan.project = name
    save_scan_results(name, scan)
    return case, make_project(
        case.repo.path, package_manager="bun", test_unit=test_unit
    )


def _update(
    case: RepositoryCase, project: ProjectConfig, emit: RecordingEmit | None = None
) -> update_service.ProjectUpdate:
    return update_service.update_project(
        "api",
        project,
        choose=None,
        vcs=VcsServices(repository=case.bind),
        emit=emit or RecordingEmit(),
    )


def _resolve(
    case: RepositoryCase, project: ProjectConfig, *, continue_: bool
) -> Outcome:
    return resolve_service.resolve_project(
        "api",
        project,
        continue_=continue_,
        vcs=VcsServices(repository=case.bind),
        emit=RecordingEmit(),
    )


def _files(path: Path, revision: str) -> set[str]:
    listed = run_jj(path, "file", "list", "-r", revision)
    assert listed.returncode == 0, listed.stderr
    return set(listed.stdout.split())
