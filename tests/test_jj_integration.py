"""Update and resolve lifecycles against real jj in disposable repositories."""

import shutil
from pathlib import Path

import pytest

from maintenance_man import updater, vcs_workflow
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import OperationFailed, Outcome, PromotionFailed
from maintenance_man.models.scan import Failed, Ready, Workflow
from maintenance_man.services import resolve as resolve_service
from maintenance_man.services import update as update_service
from maintenance_man.storage import load_scan_results, save_scan_results
from maintenance_man.vcs import JjRepository
from tests.fakes import RecordingEmit
from tests.support.findings import make_scan_result, make_update
from tests.support.projects import make_config, make_project
from tests.support.repository import (
    MANAGED,
    commit_file,
    commit_to_main,
    copy_jj_repository,
    run_jj,
    write_file,
)

FAILS_B = "test ! -e deps/pkg-b || test -e repair.txt"
RESOLVE_BOOKMARK = "mm/resolve-dependencies"


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
    repo, project = _bun_project(tmp_path, "api", FAILS_B)
    path = repo.path
    main_before = repo.resolve_revision(revision="main")

    first = _update(project)

    assert first.outcome is Outcome.FAILED
    assert [row.state for row in load_scan_results("api").updates] == [
        Ready(flow=Workflow.UPDATE),
        Failed(flow=Workflow.UPDATE, phase="unit"),
        Ready(flow=Workflow.UPDATE),
    ]
    assert repo.resolve_revision(revision="main") == main_before
    assert {"deps/pkg-a", "deps/pkg-c"} <= _files(path, MANAGED)
    assert "deps/pkg-b" not in _files(path, MANAGED)

    second = _update(project.model_copy(update={"test_unit": "true"}))

    assert second.outcome is Outcome.SUCCEEDED
    assert applied == ["pkg-a", "pkg-b", "pkg-c", "pkg-b"]
    assert repo.is_ancestor(ancestor=main_before, descendant="main")
    assert {"deps/pkg-a", "deps/pkg-b", "deps/pkg-c"} <= _files(path, "main")
    assert load_scan_results("api").updates == []
    assert not repo.bookmark_exists(bookmark=MANAGED)
    assert (path / "deps" / "pkg-b").is_file()


def test_given_main_moved_sideways_when_promoting_then_work_stays_pending_until_rebased(
    tmp_path: Path, applied: list[str]
) -> None:
    repo, project = _bun_project(tmp_path, "api", FAILS_B)
    path = repo.path
    passing = project.model_copy(update={"test_unit": "true"})
    _update(project)
    assert run_jj(path, "new", "main").returncode == 0
    unrelated = commit_file(repo, "unrelated.txt", "x\n", "unrelated")
    repo.set_bookmark(bookmark="main", revision=unrelated)
    emit = RecordingEmit()

    second = _update(passing, emit)

    assert second.outcome is Outcome.FAILED
    assert emit.of_type(OperationFailed) == []
    failures = emit.of_type(PromotionFailed)
    assert [event.project for event in failures] == ["api"]
    assert failures[0].error.endswith(
        f" · rebase with jj rebase -b {MANAGED} -d main, then rerun"
    )
    assert [row.state for row in load_scan_results("api").updates] == [
        Ready(flow=Workflow.UPDATE)
    ] * 3
    assert repo.resolve_revision(revision="main") == unrelated

    rebased = run_jj(path, "rebase", "-b", MANAGED, "-d", "main")
    assert rebased.returncode == 0, rebased.stderr
    applications = list(applied)

    third = _update(passing)

    assert third.outcome is Outcome.SUCCEEDED
    assert applied == applications
    assert load_scan_results("api").updates == []
    assert not repo.bookmark_exists(bookmark=MANAGED)
    assert {"unrelated.txt", "deps/pkg-a", "deps/pkg-b", "deps/pkg-c"} <= _files(
        path, "main"
    )


def test_given_pending_stack_when_resolve_takes_over_and_repairs_then_main_gets_all(
    tmp_path: Path, applied: list[str]
) -> None:
    repo, project = _bun_project(tmp_path, "api", FAILS_B)
    path = repo.path
    _update(project)
    update_tip = repo.resolve_revision(revision=MANAGED)

    paused = _resolve(project, continue_=False)

    assert paused is Outcome.FAILED
    assert [row.state for row in load_scan_results("api").updates] == [
        Ready(flow=Workflow.RESOLVE),
        Failed(flow=Workflow.RESOLVE, phase="unit"),
        Ready(flow=Workflow.RESOLVE),
    ]
    assert repo.resolve_revision(revision=RESOLVE_BOOKMARK) == update_tip
    assert repo.same_revision(left="@-", right=RESOLVE_BOOKMARK)
    assert not repo.bookmark_exists(bookmark=MANAGED)
    assert (path / "deps" / "pkg-b").is_file()

    (path / "repair.txt").write_text("repaired\n", encoding="utf-8")
    committed = run_jj(path, "commit", "-m", "repair pkg-b")
    assert committed.returncode == 0, committed.stderr
    applications = list(applied)

    finished = _resolve(project, continue_=True)

    assert finished is Outcome.SUCCEEDED
    assert applied == applications == ["pkg-a", "pkg-b", "pkg-c", "pkg-b"]
    assert {"deps/pkg-a", "deps/pkg-b", "deps/pkg-c", "repair.txt"} <= _files(
        path, "main"
    )
    assert repo.is_ancestor(ancestor=update_tip, descendant="main")
    assert load_scan_results("api").findings == ()
    assert not repo.bookmark_exists(bookmark=MANAGED)
    assert not repo.bookmark_exists(bookmark=RESOLVE_BOOKMARK)


def test_given_cleanup_failure_when_batch_updated_then_next_project_promotes(
    tmp_path: Path, applied: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    projects = {
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
        make_config(
            projects={name: project for name, (_, project) in projects.items()}
        ),
        ["api", "web"],
        emit=emit,
    )

    assert [item.project for item in batch.projects] == ["api", "web"]
    assert [item.outcome for item in batch.projects] == [
        Outcome.FAILED,
        Outcome.SUCCEEDED,
    ]
    for repo, _ in projects.values():
        assert "deps/pkg-a" in _files(repo.path, "main")
    assert [
        event.operation
        for event in emit.of_type(OperationFailed)
        if event.project == "api"
    ] == ["workspace cleanup"]


def _bun_project(
    tmp_path: Path, name: str, test_unit: str, packages: str = "abc"
) -> tuple[JjRepository, ProjectConfig]:
    repo = copy_jj_repository(tmp_path / name)
    write_file(repo, "package.json", "{}\n")
    commit_to_main(repo, "add manifest")
    scan = make_scan_result(
        vulns=[], updates=[make_update(pkg_name=f"pkg-{x}") for x in packages]
    )
    scan.project = name
    save_scan_results(name, scan)
    return repo, make_project(repo.path, package_manager="bun", test_unit=test_unit)


def _update(
    project: ProjectConfig, emit: RecordingEmit | None = None
) -> update_service.ProjectUpdate:
    return update_service.update_project(
        "api",
        project,
        choose=None,
        emit=emit or RecordingEmit(),
    )


def _resolve(project: ProjectConfig, *, continue_: bool) -> Outcome:
    return resolve_service.resolve_project(
        "api",
        project,
        continue_=continue_,
        emit=RecordingEmit(),
    )


def _files(path: Path, revision: str) -> set[str]:
    listed = run_jj(path, "file", "list", "-r", revision)
    assert listed.returncode == 0, listed.stderr
    return set(listed.stdout.split())
