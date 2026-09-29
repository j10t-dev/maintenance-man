from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

import pytest

from maintenance_man import paths, vcs
from maintenance_man.github import CodeHostError
from maintenance_man.gradle_updates import gradle_evidence_workspace
from maintenance_man.vcs import ExpectedRevisions, Repository, RevisionError
from maintenance_man.vcs_workflow import (
    SyncAction,
    VcsServices,
    create_workspace,
    current_label,
    ensure_main_bookmark,
    prune_stale_bookmarks,
    push_bookmark_and_create_pr,
    refresh_working_copy_from_main,
    remove_workspace,
    sync_main,
)
from tests.conftest import make_project
from tests.fake_vcs import FakeCall, FakeCodeHost, FakeJjState

MANAGED = "mm/update-dependencies"


@dataclass
class OriginPeer:
    repo: Repository
    commit_file: Callable[[str, str, str], str]
    push_main: Callable[[], None]


@dataclass
class RepositoryCase:
    repo: Repository
    bind: Callable[[Path], Repository]
    register_file: Callable[[str], None]
    write_file: Callable[[str, str | None], None]
    commit_file: Callable[[str, str, str], str]
    describe: Callable[[str], None]
    force_bookmark: Callable[[str, str], None]
    conflict_bookmark: Callable[[str, str, str], None]
    origin_peer: OriginPeer
    track_main: Callable[[bool], None]
    after_push: Callable[[Callable[[], None]], None]
    attempts: list[FakeCall] | None
    commands: list[tuple[str, ...]] | None


def _run_jj(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(JJ_USER="MM Tests", JJ_EMAIL="mm@example.invalid")
    return subprocess.run(
        ["jj", *arguments],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def _write_repository_file(
    repository: Repository, filename: str, content: str | None
) -> None:
    target = repository.path / filename
    if content is None:
        target.unlink(missing_ok=True)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _commit_repository_file(
    repository: Repository,
    register_file: Callable[[str], None],
    filename: str,
    content: str,
    message: str,
) -> str:
    register_file(filename)
    _write_repository_file(repository, filename, content)
    repository.commit(message=message)
    return repository.resolve_revision(revision="@-")


def _skip_file_registration(_filename: str) -> None:
    return None


def _initialize_real_repository(tmp_path: Path) -> tuple[vcs.JjRepository, Path]:
    path = tmp_path / "real-repository"
    path.mkdir()
    assert _run_jj(path, "git", "init", "--colocate").returncode == 0
    origin = tmp_path / "origin"
    initialized = _run_jj(tmp_path, "git", "init", "--no-colocate", str(origin))
    assert initialized.returncode == 0, initialized.stderr
    origin_git = origin / ".jj" / "repo" / "store" / "git"
    added = _run_jj(path, "git", "remote", "add", "origin", str(origin_git))
    assert added.returncode == 0, added.stderr
    (path / "dep.txt").write_text("version=1\n", encoding="utf-8")
    assert _run_jj(path, "commit", "-m", "baseline").returncode == 0
    assert _run_jj(path, "bookmark", "create", "main", "-r", "@-").returncode == 0
    return vcs.JjRepository(path), origin_git


def _initialize_real_peer(tmp_path: Path, origin_git: Path) -> OriginPeer:
    peer_path = tmp_path / "origin-peer"
    peer_path.mkdir()
    assert _run_jj(peer_path, "git", "init", "--colocate").returncode == 0
    added = _run_jj(peer_path, "git", "remote", "add", "origin", str(origin_git))
    assert added.returncode == 0, added.stderr
    fetched = _run_jj(peer_path, "git", "fetch", "--remote", "origin")
    assert fetched.returncode == 0, fetched.stderr
    created = _run_jj(peer_path, "bookmark", "create", "main", "-r", "main@origin")
    assert created.returncode == 0, created.stderr
    tracked = _run_jj(peer_path, "bookmark", "track", "main@origin")
    assert tracked.returncode == 0, tracked.stderr
    assert _run_jj(peer_path, "new", "main").returncode == 0
    peer_repo = vcs.JjRepository(peer_path)
    return OriginPeer(
        peer_repo,
        partial(_commit_repository_file, peer_repo, _skip_file_registration),
        partial(_push_real_peer_main, peer_repo),
    )


def _push_real_peer_main(repository: Repository) -> None:
    repository.set_bookmark(bookmark="main", revision="@-")
    repository.push_bookmark(bookmark="main")


def _install_real_post_push_interceptor(
    path: Path,
    monkeypatch: pytest.MonkeyPatch | None,
    pending_after_push: list[Callable[[], None]],
    commands: list[tuple[str, ...]],
) -> None:
    if monkeypatch is None:
        return
    captured_run = vcs.run_captured

    def intercept_push(command, cwd, **kwargs):
        commands.append(tuple(command))
        completed = captured_run(command, cwd, **kwargs)
        if (
            pending_after_push
            and list(command[:3]) == ["jj", "git", "push"]
            and Path(cwd).resolve() == path.resolve()
        ):
            pending_after_push.pop(0)()
        return completed

    monkeypatch.setattr(vcs, "run_captured", intercept_push)


def _bind_real_repository(path: Path) -> Repository:
    inspected = _run_jj(path, "workspace", "root")
    assert inspected.returncode == 0, f"unknown repository view: {path}"
    return vcs.JjRepository(path)


def _describe_real_repository(repository: Repository, message: str) -> None:
    result = _run_jj(repository.path, "describe", "-m", message)
    assert result.returncode == 0, result.stderr


def _force_real_bookmark(repository: Repository, bookmark: str, revision: str) -> None:
    result = _run_jj(
        repository.path,
        "bookmark",
        "set",
        bookmark,
        "-r",
        revision,
        "--allow-backwards",
    )
    assert result.returncode == 0, result.stderr


def _conflict_real_bookmark(
    repository: Repository, bookmark: str, left: str, right: str
) -> None:
    if bookmark == "main":
        untracked = _run_jj(repository.path, "bookmark", "untrack", "main@origin")
        assert untracked.returncode == 0, untracked.stderr
    if repository.bookmark_exists(bookmark=bookmark):
        deleted = _run_jj(repository.path, "bookmark", "delete", bookmark)
        assert deleted.returncode == 0, deleted.stderr
    operation = _run_jj(
        repository.path, "op", "log", "--limit", "1", "--no-graph", "-T", "id"
    ).stdout.strip()
    created = _run_jj(repository.path, "bookmark", "create", bookmark, "-r", left)
    assert created.returncode == 0, created.stderr
    conflicted = _run_jj(
        repository.path,
        "--at-op",
        operation,
        "bookmark",
        "create",
        bookmark,
        "-r",
        right,
    )
    assert conflicted.returncode == 0, conflicted.stderr
    assert _run_jj(repository.path, "bookmark", "list", bookmark).returncode == 0


def _real_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch | None = None
) -> RepositoryCase:
    repo, origin_git = _initialize_real_repository(tmp_path)
    pending_after_push: list[Callable[[], None]] = []
    commands: list[tuple[str, ...]] = []
    _install_real_post_push_interceptor(
        repo.path, monkeypatch, pending_after_push, commands
    )
    repo.push_bookmark(bookmark="main")
    origin_peer = _initialize_real_peer(tmp_path, origin_git)

    def register_file(_filename: str) -> None:
        return None

    def track_main(enabled: bool) -> None:
        action = "track" if enabled else "untrack"
        result = _run_jj(repo.path, "bookmark", action, "main@origin")
        assert result.returncode == 0, result.stderr

    def after_push(action: Callable[[], None]) -> None:
        assert not pending_after_push, "only one pending push hook is supported"
        pending_after_push.append(action)

    return RepositoryCase(
        repo=repo,
        bind=_bind_real_repository,
        register_file=register_file,
        write_file=partial(_write_repository_file, repo),
        commit_file=partial(_commit_repository_file, repo, register_file),
        describe=partial(_describe_real_repository, repo),
        force_bookmark=partial(_force_real_bookmark, repo),
        conflict_bookmark=partial(_conflict_real_bookmark, repo),
        origin_peer=origin_peer,
        track_main=track_main,
        after_push=after_push,
        attempts=None,
        commands=commands,
    )


def _register_fake_file(state: FakeJjState, path: Path, filename: str) -> None:
    state.register_files(path, filename)


def _seed_fake_bookmark(
    state: FakeJjState,
    path: Path,
    bookmark: str,
    *targets: str,
) -> None:
    state.seed_bookmark(path, bookmark=bookmark, targets=targets)


def _track_fake_main(state: FakeJjState, path: Path, enabled: bool) -> None:
    state.track_main(path, enabled=enabled)


def _install_fake_after_push(
    state: FakeJjState, path: Path, action: Callable[[], None]
) -> None:
    state.hook(
        "push_bookmark",
        phase="postcheck",
        action=action,
        path=path,
    )


def _fake_case(tmp_path: Path) -> RepositoryCase:
    state = FakeJjState()
    path = tmp_path / "fake-repository"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    repo.push_bookmark(bookmark="main")
    peer_path = tmp_path / "origin-peer"
    peer_repo = state.seed_peer(peer_path, source=path, track_main=True)

    register_file = partial(_register_fake_file, state, path)

    def describe(message: str) -> None:
        repo.describe(message=message)

    def peer_push_main() -> None:
        peer_repo.set_bookmark(bookmark="main", revision="@-")
        peer_repo.push_bookmark(bookmark="main")

    state.clear_calls()

    return RepositoryCase(
        repo=repo,
        bind=state.repository,
        register_file=register_file,
        write_file=partial(_write_repository_file, repo),
        commit_file=partial(_commit_repository_file, repo, register_file),
        describe=describe,
        force_bookmark=partial(_seed_fake_bookmark, state, path),
        conflict_bookmark=partial(_seed_fake_bookmark, state, path),
        origin_peer=OriginPeer(
            peer_repo,
            partial(
                _commit_repository_file,
                peer_repo,
                partial(_register_fake_file, state, peer_path),
            ),
            peer_push_main,
        ),
        track_main=partial(_track_fake_main, state, path),
        after_push=partial(_install_fake_after_push, state, path),
        attempts=state.attempts,
        commands=None,
    )


@pytest.fixture(params=["fake", pytest.param("real", marks=pytest.mark.integration)])
def repository_case(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> RepositoryCase:
    assert hasattr(vcs, "JjRepository"), "repository adapter is not implemented"
    return (
        _fake_case(tmp_path)
        if request.param == "fake"
        else _real_case(tmp_path, monkeypatch)
    )


def _bookmark_targets(
    repo: Repository, *, bookmark: str, candidates: set[str]
) -> frozenset[str]:
    observed = {
        revision: repo.revision_bookmarks(revision=revision) for revision in candidates
    }
    return frozenset(
        revision for revision, names in observed.items() if bookmark in names
    )


def _bookmark_state(
    repo: Repository, *, bookmark: str, candidates: set[str]
) -> tuple[bool, frozenset[str], str | None]:
    conflicted = repo.bookmark_conflicted(bookmark=bookmark)
    return (
        conflicted,
        _bookmark_targets(repo, bookmark=bookmark, candidates=candidates),
        None if conflicted else repo.resolve_revision(revision=bookmark),
    )


def _assert_origin_baseline_only(c: RepositoryCase, *, base: str) -> None:
    c.origin_peer.repo.fetch(main_only=False)
    assert c.origin_peer.repo.resolve_revision(revision="main") == base
    if isinstance(c.repo, vcs.JjRepository):
        missing = _run_jj(
            c.origin_peer.repo.path,
            "log",
            "-r",
            f"{MANAGED}@origin",
            "--no-graph",
            "-T",
            'commit_id ++ "\\n"',
        )
        assert missing.returncode != 0


def test_identity_tracks_content_and_metadata_separately(
    repository_case: RepositoryCase,
):
    c = repository_case
    original_commit = c.repo.resolve_revision(revision="@")
    original_tree = c.repo.tree_id()
    c.describe("metadata only")
    assert c.repo.resolve_revision(revision="@") != original_commit
    assert c.repo.tree_id() == original_tree
    c.register_file("dep.txt")
    c.write_file("dep.txt", "version=2\n")
    assert c.repo.tree_id() != original_tree


def test_commit_then_advance_and_delete(repository_case: RepositoryCase):
    c = repository_case
    c.register_file("dep.txt")
    c.write_file("dep.txt", "version=2\n")
    c.repo.commit(message="upgrade dependency")
    finished = c.repo.resolve_revision(revision="@-")
    c.repo.set_bookmark(bookmark=MANAGED, revision="@-")
    assert c.repo.resolve_revision(revision=MANAGED) == finished
    assert c.repo.has_changes() is False
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"
    assert c.repo.resolve_revision(revision="@") != finished
    c.repo.delete_bookmark(bookmark=MANAGED)
    assert c.repo.bookmark_exists(bookmark=MANAGED) is False


def test_read_only_file_inspection_does_not_snapshot(repository_case: RepositoryCase):
    c = repository_case
    c.commit_file("local.properties", "sdk.dir=/fixture\n", "sdk settings")
    pinned = c.repo.resolve_revision(revision="@", read_only=True)
    tree_before = c.repo.tree_id(revision=pinned)
    c.write_file("local.properties", "sdk.dir=/changed\n")
    inspected = c.repo.revision_file(revision="@", filename="local.properties")
    assert inspected.commit_id == pinned
    assert inspected.is_regular is True
    assert c.repo.resolve_revision(revision="@", read_only=True) == pinned
    assert c.repo.tree_id(revision=pinned) == tree_before
    assert c.repo.tree_id() != tree_before


def test_changed_paths_reports_add_edit_and_delete(repository_case: RepositoryCase):
    c = repository_case
    c.commit_file("gone.txt", "remove me\n", "add removable file")
    for filename in ("new.txt", "dep.txt", "gone.txt"):
        c.register_file(filename)
    c.write_file("new.txt", "new\n")
    c.write_file("dep.txt", "version=2\n")
    (c.repo.path / "gone.txt").unlink()
    assert c.repo.changed_paths() == frozenset({"new.txt", "dep.txt", "gone.txt"})


def test_discard_restores_the_parent_tree(repository_case: RepositoryCase) -> None:
    c = repository_case
    c.write_file("dep.txt", "dirty\n")
    assert c.repo.has_changes() is True

    c.repo.discard()

    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=1\n"
    assert c.repo.has_changes() is False


def test_repository_case_exposes_complete_remote_harness(
    repository_case: RepositoryCase,
):
    c = repository_case
    assert callable(c.bind)
    assert callable(c.track_main)
    assert callable(c.after_push)
    assert c.origin_peer.repo.path != c.repo.path


@pytest.mark.parametrize("error_type", [RuntimeError, RevisionError])
def test_proof_preserves_body_exception(
    repository_case: RepositoryCase, error_type: type[BaseException]
):
    c = repository_case
    project = make_project(c.repo.path)
    original = error_type("proof body failed")

    def no_host(path: Path):
        msg = f"unexpected host for {path}"
        raise AssertionError(msg)

    services = VcsServices(repository=c.bind, code_host=no_host)
    before_names = c.repo.workspace_names()
    proof_path = None
    with (
        pytest.raises(error_type) as caught,
        gradle_evidence_workspace(project, "main", vcs=services) as proof,
    ):
        proof_path = proof.path
        assert proof.path != project.path
        raise original
    assert caught.value is original
    assert c.repo.workspace_names() == before_names
    assert proof_path is not None and not proof_path.exists()


def test_bind_rejects_unknown_repository_view(
    repository_case: RepositoryCase, tmp_path: Path
):
    unknown = tmp_path / "unknown-view"
    unknown.mkdir()
    with pytest.raises(AssertionError, match="unknown"):
        repository_case.bind(unknown)


def test_write_file_none_deletes_registered_file(repository_case: RepositoryCase):
    c = repository_case
    c.register_file("dep.txt")
    c.write_file("dep.txt", None)
    assert c.repo.changed_paths() == frozenset({"dep.txt"})


def test_conflict_bookmark_accepts_separate_target_arguments(
    repository_case: RepositoryCase,
):
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    c.repo.new_change(revision="main")
    c.write_file("dep.txt", "side=1\n")
    side = c.repo.resolve_revision(revision="@")
    c.conflict_bookmark(MANAGED, base, side)
    assert c.repo.bookmark_conflicted(bookmark=MANAGED) is True


def test_missing_and_conflicted_bookmarks_are_distinct(repository_case: RepositoryCase):
    c = repository_case
    assert c.repo.bookmark_exists(bookmark=MANAGED) is False
    base = c.repo.resolve_revision(revision="main")
    c.repo.new_change(revision="main")
    c.write_file("dep.txt", "side=1\n")
    side = c.repo.resolve_revision(revision="@")
    c.conflict_bookmark(MANAGED, base, side)
    assert c.repo.bookmark_exists(bookmark=MANAGED) is True
    assert c.repo.bookmark_conflicted(bookmark=MANAGED) is True
    with pytest.raises(RevisionError, match="exactly one"):
        c.repo.resolve_revision(revision=MANAGED)


def test_workspace_views_isolate_files_and_share_bookmarks(
    repository_case: RepositoryCase, tmp_path: Path
):
    c = repository_case
    update_path = tmp_path / "update-workspace"
    c.repo.add_workspace(name="update", path=update_path, revision="main")
    update = c.bind(update_path)
    update.new_change(revision="main")
    c.register_file("dep.txt")
    (update.path / "dep.txt").write_text("version=2\n", encoding="utf-8")
    update.commit(message="update dependency")
    update.set_bookmark(bookmark=MANAGED, revision="@-")
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=1\n"
    assert c.repo.resolve_revision(revision="@") != update.resolve_revision(
        revision="@"
    )
    assert c.repo.resolve_revision(revision=MANAGED) == update.resolve_revision(
        revision=MANAGED
    )


def test_promote_then_rebase_empty_source_child_projects_updated_files(
    repository_case: RepositoryCase, tmp_path: Path
):
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    source_change = c.repo.change_id()
    update_path = tmp_path / "promotion-workspace"
    c.repo.add_workspace(name="promotion", path=update_path, revision="main")
    update = c.bind(update_path)
    update.new_change(revision="main")
    c.register_file("dep.txt")
    (update.path / "dep.txt").write_text("version=2\n", encoding="utf-8")
    update.commit(message="upgrade dependency")
    tip = update.resolve_revision(revision="@-")
    update.set_bookmark(bookmark=MANAGED, revision=tip)

    c.repo.promote_bookmark_to_main(
        bookmark=MANAGED,
        expected=ExpectedRevisions(base=base, tip=tip),
    )
    c.repo.rebase_working_copy(revision="main")

    assert c.repo.change_id() == source_change
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"
    assert c.repo.resolve_revision(revision="main") == tip


def test_rebase_preserves_change_and_new_change_preserves_old_commit(
    repository_case: RepositoryCase,
):
    c = repository_case
    c.repo.new_change(revision="main")
    change_before = c.repo.change_id()
    c.repo.rebase_working_copy(revision="main")
    assert c.repo.change_id() == change_before
    c.write_file("dep.txt", "dirty\n")
    old = c.repo.resolve_revision(revision="@")
    c.repo.new_change(revision="main")
    assert c.repo.resolve_revision(revision=old) == old
    assert c.repo.change_id() != change_before


@pytest.mark.parametrize("error", [RuntimeError("caller"), RevisionError("caller")])
def test_temporary_workspace_preserves_body_exception_identity_and_cleans_up(
    repository_case: RepositoryCase, error: Exception
):
    before = repository_case.repo.workspace_names()
    with (
        pytest.raises(type(error)) as caught,
        repository_case.repo.temporary_workspace(revision="main") as proof,
    ):
        container = proof.path.parent
        raise error
    assert caught.value is error
    assert not container.exists()
    assert repository_case.repo.workspace_names() == before


@pytest.mark.parametrize(
    ("operation", "success_target"),
    [("promote", "tip"), ("reset", "base"), ("push", "tip")],
)
def test_guarded_operations_accept_unchanged_revisions(
    repository_case: RepositoryCase, operation: str, success_target: str
):
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    c.repo.new_change(revision="main")
    c.write_file("dep.txt", "version=2\n")
    c.describe("upgrade dependency")
    tip = c.repo.resolve_revision(revision="@")
    c.repo.set_bookmark(bookmark=MANAGED, revision=tip)
    expected = ExpectedRevisions(base=base, tip=tip)
    if operation == "promote":
        c.repo.promote_bookmark_to_main(bookmark=MANAGED, expected=expected)
        assert c.repo.resolve_revision(revision="main") == tip
    elif operation == "reset":
        c.repo.reset_verified_bookmark(bookmark=MANAGED, expected=expected)
        assert c.repo.resolve_revision(revision=MANAGED) == base
    else:
        c.repo.push_bookmark(bookmark=MANAGED, expected=expected)


@pytest.mark.parametrize("operation", ["promote", "reset", "push"])
@pytest.mark.parametrize("mutation", ["base", "tip", "base-conflict", "tip-conflict"])
def test_guarded_operations_reject_moved_or_conflicted_revisions(
    repository_case: RepositoryCase, operation: str, mutation: str
):
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    c.repo.new_change(revision="main")
    c.write_file("dep.txt", "version=2\n")
    c.describe("upgrade dependency")
    tip = c.repo.resolve_revision(revision="@")
    c.repo.set_bookmark(bookmark=MANAGED, revision=tip)
    c.repo.new_change(revision="main")
    c.write_file("dep.txt", "sibling\n")
    sibling = c.repo.resolve_revision(revision="@")
    expected = ExpectedRevisions(base=base, tip=tip)
    if mutation == "base":
        c.force_bookmark("main", sibling)
    elif mutation == "tip":
        c.force_bookmark(MANAGED, base)
    elif mutation == "base-conflict":
        c.conflict_bookmark("main", base, sibling)
    else:
        c.conflict_bookmark(MANAGED, tip, sibling)
    candidates = {base, tip, sibling}
    before_targets = {
        bookmark: _bookmark_state(c.repo, bookmark=bookmark, candidates=candidates)
        for bookmark in ("main", MANAGED)
    }
    if mutation == "base-conflict":
        assert c.repo.bookmark_conflicted(bookmark="main") is True
    else:
        assert c.repo.resolve_revision(revision="main") == (
            sibling if mutation == "base" else base
        )
    if mutation == "tip-conflict":
        assert c.repo.bookmark_conflicted(bookmark=MANAGED) is True
    else:
        assert c.repo.resolve_revision(revision=MANAGED) == (
            base if mutation == "tip" else tip
        )
    _assert_origin_baseline_only(c, base=base)
    push_effects: list[str] = []
    if operation == "push":
        c.after_push(lambda: push_effects.append("pushed"))
    with pytest.raises(RevisionError):
        if operation == "promote":
            c.repo.promote_bookmark_to_main(bookmark=MANAGED, expected=expected)
        elif operation == "reset":
            c.repo.reset_verified_bookmark(bookmark=MANAGED, expected=expected)
        else:
            c.repo.push_bookmark(bookmark=MANAGED, expected=expected)
    assert {
        bookmark: _bookmark_state(c.repo, bookmark=bookmark, candidates=candidates)
        for bookmark in ("main", MANAGED)
    } == before_targets
    _assert_origin_baseline_only(c, base=base)
    assert push_effects == []


@pytest.mark.parametrize("operation", ["promote", "reset", "push"])
def test_guarded_operations_reject_unmanaged_bookmark(
    repository_case: RepositoryCase, operation: str
):
    base = repository_case.repo.resolve_revision(revision="main")
    expected = ExpectedRevisions(base=base, tip=base)
    with pytest.raises(RevisionError, match="Unexpected managed"):
        if operation == "promote":
            repository_case.repo.promote_bookmark_to_main(
                bookmark="feature/unmanaged", expected=expected
            )
        elif operation == "reset":
            repository_case.repo.reset_verified_bookmark(
                bookmark="feature/unmanaged", expected=expected
            )
        else:
            repository_case.repo.push_bookmark(
                bookmark="feature/unmanaged", expected=expected
            )


@pytest.mark.parametrize("operation", ["promote", "reset", "push"])
def test_guarded_operations_reject_sibling_base_and_tip(
    repository_case: RepositoryCase, operation: str
):
    c = repository_case
    root = c.repo.resolve_revision(revision="main")
    tip = c.commit_file("dep.txt", "tip\n", "tip")
    c.repo.new_change(revision=root)
    c.write_file("dep.txt", "sibling\n")
    c.describe("sibling")
    sibling = c.repo.resolve_revision(revision="@")
    c.force_bookmark("main", tip)
    c.force_bookmark(MANAGED, sibling)
    expected = ExpectedRevisions(base=tip, tip=sibling)
    candidates = {root, tip, sibling}
    before_targets = {
        bookmark: _bookmark_state(c.repo, bookmark=bookmark, candidates=candidates)
        for bookmark in ("main", MANAGED)
    }
    assert c.repo.resolve_revision(revision="main") == tip
    assert c.repo.resolve_revision(revision=MANAGED) == sibling
    _assert_origin_baseline_only(c, base=root)
    push_effects: list[str] = []
    if operation == "push":
        c.after_push(lambda: push_effects.append("pushed"))

    with pytest.raises(RevisionError):
        if operation == "promote":
            c.repo.promote_bookmark_to_main(bookmark=MANAGED, expected=expected)
        elif operation == "reset":
            c.repo.reset_verified_bookmark(bookmark=MANAGED, expected=expected)
        else:
            c.repo.push_bookmark(bookmark=MANAGED, expected=expected)
    assert {
        bookmark: _bookmark_state(c.repo, bookmark=bookmark, candidates=candidates)
        for bookmark in ("main", MANAGED)
    } == before_targets
    _assert_origin_baseline_only(c, base=root)
    assert push_effects == []


def test_fake_push_enables_main_tracking_for_later_peer_advance(tmp_path: Path):
    state = FakeJjState()
    path = tmp_path / "unpublished-source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    state.seed_remote(path, bookmark="main", targets=())
    state.seed_tracking(path, bookmark="main", targets=())
    state.track_main(path, enabled=False)
    baseline = repo.resolve_revision(revision="main")

    repo.push_bookmark(bookmark="main")
    assert repo.resolve_revision(revision="main@origin") == baseline

    peer_path = tmp_path / "unpublished-peer"
    peer = state.seed_peer(peer_path, source=path, track_main=True)
    state.register_files(peer_path, "dep.txt")
    peer.rebase_working_copy(revision="main")
    (peer.path / "dep.txt").write_text("peer=2\n", encoding="utf-8")
    peer.commit(message="peer advance")
    peer_tip = peer.resolve_revision(revision="@-")
    peer.set_bookmark(bookmark="main", revision="@-")
    peer.push_bookmark(bookmark="main")
    assert repo.resolve_revision(revision="main@origin") == baseline
    repo.fetch(main_only=True)

    assert repo.resolve_revision(revision="main") == peer_tip
    assert repo.resolve_revision(revision="main@origin") == peer_tip


def test_push_rejects_existing_untracked_remote_without_remote_effect(
    repository_case: RepositoryCase,
):
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    c.track_main(False)
    tip = c.commit_file("dep.txt", "sender=1\n", "sender advance")
    c.repo.set_bookmark(bookmark="main", revision=tip)
    push_effects: list[str] = []
    c.after_push(lambda: push_effects.append("pushed"))

    with pytest.raises(RevisionError):
        c.repo.push_bookmark(bookmark="main")

    c.origin_peer.repo.fetch(main_only=True)
    assert c.origin_peer.repo.resolve_revision(revision="main") == base
    assert push_effects == []


@pytest.mark.integration
def test_real_initial_push_tracks_main_for_later_peer_advance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    c = _real_case(tmp_path, monkeypatch)
    sender_tracking = c.repo.resolve_revision(revision="main@origin")
    assert sender_tracking == c.repo.resolve_revision(revision="main")

    c.origin_peer.repo.fetch(main_only=True)
    c.origin_peer.repo.rebase_working_copy(revision="main")
    peer_tip = c.origin_peer.commit_file("dep.txt", "peer=2\n", "peer advance")
    c.origin_peer.push_main()
    assert c.repo.resolve_revision(revision="main@origin") == sender_tracking
    c.repo.fetch(main_only=True)

    assert c.repo.resolve_revision(revision="main") == peer_tip
    assert c.repo.resolve_revision(revision="main@origin") == peer_tip


def test_after_push_runs_once_after_successful_sender_push(
    repository_case: RepositoryCase,
):
    c = repository_case
    observed: list[str] = []
    c.after_push(lambda: observed.append("after"))
    c.repo.push_bookmark(bookmark="main")
    c.repo.push_bookmark(bookmark="main")
    assert observed == ["after"]


def test_sync_equal_revisions_refreshes_and_reports_unchanged(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    original_change = c.repo.change_id()

    assert sync_main(repo=c.repo) is SyncAction.UNCHANGED
    assert c.repo.change_id() == original_change
    assert c.repo.same_revision(left="main", right="main@origin") is True


def test_ensure_main_creates_missing_local_bookmark_from_origin(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    origin = c.repo.resolve_revision(revision="main@origin")
    c.repo.delete_bookmark(bookmark="main")

    ensure_main_bookmark(repo=c.repo)

    assert c.repo.resolve_revision(revision="main") == origin


def test_ensure_main_leaves_existing_local_bookmark_unchanged(tmp_path: Path) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    main = repo.resolve_revision(revision="main")
    state.clear_calls()

    ensure_main_bookmark(repo=repo)

    assert repo.resolve_revision(revision="main") == main
    assert not any(
        call.method in {"create_bookmark", "set_bookmark"} for call in state.attempts
    )


def test_ensure_main_preserves_local_bookmark_inspection_failure(
    tmp_path: Path,
) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    state.clear_calls()
    failure = RevisionError("local bookmark inspection failed")
    state.fail("bookmark_exists", error=failure, path=path)

    with pytest.raises(RevisionError) as caught:
        ensure_main_bookmark(repo=repo)

    assert caught.value is failure
    assert not any(
        call.method in {"create_bookmark", "set_bookmark"} for call in state.effects
    )


def test_ensure_main_refuses_when_local_and_origin_are_absent(tmp_path: Path) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    state.seed_bookmark(path, bookmark="main", targets=())
    state.seed_tracking(path, bookmark="main", targets=())
    state.seed_remote(path, bookmark="main", targets=())
    state.clear_calls()

    with pytest.raises(RevisionError, match=r"main@origin.*exactly one"):
        ensure_main_bookmark(repo=repo)

    assert not any(
        call.method in {"create_bookmark", "set_bookmark"} for call in state.effects
    )


def test_ensure_main_preserves_origin_inspection_failure(tmp_path: Path) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    state.seed_bookmark(path, bookmark="main", targets=())
    state.clear_calls()
    failure = RevisionError("origin inspection failed")
    state.fail("resolve_revision", error=failure, path=path)

    with pytest.raises(RevisionError) as caught:
        ensure_main_bookmark(repo=repo)

    assert caught.value is failure
    assert not any(
        call.method in {"create_bookmark", "set_bookmark"} for call in state.effects
    )


def test_fake_services_bind_repository_and_shared_code_host(tmp_path: Path) -> None:
    state = FakeJjState()
    source = tmp_path / "source"
    repo = state.seed_repository(source, files={"dep.txt": "version=1\n"})
    workspace = tmp_path / "workspace"
    repo.add_workspace(name="update", path=workspace, revision="main")
    services = state.services()

    assert services.repository(source).path == source
    assert services.repository(workspace).path == workspace
    source_host = services.code_host(source)
    workspace_host = services.code_host(workspace)
    assert isinstance(source_host, FakeCodeHost)
    assert isinstance(workspace_host, FakeCodeHost)
    assert source_host.path == source
    assert workspace_host.path == workspace
    source_host.seed_pr(bookmark=MANAGED, state="merged")
    assert workspace_host.pr_bookmarks(state="merged") == frozenset({MANAGED})


@pytest.mark.parametrize("method", ["fetch", "bookmark_conflicted", "same_revision"])
def test_sync_inspection_failure_preserves_the_repository(
    tmp_path: Path, method: str
) -> None:
    state = FakeJjState()
    path = tmp_path / method
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    before = repo.resolve_revision(revision="@")
    failure = RevisionError(f"{method} failed")
    state.clear_calls()
    state.fail(method, error=failure, path=path)

    with pytest.raises(RevisionError) as caught:
        sync_main(repo=repo)

    assert caught.value is failure
    assert repo.resolve_revision(revision="@") == before
    assert not any(
        call.method
        in {"set_bookmark", "push_bookmark", "rebase_working_copy", "new_change"}
        for call in state.effects
    )


def test_sync_pulls_remote_advance_when_main_is_untracked(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    c.track_main(False)
    c.origin_peer.repo.rebase_working_copy(revision="main")
    peer_tip = c.origin_peer.commit_file("dep.txt", "version=2\n", "peer advance")
    c.origin_peer.push_main()

    assert sync_main(repo=c.repo) is SyncAction.PULLED
    assert c.repo.resolve_revision(revision="main") == peer_tip
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"


def test_sync_remote_advance_move_failure_preserves_local_main(tmp_path: Path) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    base = repo.resolve_revision(revision="main")
    tip = state.seed_commit(
        path,
        parent=base,
        files={"dep.txt": "version=2\n"},
        description="remote advance",
    )
    state.seed_remote(path, bookmark="main", targets=(tip,))
    state.seed_tracking(path, bookmark="main", targets=())
    state.track_main(path, enabled=False)
    state.clear_calls()
    failure = RevisionError("cannot move local main")
    state.fail("set_bookmark", error=failure, path=path)

    with pytest.raises(RevisionError) as caught:
        sync_main(repo=repo)

    assert caught.value is failure
    assert repo.resolve_revision(revision="main") == base
    assert (path / "dep.txt").read_text(encoding="utf-8") == "version=1\n"


def test_sync_tracked_main_remote_advance_is_already_reconciled_by_fetch(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    c.origin_peer.repo.rebase_working_copy(revision="main")
    peer_tip = c.origin_peer.commit_file("dep.txt", "version=2\n", "peer advance")
    c.origin_peer.push_main()

    assert sync_main(repo=c.repo) is SyncAction.UNCHANGED
    assert c.repo.resolve_revision(revision="main") == peer_tip
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"


def test_sync_pushes_local_advance_then_fetches_before_refresh(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    tip = c.commit_file("dep.txt", "version=2\n", "local advance")
    c.repo.set_bookmark(bookmark="main", revision=tip)

    assert sync_main(repo=c.repo) is SyncAction.PUSHED
    assert c.repo.resolve_revision(revision="main@origin") == tip
    c.origin_peer.repo.fetch(main_only=True)
    assert c.origin_peer.repo.resolve_revision(revision="main") == tip


def test_sync_rechecks_remote_before_refresh(repository_case: RepositoryCase) -> None:
    c = repository_case
    tip = c.commit_file("dep.txt", "version=2\n", "local update")
    c.repo.set_bookmark(bookmark="main", revision=tip)
    observed: dict[str, object] = {}

    def sender_advance() -> None:
        observed["attempt_index"] = len(c.attempts) if c.attempts is not None else None
        observed["command_index"] = len(c.commands) if c.commands is not None else None
        moved = c.commit_file("dep.txt", "version=3\n", "concurrent local update")
        c.repo.set_bookmark(bookmark="main", revision=moved)
        observed["main"] = moved
        observed["change"] = c.repo.change_id()

    c.after_push(sender_advance)
    with pytest.raises(RevisionError, match="match"):
        sync_main(repo=c.repo)
    assert c.repo.resolve_revision(revision="main") == observed["main"]
    assert c.repo.resolve_revision(revision="main@origin") == tip
    assert c.repo.change_id() == observed["change"]
    if c.attempts is not None:
        attempt_index = observed["attempt_index"]
        assert isinstance(attempt_index, int)
        assert not any(
            call.method in {"rebase_working_copy", "new_change"}
            for call in c.attempts[attempt_index:]
        )
    if c.commands is not None:
        command_index = observed["command_index"]
        assert isinstance(command_index, int)
        assert not any(
            command[:2] in {("jj", "rebase"), ("jj", "new")}
            for command in c.commands[command_index:]
        )


def test_sync_fetch_failure_after_push_prevents_refresh(tmp_path: Path) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    tip = state.seed_commit(
        path,
        parent=repo.resolve_revision(revision="main"),
        files={"dep.txt": "version=2\n"},
        description="local advance",
    )
    state.seed_bookmark(path, bookmark="main", targets=(tip,))
    state.clear_calls()
    state.fail(
        "fetch", ordinal=2, error=RevisionError("second fetch failed"), path=path
    )

    with pytest.raises(RevisionError, match="second fetch failed"):
        sync_main(repo=repo)

    assert any(call.method == "push_bookmark" for call in state.effects)
    assert not any(
        call.method in {"rebase_working_copy", "new_change"} for call in state.attempts
    )


def test_sync_post_push_comparison_failure_prevents_refresh(tmp_path: Path) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    tip = state.seed_commit(
        path,
        parent=repo.resolve_revision(revision="main"),
        files={"dep.txt": "version=2\n"},
        description="local advance",
    )
    state.seed_bookmark(path, bookmark="main", targets=(tip,))
    state.clear_calls()
    failure = RevisionError("post-push comparison failed")
    state.fail("same_revision", ordinal=2, error=failure, path=path)

    with pytest.raises(RevisionError) as caught:
        sync_main(repo=repo)

    assert caught.value is failure
    assert any(call.method == "push_bookmark" for call in state.effects)
    assert not any(
        call.method in {"rebase_working_copy", "new_change"} for call in state.attempts
    )


def test_sync_refuses_divergent_main_without_refresh(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    local = c.commit_file("dep.txt", "local\n", "local advance")
    c.repo.set_bookmark(bookmark="main", revision=local)
    c.origin_peer.repo.rebase_working_copy(revision="main")
    c.origin_peer.commit_file("dep.txt", "remote\n", "remote advance")
    c.origin_peer.push_main()
    change_before = c.repo.change_id()

    with pytest.raises(RevisionError):
        sync_main(repo=c.repo)
    assert c.repo.change_id() == change_before


def test_sync_refuses_preexisting_conflicted_main_without_refresh(
    tmp_path: Path,
) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    base = repo.resolve_revision(revision="main")
    sibling = state.seed_commit(
        path,
        parent=base,
        files={"dep.txt": "sibling\n"},
        description="sibling",
    )
    state.seed_bookmark(path, bookmark="main", targets=(base, sibling))
    state.clear_calls()

    with pytest.raises(RevisionError, match="conflicted"):
        sync_main(repo=repo)
    assert not any(
        call.method in {"rebase_working_copy", "new_change"} for call in state.attempts
    )


def test_refresh_empty_change_preserves_change_identity(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    old_change = c.repo.change_id()
    c.track_main(False)
    c.origin_peer.repo.rebase_working_copy(revision="main")
    c.origin_peer.commit_file("dep.txt", "version=2\n", "peer advance")
    c.origin_peer.push_main()
    c.repo.fetch(main_only=True)
    c.repo.set_bookmark(bookmark="main", revision="main@origin")

    refresh_working_copy_from_main(repo=c.repo)

    assert c.repo.change_id() == old_change
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"


def test_refresh_dirty_descendant_is_left_unchanged(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    c.write_file("dep.txt", "local dirty\n")
    change = c.repo.change_id()

    refresh_working_copy_from_main(repo=c.repo)

    assert c.repo.change_id() == change
    assert c.repo.has_changes() is True
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "local dirty\n"


@pytest.mark.parametrize("protected_state", ["dirty", "described", "bookmarked"])
def test_refresh_protected_change_starts_new_child_and_preserves_old_content(
    repository_case: RepositoryCase, protected_state: str
) -> None:
    c = repository_case
    expected_old_content = "version=1\n"
    if protected_state == "dirty":
        expected_old_content = "local dirty\n"
        c.write_file("dep.txt", expected_old_content)
    elif protected_state == "described":
        c.describe("work in progress")
    else:
        c.repo.set_bookmark(bookmark="feature/current", revision="@")
    old = c.repo.resolve_revision(revision="@")
    c.track_main(False)
    c.origin_peer.repo.rebase_working_copy(revision="main")
    c.origin_peer.commit_file("dep.txt", "version=2\n", "peer advance")
    c.origin_peer.push_main()
    c.repo.fetch(main_only=True)
    c.repo.set_bookmark(bookmark="main", revision="main@origin")

    refresh_working_copy_from_main(repo=c.repo)

    assert c.repo.resolve_revision(revision="@-") == c.repo.resolve_revision(
        revision="main"
    )
    assert c.repo.revision_file(revision=old, filename="dep.txt").is_regular is True
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"
    with c.repo.temporary_workspace(revision=old) as preserved:
        assert (preserved.path / "dep.txt").read_text(
            encoding="utf-8"
        ) == expected_old_content


def test_refresh_inspection_failure_has_no_mutation(tmp_path: Path) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    state.clear_calls()
    state.fail(
        "working_copy_state", error=RevisionError("inspection failed"), path=path
    )

    with pytest.raises(RevisionError, match="inspection failed"):
        refresh_working_copy_from_main(repo=repo)
    assert not any(
        call.method in {"rebase_working_copy", "new_change"} for call in state.attempts
    )


@pytest.mark.parametrize("failure_method", ["is_ancestor", "rebase_working_copy"])
def test_refresh_relationship_or_rebase_failure_has_no_completed_mutation(
    tmp_path: Path, failure_method: str
) -> None:
    state = FakeJjState()
    path = tmp_path / failure_method
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    base = repo.resolve_revision(revision="main")
    tip = state.seed_commit(
        path,
        parent=base,
        files={"dep.txt": "version=2\n"},
        description="advance main",
    )
    state.seed_bookmark(path, bookmark="main", targets=(tip,))
    change = repo.change_id()
    failure = RevisionError(f"{failure_method} failed")
    state.clear_calls()
    state.fail(failure_method, error=failure, path=path)

    with pytest.raises(RevisionError) as caught:
        refresh_working_copy_from_main(repo=repo)

    assert caught.value is failure
    assert repo.change_id() == change
    assert (path / "dep.txt").read_text(encoding="utf-8") == "version=1\n"
    assert not any(call.method == "new_change" for call in state.effects)


@pytest.mark.parametrize("failed_listing", ["merged", "closed", "local"])
def test_prune_finishes_all_listings_before_deletion(
    tmp_path: Path, failed_listing: str
) -> None:
    state = FakeJjState()
    path = tmp_path / failed_listing
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    base = repo.resolve_revision(revision="main")
    state.seed_bookmark(path, bookmark=MANAGED, targets=(base,))
    host = state.code_host(path)
    host.seed_pr(bookmark=MANAGED, state="merged")
    state.clear_calls()
    if failed_listing == "merged":
        host.fail("pr_bookmarks", ordinal=1, error=CodeHostError("merged failed"))
    elif failed_listing == "closed":
        host.fail("pr_bookmarks", ordinal=2, error=CodeHostError("closed failed"))
    else:
        state.fail("local_bookmarks", error=RevisionError("local failed"), path=path)

    with pytest.raises((CodeHostError, RevisionError)):
        prune_stale_bookmarks(repo=repo, host=host)
    assert not any(call.method == "delete_bookmark" for call in state.attempts)


def test_prune_fetch_failure_stops_before_host_or_deletion(tmp_path: Path) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    host = state.code_host(path)
    failure = RevisionError("fetch failed")
    state.clear_calls()
    state.fail("fetch", error=failure, path=path)

    with pytest.raises(RevisionError) as caught:
        prune_stale_bookmarks(repo=repo, host=host)

    assert caught.value is failure
    assert host.attempts == []
    assert not any(call.method == "delete_bookmark" for call in state.attempts)


def test_prune_deletes_sorted_managed_intersection_and_stops_on_failure(
    tmp_path: Path,
) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    base = repo.resolve_revision(revision="main")
    stale = [
        "mm/resolve-dependencies-b",
        "mm/update-dependencies-a",
        "mm/update-dependencies-c",
    ]
    for bookmark in [*stale, "feature/unrelated"]:
        state.seed_bookmark(path, bookmark=bookmark, targets=(base,))
    host = state.code_host(path)
    for bookmark in stale:
        host.seed_pr(bookmark=bookmark, state="closed")
    host.seed_pr(bookmark="feature/unrelated", state="closed")
    state.clear_calls()
    state.fail(
        "delete_bookmark", ordinal=2, error=RevisionError("delete failed"), path=path
    )

    with pytest.raises(RevisionError, match="delete failed"):
        prune_stale_bookmarks(repo=repo, host=host)

    ordered = sorted(stale)
    assert repo.bookmark_exists(bookmark=ordered[0]) is False
    assert repo.bookmark_exists(bookmark=ordered[1]) is True
    assert repo.bookmark_exists(bookmark=ordered[2]) is True
    assert repo.bookmark_exists(bookmark="feature/unrelated") is True
    delete_attempts = [
        call for call in state.attempts if call.method == "delete_bookmark"
    ]
    assert [dict(call.arguments)["bookmark"] for call in delete_attempts] == ordered[:2]


def _submission_case(tmp_path: Path):
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    base = repo.resolve_revision(revision="main")
    tip = state.seed_commit(
        path,
        parent=base,
        files={"dep.txt": "version=2\n"},
        description="update",
    )
    state.seed_bookmark(path, bookmark=MANAGED, targets=(tip,))
    state.clear_calls()
    return state, repo, state.code_host(path), ExpectedRevisions(base, tip)


def test_submission_push_failure_never_calls_host(tmp_path: Path) -> None:
    state, repo, host, expected = _submission_case(tmp_path)
    state.fail("push_bookmark", error=RevisionError("push failed"), path=repo.path)

    with pytest.raises(RevisionError, match="push failed"):
        push_bookmark_and_create_pr(
            repo=repo, host=host, bookmark=MANAGED, expected=expected
        )
    assert host.attempts == []


def test_submission_postcheck_failure_retains_push_and_never_calls_host(
    tmp_path: Path,
) -> None:
    state, repo, host, expected = _submission_case(tmp_path)
    state.hook(
        "push_bookmark",
        phase="postcheck",
        path=repo.path,
        action=lambda: state.seed_bookmark(
            repo.path, bookmark="main", targets=(expected.tip,)
        ),
    )

    with pytest.raises(RevisionError, match="changed"):
        push_bookmark_and_create_pr(
            repo=repo, host=host, bookmark=MANAGED, expected=expected
        )
    assert any(call.method == "push_bookmark" for call in state.effects)
    assert host.attempts == []


def test_submission_host_failure_retains_push_and_retry_succeeds(
    tmp_path: Path,
) -> None:
    state, repo, host, expected = _submission_case(tmp_path)
    host.fail("create_pr", error=CodeHostError("host unavailable"))

    with pytest.raises(CodeHostError, match="host unavailable"):
        push_bookmark_and_create_pr(
            repo=repo, host=host, bookmark=MANAGED, expected=expected
        )
    assert any(call.method == "push_bookmark" for call in state.effects)
    assert (
        push_bookmark_and_create_pr(
            repo=repo, host=host, bookmark=MANAGED, expected=expected
        )
        == "PR #1"
    )
    assert (
        push_bookmark_and_create_pr(
            repo=repo, host=host, bookmark=MANAGED, expected=expected
        )
        == f"PR already exists for {MANAGED}"
    )


def test_workspace_policy_creates_and_removes_registered_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "MM_HOME", tmp_path / ".mm")
    state = FakeJjState()
    repo = state.seed_repository(tmp_path / "source", files={"dep.txt": "v1\n"})

    created = create_workspace(repo=repo, project="owner/project", revision="main")
    assert created == tmp_path / ".mm" / "workspaces" / "owner_project"
    assert "mm-owner_project" in repo.workspace_names()

    remove_workspace(repo=repo, project="owner/project")
    assert not created.exists()
    assert "mm-owner_project" not in repo.workspace_names()


def test_workspace_removal_absence_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "MM_HOME", tmp_path / ".mm")
    state = FakeJjState()
    repo = state.seed_repository(tmp_path / "source", files={"dep.txt": "v1\n"})
    state.clear_calls()

    remove_workspace(repo=repo, project="missing")

    assert not any(call.method == "forget_workspace" for call in state.attempts)


def test_workspace_removal_deletes_known_unregistered_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "MM_HOME", tmp_path / ".mm")
    state = FakeJjState()
    repo = state.seed_repository(tmp_path / "source", files={"dep.txt": "v1\n"})
    workspace = paths.workspaces_dir() / "recovery"
    workspace.mkdir(parents=True)
    (workspace / "keep.txt").write_text("obsolete", encoding="utf-8")

    remove_workspace(repo=repo, project="recovery")

    assert not workspace.exists()
    assert not any(call.method == "forget_workspace" for call in state.attempts)


def test_workspace_removal_rejects_final_symlink_and_preserves_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "MM_HOME", tmp_path / ".mm")
    state = FakeJjState()
    repo = state.seed_repository(tmp_path / "source", files={"dep.txt": "v1\n"})
    root = paths.workspaces_dir()
    sibling = root / "project-b"
    sibling.mkdir(parents=True)
    keep = sibling / "keep.txt"
    keep.write_text("recovery", encoding="utf-8")
    (root / "project-a").symlink_to(sibling, target_is_directory=True)

    with pytest.raises(RevisionError, match="symlink") as caught:
        remove_workspace(repo=repo, project="project-a")

    assert isinstance(caught.value.__cause__, ValueError)
    assert keep.read_text(encoding="utf-8") == "recovery"
    assert sibling.is_dir()
    assert (root / "project-a").is_symlink()


def test_workspace_path_computation_failure_is_typed_with_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "MM_HOME", tmp_path / ".mm")
    state = FakeJjState()
    repo = state.seed_repository(tmp_path / "source", files={"dep.txt": "v1\n"})
    failure = OSError("path resolution failed")

    def fail_path(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(paths, "project_file", fail_path)

    with pytest.raises(RevisionError, match="workspace path") as caught:
        create_workspace(repo=repo, project="project-a", revision="main")
    assert caught.value.__cause__ is failure


def test_workspace_listing_failure_preserves_unregistered_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "MM_HOME", tmp_path / ".mm")
    state = FakeJjState()
    source = tmp_path / "source"
    repo = state.seed_repository(source, files={"dep.txt": "v1\n"})
    recovery = paths.workspaces_dir() / "recovery"
    recovery.mkdir(parents=True)
    (recovery / "keep.txt").write_text("recovery", encoding="utf-8")
    state.fail("workspace_names", error=RevisionError("inspection failed"), path=source)

    with pytest.raises(RevisionError, match="inspection failed"):
        remove_workspace(repo=repo, project="recovery")
    assert (recovery / "keep.txt").read_text(encoding="utf-8") == "recovery"


def test_workspace_forget_failure_preserves_registered_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "MM_HOME", tmp_path / ".mm")
    state = FakeJjState()
    source = tmp_path / "source"
    repo = state.seed_repository(source, files={"dep.txt": "v1\n"})
    workspace = create_workspace(repo=repo, project="recovery", revision="main")
    (workspace / "keep.txt").write_text("recovery", encoding="utf-8")
    state.fail("forget_workspace", error=RevisionError("forget failed"), path=source)

    with pytest.raises(RevisionError, match="forget failed"):
        remove_workspace(repo=repo, project="recovery")
    assert (workspace / "keep.txt").read_text(encoding="utf-8") == "recovery"


def test_current_label_uses_current_then_parent_then_change_and_normalizes_failure(
    tmp_path: Path,
) -> None:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "v1\n"})
    repo.set_bookmark(bookmark="current", revision="@")
    assert current_label(repo=repo) == "current"
    repo.delete_bookmark(bookmark="current")
    assert current_label(repo=repo) == "main"
    repo.delete_bookmark(bookmark="main")
    assert current_label(repo=repo) == f"@ {repo.change_id()}"
    state.fail("revision_bookmarks", error=RevisionError("lookup failed"), path=path)
    assert current_label(repo=repo) == "unknown"


@pytest.mark.integration
@pytest.mark.parametrize("operation", ["promote", "reset", "push"])
def test_real_guarded_postcheck_race_retains_completed_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
):
    c = _real_case(tmp_path, monkeypatch)
    base = c.repo.resolve_revision(revision="main")
    tip = c.commit_file("dep.txt", "tip\n", "tip")
    c.repo.set_bookmark(bookmark=MANAGED, revision=tip)
    c.repo.new_change(revision=base)
    c.write_file("dep.txt", "sibling\n")
    c.describe("sibling")
    sibling = c.repo.resolve_revision(revision="@")
    expected = ExpectedRevisions(base=base, tip=tip)
    operation_id = _run_jj(
        c.repo.path, "op", "log", "--limit", "1", "--no-graph", "-T", "id"
    ).stdout.strip()
    assert operation_id

    captured_run = vcs.run_captured
    injected = False

    def inject_race(command, cwd, **kwargs):
        nonlocal injected
        completed = captured_run(command, cwd, **kwargs)
        arguments = list(command)
        is_target = (
            (operation == "promote" and arguments[1:4] == ["bookmark", "set", "main"])
            or (operation == "reset" and arguments[1:4] == ["bookmark", "set", MANAGED])
            or (operation == "push" and arguments[1:3] == ["git", "push"])
        )
        if injected or not is_target or Path(cwd).resolve() != c.repo.path.resolve():
            return completed
        injected = True
        target = "main" if operation in {"promote", "push"} else MANAGED
        prefix = [] if operation == "push" else ["--at-op", operation_id]
        raced = _run_jj(
            c.repo.path,
            *prefix,
            "bookmark",
            "set",
            target,
            "-r",
            sibling,
            "--allow-backwards",
        )
        assert raced.returncode == 0, raced.stderr
        return completed

    monkeypatch.setattr(vcs, "run_captured", inject_race)
    with pytest.raises(RevisionError):
        if operation == "promote":
            c.repo.promote_bookmark_to_main(bookmark=MANAGED, expected=expected)
        elif operation == "reset":
            c.repo.reset_verified_bookmark(bookmark=MANAGED, expected=expected)
        else:
            c.repo.push_bookmark(bookmark=MANAGED, expected=expected)
    assert injected is True

    if operation == "promote":
        assert c.repo.bookmark_conflicted(bookmark="main") is True
        assert _bookmark_targets(
            c.repo, bookmark="main", candidates={base, tip, sibling}
        ) == frozenset({tip, sibling})
    elif operation == "reset":
        assert c.repo.bookmark_conflicted(bookmark=MANAGED) is True
        assert _bookmark_targets(
            c.repo, bookmark=MANAGED, candidates={base, tip, sibling}
        ) == frozenset({base, sibling})
    else:
        assert c.repo.resolve_revision(revision="main") == sibling
        fetched = _run_jj(c.origin_peer.repo.path, "git", "fetch", "--remote", "origin")
        assert fetched.returncode == 0, fetched.stderr
        published = _run_jj(
            c.origin_peer.repo.path,
            "log",
            "-r",
            f"{MANAGED}@origin",
            "--no-graph",
            "-T",
            'commit_id ++ "\\n"',
        )
        assert published.returncode == 0, published.stderr
        assert published.stdout.strip() == tip


def test_fake_failure_and_hook_ordinals_are_relative_to_registration(tmp_path: Path):
    state = FakeJjState()
    path = tmp_path / "ordinal-repository"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    repo.has_changes()
    failure = RevisionError("registered failure")
    state.fail("has_changes", error=failure, path=path)
    with pytest.raises(RevisionError) as caught:
        repo.has_changes()
    assert caught.value is failure

    repo.bookmark_exists(bookmark="main")
    observed: list[str] = []
    state.hook(
        "bookmark_exists",
        phase="before",
        action=lambda: observed.append("hook"),
        path=path,
    )
    assert repo.bookmark_exists(bookmark="main") is True
    assert observed == ["hook"]

    state.clear_calls()
    state.fail("working_copy_state", error=RevisionError("after clear"), path=path)
    with pytest.raises(RevisionError, match="after clear"):
        repo.working_copy_state()


@pytest.mark.integration
def test_guarded_change_push_names_only_the_managed_bookmark(tmp_path: Path):
    c = _real_case(tmp_path)
    base = c.repo.resolve_revision(revision="main")
    c.repo.new_change(revision="main")
    c.write_file("dep.txt", "version=2\n")
    c.describe("upgrade dependency")
    tip = c.repo.resolve_revision(revision="@")
    c.repo.set_bookmark(bookmark=MANAGED, revision=tip)
    c.repo.set_bookmark(bookmark="unrelated", revision=tip)
    expected = ExpectedRevisions(base=base, tip=tip)
    c.repo.push_bookmark(bookmark=MANAGED, expected=expected)
    c.repo.push_bookmark(bookmark=MANAGED, expected=expected)
    fetched = _run_jj(c.repo.path, "git", "fetch", "--remote", "origin")
    assert fetched.returncode == 0, fetched.stderr
    assert _run_jj(c.repo.path, "log", "-r", f"{MANAGED}@origin").returncode == 0
    assert _run_jj(c.repo.path, "log", "-r", "unrelated@origin").returncode != 0


@pytest.mark.parametrize(
    ("method", "changed_bookmark"),
    [
        ("promote_bookmark_to_main", "main"),
        ("reset_verified_bookmark", MANAGED),
        ("push_bookmark", "main"),
    ],
)
def test_fake_postcheck_race_keeps_completed_effect(
    tmp_path: Path, method: str, changed_bookmark: str
):
    state = FakeJjState()
    path = tmp_path / method
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    base = repo.resolve_revision(revision="main")
    tip = state.seed_commit(
        path,
        parent=base,
        files={"dep.txt": "version=2\n"},
        description="upgrade dependency",
    )
    sibling = state.seed_commit(
        path,
        parent=base,
        files={"dep.txt": "sibling\n"},
        description="concurrent change",
    )
    state.seed_bookmark(path, bookmark=MANAGED, targets=(tip,))
    expected = ExpectedRevisions(base=base, tip=tip)
    state.clear_calls()
    state.hook(
        method,
        phase="postcheck",
        action=lambda: state.seed_bookmark(
            path, bookmark=changed_bookmark, targets=(sibling,)
        ),
    )

    with pytest.raises(RevisionError, match="changed"):
        if method == "promote_bookmark_to_main":
            repo.promote_bookmark_to_main(bookmark=MANAGED, expected=expected)
        elif method == "reset_verified_bookmark":
            repo.reset_verified_bookmark(bookmark=MANAGED, expected=expected)
        else:
            repo.push_bookmark(bookmark=MANAGED, expected=expected)

    assert any(call.method == method for call in state.effects)
    assert repo.resolve_revision(revision=changed_bookmark) == sibling


def test_temporary_workspace_registration_failure_removes_owned_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    container = tmp_path / "allocated-proof"
    state.fail("add_workspace", error=RevisionError("registration failed"))

    def allocate(*, prefix: str) -> str:
        assert prefix == "mm-gradle-proof-"
        container.mkdir()
        return str(container)

    monkeypatch.setattr(vcs.tempfile, "mkdtemp", allocate)
    entered = False
    with (
        pytest.raises(RevisionError, match="registration failed"),
        repo.temporary_workspace(revision="main"),
    ):
        entered = True
    assert entered is False
    assert not any(call.method == "forget_workspace" for call in state.attempts)
    assert not container.exists()


@pytest.mark.parametrize("mutation", ["replace", "symlink"])
def test_temporary_workspace_marker_tampering_prevents_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
):
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    container = tmp_path / "allocated-proof"

    def allocate(*, prefix: str) -> str:
        assert prefix == "mm-gradle-proof-"
        container.mkdir()
        return str(container)

    monkeypatch.setattr(vcs.tempfile, "mkdtemp", allocate)
    with (
        pytest.raises(RevisionError, match="ownership marker changed"),
        repo.temporary_workspace(revision="main"),
    ):
        marker = container / ".mm-proof-owner"
        if mutation == "replace":
            marker.write_text("replacement", encoding="utf-8")
        else:
            marker.unlink()
            marker.symlink_to(container / "replacement")
    assert container.exists()


def test_temporary_workspace_body_error_keeps_cleanup_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    container = tmp_path / "allocated-proof"
    state.fail("forget_workspace", error=RevisionError("forget failed"))

    def allocate(*, prefix: str) -> str:
        assert prefix == "mm-gradle-proof-"
        container.mkdir()
        return str(container)

    monkeypatch.setattr(vcs.tempfile, "mkdtemp", allocate)

    def fail_remove(_path: Path) -> None:
        msg = "remove failed"
        raise OSError(msg)

    monkeypatch.setattr(vcs.shutil, "rmtree", fail_remove)
    body_error = RuntimeError("caller")
    with (
        pytest.raises(RuntimeError) as caught,
        repo.temporary_workspace(revision="main"),
    ):
        raise body_error
    assert caught.value is body_error
    assert caught.value.__notes__ == [
        "forget workspace failed: forget failed; "
        "remove proof workspace failed: remove failed"
    ]


def test_temporary_workspace_propagates_unexpected_cleanup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    container = tmp_path / "allocated-proof"

    def allocate(*, prefix: str) -> str:
        assert prefix == "mm-gradle-proof-"
        container.mkdir()
        return str(container)

    unexpected = TypeError("unexpected cleanup failure")

    def fail_remove(_path: Path) -> None:
        raise unexpected

    monkeypatch.setattr(vcs.tempfile, "mkdtemp", allocate)
    with (
        pytest.raises(TypeError) as caught,
        monkeypatch.context() as cleanup_patch,
    ):
        cleanup_patch.setattr(vcs.shutil, "rmtree", fail_remove)
        with repo.temporary_workspace(revision="main"):
            pass
    assert caught.value is unexpected
    vcs.shutil.rmtree(container)


def test_temporary_workspace_cleanup_errors_raise_combined_revision_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    container = tmp_path / "allocated-proof"
    state.fail("forget_workspace", error=RevisionError("forget failed"))

    def allocate(*, prefix: str) -> str:
        assert prefix == "mm-gradle-proof-"
        container.mkdir()
        return str(container)

    def fail_remove(_path: Path) -> None:
        msg = "remove failed"
        raise OSError(msg)

    monkeypatch.setattr(vcs.tempfile, "mkdtemp", allocate)
    monkeypatch.setattr(vcs.shutil, "rmtree", fail_remove)
    with (
        pytest.raises(RevisionError) as caught,
        repo.temporary_workspace(revision="main"),
    ):
        pass
    assert "forget failed" in str(caught.value)
    assert "remove failed" in str(caught.value)


def test_fake_tracked_fetch_reconciles_descendant_remote_advance(tmp_path: Path):
    state = FakeJjState()
    source_path = tmp_path / "source"
    source = state.seed_repository(source_path, files={"dep.txt": "version=1\n"})
    peer = state.seed_peer(tmp_path / "peer", source=source_path)
    base = source.resolve_revision(revision="main")
    advanced = state.seed_commit(
        source_path,
        parent=base,
        files={"dep.txt": "version=2\n"},
        description="remote advance",
    )
    state.seed_remote(source_path, bookmark="main", targets=(advanced,))
    peer.fetch(main_only=True)
    assert peer.resolve_revision(revision="main") == advanced
    assert peer.resolve_revision(revision="main@origin") == advanced


def test_fake_untracked_fetch_updates_tracking_without_moving_main(tmp_path: Path):
    state = FakeJjState()
    source_path = tmp_path / "source"
    source = state.seed_repository(source_path, files={"dep.txt": "version=1\n"})
    peer = state.seed_peer(tmp_path / "peer", source=source_path, track_main=False)
    base = source.resolve_revision(revision="main")
    advanced = state.seed_commit(
        source_path,
        parent=base,
        files={"dep.txt": "version=2\n"},
        description="remote advance",
    )
    state.seed_remote(source_path, bookmark="main", targets=(advanced,))
    peer.fetch(main_only=True)
    assert peer.resolve_revision(revision="main") == base
    assert peer.resolve_revision(revision="main@origin") == advanced
