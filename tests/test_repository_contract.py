from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from maintenance_man import vcs
from maintenance_man.vcs import ExpectedRevisions, Repository, RevisionError
from tests.fake_vcs import FakeJjState

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


def _real_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch | None = None
) -> RepositoryCase:
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
    repo = vcs.JjRepository(path)
    pending_after_push: list[Callable[[], None]] = []
    if monkeypatch is not None:
        captured_run = vcs.run_captured

        def intercept_push(command, cwd, **kwargs):
            completed = captured_run(command, cwd, **kwargs)
            if (
                pending_after_push
                and list(command[:3]) == ["jj", "git", "push"]
                and Path(cwd).resolve() == path.resolve()
            ):
                action = pending_after_push.pop(0)
                action()
            return completed

        monkeypatch.setattr(vcs, "run_captured", intercept_push)
    repo.push_bookmark(bookmark="main")

    peer_path = tmp_path / "origin-peer"
    peer_path.mkdir()
    assert _run_jj(peer_path, "git", "init", "--colocate").returncode == 0
    assert (
        _run_jj(peer_path, "git", "remote", "add", "origin", str(origin_git)).returncode
        == 0
    )
    fetched = _run_jj(peer_path, "git", "fetch", "--remote", "origin")
    assert fetched.returncode == 0, fetched.stderr
    assert (
        _run_jj(peer_path, "bookmark", "create", "main", "-r", "main@origin").returncode
        == 0
    )
    tracked = _run_jj(peer_path, "bookmark", "track", "main@origin")
    assert tracked.returncode == 0, tracked.stderr
    assert _run_jj(peer_path, "new", "main").returncode == 0
    peer_repo = vcs.JjRepository(peer_path)

    def bind(bound_path: Path) -> Repository:
        inspected = _run_jj(bound_path, "workspace", "root")
        assert inspected.returncode == 0, f"unknown repository view: {bound_path}"
        return vcs.JjRepository(bound_path)

    def register_file(_filename: str) -> None:
        return None

    def write_file(filename: str, content: str | None) -> None:
        target = repo.path / filename
        if content is None:
            target.unlink(missing_ok=True)
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def commit_file(filename: str, content: str, message: str) -> str:
        write_file(filename, content)
        repo.commit(message=message)
        return repo.resolve_revision(revision="@-")

    def describe(message: str) -> None:
        result = _run_jj(repo.path, "describe", "-m", message)
        assert result.returncode == 0, result.stderr

    def force_bookmark(bookmark: str, revision: str) -> None:
        result = _run_jj(
            repo.path,
            "bookmark",
            "set",
            bookmark,
            "-r",
            revision,
            "--allow-backwards",
        )
        assert result.returncode == 0, result.stderr

    def conflict_bookmark(bookmark: str, left: str, right: str) -> None:
        if bookmark == "main":
            untracked = _run_jj(repo.path, "bookmark", "untrack", "main@origin")
            assert untracked.returncode == 0, untracked.stderr
        if repo.bookmark_exists(bookmark=bookmark):
            deleted = _run_jj(repo.path, "bookmark", "delete", bookmark)
            assert deleted.returncode == 0, deleted.stderr
        operation = _run_jj(
            repo.path, "op", "log", "--limit", "1", "--no-graph", "-T", "id"
        ).stdout.strip()
        assert (
            _run_jj(
                repo.path,
                "bookmark",
                "create",
                bookmark,
                "-r",
                left,
            ).returncode
            == 0
        )
        assert (
            _run_jj(
                repo.path,
                "--at-op",
                operation,
                "bookmark",
                "create",
                bookmark,
                "-r",
                right,
            ).returncode
            == 0
        )
        assert _run_jj(repo.path, "bookmark", "list", bookmark).returncode == 0

    def peer_commit_file(filename: str, content: str, message: str) -> str:
        target = peer_repo.path / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        peer_repo.commit(message=message)
        return peer_repo.resolve_revision(revision="@-")

    def peer_push_main() -> None:
        peer_repo.set_bookmark(bookmark="main", revision="@-")
        peer_repo.push_bookmark(bookmark="main")

    def track_main(enabled: bool) -> None:
        action = "track" if enabled else "untrack"
        result = _run_jj(repo.path, "bookmark", action, "main@origin")
        assert result.returncode == 0, result.stderr

    def after_push(action: Callable[[], None]) -> None:
        assert not pending_after_push, "only one pending push hook is supported"
        pending_after_push.append(action)

    return RepositoryCase(
        repo=repo,
        bind=bind,
        register_file=register_file,
        write_file=write_file,
        commit_file=commit_file,
        describe=describe,
        force_bookmark=force_bookmark,
        conflict_bookmark=conflict_bookmark,
        origin_peer=OriginPeer(peer_repo, peer_commit_file, peer_push_main),
        track_main=track_main,
        after_push=after_push,
    )


def _fake_case(tmp_path: Path) -> RepositoryCase:
    state = FakeJjState()
    path = tmp_path / "fake-repository"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    repo.push_bookmark(bookmark="main")
    peer_path = tmp_path / "origin-peer"
    peer_repo = state.seed_peer(peer_path, source=path, track_main=True)

    def register_file(filename: str) -> None:
        state.register_files(path, filename)

    def write_file(filename: str, content: str | None) -> None:
        target = repo.path / filename
        if content is None:
            target.unlink(missing_ok=True)
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def commit_file(filename: str, content: str, message: str) -> str:
        register_file(filename)
        write_file(filename, content)
        repo.commit(message=message)
        return repo.resolve_revision(revision="@-")

    def describe(message: str) -> None:
        repo.describe(message=message)

    def force_bookmark(bookmark: str, revision: str) -> None:
        state.seed_bookmark(path, bookmark=bookmark, targets=(revision,))

    def conflict_bookmark(bookmark: str, left: str, right: str) -> None:
        state.seed_bookmark(path, bookmark=bookmark, targets=(left, right))

    def peer_commit_file(filename: str, content: str, message: str) -> str:
        state.register_files(peer_path, filename)
        target = peer_repo.path / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        peer_repo.commit(message=message)
        return peer_repo.resolve_revision(revision="@-")

    def peer_push_main() -> None:
        peer_repo.set_bookmark(bookmark="main", revision="@-")
        peer_repo.push_bookmark(bookmark="main")

    def track_main(enabled: bool) -> None:
        state.track_main(path, enabled=enabled)

    def after_push(action: Callable[[], None]) -> None:
        state.hook(
            "push_bookmark",
            phase="postcheck",
            action=action,
            path=path,
        )

    state.clear_calls()

    return RepositoryCase(
        repo=repo,
        bind=state.repository,
        register_file=register_file,
        write_file=write_file,
        commit_file=commit_file,
        describe=describe,
        force_bookmark=force_bookmark,
        conflict_bookmark=conflict_bookmark,
        origin_peer=OriginPeer(peer_repo, peer_commit_file, peer_push_main),
        track_main=track_main,
        after_push=after_push,
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


def test_repository_case_exposes_complete_remote_harness(
    repository_case: RepositoryCase,
):
    c = repository_case
    assert callable(c.bind)
    assert callable(c.track_main)
    assert callable(c.after_push)
    assert c.origin_peer.repo.path != c.repo.path


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
    with (
        pytest.raises(RevisionError, match="registration failed"),
        repo.temporary_workspace(revision="main"),
    ):
        pytest.fail("registration failure must prevent entry")
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
        raise OSError("remove failed")

    monkeypatch.setattr(vcs.shutil, "rmtree", fail_remove)
    body_error = RuntimeError("caller")
    with (
        pytest.raises(RuntimeError) as caught,
        repo.temporary_workspace(revision="main"),
    ):
        raise body_error
    assert caught.value is body_error
    notes = "\n".join(caught.value.__notes__)
    assert "forget failed" in notes
    assert "remove failed" in notes


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
        raise OSError("remove failed")

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
