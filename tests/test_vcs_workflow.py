from pathlib import Path

import pytest

from maintenance_man import paths
from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import (
    SyncAction,
    create_workspace,
    current_label,
    ensure_main_bookmark,
    refresh_working_copy_from_main,
    remove_workspace,
    sync_main,
)
from tests.support.repository import (
    RepositoryCase,
    commit_file,
    conflict_bookmark,
    describe,
    fail_repository_method,
    push_peer_main,
    remote_bookmark_target,
    run_after_jj_command,
    run_jj,
    track_main,
    write_file,
)


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


def test_ensure_main_leaves_existing_local_bookmark_unchanged(
    repository_case: RepositoryCase,
) -> None:
    repo = repository_case.repo
    main = repo.resolve_revision(revision="main")

    ensure_main_bookmark(repo=repo)

    assert repo.resolve_revision(revision="main") == main


def test_ensure_main_refuses_when_local_and_origin_are_absent(
    repository_case: RepositoryCase,
) -> None:
    repo = repository_case.repo
    forgotten = run_jj(repo.path, "bookmark", "forget", "--include-remotes", "main")
    assert forgotten.returncode == 0, forgotten.stderr

    with pytest.raises(RevisionError, match=r"main@origin"):
        ensure_main_bookmark(repo=repo)

    assert repo.bookmark_exists(bookmark="main") is False


@pytest.mark.parametrize(
    ("method", "delete_main_first", "main_exists_after"),
    [("bookmark_exists", False, True), ("resolve_revision", True, False)],
)
def test_given_inspection_failure_when_ensuring_main_then_failure_propagates_unchanged(
    repository_case: RepositoryCase,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    delete_main_first: bool,
    main_exists_after: bool,
) -> None:
    repo = repository_case.repo
    if delete_main_first:
        repo.delete_bookmark(bookmark="main")
    failure = RevisionError(f"{method} failed")
    fail_repository_method(monkeypatch, repo.path, method, failure)

    with pytest.raises(RevisionError) as caught:
        ensure_main_bookmark(repo=repo)

    assert caught.value is failure
    assert repo.bookmark_exists(bookmark="main") is main_exists_after


@pytest.mark.parametrize("method", ["fetch", "bookmark_conflicted", "same_revision"])
def test_sync_inspection_failure_preserves_the_repository(
    repository_case: RepositoryCase,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    c = repository_case
    main_before = c.repo.resolve_revision(revision="main")
    change_before = c.repo.change_id()
    working_copy_before = c.repo.resolve_revision(revision="@")
    file_before = (c.repo.path / "dep.txt").read_text(encoding="utf-8")
    failure = RevisionError(f"{method} failed")
    fail_repository_method(monkeypatch, c.repo.path, method, failure)

    with pytest.raises(RevisionError) as caught:
        sync_main(repo=c.repo)

    assert caught.value is failure
    assert c.repo.resolve_revision(revision="main") == main_before
    assert c.repo.change_id() == change_before
    assert c.repo.resolve_revision(revision="@") == working_copy_before
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == file_before


def test_sync_pulls_remote_advance_when_main_is_untracked(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    track_main(c.repo, enabled=False)
    c.peer.rebase_working_copy(revision="main")
    peer_tip = commit_file(c.peer, "dep.txt", "version=2\n", "peer advance")
    push_peer_main(c.peer)

    assert sync_main(repo=c.repo) is SyncAction.PULLED
    assert c.repo.resolve_revision(revision="main") == peer_tip
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"


def test_sync_remote_advance_move_failure_preserves_local_main(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = repository_case
    repo = c.repo
    base = repo.resolve_revision(revision="main")
    track_main(c.repo, enabled=False)
    c.peer.rebase_working_copy(revision="main")
    commit_file(c.peer, "dep.txt", "version=2\n", "remote advance")
    push_peer_main(c.peer)
    failure = RevisionError("cannot move local main")
    fail_repository_method(monkeypatch, c.repo.path, "set_bookmark", failure)

    with pytest.raises(RevisionError) as caught:
        sync_main(repo=repo)

    assert caught.value is failure
    assert repo.resolve_revision(revision="main") == base
    assert (repo.path / "dep.txt").read_text(encoding="utf-8") == "version=1\n"


def test_sync_tracked_main_remote_advance_is_already_reconciled_by_fetch(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    c.peer.rebase_working_copy(revision="main")
    peer_tip = commit_file(c.peer, "dep.txt", "version=2\n", "peer advance")
    push_peer_main(c.peer)

    assert sync_main(repo=c.repo) is SyncAction.UNCHANGED
    assert c.repo.resolve_revision(revision="main") == peer_tip
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"


def test_sync_pushes_local_advance_then_fetches_before_refresh(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    tip = commit_file(c.repo, "dep.txt", "version=2\n", "local advance")
    c.repo.set_bookmark(bookmark="main", revision=tip)

    assert sync_main(repo=c.repo) is SyncAction.PUSHED
    assert c.repo.resolve_revision(revision="main@origin") == tip
    c.peer.fetch(main_only=True)
    assert c.peer.resolve_revision(revision="main") == tip


def test_sync_rechecks_remote_before_refresh(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = repository_case
    tip = commit_file(c.repo, "dep.txt", "version=2\n", "local update")
    c.repo.set_bookmark(bookmark="main", revision=tip)
    observed: dict[str, str] = {}

    def sender_advance() -> None:
        moved = commit_file(c.repo, "dep.txt", "version=3\n", "concurrent local update")
        c.repo.set_bookmark(bookmark="main", revision=moved)
        observed["main"] = moved
        observed["change"] = c.repo.change_id()

    run_after_jj_command(monkeypatch, c.repo.path, ("git", "push"), sender_advance)
    with pytest.raises(RevisionError, match="match"):
        sync_main(repo=c.repo)
    assert c.repo.resolve_revision(revision="main") == observed["main"]
    assert c.repo.resolve_revision(revision="main@origin") == tip
    assert c.repo.change_id() == observed["change"]


@pytest.mark.parametrize(
    ("method", "message"),
    [
        ("fetch", "second fetch failed"),
        ("same_revision", "post-push comparison failed"),
    ],
)
def test_sync_post_push_failure_prevents_refresh(
    repository_case: RepositoryCase,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    message: str,
) -> None:
    c = repository_case
    repo = c.repo
    tip = commit_file(repo, "dep.txt", "version=2\n", "local advance")
    repo.set_bookmark(bookmark="main", revision=tip)
    change_before = repo.change_id()
    working_copy_before = repo.resolve_revision(revision="@")
    file_before = (repo.path / "dep.txt").read_text(encoding="utf-8")
    failure = RevisionError(message)
    fail_repository_method(monkeypatch, repo.path, method, failure, call=2)

    with pytest.raises(RevisionError) as caught:
        sync_main(repo=repo)

    assert caught.value is failure
    assert remote_bookmark_target(c.peer, "main") == tip
    assert repo.change_id() == change_before
    assert repo.resolve_revision(revision="@") == working_copy_before
    assert (repo.path / "dep.txt").read_text(encoding="utf-8") == file_before


def test_given_local_and_remote_main_diverge_when_syncing_then_repository_is_preserved(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    local = commit_file(c.repo, "dep.txt", "local\n", "local advance")
    c.repo.set_bookmark(bookmark="main", revision=local)
    c.peer.rebase_working_copy(revision="main")
    commit_file(c.peer, "dep.txt", "remote\n", "remote advance")
    push_peer_main(c.peer)
    change_before = c.repo.change_id()
    working_copy_before = c.repo.resolve_revision(revision="@")
    file_before = (c.repo.path / "dep.txt").read_text(encoding="utf-8")

    with pytest.raises(RevisionError):
        sync_main(repo=c.repo)
    assert c.repo.change_id() == change_before
    assert c.repo.resolve_revision(revision="@") == working_copy_before
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == file_before


def test_given_descendant_main_when_syncing_then_unconflicted_bookmark_reaches_push(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    c.repo.new_change(revision=base)
    write_file(c.repo, "dep.txt", "descendant\n")
    describe(c.repo, "descendant")
    descendant = c.repo.resolve_revision(revision="@")
    conflict_bookmark(c.repo, "main", base, descendant)
    push_attempted = RevisionError("push attempted")
    fail_repository_method(monkeypatch, c.repo.path, "push_bookmark", push_attempted)

    assert c.repo.bookmark_conflicted(bookmark="main") is False
    with pytest.raises(RevisionError) as caught:
        sync_main(repo=c.repo)
    assert caught.value is push_attempted


def test_given_sibling_main_targets_when_syncing_then_conflict_is_refused(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    repo = c.repo
    base = repo.resolve_revision(revision="main")
    repo.new_change(revision=base)
    write_file(c.repo, "dep.txt", "left sibling\n")
    describe(c.repo, "left sibling")
    left = repo.resolve_revision(revision="@")
    repo.new_change(revision=base)
    write_file(c.repo, "dep.txt", "right sibling\n")
    describe(c.repo, "right sibling")
    right = repo.resolve_revision(revision="@")
    conflict_bookmark(c.repo, "main", left, right)

    with pytest.raises(RevisionError, match="conflicted"):
        sync_main(repo=repo)
    assert repo.bookmark_conflicted(bookmark="main") is True


def test_refresh_empty_change_preserves_change_identity(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    old_change = c.repo.change_id()
    track_main(c.repo, enabled=False)
    c.peer.rebase_working_copy(revision="main")
    commit_file(c.peer, "dep.txt", "version=2\n", "peer advance")
    push_peer_main(c.peer)
    c.repo.fetch(main_only=True)
    c.repo.set_bookmark(bookmark="main", revision="main@origin")

    refresh_working_copy_from_main(repo=c.repo)

    assert c.repo.change_id() == old_change
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"


def test_refresh_dirty_descendant_is_left_unchanged(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    write_file(c.repo, "dep.txt", "local dirty\n")
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
        write_file(c.repo, "dep.txt", expected_old_content)
    elif protected_state == "described":
        describe(c.repo, "work in progress")
    else:
        c.repo.set_bookmark(bookmark="feature/current", revision="@")
    old = c.repo.resolve_revision(revision="@")
    track_main(c.repo, enabled=False)
    c.peer.rebase_working_copy(revision="main")
    commit_file(c.peer, "dep.txt", "version=2\n", "peer advance")
    push_peer_main(c.peer)
    c.repo.fetch(main_only=True)
    c.repo.set_bookmark(bookmark="main", revision="main@origin")

    refresh_working_copy_from_main(repo=c.repo)

    assert c.repo.resolve_revision(revision="@-") == c.repo.resolve_revision(
        revision="main"
    )
    assert c.repo.revision_file(revision=old, filename="dep.txt").is_regular is True
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=2\n"
    c.repo.new_change(revision=old)
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == expected_old_content


@pytest.mark.parametrize(
    "failure_method", ["is_blank_working_copy", "is_ancestor", "rebase_working_copy"]
)
def test_given_refresh_step_failure_when_refreshing_then_working_copy_is_unchanged(
    repository_case: RepositoryCase,
    monkeypatch: pytest.MonkeyPatch,
    failure_method: str,
) -> None:
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    tip = commit_file(c.repo, "dep.txt", "version=2\n", "advance main")
    c.repo.set_bookmark(bookmark="main", revision=tip)
    c.repo.new_change(revision=base)
    before = c.repo.resolve_revision(revision="@")
    failure = RevisionError(f"{failure_method} failed")
    fail_repository_method(monkeypatch, c.repo.path, failure_method, failure)

    with pytest.raises(RevisionError) as caught:
        refresh_working_copy_from_main(repo=c.repo)

    assert caught.value is failure
    assert c.repo.resolve_revision(revision="@") == before
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=1\n"


def test_workspace_policy_creates_and_removes_registered_path(
    repository_case: RepositoryCase, tmp_path: Path
) -> None:
    repo = repository_case.repo

    created = create_workspace(repo=repo, project="owner/project", revision="main")
    assert created == tmp_path / ".mm" / "workspaces" / "owner_project"
    assert "mm-owner_project" in repo.workspace_names()

    remove_workspace(repo=repo, project="owner/project")
    assert not created.exists()
    assert "mm-owner_project" not in repo.workspace_names()


def test_workspace_removal_absence_is_noop(
    repository_case: RepositoryCase,
) -> None:
    repo = repository_case.repo

    remove_workspace(repo=repo, project="missing")

    assert repo.workspace_names() == frozenset({"default"})


def test_workspace_removal_deletes_known_unregistered_path(
    repository_case: RepositoryCase,
) -> None:
    repo = repository_case.repo
    workspace = paths.workspaces_dir() / "recovery"
    workspace.mkdir(parents=True)
    (workspace / "keep.txt").write_text("obsolete", encoding="utf-8")

    remove_workspace(repo=repo, project="recovery")

    assert not workspace.exists()
    assert repo.workspace_names() == frozenset({"default"})


def test_workspace_removal_rejects_final_symlink_and_preserves_sibling(
    repository_case: RepositoryCase,
) -> None:
    repo = repository_case.repo
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
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repository_case.repo
    failure = OSError("path resolution failed")

    def fail_path(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(paths, "project_file", fail_path)

    with pytest.raises(RevisionError, match="workspace path") as caught:
        create_workspace(repo=repo, project="project-a", revision="main")
    assert caught.value.__cause__ is failure


def test_workspace_listing_failure_preserves_unregistered_files(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repository_case.repo
    recovery = paths.workspaces_dir() / "recovery"
    recovery.mkdir(parents=True)
    (recovery / "keep.txt").write_text("recovery", encoding="utf-8")
    fail_repository_method(
        monkeypatch, repo.path, "workspace_names", RevisionError("inspection failed")
    )

    with pytest.raises(RevisionError, match="inspection failed"):
        remove_workspace(repo=repo, project="recovery")
    assert (recovery / "keep.txt").read_text(encoding="utf-8") == "recovery"


def test_workspace_forget_failure_preserves_registered_files(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repository_case.repo
    workspace = create_workspace(repo=repo, project="recovery", revision="main")
    (workspace / "keep.txt").write_text("recovery", encoding="utf-8")
    fail_repository_method(
        monkeypatch, repo.path, "forget_workspace", RevisionError("forget failed")
    )

    with pytest.raises(RevisionError, match="forget failed"):
        remove_workspace(repo=repo, project="recovery")
    assert (workspace / "keep.txt").read_text(encoding="utf-8") == "recovery"


def test_current_label_uses_current_then_parent_then_change_and_normalizes_failure(
    repository_case: RepositoryCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = repository_case.repo
    repo.set_bookmark(bookmark="current", revision="@")
    assert current_label(repo=repo) == "current"
    repo.delete_bookmark(bookmark="current")
    assert current_label(repo=repo) == "main"
    repo.delete_bookmark(bookmark="main")
    assert current_label(repo=repo) == f"@ {repo.change_id()}"
    fail_repository_method(
        monkeypatch, repo.path, "revision_bookmarks", RevisionError("lookup failed")
    )
    assert current_label(repo=repo) == "unknown"
