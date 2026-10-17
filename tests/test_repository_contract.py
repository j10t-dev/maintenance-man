from __future__ import annotations

from pathlib import Path

import pytest

from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import refresh_working_copy_from_main
from tests.fake_vcs import FakeJjState
from tests.support.repository import (
    MANAGED,
    RepositoryCase,
)


def test_given_missing_main_when_resolved_then_revision_error_is_raised(
    repository_case: RepositoryCase,
) -> None:
    repository_case.repo.delete_bookmark(bookmark="main")

    with pytest.raises(RevisionError):
        repository_case.repo.resolve_revision(revision="main")


def test_given_missing_bookmark_when_inspecting_conflict_then_revision_error_is_raised(
    repository_case: RepositoryCase,
) -> None:
    repository_case.repo.delete_bookmark(bookmark="main")

    with pytest.raises(
        RevisionError, match="Cannot inspect bookmark conflict for main"
    ):
        repository_case.repo.bookmark_conflicted(bookmark="main")


def test_given_amended_main_when_resolved_then_commit_identity_changes(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    c.repo.set_bookmark(bookmark="main", revision="@")
    before = c.repo.resolve_revision(revision="main")

    c.describe("amended main")
    c.repo.set_bookmark(bookmark="main", revision="@")

    assert c.repo.resolve_revision(revision="main") != before


def test_identity_tracks_content_and_metadata_separately(
    repository_case: RepositoryCase,
):
    c = repository_case
    original_commit = c.repo.resolve_revision(revision="@")
    original_tree = c.repo.tree_id()
    assert original_tree == c.repo.tree_id(revision="main")
    c.describe("metadata only")
    assert c.repo.resolve_revision(revision="@") != original_commit
    assert c.repo.tree_id() == original_tree
    c.register_file("dep.txt")
    c.write_file("dep.txt", "version=2\n")
    assert c.repo.tree_id() != original_tree
    assert c.repo.tree_id(revision="main") == original_tree
    c.write_file("dep.txt", "version=1\n")
    assert c.repo.tree_id() == original_tree


def test_revision_relationship_methods_distinguish_parent_and_child(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    parent = c.repo.resolve_revision(revision="main")
    c.repo.new_change(revision="main")
    c.describe("child")
    child = c.repo.resolve_revision(revision="@")

    assert c.repo.same_revision(left=parent, right=parent)
    assert not c.repo.same_revision(left=parent, right=child)
    assert c.repo.is_ancestor(ancestor=parent, descendant=child)
    assert not c.repo.is_ancestor(ancestor=child, descendant=parent)


def test_commit_then_advance_and_delete(repository_case: RepositoryCase):
    c = repository_case
    before = c.repo.resolve_revision(revision="main")
    c.register_file("dep.txt")
    c.write_file("dep.txt", "version=2\n")
    c.repo.commit(message="upgrade dependency")
    finished = c.repo.resolve_revision(revision="@-")
    assert finished != before
    assert c.repo.resolve_revision(revision="@-") == finished
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


def test_discard_restores_the_parent_tree(repository_case: RepositoryCase) -> None:
    c = repository_case
    c.write_file("dep.txt", "dirty\n")
    assert c.repo.has_changes() is True

    c.repo.discard()

    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=1\n"
    assert c.repo.has_changes() is False


def test_given_conflicted_bookmark_when_resolving_then_raises_and_direct_id_resolves(
    repository_case: RepositoryCase,
):
    c = repository_case
    assert c.repo.bookmark_exists(bookmark=MANAGED) is False
    c.repo.new_change(revision="main")
    c.write_file("dep.txt", "side=1\n")
    left = c.repo.resolve_revision(revision="@")
    c.repo.new_change(revision="main")
    c.write_file("dep.txt", "side=2\n")
    right = c.repo.resolve_revision(revision="@")
    c.conflict_bookmark(MANAGED, left, right)
    assert c.repo.bookmark_exists(bookmark=MANAGED) is True
    assert c.repo.bookmark_conflicted(bookmark=MANAGED) is True
    assert c.repo.resolve_revision(revision=left) == left
    with pytest.raises(RevisionError):
        c.repo.resolve_revision(revision=MANAGED)


def test_given_conflicted_bookmark_when_inspected_then_topic_survives_refresh(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    original = c.repo.resolve_revision(revision="@")
    c.repo.new_change(revision="main")
    c.write_file("dep.txt", "protected local change\n")
    c.repo.working_copy_state()
    current = c.repo.resolve_revision(revision="@")
    change_id = c.repo.change_id()
    c.conflict_bookmark("topic", current, original)

    state = c.repo.working_copy_state()
    assert state.bookmarks == ("topic",)
    assert c.repo.revision_bookmarks(revision="@") == ("topic",)

    refresh_working_copy_from_main(repo=c.repo)

    assert c.repo.revision_bookmarks(revision=current) == ("topic",)
    c.repo.new_change(revision=current)
    assert c.repo.change_id(revision="@-") == change_id
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == (
        "protected local change\n"
    )


def test_given_fake_conflicted_bookmark_when_inspected_then_one_attempt_is_recorded(
    tmp_path: Path,
) -> None:
    state = FakeJjState()
    path = tmp_path / "fake-repository"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    current = repo.resolve_revision(revision="@")
    main = repo.resolve_revision(revision="main")
    sibling = state.seed_commit(
        path,
        parent=main,
        files={"dep.txt": "sibling\n"},
        description="sibling",
    )
    state.seed_bookmark(path, bookmark="topic", targets=(current, sibling))
    state.clear_calls()

    working_copy = repo.working_copy_state()

    assert working_copy.bookmarks == ("topic",)
    assert [call.method for call in state.attempts] == ["working_copy_state"]


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

    c.repo.promote_bookmark_to_main(bookmark=MANAGED)
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
    assert "main" in c.repo.revision_bookmarks(revision="@-")
    c.write_file("dep.txt", "dirty\n")
    old = c.repo.resolve_revision(revision="@")
    c.repo.new_change(revision="main")
    assert c.repo.resolve_revision(revision=old) == old
    assert c.repo.change_id() != change_before


def test_initial_push_tracks_main_for_later_peer_advance(
    repository_case: RepositoryCase,
):
    c = repository_case
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
