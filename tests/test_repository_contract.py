from pathlib import Path

import pytest

from maintenance_man.config import load_config
from maintenance_man.vcs import JjRepository, RevisionError
from maintenance_man.vcs_workflow import refresh_working_copy_from_main
from tests.support.repository import (
    MANAGED,
    RepositoryCase,
    commit_file,
    configure_jj_projects,
    conflict_bookmark,
    describe,
    push_peer_main,
    remote_bookmark_target,
    track_main,
    write_file,
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


def test_given_invalid_bookmark_name_when_reading_remote_target_then_jj_error_is_raised(
    repository_case: RepositoryCase,
) -> None:
    with pytest.raises(AssertionError, match="Failed to parse revset"):
        remote_bookmark_target(repository_case.repo, "not a bookmark")


def test_given_amended_main_when_resolved_then_commit_identity_changes(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    c.repo.set_bookmark(bookmark="main", revision="@")
    before = c.repo.resolve_revision(revision="main")

    describe(c.repo, "amended main")
    c.repo.set_bookmark(bookmark="main", revision="@")

    assert c.repo.resolve_revision(revision="main") != before


def test_identity_tracks_content_and_metadata_separately(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    original_commit = c.repo.resolve_revision(revision="@")

    describe(c.repo, "metadata only")
    assert c.repo.resolve_revision(revision="@") != original_commit
    assert c.repo.has_changes() is False

    write_file(c.repo, "dep.txt", "version=2\n")
    assert c.repo.has_changes() is True

    write_file(c.repo, "dep.txt", "version=1\n")
    assert c.repo.has_changes() is False


@pytest.mark.parametrize(
    "arrange, expected",
    [("blank", True), ("dirty", False), ("described", False), ("bookmarked", False)],
)
def test_given_working_copy_when_inspected_then_only_a_blank_change_is_blank(
    repository_case: RepositoryCase, arrange: str, expected: bool
) -> None:
    repo = repository_case.repo
    if arrange == "dirty":
        write_file(repo, "dep.txt", "local\n")
    elif arrange == "described":
        describe(repo, "work in progress")
    elif arrange == "bookmarked":
        repo.set_bookmark(bookmark="topic", revision="@")

    assert repo.is_blank_working_copy() is expected


def test_revision_relationship_methods_distinguish_parent_and_child(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    parent = c.repo.resolve_revision(revision="main")
    c.repo.new_change(revision="main")
    describe(c.repo, "child")
    child = c.repo.resolve_revision(revision="@")

    assert c.repo.same_revision(left=parent, right=parent)
    assert not c.repo.same_revision(left=parent, right=child)
    assert c.repo.is_ancestor(ancestor=parent, descendant=child)
    assert not c.repo.is_ancestor(ancestor=child, descendant=parent)


def test_commit_then_advance_and_delete(repository_case: RepositoryCase):
    c = repository_case
    before = c.repo.resolve_revision(revision="main")
    write_file(c.repo, "dep.txt", "version=2\n")
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
    commit_file(c.repo, "local.properties", "sdk.dir=/fixture\n", "sdk settings")
    pinned = c.repo.resolve_revision(revision="@", read_only=True)
    write_file(c.repo, "local.properties", "sdk.dir=/changed\n")
    inspected = c.repo.revision_file(revision="@", filename="local.properties")
    assert inspected.commit_id == pinned
    assert inspected.is_regular is True
    assert c.repo.resolve_revision(revision="@", read_only=True) == pinned
    assert c.repo.resolve_revision(revision="@") != pinned


def test_discard_restores_the_parent_tree(repository_case: RepositoryCase) -> None:
    c = repository_case
    write_file(c.repo, "dep.txt", "dirty\n")
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
    write_file(c.repo, "dep.txt", "side=1\n")
    left = c.repo.resolve_revision(revision="@")
    c.repo.new_change(revision="main")
    write_file(c.repo, "dep.txt", "side=2\n")
    right = c.repo.resolve_revision(revision="@")
    conflict_bookmark(c.repo, MANAGED, left, right)
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
    write_file(c.repo, "dep.txt", "protected local change\n")
    assert c.repo.has_changes() is True
    current = c.repo.resolve_revision(revision="@")
    change_id = c.repo.change_id()
    conflict_bookmark(c.repo, "topic", current, original)

    assert c.repo.has_changes() is True
    assert c.repo.revision_bookmarks(revision="@") == ("topic",)

    refresh_working_copy_from_main(repo=c.repo)

    assert c.repo.revision_bookmarks(revision=current) == ("topic",)
    c.repo.new_change(revision=current)
    assert c.repo.change_id(revision="@-") == change_id
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == (
        "protected local change\n"
    )


def test_workspace_views_isolate_files_and_share_bookmarks(
    repository_case: RepositoryCase, tmp_path: Path
):
    c = repository_case
    update_path = tmp_path / "update-workspace"
    c.repo.add_workspace(name="update", path=update_path, revision="main")
    update = JjRepository(update_path)
    update.new_change(revision="main")
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
    update = JjRepository(update_path)
    update.new_change(revision="main")
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
    write_file(c.repo, "dep.txt", "dirty\n")
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

    c.peer.fetch(main_only=True)
    c.peer.rebase_working_copy(revision="main")
    peer_tip = commit_file(c.peer, "dep.txt", "peer=2\n", "peer advance")
    push_peer_main(c.peer)
    assert c.repo.resolve_revision(revision="main@origin") == sender_tracking
    c.repo.fetch(main_only=True)

    assert c.repo.resolve_revision(revision="main") == peer_tip
    assert c.repo.resolve_revision(revision="main@origin") == peer_tip


def test_push_rejects_existing_untracked_remote_without_remote_effect(
    repository_case: RepositoryCase,
):
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    track_main(c.repo, enabled=False)
    tip = commit_file(c.repo, "dep.txt", "sender=1\n", "sender advance")
    c.repo.set_bookmark(bookmark="main", revision=tip)

    with pytest.raises(RevisionError):
        c.repo.push_bookmark(bookmark="main")

    c.peer.fetch(main_only=True)
    assert c.peer.resolve_revision(revision="main") == base


def test_given_projects_with_prefix_paths_when_configured_then_each_gets_its_own_copy(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text(
        f"""\
[projects.api]
path = "{tmp_path / "x" / "api"}"
package_manager = "uv"
test_unit = "pytest"

[projects.web]
path = "{tmp_path / "x" / "api-web"}"
package_manager = "bun"
""",
        encoding="utf-8",
    )

    copies = configure_jj_projects(home, tmp_path)

    expected = {
        "api": tmp_path / "repositories" / "repo-0",
        "web": tmp_path / "repositories" / "repo-1",
    }
    configured = load_config(home / "config.toml")
    assert copies == expected
    assert {name: project.path for name, project in configured.projects.items()} == (
        expected
    )
    assert configured.projects["api"].test_unit == "pytest"
