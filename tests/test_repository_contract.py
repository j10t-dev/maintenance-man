import re

import pytest

from maintenance_man.vcs import RevisionError
from maintenance_man.vcs_workflow import refresh_working_copy_from_main
from tests.support.repository import (
    MANAGED,
    RepositoryCase,
    commit_file,
    conflict_bookmark,
    describe,
    run_jj,
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


@pytest.mark.parametrize(
    ("arrange", "filename", "expected"),
    [
        pytest.param("none", "dep.txt", True, id="regular-file"),
        pytest.param("none", "local.properties", False, id="absent"),
        pytest.param("symlink", "link.txt", False, id="symlink"),
        pytest.param("directory", "gradle", False, id="directory"),
    ],
)
def test_given_committed_path_when_inspected_then_only_a_regular_file_counts(
    repository_case: RepositoryCase, arrange: str, filename: str, expected: bool
) -> None:
    repo = repository_case.repo
    if arrange == "symlink":
        (repo.path / "link.txt").symlink_to("dep.txt")
    elif arrange == "directory":
        write_file(repo, "gradle/libs.versions.toml", "[versions]\n")
    repo.commit(message="arrange")

    assert repo.has_regular_file(revision="@-", filename=filename) is expected


@pytest.mark.parametrize("revision", ["all()", "missing-bookmark"])
def test_given_revision_not_naming_one_commit_when_inspected_then_revision_error(
    repository_case: RepositoryCase, revision: str
) -> None:
    with pytest.raises(RevisionError):
        repository_case.repo.has_regular_file(revision=revision, filename="dep.txt")


def test_given_dirty_working_copy_when_file_inspected_then_nothing_is_snapshotted(
    repository_case: RepositoryCase,
) -> None:
    repo = repository_case.repo
    commit_file(repo, "local.properties", "sdk.dir=/fixture\n", "sdk settings")
    pinned = repo.resolve_revision(revision="@")
    write_file(repo, "local.properties", None)

    assert repo.has_regular_file(revision="@", filename="local.properties") is True
    assert (
        run_jj(
            repo.path,
            "--ignore-working-copy",
            "log",
            "-r",
            "@",
            "--no-graph",
            "-T",
            "commit_id",
        ).stdout
        == pinned
    )


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


def test_given_colour_forced_when_jj_reads_then_identities_and_conflict_state_parse(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = repository_case.repo.path.parent / "colour.toml"
    config.write_text('[ui]\ncolor = "always"\n', encoding="utf-8")
    monkeypatch.setenv("JJ_CONFIG", str(config))
    repo = repository_case.repo

    commit = repo.resolve_revision(revision="@")

    assert re.fullmatch(r"[0-9a-f]{40,64}", commit)
    assert repo.bookmark_conflicted(bookmark="main") is False
