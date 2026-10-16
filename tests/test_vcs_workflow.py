from pathlib import Path

import pytest

from maintenance_man import paths
from maintenance_man.github import CodeHostError
from maintenance_man.vcs import ExpectedRevisions, RevisionError
from maintenance_man.vcs_workflow import (
    SyncAction,
    create_workspace,
    current_label,
    ensure_main_bookmark,
    prune_stale_bookmarks,
    push_bookmark_and_create_pr,
    refresh_working_copy_from_main,
    remove_workspace,
    sync_main,
)
from tests.conftest import MANAGED, RepositoryCase
from tests.fake_vcs import FakeCodeHost


def _fail_repository_method(
    monkeypatch: pytest.MonkeyPatch,
    case: RepositoryCase,
    method: str,
    failure: RevisionError,
) -> None:
    repository_type = type(case.repo)
    original = getattr(repository_type, method)

    def fail(repository, *args, **kwargs):
        if repository.path == case.repo.path:
            raise failure
        return original(repository, *args, **kwargs)

    monkeypatch.setattr(repository_type, method, fail)


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


def test_ensure_main_preserves_local_bookmark_inspection_failure(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = repository_case
    main = c.repo.resolve_revision(revision="main")
    tree = c.repo.tree_id()
    failure = RevisionError("local bookmark inspection failed")
    _fail_repository_method(monkeypatch, c, "bookmark_exists", failure)

    with pytest.raises(RevisionError) as caught:
        ensure_main_bookmark(repo=c.repo)

    assert caught.value is failure
    assert c.repo.resolve_revision(revision="main") == main
    assert c.repo.tree_id() == tree


def test_ensure_main_refuses_when_local_and_origin_are_absent(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repository_case.repo
    repo.delete_bookmark(bookmark="main")
    original = type(repo).resolve_revision

    def missing(repository, *, revision: str, read_only: bool = False):
        if repository.path == repo.path and revision == "main@origin":
            message = "main@origin must resolve to exactly one commit, got 0"
            raise RevisionError(message)
        return original(repository, revision=revision, read_only=read_only)

    monkeypatch.setattr(type(repo), "resolve_revision", missing)

    with pytest.raises(RevisionError, match=r"main@origin.*exactly one"):
        ensure_main_bookmark(repo=repo)

    assert repo.bookmark_exists(bookmark="main") is False


def test_ensure_main_preserves_origin_inspection_failure(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = repository_case
    c.repo.delete_bookmark(bookmark="main")
    failure = RevisionError("origin inspection failed")
    _fail_repository_method(monkeypatch, c, "resolve_revision", failure)

    with pytest.raises(RevisionError) as caught:
        ensure_main_bookmark(repo=c.repo)

    assert caught.value is failure
    assert c.repo.bookmark_exists(bookmark="main") is False


@pytest.mark.parametrize("method", ["fetch", "bookmark_conflicted", "same_revision"])
def test_sync_inspection_failure_preserves_the_repository(
    repository_case: RepositoryCase,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    c = repository_case
    main_before = c.repo.resolve_revision(revision="main")
    change_before = c.repo.change_id()
    tree_before = c.repo.tree_id()
    file_before = (c.repo.path / "dep.txt").read_text(encoding="utf-8")
    failure = RevisionError(f"{method} failed")
    _fail_repository_method(monkeypatch, c, method, failure)

    with pytest.raises(RevisionError) as caught:
        sync_main(repo=c.repo)

    assert caught.value is failure
    assert c.repo.resolve_revision(revision="main") == main_before
    assert c.repo.change_id() == change_before
    assert c.repo.tree_id() == tree_before
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == file_before


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


def test_sync_remote_advance_move_failure_preserves_local_main(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = repository_case
    repo = c.repo
    base = repo.resolve_revision(revision="main")
    c.track_main(False)
    c.origin_peer.repo.rebase_working_copy(revision="main")
    c.origin_peer.commit_file("dep.txt", "version=2\n", "remote advance")
    c.origin_peer.push_main()
    failure = RevisionError("cannot move local main")
    _fail_repository_method(monkeypatch, c, "set_bookmark", failure)

    with pytest.raises(RevisionError) as caught:
        sync_main(repo=repo)

    assert caught.value is failure
    assert repo.resolve_revision(revision="main") == base
    assert (repo.path / "dep.txt").read_text(encoding="utf-8") == "version=1\n"


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
    tip = c.commit_file("dep.txt", "version=2\n", "local advance")
    repo.set_bookmark(bookmark="main", revision=tip)
    change_before = repo.change_id()
    tree_before = repo.tree_id()
    file_before = (repo.path / "dep.txt").read_text(encoding="utf-8")
    attempt_index = len(c.attempts) if c.attempts is not None else None
    command_index = len(c.commands) if c.commands is not None else None
    failure = RevisionError(message)
    repository_type = type(repo)
    original = getattr(repository_type, method)
    calls = 0

    def fail_second(repository, *args, **kwargs):
        nonlocal calls
        if repository.path == repo.path:
            calls += 1
            if calls == 2:
                raise failure
        return original(repository, *args, **kwargs)

    monkeypatch.setattr(repository_type, method, fail_second)

    with pytest.raises(RevisionError) as caught:
        sync_main(repo=repo)

    assert caught.value is failure
    assert c.origin_peer.remote_bookmark_targets("main") == (tip,)
    assert repo.change_id() == change_before
    assert repo.tree_id() == tree_before
    assert (repo.path / "dep.txt").read_text(encoding="utf-8") == file_before
    if c.attempts is not None:
        assert attempt_index is not None
        assert not any(
            call.method in {"rebase_working_copy", "new_change"}
            for call in c.attempts[attempt_index:]
        )
    if c.commands is not None:
        assert command_index is not None
        assert not any(
            command[:2] in {("jj", "rebase"), ("jj", "new")}
            for command in c.commands[command_index:]
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
    tree_before = c.repo.tree_id()
    file_before = (c.repo.path / "dep.txt").read_text(encoding="utf-8")
    attempt_index = len(c.attempts) if c.attempts is not None else None
    command_index = len(c.commands) if c.commands is not None else None

    with pytest.raises(RevisionError):
        sync_main(repo=c.repo)
    assert c.repo.change_id() == change_before
    assert c.repo.tree_id() == tree_before
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == file_before
    if c.attempts is not None:
        assert attempt_index is not None
        assert not any(
            call.method in {"rebase_working_copy", "new_change"}
            for call in c.attempts[attempt_index:]
        )
    if c.commands is not None:
        assert command_index is not None
        assert not any(
            command[:2] in {("jj", "rebase"), ("jj", "new")}
            for command in c.commands[command_index:]
        )


def test_sync_refuses_preexisting_conflicted_main_without_refresh(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    repo = c.repo
    base = repo.resolve_revision(revision="main")
    repo.new_change(revision=base)
    c.write_file("dep.txt", "sibling\n")
    c.describe("sibling")
    sibling = repo.resolve_revision(revision="@")
    c.conflict_bookmark("main", base, sibling)

    with pytest.raises(RevisionError, match="conflicted"):
        sync_main(repo=repo)
    assert repo.bookmark_conflicted(bookmark="main") is True


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


def test_refresh_inspection_failure_has_no_mutation(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    tip = c.commit_file("dep.txt", "version=2\n", "advance main")
    c.repo.set_bookmark(bookmark="main", revision=tip)
    c.repo.new_change(revision=base)
    before = c.repo.resolve_revision(revision="@")
    failure = RevisionError("inspection failed")
    _fail_repository_method(monkeypatch, c, "working_copy_state", failure)

    with pytest.raises(RevisionError) as caught:
        refresh_working_copy_from_main(repo=c.repo)

    assert caught.value is failure
    assert c.repo.resolve_revision(revision="@") == before


@pytest.mark.parametrize("failure_method", ["is_ancestor", "rebase_working_copy"])
def test_refresh_relationship_or_rebase_failure_has_no_completed_mutation(
    repository_case: RepositoryCase,
    monkeypatch: pytest.MonkeyPatch,
    failure_method: str,
) -> None:
    c = repository_case
    base = c.repo.resolve_revision(revision="main")
    tip = c.commit_file("dep.txt", "version=2\n", "advance main")
    c.repo.set_bookmark(bookmark="main", revision=tip)
    c.repo.new_change(revision=base)
    before = c.repo.resolve_revision(revision="@")
    failure = RevisionError(f"{failure_method} failed")
    _fail_repository_method(monkeypatch, c, failure_method, failure)

    with pytest.raises(RevisionError) as caught:
        refresh_working_copy_from_main(repo=c.repo)

    assert caught.value is failure
    assert c.repo.resolve_revision(revision="@") == before
    assert (c.repo.path / "dep.txt").read_text(encoding="utf-8") == "version=1\n"


@pytest.mark.parametrize("failed_listing", ["merged", "closed", "local"])
def test_prune_finishes_all_listings_before_deletion(
    repository_case: RepositoryCase,
    monkeypatch: pytest.MonkeyPatch,
    failed_listing: str,
) -> None:
    c = repository_case
    repo = c.repo
    base = repo.resolve_revision(revision="main")
    repo.set_bookmark(bookmark=MANAGED, revision=base)
    host = FakeCodeHost(repo.path)
    host.seed_pr(bookmark=MANAGED, state="merged")
    if failed_listing == "merged":
        host.fail("pr_bookmarks", ordinal=1, error=CodeHostError("merged failed"))
    elif failed_listing == "closed":
        host.fail("pr_bookmarks", ordinal=2, error=CodeHostError("closed failed"))
    else:
        _fail_repository_method(
            monkeypatch, c, "local_bookmarks", RevisionError("local failed")
        )

    with pytest.raises((CodeHostError, RevisionError)):
        prune_stale_bookmarks(repo=repo, host=host)
    assert repo.bookmark_exists(bookmark=MANAGED) is True


def test_prune_fetch_failure_stops_before_host_or_deletion(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = repository_case
    host = FakeCodeHost(c.repo.path)
    failure = RevisionError("fetch failed")
    _fail_repository_method(monkeypatch, c, "fetch", failure)

    with pytest.raises(RevisionError) as caught:
        prune_stale_bookmarks(repo=c.repo, host=host)

    assert caught.value is failure
    assert host.attempts == []


def test_prune_deletes_sorted_managed_intersection_and_stops_on_failure(
    repository_case: RepositoryCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = repository_case
    repo = c.repo
    base = repo.resolve_revision(revision="main")
    stale = [
        "mm/resolve-dependencies-b",
        "mm/update-dependencies-a",
        "mm/update-dependencies-c",
    ]
    for bookmark in [*stale, "feature/unrelated"]:
        repo.set_bookmark(bookmark=bookmark, revision=base)
    host = FakeCodeHost(repo.path)
    for bookmark in stale:
        host.seed_pr(bookmark=bookmark, state="closed")
    host.seed_pr(bookmark="feature/unrelated", state="closed")
    original = type(repo).delete_bookmark
    calls = 0

    def fail_second(repository, *, bookmark: str):
        nonlocal calls
        if repository.path == repo.path:
            calls += 1
            if calls == 2:
                message = "delete failed"
                raise RevisionError(message)
        return original(repository, bookmark=bookmark)

    monkeypatch.setattr(type(repo), "delete_bookmark", fail_second)

    with pytest.raises(RevisionError, match="delete failed"):
        prune_stale_bookmarks(repo=repo, host=host)

    ordered = sorted(stale)
    assert repo.bookmark_exists(bookmark=ordered[0]) is False
    assert repo.bookmark_exists(bookmark=ordered[1]) is True
    assert repo.bookmark_exists(bookmark=ordered[2]) is True
    assert repo.bookmark_exists(bookmark="feature/unrelated") is True
    assert calls == 2


def _submission_case(c: RepositoryCase):
    repo = c.repo
    base = repo.resolve_revision(revision="main")
    tip = c.commit_file("dep.txt", "version=2\n", "update")
    repo.set_bookmark(bookmark=MANAGED, revision=tip)
    return repo, FakeCodeHost(repo.path), ExpectedRevisions(base, tip)


def test_submission_push_failure_never_calls_host(
    repository_case: RepositoryCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, host, expected = _submission_case(repository_case)
    _fail_repository_method(
        monkeypatch, repository_case, "push_bookmark", RevisionError("push failed")
    )

    with pytest.raises(RevisionError, match="push failed"):
        push_bookmark_and_create_pr(
            repo=repo, host=host, bookmark=MANAGED, expected=expected
        )
    assert host.attempts == []


def test_submission_postcheck_failure_retains_push_and_never_calls_host(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    repo, host, expected = _submission_case(c)
    c.after_push(lambda: c.force_bookmark("main", expected.tip))

    with pytest.raises(RevisionError, match="changed"):
        push_bookmark_and_create_pr(
            repo=repo, host=host, bookmark=MANAGED, expected=expected
        )
    assert c.origin_peer.remote_bookmark_targets(MANAGED) == (expected.tip,)
    assert host.attempts == []


def test_submission_host_failure_retains_push_and_retry_succeeds(
    repository_case: RepositoryCase,
) -> None:
    c = repository_case
    repo, host, expected = _submission_case(c)
    host.fail("create_pr", error=CodeHostError("host unavailable"))

    with pytest.raises(CodeHostError, match="host unavailable"):
        push_bookmark_and_create_pr(
            repo=repo, host=host, bookmark=MANAGED, expected=expected
        )
    assert c.origin_peer.remote_bookmark_targets(MANAGED) == (expected.tip,)
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
    repository_case: RepositoryCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repository_case.repo

    created = create_workspace(repo=repo, project="owner/project", revision="main")
    assert created == tmp_path / ".mm" / "workspaces" / "owner_project"
    assert "mm-owner_project" in repo.workspace_names()

    remove_workspace(repo=repo, project="owner/project")
    assert not created.exists()
    assert "mm-owner_project" not in repo.workspace_names()


def test_workspace_removal_absence_is_noop(
    repository_case: RepositoryCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repository_case.repo

    remove_workspace(repo=repo, project="missing")

    assert repo.workspace_names() == frozenset({"default"})


def test_workspace_removal_deletes_known_unregistered_path(
    repository_case: RepositoryCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repository_case.repo
    workspace = paths.workspaces_dir() / "recovery"
    workspace.mkdir(parents=True)
    (workspace / "keep.txt").write_text("obsolete", encoding="utf-8")

    remove_workspace(repo=repo, project="recovery")

    assert not workspace.exists()
    assert repo.workspace_names() == frozenset({"default"})


def test_workspace_removal_rejects_final_symlink_and_preserves_sibling(
    repository_case: RepositoryCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    repository_case: RepositoryCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    repository_case: RepositoryCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repository_case.repo
    recovery = paths.workspaces_dir() / "recovery"
    recovery.mkdir(parents=True)
    (recovery / "keep.txt").write_text("recovery", encoding="utf-8")
    _fail_repository_method(
        monkeypatch,
        repository_case,
        "workspace_names",
        RevisionError("inspection failed"),
    )

    with pytest.raises(RevisionError, match="inspection failed"):
        remove_workspace(repo=repo, project="recovery")
    assert (recovery / "keep.txt").read_text(encoding="utf-8") == "recovery"


def test_workspace_forget_failure_preserves_registered_files(
    repository_case: RepositoryCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repository_case.repo
    workspace = create_workspace(repo=repo, project="recovery", revision="main")
    (workspace / "keep.txt").write_text("recovery", encoding="utf-8")
    _fail_repository_method(
        monkeypatch, repository_case, "forget_workspace", RevisionError("forget failed")
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
    _fail_repository_method(
        monkeypatch,
        repository_case,
        "revision_bookmarks",
        RevisionError("lookup failed"),
    )
    assert current_label(repo=repo) == "unknown"
