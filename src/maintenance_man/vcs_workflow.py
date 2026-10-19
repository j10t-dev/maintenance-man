import shutil
from enum import StrEnum
from pathlib import Path

from maintenance_man import vcs
from maintenance_man.paths import sanitise_project_name
from maintenance_man.vcs import JjRepository, RevisionError


class SyncAction(StrEnum):
    UNCHANGED = "already up to date"
    PULLED = "pulled from remote"
    PUSHED = "pushed to remote"


def ensure_main_bookmark(*, repo: JjRepository) -> None:
    if repo.bookmark_exists(bookmark="main"):
        return
    repo.resolve_revision(revision="main@origin")
    repo.set_bookmark(bookmark="main", revision="main@origin")


def refresh_working_copy_from_main(*, repo: JjRepository) -> None:
    if repo.is_ancestor(ancestor="main", descendant="@"):
        return
    if repo.is_blank_working_copy():
        repo.rebase_working_copy(revision="main")
        return
    repo.new_change(revision="main")


def sync_main(*, repo: JjRepository) -> SyncAction:
    """Fetch, reconcile local main with origin and refresh the working copy.

    PULLED when the sync created or moved main, PUSHED when local main was ahead.
    Raises RevisionError for a conflicted or diverged main.
    """
    before = _main_commit(repo)
    repo.fetch()
    ensure_main_bookmark(repo=repo)
    if repo.bookmark_conflicted(bookmark="main"):
        msg = (
            "main bookmark is conflicted; resolve with jj bookmark commands "
            "before syncing"
        )
        raise RevisionError(msg)

    if repo.same_revision(left="main", right="main@origin"):
        refresh_working_copy_from_main(repo=repo)
        return _pulled_or_unchanged(repo, before)

    if repo.is_ancestor(ancestor="main", descendant="main@origin"):
        repo.set_bookmark(bookmark="main", revision="main@origin")
        refresh_working_copy_from_main(repo=repo)
        return SyncAction.PULLED

    if repo.is_ancestor(ancestor="main@origin", descendant="main"):
        repo.push_bookmark(bookmark="main")
        repo.fetch()
        if not repo.same_revision(left="main", right="main@origin"):
            msg = "pushed main but origin/main did not update to match"
            raise RevisionError(msg)
        refresh_working_copy_from_main(repo=repo)
        return SyncAction.PUSHED

    msg = "local main and origin/main have diverged; resolve manually before syncing"
    raise RevisionError(msg)


def _main_commit(repo: JjRepository) -> str | None:
    """main's commit, or None when the bookmark is absent or conflicted."""
    if not repo.bookmark_exists(bookmark="main") or repo.bookmark_conflicted(
        bookmark="main"
    ):
        return None
    return repo.resolve_revision(revision="main")


def _pulled_or_unchanged(repo: JjRepository, before: str | None) -> SyncAction:
    if before == repo.resolve_revision(revision="main"):
        return SyncAction.UNCHANGED
    return SyncAction.PULLED


def current_label(*, repo: JjRepository) -> str:
    try:
        current = repo.revision_bookmarks(revision="@")
        if current:
            return current[0]
        parent = repo.revision_bookmarks(revision="@-")
        if parent:
            return parent[0]
        return f"@ {repo.change_id(revision='@')}"
    except RevisionError:
        return "unknown"


def _workspace_name(project: str) -> str:
    return f"mm-{sanitise_project_name(project)}"


def _safe_workspace_path(project: str) -> Path:
    try:
        return vcs.workspace_path_for_project(project)
    except (OSError, ValueError) as exc:
        msg = f"Cannot inspect workspace path: {exc}"
        raise RevisionError(msg) from exc


def create_workspace(*, repo: JjRepository, project: str, revision: str) -> Path:
    workspace_path = _safe_workspace_path(project)
    try:
        workspace_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        msg = f"Cannot prepare workspace path: {exc}"
        raise RevisionError(msg) from exc
    repo.add_workspace(
        name=_workspace_name(project), path=workspace_path, revision=revision
    )
    return workspace_path


def remove_workspace(*, repo: JjRepository, project: str) -> None:
    names = repo.workspace_names()
    workspace_name = _workspace_name(project)
    workspace_path = _safe_workspace_path(project)
    if workspace_name in names:
        repo.forget_workspace(name=workspace_name)
    try:
        shutil.rmtree(workspace_path)
    except FileNotFoundError:
        return
    except OSError as exc:
        msg = f"Cannot remove workspace path {workspace_path}: {exc}"
        raise RevisionError(msg) from exc
