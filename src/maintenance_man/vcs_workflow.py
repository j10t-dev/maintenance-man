from __future__ import annotations

import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from maintenance_man import paths
from maintenance_man.github import CodeHost, GitHubCodeHost
from maintenance_man.models.scan import WORKFLOW_BOOKMARKS
from maintenance_man.paths import sanitise_project_name
from maintenance_man.vcs import (
    ExpectedRevisions,
    JjRepository,
    Repository,
    RevisionError,
)


@dataclass(frozen=True, slots=True)
class VcsServices:
    repository: Callable[[Path], Repository]
    code_host: Callable[[Path], CodeHost]


class SyncAction(StrEnum):
    UNCHANGED = "already up to date"
    PULLED = "pulled from remote"
    PUSHED = "pushed to remote"


def make_vcs_services() -> VcsServices:
    return VcsServices(repository=JjRepository, code_host=GitHubCodeHost)


def ensure_main_bookmark(*, repo: Repository) -> None:
    if repo.bookmark_exists(bookmark="main"):
        return
    repo.resolve_revision(revision="main@origin")
    repo.create_bookmark(bookmark="main", revision="main@origin")


def refresh_working_copy_from_main(*, repo: Repository) -> None:
    state = repo.working_copy_state()
    if repo.is_ancestor(ancestor="main", descendant="@"):
        return
    if not state.has_changes and not state.description and not state.bookmarks:
        repo.rebase_working_copy(revision="main")
        return
    repo.new_change(revision="main")


def sync_main(*, repo: Repository) -> SyncAction:
    repo.fetch(main_only=True)
    ensure_main_bookmark(repo=repo)
    if repo.bookmark_conflicted(bookmark="main"):
        raise RevisionError(
            "main bookmark is conflicted; resolve with jj bookmark commands "
            "before syncing"
        )

    if repo.same_revision(left="main", right="main@origin"):
        refresh_working_copy_from_main(repo=repo)
        return SyncAction.UNCHANGED

    if repo.is_ancestor(ancestor="main", descendant="main@origin"):
        repo.set_bookmark(bookmark="main", revision="main@origin")
        refresh_working_copy_from_main(repo=repo)
        return SyncAction.PULLED

    if repo.is_ancestor(ancestor="main@origin", descendant="main"):
        repo.push_bookmark(bookmark="main")
        repo.fetch(main_only=True)
        if not repo.same_revision(left="main", right="main@origin"):
            raise RevisionError("pushed main but origin/main did not update to match")
        refresh_working_copy_from_main(repo=repo)
        return SyncAction.PUSHED

    raise RevisionError(
        "local main and origin/main have diverged; resolve manually before syncing"
    )


def prune_stale_bookmarks(*, repo: Repository, host: CodeHost) -> None:
    repo.fetch()
    merged = host.pr_bookmarks(state="merged")
    closed = host.pr_bookmarks(state="closed")
    local = repo.local_bookmarks()
    managed_prefixes = tuple(WORKFLOW_BOOKMARKS.values())
    stale = {
        bookmark
        for bookmark in merged | closed
        if bookmark.startswith(managed_prefixes)
    }
    for bookmark in sorted(local & stale):
        repo.delete_bookmark(bookmark=bookmark)


def push_bookmark_and_create_pr(
    *,
    repo: Repository,
    host: CodeHost,
    bookmark: str,
    expected: ExpectedRevisions | None = None,
) -> str:
    repo.push_bookmark(bookmark=bookmark, expected=expected)
    return host.create_pr(bookmark=bookmark)


def current_label(*, repo: Repository) -> str:
    try:
        current = repo.revision_bookmarks(revision="@")
        if current:
            return current[0]
        parent = repo.revision_bookmarks(revision="@-")
        if parent:
            return parent[0]
        change = repo.change_id(revision="@")
        if change:
            return f"@ {change}"
    except RevisionError:
        return "unknown"
    return "unknown"


def _workspace_name(project: str) -> str:
    return f"mm-{sanitise_project_name(project)}"


def _workspace_path(project: str) -> Path:
    try:
        return paths.project_file(paths.workspaces_dir(), project)
    except OSError as exc:
        raise RevisionError(f"Cannot compute workspace path: {exc}") from exc


def _safe_workspace_path(project: str) -> Path:
    candidate = _workspace_path(project)
    try:
        try:
            candidate_status = candidate.lstat()
        except FileNotFoundError:
            candidate_status = None
        if candidate_status is not None and stat.S_ISLNK(candidate_status.st_mode):
            raise RevisionError(
                f"Refusing to remove symlink workspace path: {candidate}"
            )
        root = paths.workspaces_dir().resolve()
        target = candidate.resolve()
    except OSError as exc:
        raise RevisionError(f"Cannot inspect workspace path: {exc}") from exc
    if target == root or root not in target.parents or target.parent != root:
        raise RevisionError(f"Refusing to remove unsafe workspace path: {target}")
    return candidate


def create_workspace(*, repo: Repository, project: str, revision: str) -> Path:
    workspace_path = _workspace_path(project)
    try:
        workspace_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RevisionError(f"Cannot prepare workspace path: {exc}") from exc
    repo.add_workspace(
        name=_workspace_name(project), path=workspace_path, revision=revision
    )
    return workspace_path


def remove_workspace(*, repo: Repository, project: str) -> None:
    names = repo.workspace_names()
    workspace_name = _workspace_name(project)
    workspace_path = _safe_workspace_path(project)
    if workspace_name in names:
        repo.forget_workspace(name=workspace_name)
    try:
        workspace_status = workspace_path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RevisionError(f"Cannot inspect workspace path: {exc}") from exc
    if stat.S_ISLNK(workspace_status.st_mode):
        raise RevisionError(
            f"Refusing to remove symlink workspace path: {workspace_path}"
        )
    try:
        shutil.rmtree(workspace_path)
    except OSError as exc:
        raise RevisionError(
            f"Cannot remove workspace path {workspace_path}: {exc}"
        ) from exc
