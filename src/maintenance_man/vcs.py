from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from rich import print as rprint

from maintenance_man import paths
from maintenance_man.models.scan import WORKFLOW_BOOKMARKS
from maintenance_man.paths import sanitise_project_name
from maintenance_man.process import run_captured

JJ_INSTALL_HINT = "Install it from https://jj-vcs.github.io/jj/"
GH_INSTALL_HINT = "Install it from https://cli.github.com/"


class BookmarkLookupError(RuntimeError):
    """A bookmark could not be inspected; its existence is unknown."""


class RevisionError(Exception):
    """A jj or gh command could not run, or a revision could not be resolved."""


@dataclass(frozen=True, slots=True)
class ExpectedRevisions:
    base: str
    tip: str


@dataclass(frozen=True, slots=True)
class RevisionFile:
    commit_id: str
    is_regular: bool


@dataclass(frozen=True, slots=True)
class WorkingCopyState:
    has_changes: bool
    description: str
    bookmarks: tuple[str, ...]


class Repository(Protocol):
    @property
    def path(self) -> Path: ...

    def bookmark_exists(self, *, bookmark: str) -> bool: ...
    def local_bookmarks(self) -> frozenset[str]: ...
    def bookmark_conflicted(self, *, bookmark: str) -> bool: ...
    def resolve_revision(self, *, revision: str, read_only: bool = False) -> str: ...
    def revision_file(self, *, revision: str, filename: str) -> RevisionFile: ...
    def tree_id(self, *, revision: str = "@") -> str: ...
    def same_revision(self, *, left: str, right: str) -> bool: ...
    def is_ancestor(self, *, ancestor: str, descendant: str) -> bool: ...
    def revision_bookmarks(self, *, revision: str) -> tuple[str, ...]: ...
    def change_id(self, *, revision: str = "@") -> str: ...
    def working_copy_state(self) -> WorkingCopyState: ...
    def has_changes(self) -> bool: ...
    def changed_paths(self, *, revision: str = "@") -> frozenset[str]: ...
    def create_bookmark(self, *, bookmark: str, revision: str) -> None: ...
    def set_bookmark(self, *, bookmark: str, revision: str) -> None: ...
    def delete_bookmark(self, *, bookmark: str) -> None: ...
    def new_change(self, *, revision: str) -> None: ...
    def commit(self, *, message: str) -> None: ...
    def discard(self) -> None: ...
    def rebase_working_copy(self, *, revision: str) -> None: ...
    def promote_bookmark_to_main(
        self, *, bookmark: str, expected: ExpectedRevisions | None = None
    ) -> None: ...
    def reset_verified_bookmark(
        self, *, bookmark: str, expected: ExpectedRevisions
    ) -> None: ...
    def fetch(self, *, main_only: bool = False) -> None: ...
    def push_bookmark(
        self, *, bookmark: str, expected: ExpectedRevisions | None = None
    ) -> None: ...
    def workspace_names(self) -> frozenset[str]: ...
    def add_workspace(self, *, name: str, path: Path, revision: str) -> None: ...
    def forget_workspace(self, *, name: str) -> None: ...
    def temporary_workspace(
        self, *, revision: str
    ) -> AbstractContextManager[Repository]: ...


@dataclass(frozen=True)
class RevisionCheck:
    ok: bool
    value: bool = False
    error: str = ""


@dataclass(frozen=True)
class RevisionResolve:
    ok: bool
    commit_id: str = ""
    error: str = ""


@dataclass(frozen=True)
class RevisionFileCheck:
    ok: bool
    value: bool = False
    commit_id: str = ""
    error: str = ""


def revision_file(path: Path, revision: str, filename: str) -> RevisionFileCheck:
    """Inspect an exact regular file in one revision without snapshotting."""
    resolved = _single_commit_id(path, revision, read_only=True)
    if not resolved.ok:
        return RevisionFileCheck(ok=False, error=resolved.error)
    try:
        result = _run(
            [
                "jj",
                "--ignore-working-copy",
                "--color",
                "never",
                "file",
                "list",
                "-r",
                resolved.commit_id,
                "-T",
                'file_type ++ "\\n"',
                f"root-file:{filename}",
            ],
            path,
        )
    except RevisionError as e:
        return RevisionFileCheck(ok=False, error=str(e))
    if result.returncode != 0:
        return RevisionFileCheck(ok=False, error=result.stderr.strip())
    types = result.stdout.splitlines()
    if types not in (
        [],
        ["file"],
        ["symlink"],
        ["tree"],
        ["git-submodule"],
        ["conflict"],
    ):
        return RevisionFileCheck(ok=False, error="unexpected revision file listing")
    return RevisionFileCheck(
        ok=True,
        value=types == ["file"],
        commit_id=resolved.commit_id,
    )


_MANAGED_BOOKMARK_PREFIXES = tuple(WORKFLOW_BOOKMARKS.values())


def _jj_stdout(cmd: list[str], project_path: Path) -> str:
    completed = _run(cmd, project_path)
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def current_label(path: Path) -> str:
    """Return a non-empty jj-aware revision label for activity tracking."""
    try:
        current_bookmark = _jj_stdout(
            ["jj", "log", "-r", "@", "--no-graph", "-T", 'bookmarks.join(" ")'],
            path,
        )
        if current_bookmark:
            return current_bookmark.split()[0]

        parent_bookmark = _jj_stdout(
            ["jj", "log", "-r", "@-", "--no-graph", "-T", 'bookmarks.join(" ")'],
            path,
        )
        if parent_bookmark:
            return parent_bookmark.split()[0]

        change_id = _jj_stdout(
            ["jj", "log", "-r", "@", "--no-graph", "-T", "change_id.shortest()"],
            path,
        )
        if change_id:
            return f"@ {change_id}"
    except Exception:
        return "unknown"
    return "unknown"


def bookmark_exists(bookmark: str, path: Path) -> bool:
    try:
        result = _run(
            ["jj", "--ignore-working-copy", "bookmark", "list", "-T", "name", bookmark],
            path,
        )
    except RevisionError as exc:
        raise BookmarkLookupError(
            f"Cannot inspect bookmark '{bookmark}': {exc}"
        ) from exc
    if result.returncode != 0:
        raise BookmarkLookupError(
            f"Cannot inspect bookmark '{bookmark}': {result.stderr.strip()}"
        )
    return bool(result.stdout.strip())


def create_or_reset_bookmark(bookmark: str, path: Path, revision: str) -> bool:
    result = _run(["jj", "bookmark", "set", bookmark, "-r", revision], path)
    if result.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] jj bookmark set {bookmark} failed: "
            f"{result.stderr.strip()}"
        )
        return False
    return True


def edit_new_change(path: Path, revision: str) -> bool:
    result = _run(["jj", "new", revision], path)
    if result.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] jj new {revision} failed: "
            f"{result.stderr.strip()}"
        )
        return False
    return True


def commit_current_change(path: Path, message: str) -> bool:
    result = _run(["jj", "commit", "-m", message], path)
    if result.returncode != 0:
        rprint(f"  [bold red]FAIL[/] jj commit failed: {result.stderr.strip()}")
        return False
    return True


def current_change_has_changes(path: Path) -> bool:
    result = _run(["jj", "diff", "--summary"], path)
    if result.returncode != 0:
        return True
    return bool(result.stdout.strip())


def _current_change_is_reusable_empty(path: Path) -> bool:
    diff = _run(["jj", "diff", "--summary"], path)
    if diff.returncode != 0 or diff.stdout.strip():
        return False

    description = _run(
        ["jj", "log", "-r", "@", "--no-graph", "-T", "description"], path
    )
    if description.returncode != 0 or description.stdout.strip():
        return False

    bookmarks = _run(
        [
            "jj",
            "log",
            "-r",
            "@",
            "--no-graph",
            "-T",
            'bookmarks.join(" ")',
        ],
        path,
    )
    return bookmarks.returncode == 0 and not bookmarks.stdout.strip()


def discard_current_change(path: Path) -> bool:
    result = _run(["jj", "restore", "--from", "@-"], path)
    if result.returncode != 0:
        rprint(f"  [bold yellow]Warning:[/] jj restore failed: {result.stderr.strip()}")
        return False
    return True


def _refresh_working_copy_from_main_result(path: Path) -> tuple[bool, str]:
    if _current_change_is_reusable_empty(path):
        descendant = is_ancestor(path, "main", "@")
        if not descendant.ok:
            message = f"failed to inspect working copy ancestry: {descendant.error}"
            rprint(f"  [bold yellow]Warning:[/] {message}")
            return False, message
        if descendant.value:
            return True, ""

        result = _run(["jj", "rebase", "-r", "@", "-d", "main"], path)
        if result.returncode != 0:
            message = (
                f"failed to rebase working copy onto main: {result.stderr.strip()}"
            )
            rprint(f"  [bold yellow]Warning:[/] {message}")
            return False, message
        return True, ""

    descendant = is_ancestor(path, "main", "@")
    if not descendant.ok:
        message = f"failed to inspect working copy ancestry: {descendant.error}"
        rprint(f"  [bold yellow]Warning:[/] {message}")
        return False, message
    if descendant.value:
        return True, ""

    result = _run(["jj", "new", "main"], path)
    if result.returncode != 0:
        message = f"failed to refresh working copy from main: {result.stderr.strip()}"
        rprint(f"  [bold yellow]Warning:[/] {message}")
        return False, message
    return True, ""


def refresh_working_copy_from_main(path: Path) -> bool:
    ok, _message = _refresh_working_copy_from_main_result(path)
    return ok


def delete_bookmark(bookmark: str, path: Path) -> bool:
    result = _run(["jj", "bookmark", "delete", bookmark], path)
    if result.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] jj bookmark delete {bookmark} failed: "
            f"{result.stderr.strip()}"
        )
        return False
    return True


def workspace_path_for_project(project: str) -> Path:
    return paths.project_file(paths.workspaces_dir(), project)


def assert_safe_workspace_path(path: Path) -> Path:
    root = paths.workspaces_dir().resolve()
    target = path.resolve()

    if target == root:
        raise ValueError("refusing to remove workspace root")

    if root not in target.parents:
        raise ValueError(f"refusing to remove path outside {root}: {target}")

    if target.parent != root:
        raise ValueError(
            f"refusing to remove nested/non-project workspace path: {target}"
        )

    return target


def create_workspace(repo_path: Path, project: str, revision: str) -> bool:
    workspace_name = f"mm-{sanitise_project_name(project)}"
    workspace_path = workspace_path_for_project(project)
    workspace_path.parent.mkdir(parents=True, exist_ok=True)
    result = _run(
        [
            "jj",
            "workspace",
            "add",
            "--name",
            workspace_name,
            str(workspace_path),
            "-r",
            revision,
        ],
        repo_path,
        timeout=30,
    )
    if result.returncode != 0:
        rprint(
            f"  [bold red]Error:[/] workspace creation failed: {result.stderr.strip()}"
        )
        return False
    return True


def remove_workspace(repo_path: Path, project: str) -> None:
    workspace_name = f"mm-{sanitise_project_name(project)}"
    workspace_path = assert_safe_workspace_path(workspace_path_for_project(project))

    _run(["jj", "workspace", "forget", workspace_name], repo_path)

    if workspace_path.exists():
        shutil.rmtree(workspace_path)


def _revision_check(path: Path, revset: str) -> RevisionCheck:
    result = _run(["jj", "log", "-r", revset, "--no-graph", "-T", "commit_id"], path)
    if result.returncode != 0:
        return RevisionCheck(ok=False, error=result.stderr.strip())
    return RevisionCheck(ok=True, value=bool(result.stdout.strip()))


def main_commit_id(path: Path) -> RevisionResolve:
    """Resolve the local main bookmark to its single commit_id.

    Returns ok=False when main is absent, ambiguous, or jj errors — the
    fail-closed trigger for the deploy change-detection gate.
    """
    return _single_commit_id(path, "main")


def _single_commit_id(
    path: Path, revision: str, *, read_only: bool = False
) -> RevisionResolve:
    prefix = (
        ["jj", "--ignore-working-copy", "--color", "never"] if read_only else ["jj"]
    )
    try:
        result = _run(
            [*prefix, "log", "-r", revision, "--no-graph", "-T", 'commit_id ++ "\\n"'],
            path,
        )
    except RevisionError as e:
        return RevisionResolve(ok=False, error=str(e))
    if result.returncode != 0:
        return RevisionResolve(ok=False, error=result.stderr.strip())

    commit_ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(commit_ids) != 1:
        return RevisionResolve(
            ok=False,
            error=(
                f"{revision} must resolve to exactly one commit, got {len(commit_ids)}"
            ),
        )
    return RevisionResolve(ok=True, commit_id=commit_ids[0])


def same_revision(path: Path, left: str, right: str) -> RevisionCheck:
    """Return whether two revisions identify the same unambiguous commit."""
    left_commit = _single_commit_id(path, left)
    if not left_commit.ok:
        return RevisionCheck(ok=False, error=left_commit.error)
    right_commit = _single_commit_id(path, right)
    if not right_commit.ok:
        return RevisionCheck(ok=False, error=right_commit.error)
    return RevisionCheck(ok=True, value=left_commit.commit_id == right_commit.commit_id)


def is_ancestor(path: Path, ancestor: str, descendant: str) -> RevisionCheck:
    """Return whether ancestor is in descendant's ancestry."""
    ancestor_commit = _single_commit_id(path, ancestor)
    if not ancestor_commit.ok:
        return RevisionCheck(ok=False, error=ancestor_commit.error)
    descendant_commit = _single_commit_id(path, descendant)
    if not descendant_commit.ok:
        return RevisionCheck(ok=False, error=descendant_commit.error)
    return _revision_check(
        path,
        f"{ancestor_commit.commit_id}::{descendant_commit.commit_id} "
        f"& {descendant_commit.commit_id}",
    )


def ensure_main_bookmark(path: Path) -> bool:
    if bookmark_exists("main", path):
        return True
    origin_check = _revision_check(path, "main@origin")
    if not origin_check.ok:
        rprint(
            f"  [bold red]Error:[/] could not check main@origin: {origin_check.error}"
        )
        return False
    if not origin_check.value:
        rprint("  [bold red]Error:[/] main bookmark not found")
        return False
    result = _run(["jj", "bookmark", "create", "main", "-r", "main@origin"], path)
    if result.returncode != 0:
        rprint(
            f"  [bold red]Error:[/] could not create main bookmark: "
            f"{result.stderr.strip()}"
        )
        return False
    return True


def _main_bookmark_is_conflicted(path: Path) -> bool:
    result = _run(
        ["jj", "bookmark", "list", "-T", 'name ++ " " ++ conflict', "main"],
        path,
    )
    if result.returncode != 0:
        return True
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "main":
            return parts[1].lower() == "true"
    return False


def resolve_bookmark_contains_current_change(path: Path, bookmark: str) -> bool:
    result = _run(
        ["jj", "log", "-r", f"{bookmark}::@ & @", "--no-graph", "-T", "change_id"],
        path,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def _gh_list_pr_bookmarks(
    state: str, prefixes: tuple[str, ...], project_path: Path
) -> set[str]:
    """Return bookmark names for PRs in the given state matching any prefix."""
    completed = _run(
        [
            "gh",
            "pr",
            "list",
            "--state",
            state,
            "--json",
            "headRefName",
            "--jq",
            ".[ ].headRefName".replace(" ", ""),
        ],
        project_path,
    )
    if completed.returncode != 0:
        return set()
    return {
        b.strip()
        for b in completed.stdout.splitlines()
        if b.strip().startswith(prefixes)
    }


def _local_bookmark_names(project_path: Path) -> set[str]:
    completed = _run(["jj", "bookmark", "list"], project_path)
    if completed.returncode != 0:
        return set()
    names: set[str] = set()
    for line in completed.stdout.splitlines():
        if ":" not in line:
            continue
        name = line.split(":", 1)[0].strip().lstrip("*").strip()
        if name:
            names.add(name)
    return names


def prune_stale_bookmarks(project_path: Path) -> bool:
    fetch_result = _run(
        ["jj", "git", "fetch", "--remote", "origin"], project_path, timeout=120
    )
    if fetch_result.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] jj git fetch failed: "
            f"{fetch_result.stderr.strip()}"
        )
        return False

    stale_bookmarks = _gh_list_pr_bookmarks(
        "merged", _MANAGED_BOOKMARK_PREFIXES, project_path
    )
    stale_bookmarks |= _gh_list_pr_bookmarks(
        "closed", _MANAGED_BOOKMARK_PREFIXES, project_path
    )

    for bookmark in sorted(_local_bookmark_names(project_path) & stale_bookmarks):
        delete_bookmark(bookmark, project_path)

    return True


def _fetch_origin_main(project_path: Path) -> subprocess.CompletedProcess[str]:
    return _run(
        ["jj", "git", "fetch", "--remote", "origin", "--branch", "main"],
        project_path,
        timeout=120,
    )


def _refresh_after_sync(project_path: Path, action: str) -> tuple[bool, str]:
    ok, err = _refresh_working_copy_from_main_result(project_path)
    return ok, action if ok else err


def sync_main(project_path: Path) -> tuple[bool, str]:
    """Reconcile local main and origin/main bidirectionally."""
    fetch = _fetch_origin_main(project_path)
    if fetch.returncode != 0:
        return False, fetch.stderr.strip()

    try:
        if not ensure_main_bookmark(project_path):
            return False, "main bookmark not found"
    except BookmarkLookupError as exc:
        return False, str(exc)

    if _main_bookmark_is_conflicted(project_path):
        return (
            False,
            "main bookmark is conflicted; resolve with jj bookmark commands "
            "before syncing",
        )

    same = same_revision(project_path, "main", "main@origin")
    if not same.ok:
        return False, f"could not compare main and origin/main: {same.error}"
    if same.value:
        return _refresh_after_sync(project_path, "already up to date")

    remote_ahead = is_ancestor(project_path, "main", "main@origin")
    if not remote_ahead.ok:
        return (
            False,
            f"could not determine whether origin/main is ahead: {remote_ahead.error}",
        )
    if remote_ahead.value:
        if not create_or_reset_bookmark("main", project_path, "main@origin"):
            return False, "failed to move main to origin/main"
        return _refresh_after_sync(project_path, "pulled from remote")

    local_ahead = is_ancestor(project_path, "main@origin", "main")
    if not local_ahead.ok:
        return (
            False,
            f"could not determine whether local main is ahead: {local_ahead.error}",
        )
    if local_ahead.value:
        push = _run(
            ["jj", "git", "push", "--bookmark", "main", "--remote", "origin"],
            project_path,
            timeout=120,
        )
        if push.returncode != 0:
            return False, push.stderr.strip()

        post_push_fetch = _fetch_origin_main(project_path)
        if post_push_fetch.returncode != 0:
            return False, post_push_fetch.stderr.strip()

        verified = same_revision(project_path, "main", "main@origin")
        if not verified.ok:
            return False, f"could not verify pushed main: {verified.error}"
        if not verified.value:
            return False, "pushed main but origin/main did not update to match"
        return _refresh_after_sync(project_path, "pushed to remote")

    return (
        False,
        "local main and origin/main have diverged; resolve manually before syncing",
    )


def _run(
    cmd: list[str],
    cwd: Path,
    *,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    """Run a jj or gh command; statuses are left to each caller."""
    return run_captured(
        cmd,
        cwd,
        timeout=timeout,
        label=shlex.join(cmd),
        error=RevisionError,
        ok_codes=None,
    )


def revision_tree_id(path: Path, revision: str = "@") -> str:
    resolved = _single_commit_id(path, revision)
    if not resolved.ok:
        raise RevisionError(resolved.error)
    result = _run(
        ["jj", "debug", "object", "commit", resolved.commit_id],
        path,
    )
    # jj exposes the stored tree through its object inspector, not a template
    # keyword. Refuse conflicted trees and unfamiliar inspector output.
    trees = re.findall(
        r'^    root_tree: Resolved\(\s*TreeId\(\s*"([0-9a-f]{40,64})",?\s*\),?\s*\),$',
        result.stdout,
        re.MULTILINE,
    )
    if result.returncode != 0 or len(trees) != 1:
        raise RevisionError("Cannot identify the verified jj tree")
    return trees[0]


def exact_commit_id(path: Path, revision: str) -> str:
    result = _single_commit_id(path, revision)
    if not result.ok:
        raise RevisionError(result.error)
    return result.commit_id


def _guarded_tip(source_bookmark: str, expected_base: str, expected_tip: str) -> str:
    if source_bookmark not in _MANAGED_BOOKMARK_PREFIXES:
        raise RevisionError("Unexpected managed Gradle bookmark")
    if not all(
        re.fullmatch(r"[0-9a-f]{40,64}", value)
        for value in (expected_base, expected_tip)
    ):
        raise RevisionError("Invalid expected revision identity")
    # Cardinality is tested before intersection so conflicted bookmarks cannot
    # be reduced to the one expected arm and accidentally accepted.
    base = f"exactly(exactly(main, 1) & {expected_base}, 1)"
    tip = f"exactly(exactly({source_bookmark}, 1) & {expected_tip}, 1)"
    return f"exactly(({base})::({tip}) & ({tip}), 1)"


def promote_bookmark_to_main(
    path: Path,
    source_bookmark: str,
    *,
    expected_base: str | None = None,
    expected_tip: str | None = None,
) -> bool:
    if expected_base is None and expected_tip is None:
        return create_or_reset_bookmark("main", path, source_bookmark)
    if expected_base is None or expected_tip is None:
        return False
    try:
        guarded = _guarded_tip(source_bookmark, expected_base, expected_tip)
        result = _run(["jj", "bookmark", "set", "main", "-r", guarded], path)
        if result.returncode != 0:
            return False
        # Concurrent jj operations may merge into a conflicted bookmark. Never
        # report finalization success unless the single result remains exact.
        return (
            exact_commit_id(path, "main") == expected_tip
            and exact_commit_id(path, source_bookmark) == expected_tip
        )
    except RevisionError:
        return False


def push_bookmark_and_create_pr(
    project_path: Path,
    bookmark: str,
    *,
    expected_base: str | None = None,
    expected_tip: str | None = None,
) -> tuple[bool, str]:
    if expected_base is None and expected_tip is None:
        selector = ["--bookmark", bookmark]
    elif expected_base is None or expected_tip is None:
        return False, "Both expected revision identities are required"
    else:
        try:
            selector = [
                "--named",
                f"{bookmark}={_guarded_tip(bookmark, expected_base, expected_tip)}",
            ]
        except RevisionError as exc:
            return False, str(exc)
    push = _run(
        ["jj", "git", "push", *selector, "--remote", "origin"],
        project_path,
        timeout=120,
    )
    if push.returncode != 0:
        return False, push.stderr.strip()
    if expected_tip is not None:
        try:
            if (
                exact_commit_id(project_path, bookmark) != expected_tip
                or exact_commit_id(project_path, "main") != expected_base
            ):
                return False, "Local revisions changed during submission"
        except RevisionError as exc:
            return False, str(exc)
    pr = _run(
        ["gh", "pr", "create", "--fill", "--head", bookmark, "--base", "main"],
        project_path,
        timeout=60,
    )
    if pr.returncode != 0:
        if "already exists" in pr.stderr.lower():
            return True, f"PR already exists for {bookmark}"
        return False, pr.stderr.strip()
    return True, pr.stdout.strip()


def reset_verified_gradle_bookmark(
    path: Path, bookmark: str, *, expected_base: str, expected_tip: str
) -> bool:
    try:
        guarded = _guarded_tip(bookmark, expected_base, expected_tip)
        base = f"exactly({expected_base} & ::({guarded}), 1)"
        result = _run(
            ["jj", "bookmark", "set", bookmark, "--allow-backwards", "-r", base], path
        )
        return (
            result.returncode == 0 and exact_commit_id(path, bookmark) == expected_base
        )
    except RevisionError:
        return False


_COMMIT_ID = re.compile(r"[0-9a-f]{40,64}")


def _checked_jj(
    path: Path, arguments: list[str], *, timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    command = ["jj", *arguments]
    return run_captured(
        command,
        path,
        timeout=timeout,
        label=shlex.join(command),
        error=RevisionError,
    )


def _one_line(output: str, *, subject: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RevisionError(
            f"{subject} must resolve to exactly one value, got {len(lines)}"
        )
    return lines[0]


def _exact_commit(output: str, *, revision: str) -> str:
    commit_id = _one_line(output, subject=revision)
    if _COMMIT_ID.fullmatch(commit_id) is None:
        raise RevisionError(f"{revision} returned a malformed commit identity")
    return commit_id


class JjRepository:
    """A path-bound repository adapter with typed failure semantics."""

    def __init__(self, path: Path):
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def _run(
        self, arguments: list[str], *, timeout: int = 30
    ) -> subprocess.CompletedProcess[str]:
        return _checked_jj(self.path, arguments, timeout=timeout)

    def _bookmark_listing(self, bookmark: str) -> tuple[str, ...]:
        result = self._run(
            [
                "--ignore-working-copy",
                "--color",
                "never",
                "bookmark",
                "list",
                "-T",
                'if(remote == "origin", "", name ++ "\\n")',
                bookmark,
            ]
        )
        names = tuple(
            line.strip() for line in result.stdout.splitlines() if line.strip()
        )
        if any(name != bookmark for name in names):
            raise RevisionError(f"Unexpected bookmark listing for {bookmark}")
        return names

    def bookmark_exists(self, *, bookmark: str) -> bool:
        return bool(self._bookmark_listing(bookmark))

    def local_bookmarks(self) -> frozenset[str]:
        result = self._run(
            [
                "--ignore-working-copy",
                "--color",
                "never",
                "bookmark",
                "list",
                "-T",
                'if(remote == "origin", "", name ++ "\\n")',
            ]
        )
        names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return frozenset(names)

    def bookmark_conflicted(self, *, bookmark: str) -> bool:
        names = self._bookmark_listing(bookmark)
        if not names:
            raise RevisionError(f"Cannot inspect bookmark conflict for {bookmark}")
        return len(names) > 1

    def resolve_revision(self, *, revision: str, read_only: bool = False) -> str:
        if (
            revision in self.local_bookmarks()
            and len(self._bookmark_listing(revision)) > 1
        ):
            raise RevisionError(
                f"{revision} must resolve to exactly one commit, got multiple targets"
            )
        prefix = ["--ignore-working-copy", "--color", "never"] if read_only else []
        result = self._run(
            [
                *prefix,
                "log",
                "-r",
                revision,
                "--no-graph",
                "-T",
                'commit_id ++ "\\n"',
            ]
        )
        return _exact_commit(result.stdout, revision=revision)

    def revision_file(self, *, revision: str, filename: str) -> RevisionFile:
        commit_id = self.resolve_revision(revision=revision, read_only=True)
        result = self._run(
            [
                "--ignore-working-copy",
                "--color",
                "never",
                "file",
                "list",
                "-r",
                commit_id,
                "-T",
                'file_type ++ "\\n"',
                f"root-file:{filename}",
            ]
        )
        kinds = result.stdout.splitlines()
        if kinds not in (
            [],
            ["file"],
            ["symlink"],
            ["tree"],
            ["git-submodule"],
            ["conflict"],
        ):
            raise RevisionError("Unexpected revision file listing")
        return RevisionFile(commit_id=commit_id, is_regular=kinds == ["file"])

    def tree_id(self, *, revision: str = "@") -> str:
        commit_id = self.resolve_revision(revision=revision)
        result = self._run(["debug", "object", "commit", commit_id])
        trees = re.findall(
            r"^    root_tree: Resolved\(\s*TreeId\("
            r'\s*"([0-9a-f]{40,64})",?\s*\),?\s*\),$',
            result.stdout,
            re.MULTILINE,
        )
        if len(trees) != 1:
            raise RevisionError("Cannot identify the verified jj tree")
        return trees[0]

    def same_revision(self, *, left: str, right: str) -> bool:
        return self.resolve_revision(revision=left) == self.resolve_revision(
            revision=right
        )

    def is_ancestor(self, *, ancestor: str, descendant: str) -> bool:
        ancestor_id = self.resolve_revision(revision=ancestor)
        descendant_id = self.resolve_revision(revision=descendant)
        result = self._run(
            [
                "log",
                "-r",
                f"{ancestor_id}::{descendant_id} & {descendant_id}",
                "--no-graph",
                "-T",
                'commit_id ++ "\\n"',
            ]
        )
        values = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if values not in ([], [descendant_id]):
            raise RevisionError("Unexpected ancestry result")
        return bool(values)

    def revision_bookmarks(self, *, revision: str) -> tuple[str, ...]:
        commit_id = self.resolve_revision(revision=revision)
        result = self._run(
            [
                "log",
                "-r",
                commit_id,
                "--no-graph",
                "-T",
                (
                    "bookmarks.filter(|bookmark| !bookmark.remote()"
                    ' || bookmark.remote() == "git")'
                    '.map(|bookmark| bookmark.name()).join("\\n") ++ "\\n"'
                ),
            ]
        )
        return tuple(
            line.strip() for line in result.stdout.splitlines() if line.strip()
        )

    def change_id(self, *, revision: str = "@") -> str:
        result = self._run(
            [
                "log",
                "-r",
                revision,
                "--no-graph",
                "-T",
                'change_id ++ "\\n"',
            ]
        )
        return _one_line(result.stdout, subject=f"change id for {revision}")

    def working_copy_state(self) -> WorkingCopyState:
        return WorkingCopyState(
            has_changes=self.has_changes(),
            description=self._run(
                ["log", "-r", "@", "--no-graph", "-T", "description"]
            ).stdout.rstrip("\n"),
            bookmarks=self.revision_bookmarks(revision="@"),
        )

    def has_changes(self) -> bool:
        return bool(self._run(["diff", "--summary"]).stdout.strip())

    def changed_paths(self, *, revision: str = "@") -> frozenset[str]:
        result = self._run(["diff", "-r", revision, "--name-only"])
        return frozenset(line for line in result.stdout.splitlines() if line)

    def create_bookmark(self, *, bookmark: str, revision: str) -> None:
        self._run(["bookmark", "create", bookmark, "-r", revision])

    def set_bookmark(self, *, bookmark: str, revision: str) -> None:
        self._run(["bookmark", "set", bookmark, "-r", revision])

    def delete_bookmark(self, *, bookmark: str) -> None:
        self._run(["bookmark", "delete", bookmark])

    def new_change(self, *, revision: str) -> None:
        self._run(["new", revision])

    def commit(self, *, message: str) -> None:
        self._run(["commit", "-m", message])

    def discard(self) -> None:
        self._run(["restore", "--from", "@-"])

    def rebase_working_copy(self, *, revision: str) -> None:
        self._run(["rebase", "-r", "@", "-d", revision])

    def promote_bookmark_to_main(
        self, *, bookmark: str, expected: ExpectedRevisions | None = None
    ) -> None:
        selector = bookmark
        if expected is not None:
            selector = _guarded_tip(bookmark, expected.base, expected.tip)
        self._run(["bookmark", "set", "main", "-r", selector])
        if expected is not None and (
            self.resolve_revision(revision="main") != expected.tip
            or self.resolve_revision(revision=bookmark) != expected.tip
        ):
            raise RevisionError("Local revisions changed during promotion")

    def reset_verified_bookmark(
        self, *, bookmark: str, expected: ExpectedRevisions
    ) -> None:
        guarded = _guarded_tip(bookmark, expected.base, expected.tip)
        base = f"exactly({expected.base} & ::({guarded}), 1)"
        self._run(["bookmark", "set", bookmark, "--allow-backwards", "-r", base])
        if self.resolve_revision(revision=bookmark) != expected.base:
            raise RevisionError("Local revisions changed during reset")

    def fetch(self, *, main_only: bool = False) -> None:
        arguments = ["git", "fetch", "--remote", "origin"]
        if main_only:
            arguments.extend(["--branch", "main"])
        self._run(arguments, timeout=120)

    def push_bookmark(
        self, *, bookmark: str, expected: ExpectedRevisions | None = None
    ) -> None:
        if expected is None:
            selector = ["--bookmark", bookmark]
        else:
            guarded = _guarded_tip(bookmark, expected.base, expected.tip)
            push_name = f'templates.git_push_bookmark="\\"{bookmark}\\""'
            selector = ["--change", guarded, "--config", push_name]
        self._run(["git", "push", *selector, "--remote", "origin"], timeout=120)
        if expected is not None and (
            self.resolve_revision(revision="main") != expected.base
            or self.resolve_revision(revision=bookmark) != expected.tip
        ):
            raise RevisionError("Local revisions changed during submission")

    def workspace_names(self) -> frozenset[str]:
        result = self._run(["workspace", "list", "-T", 'name ++ "\\n"'])
        names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(names) != len(set(names)):
            raise RevisionError("Unexpected duplicate workspace listing")
        return frozenset(names)

    def add_workspace(self, *, name: str, path: Path, revision: str) -> None:
        self._run(["workspace", "add", "--name", name, str(path), "-r", revision])

    def forget_workspace(self, *, name: str) -> None:
        self._run(["workspace", "forget", name])

    def temporary_workspace(
        self, *, revision: str
    ) -> AbstractContextManager[Repository]:
        return _temporary_workspace(self, revision=revision, bind=JjRepository)


@contextmanager
def _temporary_workspace(
    repository: Repository,
    *,
    revision: str,
    bind: Callable[[Path], Repository],
) -> Iterator[Repository]:
    resolved = repository.resolve_revision(revision=revision)
    try:
        container = Path(tempfile.mkdtemp(prefix="mm-gradle-proof-"))
    except OSError as exc:
        raise RevisionError(f"Cannot allocate proof workspace: {exc}") from exc
    token = uuid.uuid4().hex
    marker = container / ".mm-proof-owner"
    name = f"mm-proof-{token}"
    root = container / "workspace"
    try:
        marker.write_text(token, encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        cleanup = ""
        try:
            if not container.is_symlink():
                shutil.rmtree(container)
            else:
                cleanup = "; allocated path became a symlink and was not removed"
        except OSError as cleanup_exc:
            cleanup = f"; cleanup failed: {cleanup_exc}"
        raise RevisionError(f"Cannot mark proof workspace: {exc}{cleanup}") from exc
    registered = False
    body_error: BaseException | None = None
    try:
        repository.add_workspace(name=name, path=root, revision=resolved)
        registered = True
        proof = bind(root)
        proof.new_change(revision=resolved)
        try:
            yield proof
        except BaseException as exc:
            body_error = exc
            raise
    finally:
        diagnostics: list[str] = []
        if registered:
            try:
                repository.forget_workspace(name=name)
            except RevisionError as exc:
                diagnostics.append(f"forget workspace failed: {exc}")
        try:
            owned = (
                not container.is_symlink()
                and not marker.is_symlink()
                and marker.is_file()
                and marker.read_text(encoding="utf-8") == token
            )
            if owned:
                shutil.rmtree(container)
            elif container.exists() or container.is_symlink():
                diagnostics.append("proof workspace ownership marker changed")
        except (OSError, UnicodeError) as exc:
            diagnostics.append(f"remove proof workspace failed: {exc}")
        if diagnostics:
            detail = "; ".join(diagnostics)
            if body_error is not None:
                body_error.add_note(detail)
            else:
                raise RevisionError(detail)
