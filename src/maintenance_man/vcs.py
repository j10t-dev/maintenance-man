import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from rich import print as rprint

from maintenance_man import config as _config
from maintenance_man import sanitise_project_name


class GitHubCLINotFoundError(Exception):
    pass


class JJCLINotFoundError(Exception):
    pass


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


_MANAGED_BOOKMARK_PREFIXES = (
    "mm/update-dependencies",
    "mm/resolve-dependencies",
)

MM_WORKSPACES = _config.MM_HOME / "workspaces"


def check_jj_available() -> None:
    """Raise JJCLINotFoundError if jj is not on PATH."""
    if shutil.which("jj") is None:
        raise JJCLINotFoundError("jj is required for maintenance-man VCS operations")


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
    result = _run(["jj", "bookmark", "list", "-T", "name", bookmark], path)
    return result.returncode == 0 and bool(result.stdout.strip())


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


def promote_bookmark_to_main(path: Path, source_bookmark: str) -> bool:
    return create_or_reset_bookmark("main", path, source_bookmark)


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


def bookmark_slug(pkg_name: str) -> str:
    """Normalise a package name into a bookmark-safe slug."""
    return pkg_name.lstrip("@").replace("/", "-")


def workspace_path_for_project(project: str) -> Path:
    return MM_WORKSPACES / sanitise_project_name(project)


def assert_safe_workspace_path(path: Path) -> Path:
    root = MM_WORKSPACES.resolve()
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


def _single_commit_id(path: Path, revision: str) -> RevisionResolve:
    result = _run(
        ["jj", "log", "-r", revision, "--no-graph", "-T", 'commit_id ++ "\\n"'],
        path,
    )
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


def push_bookmark_and_create_pr(project_path: Path, bookmark: str) -> tuple[bool, str]:
    """Push a managed jj bookmark and create a GitHub PR.

    ``jj git push --bookmark`` has force-with-lease-style safety: the remote
    bookmark is updated only when it still matches the last fetched state.
    """
    push = _run(
        ["jj", "git", "push", "--bookmark", bookmark, "--remote", "origin"],
        project_path,
        timeout=120,
    )
    if push.returncode != 0:
        return False, push.stderr.strip()

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

    if not ensure_main_bookmark(project_path):
        return False, "main bookmark not found"

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


def check_gh_available() -> None:
    """Raise GitHubCLINotFoundError if gh is not on PATH."""
    if shutil.which("gh") is None:
        raise GitHubCLINotFoundError(
            "GitHub CLI (gh) is not installed or not on PATH. "
            "Install it from https://cli.github.com/"
        )


def _run(
    cmd: list[str],
    cwd: Path,
    *,
    timeout: int = 30,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with standard capture settings."""
    return subprocess.run(
        cmd,
        cwd=cwd,
        timeout=timeout,
        capture_output=True,
        text=True,
        env=env,
    )
