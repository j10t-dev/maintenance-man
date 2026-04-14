import shutil
import subprocess
from pathlib import Path

from rich import print as rprint


class GitHubCLINotFoundError(Exception):
    pass


class RepoDirtyError(Exception):
    pass


def sync_remote(project_path: Path) -> bool:
    """Fetch from remote, prune stale refs, delete merged/closed branches.

    Runs ``git fetch --prune`` to update remote state, then deletes any
    managed local branches whose GitHub PRs have been merged or closed.
    """
    fetch_result = _run(["git", "fetch", "--prune"], project_path, timeout=120)
    if fetch_result.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] git fetch failed: "
            f"{fetch_result.stderr.strip()}"
        )
        return False

    stale_branches = _gh_list_pr_branches(
        "merged", ("bump/", "fix/"), project_path
    )
    stale_branches |= _gh_list_pr_branches(
        "closed", ("bump/", "fix/"), project_path
    )

    local = _run(
        ["git", "branch", "--format=%(refname:short)"], project_path, timeout=10
    )
    if local.returncode != 0:
        return True

    local_branches = {b.strip() for b in local.stdout.splitlines()}

    for branch in sorted(local_branches & stale_branches):
        git_delete_branch(branch, project_path)

    return True


def push_and_create_pr(project_path: Path) -> tuple[bool, str]:
    """Push current branch and create a GitHub PR.

    Pushes the current branch to origin. Automatic ``--force-with-lease``
    retry is restricted to managed update branches (``bump/`` and ``fix/``),
    where this tool owns the branch lifecycle.
    """
    branch = get_current_branch(project_path)
    if not branch:
        return False, "Not on a branch (detached HEAD)."

    push = _run(
        ["git", "push", "-u", "origin", branch],
        project_path,
        timeout=120,
    )
    if push.returncode != 0 and _is_non_fast_forward_push(push.stderr):
        if not _is_managed_update_branch(branch):
            return False, push.stderr.strip()
        rprint(
            "  [bold yellow]Warning:[/] remote branch diverged — retrying "
            "with --force-with-lease"
        )
        push = _run(
            ["git", "push", "--force-with-lease", "-u", "origin", branch],
            project_path,
            timeout=120,
        )
    if push.returncode != 0:
        return False, push.stderr.strip()

    pr = _run(
        ["gh", "pr", "create", "--fill", "--head", branch],
        project_path,
        timeout=60,
    )
    if pr.returncode != 0:
        if "already exists" in pr.stderr.lower():
            return True, f"PR already exists for {branch}"
        return False, pr.stderr.strip()

    return True, pr.stdout.strip()


def git_checkout(branch: str, project_path: Path) -> bool:
    """Check out a git branch. Returns True on success."""
    completed = _run(["git", "checkout", branch], project_path)
    if completed.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] git checkout {branch} failed: "
            f"{completed.stderr.strip()}"
        )
        return False
    return True


def git_create_branch(branch_name: str, project_path: Path) -> bool:
    """Create and check out a new git branch. Returns True on success.

    If the branch already exists, deletes it first and recreates.
    """
    result = _run(["git", "checkout", "-b", branch_name], project_path)
    if result.returncode != 0:
        if "already exists" in result.stderr:
            git_delete_branch(branch_name, project_path)
            retry = _run(["git", "checkout", "-b", branch_name], project_path)
            if retry.returncode != 0:
                rprint(
                    f"  [bold red]FAIL[/] branch creation (retry) failed: "
                    f"{retry.stderr.strip()}"
                )
                return False
            return True
        rprint(f"  [bold red]FAIL[/] branch creation failed: {result.stderr.strip()}")
        return False
    return True


def git_commit_all(message: str, project_path: Path) -> bool:
    """Stage all changes and commit. Returns True on success."""
    add = _run(["git", "add", "-A"], project_path)
    if add.returncode != 0:
        rprint(f"  [bold red]FAIL[/] git add failed: {add.stderr.strip()}")
        return False

    result = _run(["git", "commit", "-m", message], project_path)
    if result.returncode != 0:
        rprint(
            f"  [bold red]FAIL[/] git commit failed: {result.stderr.strip()}"
        )
        return False
    return True


def git_delete_branch(branch_name: str, project_path: Path) -> bool:
    """Force-delete a local git branch. Returns True on success."""
    completed = _run(["git", "branch", "-D", branch_name], project_path)
    if completed.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] git branch -D {branch_name} failed: "
            f"{completed.stderr.strip()}"
        )
        return False
    return True


def check_gh_available() -> None:
    """Raise GitHubCLINotFoundError if gh is not on PATH."""
    if shutil.which("gh") is None:
        raise GitHubCLINotFoundError(
            "GitHub CLI (gh) is not installed or not on PATH. "
            "Install it from https://cli.github.com/"
        )


def check_repo_clean(project_path: Path) -> None:
    """Raise RepoDirtyError if the git repo has uncommitted changes."""
    completed = _run(["git", "status", "--porcelain"], project_path)
    if completed.stdout.strip():
        raise RepoDirtyError(
            f"Repository has uncommitted changes:\n{completed.stdout.strip()}"
        )


def get_current_branch(project_path: Path) -> str:
    """Return the current git branch name."""
    return _run(["git", "branch", "--show-current"], project_path).stdout.strip()


def ensure_on_main(project_path: Path) -> bool:
    """Ensure the repo is on the main branch. Returns True if successful."""
    if get_current_branch(project_path) == "main":
        return True
    return git_checkout("main", project_path)


def create_worktree(project_path: Path, worktree_path: Path) -> bool:
    """Create a git worktree at worktree_path, checked out to main."""
    r = _run(
        ["git", "worktree", "add", "--detach", str(worktree_path), "main"],
        project_path,
        timeout=30,
    )
    if r.returncode != 0:
        rprint(f"  [bold red]Error:[/] worktree creation failed: {r.stderr.strip()}")
        return False
    return True


def remove_worktree(project_path: Path, worktree_path: Path) -> None:
    """Remove a temporary worktree."""
    r = _run(
        ["git", "worktree", "remove", "--force", str(worktree_path)],
        project_path,
        timeout=30,
    )
    if r.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] worktree removal failed: {r.stderr.strip()}"
        )


def discard_changes(project_path: Path) -> None:
    """Discard all uncommitted changes in the working tree."""
    _run(["git", "checkout", "--", "."], project_path)
    _run(["git", "clean", "-fd"], project_path)


def reset_to_main(project_path: Path) -> None:
    """Discard all changes and check out main."""
    _run(["git", "checkout", "main", "--", "."], project_path)
    _run(["git", "clean", "-fd"], project_path)
    git_checkout("main", project_path)


def branch_slug(pkg_name: str) -> str:
    """Normalise a package name into a branch-safe slug."""
    return pkg_name.lstrip("@").replace("/", "-")


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


def _gh_list_pr_branches(
    state: str, prefixes: tuple[str, ...], project_path: Path
) -> set[str]:
    """Return branch names for PRs in the given state matching any prefix."""
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
            ".[].headRefName",
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


def _is_managed_update_branch(branch: str) -> bool:
    """Return True for branches managed by the automated update flow."""
    return branch.startswith(("bump/", "fix/"))



def _is_non_fast_forward_push(stderr: str) -> bool:
    """Return True when a push failed due to remote divergence."""
    error = stderr.lower()
    return "non-fast-forward" in error or "fetch first" in error
