import shutil
import subprocess
from pathlib import Path

from rich import print as rprint


class GitHubCLINotFoundError(Exception):
    pass


class RepoDirtyError(Exception):
    pass


_MANAGED_BRANCH_PREFIXES = (
    "mm/update-dependencies",
    "mm/resolve-dependencies",
)


def prune_stale_branches(project_path: Path) -> bool:
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
        "merged", _MANAGED_BRANCH_PREFIXES, project_path
    )
    stale_branches |= _gh_list_pr_branches(
        "closed", _MANAGED_BRANCH_PREFIXES, project_path
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
    retry is restricted to managed maintenance branches (see
    ``_MANAGED_BRANCH_PREFIXES``), where this tool owns the branch lifecycle.
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


def sync_main(project_path: Path) -> tuple[bool, str]:
    """Fetch, fast-forward local main, and push to origin.

    Works without checking out main. When on main, uses merge --ff-only.
    When on another branch, uses fetch origin main:main (which git rejects
    for checked-out branches).
    """
    branch = get_current_branch(project_path)
    if not branch:
        return False, "Not on a branch (detached HEAD)."

    if branch == "main":
        pull = _run(["git", "pull"], project_path, timeout=120)
        if pull.returncode != 0:
            return False, _clean_git_stderr(pull.stderr)
    else:
        fetch = _run(["git", "fetch", "origin"], project_path, timeout=120)
        if fetch.returncode != 0:
            return False, _clean_git_stderr(fetch.stderr)
        fetch_main = _run(
            ["git", "fetch", "origin", "main:main"], project_path, timeout=120
        )
        if fetch_main.returncode != 0:
            return False, _clean_git_stderr(fetch_main.stderr)

    push = _run(["git", "push", "origin", "main"], project_path, timeout=120)
    if push.returncode != 0:
        return False, _clean_git_stderr(push.stderr)

    return True, ""


def git_branch_exists(branch: str, project_path: Path) -> bool:
    """Return True if *branch* exists locally."""
    r = _run(["git", "rev-parse", "--verify", branch], project_path)
    return r.returncode == 0


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


def git_has_changes(project_path: Path) -> bool:
    """Return True when the repo has tracked or untracked changes."""
    r = _run(["git", "status", "--porcelain"], project_path)
    if r.returncode != 0:
        return True
    return bool(r.stdout.strip())


def git_merge_fast_forward(branch: str, project_path: Path) -> bool:
    """Fast-forward merge *branch* into the current branch. Returns True on success."""
    r = _run(["git", "merge", "--ff-only", branch], project_path)
    if r.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] git merge --ff-only {branch} failed: "
            f"{r.stderr.strip()}"
        )
        return False
    return True


def git_replace_branch(branch: str, project_path: Path) -> bool:
    """Replace *branch* by checking out main, deleting, and recreating.

    A detached HEAD (empty current branch) skips the initial checkout.
    """
    if get_current_branch(project_path) and not git_checkout("main", project_path):
        return False
    if not git_delete_branch(branch, project_path):
        return False
    return git_create_branch(branch, project_path)


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
        rprint(f"  [bold red]FAIL[/] git commit failed: {result.stderr.strip()}")
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


def create_worktree(
    project_path: Path,
    worktree_path: Path,
    *,
    branch: str = "main",
    detach: bool = True,
) -> bool:
    """Create a git worktree at worktree_path on the requested branch."""
    cmd = ["git", "worktree", "add"]
    if detach:
        cmd.append("--detach")
    cmd.extend([str(worktree_path), branch])
    r = _run(
        cmd,
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
    return branch.startswith(_MANAGED_BRANCH_PREFIXES)


def _is_non_fast_forward_push(stderr: str) -> bool:
    """Return True when a push failed due to remote divergence."""
    error = stderr.lower()
    return "non-fast-forward" in error or "fetch first" in error


def _clean_git_stderr(stderr: str) -> str:
    """Strip git hint lines from stderr, returning only the error message."""
    lines = [line for line in stderr.splitlines() if not line.startswith("hint:")]
    return "\n".join(lines).strip()
