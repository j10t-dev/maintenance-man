import shutil
import subprocess
from pathlib import Path

from rich import print as rprint


class GraphiteNotFoundError(Exception):
    pass


class RepoDirtyError(Exception):
    pass


def sync_graphite(project_path: Path) -> bool:
    """Sync with remote and delete local branches whose PRs are merged/closed.

    Runs ``gt sync`` to fetch and update trunk, then explicitly deletes any
    tracked ``bump/`` or ``fix/`` branches whose GitHub PRs have been merged
    or closed.  This avoids stale branches blocking future stack submissions.
    """
    _run(["gt", "sync", "--no-interactive"], project_path, timeout=120)

    prefixes = ("bump/", "fix/")
    stale_branches = _gh_list_pr_branches("merged", prefixes, project_path)
    stale_branches |= _gh_list_pr_branches("closed", prefixes, project_path)

    local = _run(
        ["git", "branch", "--format=%(refname:short)"], project_path, timeout=10
    )
    if local.returncode != 0:
        return True

    local_branches = {b.strip() for b in local.stdout.splitlines()}

    # Delete stale branches — gt delete handles metadata + restacks children;
    # fall back to git branch -D for branches Graphite doesn't track.
    for branch in sorted(local_branches & stale_branches):
        if not gt_delete(branch, project_path):
            _run(["git", "branch", "-D", branch], project_path, timeout=10)

    return True


def submit_stack(project_path: Path) -> tuple[bool, str]:
    """Run gt submit --stack. Returns (success, output)."""
    r = _run(["gt", "submit", "--stack"], project_path, timeout=120)
    ok = r.returncode == 0
    return ok, (r.stdout if ok else r.stderr).strip()


def gt_create(message: str, branch_name: str, project_path: Path) -> bool:
    """Create a Graphite branch, deleting any stale branch with the same name first."""
    cmd = ["gt", "create", branch_name, "-a", "-m", message]
    first = _run(cmd, project_path, timeout=60)

    match (first.returncode, "already exists" in first.stderr):
        case (0, _):
            return True
        case (_, True):
            # Stale branch -- delete and recreate
            gt_delete(branch_name, project_path)
            retry = _run(cmd, project_path, timeout=60)
            if retry.returncode != 0:
                rprint(
                    f"  [bold red]FAIL[/] gt create (retry) failed: "
                    f"{retry.stderr.strip()}"
                )
                return False
            return True
        case _:
            rprint(f"  [bold red]FAIL[/] gt create failed: {first.stderr.strip()}")
            return False


def gt_delete(branch_name: str, project_path: Path) -> bool:
    """Delete a Graphite branch. Returns True on success."""
    completed = _run(["gt", "delete", "-f", branch_name], project_path)
    if completed.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] gt delete {branch_name} failed: "
            f"{completed.stderr.strip()}"
        )
        return False
    return True


def gt_checkout(branch: str, project_path: Path) -> bool:
    """Check out a Graphite branch. Returns True on success."""
    completed = _run(["gt", "checkout", branch], project_path)
    if completed.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] gt checkout {branch} failed: "
            f"{completed.stderr.strip()}"
        )
        return False
    return True


def check_graphite_available() -> None:
    """Raise GraphiteNotFoundError if gt is not on PATH."""
    if shutil.which("gt") is None:
        raise GraphiteNotFoundError(
            "Graphite CLI (gt) is not installed or not on PATH. "
            "Install it from https://graphite.dev/docs/installing-the-cli"
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


def discard_changes(project_path: Path) -> None:
    """Discard all uncommitted changes in the working tree."""
    _run(["git", "checkout", "--", "."], project_path)
    _run(["git", "clean", "-fd"], project_path)


def reset_to_main(project_path: Path) -> None:
    """Discard all changes and check out main."""
    _run(["git", "checkout", "main", "--", "."], project_path)
    _run(["git", "clean", "-fd"], project_path)
    gt_checkout("main", project_path)


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
