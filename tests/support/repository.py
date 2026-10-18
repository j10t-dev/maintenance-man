"""Disposable real jj repositories copied from one template built per test process."""

import atexit
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import pytest

from maintenance_man import vcs
from maintenance_man.config import load_config
from maintenance_man.vcs import JjRepository

MANAGED = "mm/update-dependencies"


@dataclass(frozen=True, slots=True)
class RepositoryCase:
    """A repository with its origin, and a second checkout of that origin."""

    repo: JjRepository
    peer: JjRepository


@cache
def _scratch_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="mm-tests-jj-"))
    atexit.register(shutil.rmtree, root, True)
    (root / "jj-config.toml").write_text("", encoding="utf-8")
    return root


@cache
def jj_environment() -> dict[str, str]:
    """Identity, empty user config and non-interactive editor and pager for jj."""
    return {
        "JJ_USER": "MM Tests",
        "JJ_EMAIL": "mm@example.invalid",
        "JJ_CONFIG": str(_scratch_root() / "jj-config.toml"),
        "JJ_EDITOR": "true",
        "JJ_PAGER": "cat",
    }


def run_jj(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run jj in a disposable test repository; the caller checks the exit code."""
    return subprocess.run(
        ["jj", *arguments],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | jj_environment(),
    )


def _jj(path: Path, *arguments: str) -> str:
    result = run_jj(path, *arguments)
    assert result.returncode == 0, result.stderr
    return result.stdout


@cache
def _template() -> Path:
    root = _scratch_root() / "template"
    root.mkdir()
    repo, origin, peer = root / "repo", root / "origin", root / "peer"
    _jj(root, "git", "init", "repo")
    (repo / "dep.txt").write_text("version=1\n", encoding="utf-8")
    _jj(repo, "commit", "-m", "baseline")
    _jj(repo, "bookmark", "create", "main", "-r", "@-")
    _jj(root, "git", "init", "--colocate", "origin")
    _jj(origin, "new")
    _jj(repo, "git", "remote", "add", "origin", str(origin))
    _jj(repo, "git", "push", "--bookmark", "main")
    _jj(root, "git", "init", "peer")
    _jj(peer, "git", "remote", "add", "origin", str(origin))
    _jj(peer, "git", "fetch", "--remote", "origin")
    _jj(peer, "bookmark", "create", "main", "-r", "main@origin")
    _jj(peer, "bookmark", "track", "main@origin")
    _jj(peer, "new", "main")
    return root


def _origin_of(path: Path) -> Path:
    return path.with_name(f"{path.name}-origin")


def copy_jj_repository(path: Path) -> JjRepository:
    """Copy the template to *path*.

    Commit 'baseline' with dep.txt = 'version=1' is on main, pushed to its own origin
    at <path>-origin; the working copy is an empty child.
    """
    origin = _origin_of(path)
    shutil.copytree(_template() / "repo", path, symlinks=True, dirs_exist_ok=True)
    shutil.copytree(_template() / "origin", origin, symlinks=True)
    _jj(path, "git", "remote", "set-url", "origin", str(origin))
    return JjRepository(path)


def copy_jj_peer(repo: JjRepository) -> JjRepository:
    """Copy the template's second checkout beside *repo*, pointed at *repo*'s origin."""
    peer = repo.path.with_name(f"{repo.path.name}-peer")
    shutil.copytree(_template() / "peer", peer, symlinks=True)
    _jj(peer, "git", "remote", "set-url", "origin", str(_origin_of(repo.path)))
    return JjRepository(peer)


def configure_jj_projects(home: Path, tmp_path: Path) -> dict[str, Path]:
    """Point each configured project at its own copied jj repository.

    Projects that shared a path share one copy. Returns each project's repository path.
    """
    config_path = home / "config.toml"
    configured = load_config(config_path)
    copies: dict[Path, Path] = {}
    tables = {"defaults": configured.defaults.model_dump(exclude_none=True)}
    for name, project in configured.projects.items():
        if project.path not in copies:
            target = tmp_path / "repositories" / f"repo-{len(copies)}"
            copy_jj_repository(target)
            copies[project.path] = target
        fields = project.model_dump(mode="json", exclude_none=True)
        tables[f"projects.{json.dumps(name)}"] = fields | {
            "path": str(copies[project.path])
        }
    config_path.write_text(
        "".join(_toml_table(header, fields) for header, fields in tables.items()),
        encoding="utf-8",
    )
    return {name: copies[project.path] for name, project in configured.projects.items()}


def _toml_table(header: str, fields: dict[str, object]) -> str:
    lines = [f"[{header}]", *(f"{key} = {json.dumps(v)}" for key, v in fields.items())]
    return "\n".join(lines) + "\n\n"


def write_file(repo: JjRepository, filename: str, content: str | None) -> None:
    """Write *content* to *filename* in the working copy, or delete it when None."""
    target = repo.path / filename
    if content is None:
        target.unlink(missing_ok=True)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def commit_file(repo: JjRepository, filename: str, content: str, message: str) -> str:
    """Commit *content* as *filename*; returns the new commit's id."""
    write_file(repo, filename, content)
    repo.commit(message=message)
    return repo.resolve_revision(revision="@-")


def commit_to_main(repo: JjRepository, message: str) -> str:
    """Commit the working copy, move main onto the commit and return its id."""
    repo.commit(message=message)
    repo.set_bookmark(bookmark="main", revision="@-")
    return repo.resolve_revision(revision="@-")


def describe(repo: JjRepository, message: str) -> None:
    """Describe the working-copy change."""
    _jj(repo.path, "describe", "-m", message)


def conflict_bookmark(repo: JjRepository, bookmark: str, left: str, right: str) -> None:
    """Make *bookmark* a conflicted bookmark targeting both *left* and *right*."""
    if bookmark == "main":
        _jj(repo.path, "bookmark", "untrack", "main@origin")
    if repo.bookmark_exists(bookmark=bookmark):
        _jj(repo.path, "bookmark", "delete", bookmark)
    operation = operation_id(repo)
    _jj(repo.path, "bookmark", "create", bookmark, "-r", left)
    _jj(repo.path, "--at-op", operation, "bookmark", "create", bookmark, "-r", right)
    _jj(repo.path, "bookmark", "list", bookmark)


def track_main(repo: JjRepository, *, enabled: bool) -> None:
    """Track or untrack main@origin."""
    _jj(repo.path, "bookmark", "track" if enabled else "untrack", "main@origin")


def push_peer_main(peer: JjRepository) -> None:
    """Move the peer's main onto its last commit and push it."""
    peer.set_bookmark(bookmark="main", revision="@-")
    peer.push_bookmark(bookmark="main")


def remote_bookmark_target(repo: JjRepository, bookmark: str) -> str | None:
    """Fetch in *repo*, then return origin's target for *bookmark*; None when absent.

    Pass the peer to leave the repository under test untouched.
    """
    _jj(repo.path, "git", "fetch", "--remote", "origin")
    result = run_jj(
        repo.path,
        "log",
        "-r",
        f"{bookmark}@origin",
        "--no-graph",
        "-T",
        'commit_id ++ "\\n"',
    )
    return result.stdout.strip() if result.returncode == 0 else None


def commit_descriptions(repo: JjRepository, revset: str) -> list[str]:
    """First description lines of the commits in *revset*, oldest first."""
    return _jj(
        repo.path,
        "log",
        "-r",
        revset,
        "--no-graph",
        "--reversed",
        "-T",
        'description.first_line() ++ "\\n"',
    ).splitlines()


def operation_id(repo: JjRepository) -> str:
    """Snapshot the working copy, then return the latest operation id.

    The same id before and after an action means the action changed nothing.
    """
    _jj(repo.path, "status")
    return _jj(
        repo.path,
        "op",
        "log",
        "--ignore-working-copy",
        "--no-graph",
        "--limit",
        "1",
        "-T",
        'id ++ "\\n"',
    ).strip()


def fail_repository_method(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    method: str,
    failure: Exception,
    *,
    call: int = 1,
) -> None:
    """Raise *failure* on the *call*-th use of ``JjRepository.<method>`` for *path*.

    Methods that other methods call count those internal calls too.
    """
    original = getattr(JjRepository, method)
    calls = 0

    def fail(repository, *args, **kwargs):
        nonlocal calls
        if repository.path.resolve() == path.resolve():
            calls += 1
            if calls == call:
                raise failure
        return original(repository, *args, **kwargs)

    monkeypatch.setattr(JjRepository, method, fail)


def run_after_jj_command(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    prefix: tuple[str, ...],
    action: Callable[[], None],
) -> None:
    """Run *action* once, right after the first jj command in *path* with *prefix*."""
    original = vcs.run_captured
    fired = False

    def run(command, cwd, **kwargs):
        nonlocal fired
        completed = original(command, cwd, **kwargs)
        if (
            not fired
            and Path(cwd).resolve() == path.resolve()
            and tuple(command[1 : 1 + len(prefix)]) == prefix
        ):
            fired = True
            action()
        return completed

    monkeypatch.setattr(vcs, "run_captured", run)
