"""The same repository scenarios against real jj and its in-memory fake."""

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

import pytest

from maintenance_man import vcs
from maintenance_man.vcs import Repository
from tests.fake_vcs import FakeCall, FakeJjState

MANAGED = "mm/update-dependencies"


@dataclass
class OriginPeer:
    """A second checkout sharing the repository origin."""

    repo: Repository
    commit_file: Callable[[str, str, str], str]
    push_main: Callable[[], None]
    remote_bookmark_targets: Callable[[str], tuple[str, ...]]


@dataclass
class RepositoryCase:
    """The same scenario controls for real jj and its in-memory fake."""

    repo: Repository
    bind: Callable[[Path], Repository]
    register_file: Callable[[str], None]
    write_file: Callable[[str, str | None], None]
    commit_file: Callable[[str, str, str], str]
    describe: Callable[[str], None]
    conflict_bookmark: Callable[[str, str, str], None]
    origin_peer: OriginPeer
    track_main: Callable[[bool], None]
    after_push: Callable[[Callable[[], None]], None]
    attempts: list[FakeCall] | None
    commands: list[tuple[str, ...]] | None


def real_repository_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch | None = None
) -> RepositoryCase:
    """Create isolated jj checkouts and an origin, with optional operation hooks."""
    repo, origin_git = _initialize_real_repository(tmp_path)
    pending_after_push: list[Callable[[], None]] = []
    commands: list[tuple[str, ...]] = []
    _install_real_postcheck_interceptor(
        repo.path, monkeypatch, pending_after_push, commands
    )
    repo.push_bookmark(bookmark="main")
    origin_peer = _initialize_real_peer(tmp_path, origin_git)

    def register_file(_filename: str) -> None:
        return None

    def track_main(enabled: bool) -> None:
        action = "track" if enabled else "untrack"
        result = run_jj(repo.path, "bookmark", action, "main@origin")
        assert result.returncode == 0, result.stderr

    def after_push(action: Callable[[], None]) -> None:
        assert not pending_after_push, "only one pending push action is supported"
        pending_after_push.append(action)

    return RepositoryCase(
        repo=repo,
        bind=_bind_real_repository,
        register_file=register_file,
        write_file=partial(_write_repository_file, repo),
        commit_file=partial(_commit_repository_file, repo, register_file),
        describe=partial(_describe_real_repository, repo),
        conflict_bookmark=partial(_conflict_real_bookmark, repo),
        origin_peer=origin_peer,
        track_main=track_main,
        after_push=after_push,
        attempts=None,
        commands=commands,
    )


def fake_repository_case(tmp_path: Path) -> RepositoryCase:
    """Create the in-memory counterpart of the real repository scenario."""
    state = FakeJjState()
    path = tmp_path / "fake-repository"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    repo.push_bookmark(bookmark="main")
    peer_path = tmp_path / "origin-peer"
    peer_repo = state.seed_peer(peer_path, source=path, track_main=True)

    register_file = partial(_register_fake_file, state, path)

    def describe(message: str) -> None:
        repo.describe(message=message)

    def peer_push_main() -> None:
        peer_repo.set_bookmark(bookmark="main", revision="@-")
        peer_repo.push_bookmark(bookmark="main")

    state.clear_calls()

    return RepositoryCase(
        repo=repo,
        bind=state.repository,
        register_file=register_file,
        write_file=partial(_write_repository_file, repo),
        commit_file=partial(_commit_repository_file, repo, register_file),
        describe=describe,
        conflict_bookmark=partial(_seed_fake_bookmark, state, path),
        origin_peer=OriginPeer(
            peer_repo,
            partial(
                _commit_repository_file,
                peer_repo,
                partial(_register_fake_file, state, peer_path),
            ),
            peer_push_main,
            lambda bookmark: state.remote_bookmark_targets(
                peer_path, bookmark=bookmark
            ),
        ),
        track_main=partial(_track_fake_main, state, path),
        after_push=partial(_install_fake_after_push, state, path),
        attempts=state.attempts,
        commands=None,
    )


def run_jj(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run jj in a disposable test repository with a fixed author identity."""
    environment = os.environ.copy()
    environment.update(JJ_USER="MM Tests", JJ_EMAIL="mm@example.invalid")
    return subprocess.run(
        ["jj", *arguments],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def _initialize_real_repository(tmp_path: Path) -> tuple[vcs.JjRepository, Path]:
    path = tmp_path / "real-repository"
    path.mkdir()
    assert run_jj(path, "git", "init", "--colocate").returncode == 0
    origin = tmp_path / "origin"
    initialized = run_jj(tmp_path, "git", "init", "--no-colocate", str(origin))
    assert initialized.returncode == 0, initialized.stderr
    origin_git = origin / ".jj" / "repo" / "store" / "git"
    added = run_jj(path, "git", "remote", "add", "origin", str(origin_git))
    assert added.returncode == 0, added.stderr
    (path / "dep.txt").write_text("version=1\n", encoding="utf-8")
    assert run_jj(path, "commit", "-m", "baseline").returncode == 0
    assert run_jj(path, "bookmark", "create", "main", "-r", "@-").returncode == 0
    return vcs.JjRepository(path), origin_git


def _install_real_postcheck_interceptor(
    path: Path,
    monkeypatch: pytest.MonkeyPatch | None,
    pending_after_push: list[Callable[[], None]],
    commands: list[tuple[str, ...]],
) -> None:
    if monkeypatch is None:
        return
    captured_run = vcs.run_captured

    def intercept_push(command, cwd, **kwargs):
        commands.append(tuple(command))
        completed = captured_run(command, cwd, **kwargs)
        is_push = list(command)[1:3] == ["git", "push"]
        if is_push and pending_after_push and Path(cwd).resolve() == path.resolve():
            pending_after_push.pop(0)()
        return completed

    monkeypatch.setattr(vcs, "run_captured", intercept_push)


def _initialize_real_peer(tmp_path: Path, origin_git: Path) -> OriginPeer:
    peer_path = tmp_path / "origin-peer"
    peer_path.mkdir()
    assert run_jj(peer_path, "git", "init", "--colocate").returncode == 0
    added = run_jj(peer_path, "git", "remote", "add", "origin", str(origin_git))
    assert added.returncode == 0, added.stderr
    fetched = run_jj(peer_path, "git", "fetch", "--remote", "origin")
    assert fetched.returncode == 0, fetched.stderr
    created = run_jj(peer_path, "bookmark", "create", "main", "-r", "main@origin")
    assert created.returncode == 0, created.stderr
    tracked = run_jj(peer_path, "bookmark", "track", "main@origin")
    assert tracked.returncode == 0, tracked.stderr
    assert run_jj(peer_path, "new", "main").returncode == 0
    peer_repo = vcs.JjRepository(peer_path)

    def remote_bookmark_targets(bookmark: str) -> tuple[str, ...]:
        fetched = run_jj(peer_path, "git", "fetch", "--remote", "origin")
        assert fetched.returncode == 0, fetched.stderr
        result = run_jj(
            peer_path,
            "log",
            "-r",
            f"{bookmark}@origin",
            "--no-graph",
            "-T",
            'commit_id ++ "\\n"',
        )
        return () if result.returncode != 0 else (result.stdout.strip(),)

    return OriginPeer(
        peer_repo,
        partial(_commit_repository_file, peer_repo, _skip_file_registration),
        partial(_push_real_peer_main, peer_repo),
        remote_bookmark_targets,
    )


def _write_repository_file(
    repository: Repository, filename: str, content: str | None
) -> None:
    target = repository.path / filename
    if content is None:
        target.unlink(missing_ok=True)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _commit_repository_file(
    repository: Repository,
    register_file: Callable[[str], None],
    filename: str,
    content: str,
    message: str,
) -> str:
    register_file(filename)
    _write_repository_file(repository, filename, content)
    repository.commit(message=message)
    return repository.resolve_revision(revision="@-")


def _skip_file_registration(_filename: str) -> None:
    return None


def _push_real_peer_main(repository: Repository) -> None:
    repository.set_bookmark(bookmark="main", revision="@-")
    repository.push_bookmark(bookmark="main")


def _bind_real_repository(path: Path) -> Repository:
    inspected = run_jj(path, "workspace", "root")
    assert inspected.returncode == 0, f"unknown repository view: {path}"
    return vcs.JjRepository(path)


def _describe_real_repository(repository: Repository, message: str) -> None:
    result = run_jj(repository.path, "describe", "-m", message)
    assert result.returncode == 0, result.stderr


def _conflict_real_bookmark(
    repository: Repository, bookmark: str, left: str, right: str
) -> None:
    if bookmark == "main":
        untracked = run_jj(repository.path, "bookmark", "untrack", "main@origin")
        assert untracked.returncode == 0, untracked.stderr
    if repository.bookmark_exists(bookmark=bookmark):
        deleted = run_jj(repository.path, "bookmark", "delete", bookmark)
        assert deleted.returncode == 0, deleted.stderr
    operation = run_jj(
        repository.path, "op", "log", "--limit", "1", "--no-graph", "-T", "id"
    ).stdout.strip()
    created = run_jj(repository.path, "bookmark", "create", bookmark, "-r", left)
    assert created.returncode == 0, created.stderr
    conflicted = run_jj(
        repository.path,
        "--at-op",
        operation,
        "bookmark",
        "create",
        bookmark,
        "-r",
        right,
    )
    assert conflicted.returncode == 0, conflicted.stderr
    assert run_jj(repository.path, "bookmark", "list", bookmark).returncode == 0


def _register_fake_file(state: FakeJjState, path: Path, filename: str) -> None:
    state.register_files(path, filename)


def _seed_fake_bookmark(
    state: FakeJjState,
    path: Path,
    bookmark: str,
    *targets: str,
) -> None:
    state.seed_bookmark(path, bookmark=bookmark, targets=targets)


def _track_fake_main(state: FakeJjState, path: Path, enabled: bool) -> None:
    state.track_main(path, enabled=enabled)


def _install_fake_after_push(
    state: FakeJjState, path: Path, action: Callable[[], None]
) -> None:
    state.hook(
        "push_bookmark",
        phase="postcheck",
        action=action,
        path=path,
    )
