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

from maintenance_man import paths
from maintenance_man.models.scan import WORKFLOW_BOOKMARKS
from maintenance_man.process import run_captured

JJ_INSTALL_HINT = "Install it from https://jj-vcs.github.io/jj/"
GH_INSTALL_HINT = "Install it from https://cli.github.com/"


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


def workspace_path_for_project(project: str) -> Path:
    return paths.project_file(paths.workspaces_dir(), project)


def _guarded_tip(source_bookmark: str, expected_base: str, expected_tip: str) -> str:
    if source_bookmark not in tuple(WORKFLOW_BOOKMARKS.values()):
        raise RevisionError("Unexpected managed Gradle bookmark")
    if not all(
        re.fullmatch(r"[0-9a-f]{40,64}", value)
        for value in (expected_base, expected_tip)
    ):
        raise RevisionError("Invalid expected revision identity")
    base = f"exactly(exactly(main, 1) & {expected_base}, 1)"
    tip = f"exactly(exactly({source_bookmark}, 1) & {expected_tip}, 1)"
    return f"exactly(({base})::({tip}) & ({tip}), 1)"


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
                'if(remote == "origin" || !present, "", name ++ "\\n")',
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
                'if(remote == "origin" || !present, "", name ++ "\\n")',
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
