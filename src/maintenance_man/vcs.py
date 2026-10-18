import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from maintenance_man import paths
from maintenance_man.process import run_captured

JJ_INSTALL_HINT = "Install it from https://jj-vcs.github.io/jj/"


class RevisionError(Exception):
    """A jj command could not run, or a revision could not be resolved."""


_READ_ONLY = ("--ignore-working-copy", "--color", "never")


@dataclass(frozen=True, slots=True)
class RevisionFile:
    commit_id: str
    is_regular: bool


class Repository(Protocol):
    @property
    def path(self) -> Path: ...

    def bookmark_exists(self, *, bookmark: str) -> bool: ...
    def bookmark_conflicted(self, *, bookmark: str) -> bool: ...
    def resolve_revision(self, *, revision: str, read_only: bool = False) -> str: ...
    def revision_file(self, *, revision: str, filename: str) -> RevisionFile: ...
    def same_revision(self, *, left: str, right: str) -> bool: ...
    def is_ancestor(self, *, ancestor: str, descendant: str) -> bool: ...
    def revision_bookmarks(self, *, revision: str) -> tuple[str, ...]: ...
    def change_id(self, *, revision: str = "@") -> str: ...
    def is_blank_working_copy(self) -> bool: ...
    def has_changes(self) -> bool: ...
    def create_bookmark(self, *, bookmark: str, revision: str) -> None: ...
    def set_bookmark(self, *, bookmark: str, revision: str) -> None: ...
    def delete_bookmark(self, *, bookmark: str) -> None: ...
    def new_change(self, *, revision: str) -> None: ...
    def commit(self, *, message: str) -> None: ...
    def discard(self) -> None: ...
    def rebase_working_copy(self, *, revision: str) -> None: ...
    def promote_bookmark_to_main(self, *, bookmark: str) -> None: ...
    def fetch(self, *, main_only: bool = False) -> None: ...
    def push_bookmark(self, *, bookmark: str) -> None: ...
    def workspace_names(self) -> frozenset[str]: ...
    def add_workspace(self, *, name: str, path: Path, revision: str) -> None: ...
    def forget_workspace(self, *, name: str) -> None: ...


def workspace_path_for_project(project: str) -> Path:
    return paths.project_file(paths.workspaces_dir(), project)


def assert_safe_workspace_path(path: Path) -> Path:
    if path.is_symlink():
        msg = f"refusing to remove symlink workspace path: {path}"
        raise ValueError(msg)

    root = paths.workspaces_dir().resolve()
    target = path.resolve()
    if target.parent != root:
        msg = (
            f"refusing to remove {target}: "
            f"not a project workspace directly under {root}"
        )
        raise ValueError(msg)
    return target


_COMMIT_ID = re.compile(r"[0-9a-f]{40,64}")


def _lines(stdout: str) -> list[str]:
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def _one_line(output: str, *, subject: str) -> str:
    lines = _lines(output)
    if len(lines) != 1:
        msg = f"{subject} must resolve to exactly one value, got {len(lines)}"
        raise RevisionError(msg)
    return lines[0]


def _exact_commit(output: str, *, revision: str) -> str:
    commit_id = _one_line(output, subject=revision)
    if _COMMIT_ID.fullmatch(commit_id) is None:
        msg = f"{revision} returned a malformed commit identity"
        raise RevisionError(msg)
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
        command = ["jj", *arguments]
        return run_captured(
            command,
            self.path,
            timeout=timeout,
            label=shlex.join(command),
            error=RevisionError,
        )

    def _log(self, revision: str, template: str, *, read_only: bool = False) -> str:
        """Render *template* for each commit in *revision*; returns jj's stdout."""
        prefix = _READ_ONLY if read_only else ()
        return self._run(
            [*prefix, "log", "-r", revision, "--no-graph", "-T", template]
        ).stdout

    def bookmark_exists(self, *, bookmark: str) -> bool:
        result = self._run(
            [
                *_READ_ONLY,
                "bookmark",
                "list",
                "-T",
                'if(remote == "origin" || !present, "", name ++ "\\n")',
                bookmark,
            ]
        )
        listed = _lines(result.stdout)
        if any(name != bookmark for name in listed):
            msg = f"Unexpected bookmark listing for {bookmark}"
            raise RevisionError(msg)
        return bool(listed)

    def bookmark_conflicted(self, *, bookmark: str) -> bool:
        result = self._run(
            [
                *_READ_ONLY,
                "bookmark",
                "list",
                "-T",
                'if(!remote && present, conflict ++ "\\n", "")',
                bookmark,
            ]
        )
        states = _lines(result.stdout)
        if not states:
            msg = f"Cannot inspect bookmark conflict for {bookmark}"
            raise RevisionError(msg)
        if states not in (["false"], ["true"]):
            msg = f"Unexpected bookmark conflict state for {bookmark}"
            raise RevisionError(msg)
        return states == ["true"]

    def resolve_revision(self, *, revision: str, read_only: bool = False) -> str:
        output = self._log(revision, 'commit_id ++ "\\n"', read_only=read_only)
        return _exact_commit(output, revision=revision)

    def revision_file(self, *, revision: str, filename: str) -> RevisionFile:
        commit_id = self.resolve_revision(revision=revision, read_only=True)
        result = self._run(
            [
                *_READ_ONLY,
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
            msg = "Unexpected revision file listing"
            raise RevisionError(msg)
        return RevisionFile(commit_id=commit_id, is_regular=kinds == ["file"])

    def same_revision(self, *, left: str, right: str) -> bool:
        return self.resolve_revision(revision=left) == self.resolve_revision(
            revision=right
        )

    def is_ancestor(self, *, ancestor: str, descendant: str) -> bool:
        ancestor_id = self.resolve_revision(revision=ancestor)
        descendant_id = self.resolve_revision(revision=descendant)
        output = self._log(
            f"{ancestor_id}::{descendant_id} & {descendant_id}", 'commit_id ++ "\\n"'
        )
        values = _lines(output)
        if values not in ([], [descendant_id]):
            msg = "Unexpected ancestry result"
            raise RevisionError(msg)
        return bool(values)

    def revision_bookmarks(self, *, revision: str) -> tuple[str, ...]:
        commit_id = self.resolve_revision(revision=revision)
        output = self._log(
            commit_id,
            "bookmarks.filter(|bookmark| !bookmark.remote()"
            ' || bookmark.remote() == "git")'
            '.map(|bookmark| bookmark.name()).join("\\n") ++ "\\n"',
        )
        return tuple(dict.fromkeys(_lines(output)))

    def change_id(self, *, revision: str = "@") -> str:
        output = self._log(revision, 'change_id ++ "\\n"')
        return _one_line(output, subject=f"change id for {revision}")

    def is_blank_working_copy(self) -> bool:
        """Whether the working-copy change has no edits, description or bookmarks."""
        return (
            not self.has_changes()
            and not self._log("@", "description").rstrip("\n")
            and not self.revision_bookmarks(revision="@")
        )

    def has_changes(self) -> bool:
        return bool(self._run(["diff", "--summary"]).stdout.strip())

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

    def promote_bookmark_to_main(self, *, bookmark: str) -> None:
        self._run(["bookmark", "set", "main", "-r", bookmark])

    def fetch(self, *, main_only: bool = False) -> None:
        arguments = ["git", "fetch", "--remote", "origin"]
        if main_only:
            arguments.extend(["--branch", "main"])
        self._run(arguments, timeout=120)

    def push_bookmark(self, *, bookmark: str) -> None:
        self._run(
            ["git", "push", "--bookmark", bookmark, "--remote", "origin"], timeout=120
        )

    def workspace_names(self) -> frozenset[str]:
        result = self._run(["workspace", "list", "-T", 'name ++ "\\n"'])
        names = _lines(result.stdout)
        if len(names) != len(set(names)):
            msg = "Unexpected duplicate workspace listing"
            raise RevisionError(msg)
        return frozenset(names)

    def add_workspace(self, *, name: str, path: Path, revision: str) -> None:
        self._run(["workspace", "add", "--name", name, str(path), "-r", revision])

    def forget_workspace(self, *, name: str) -> None:
        self._run(["workspace", "forget", name])
