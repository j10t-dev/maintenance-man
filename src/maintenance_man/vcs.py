import re
import shlex
import subprocess
from pathlib import Path

from maintenance_man import paths
from maintenance_man.process import run_captured

JJ_INSTALL_HINT = "Install it from https://jj-vcs.github.io/jj/"


class RevisionError(Exception):
    """A jj command could not run, or a revision could not be resolved."""


_READ_ONLY = ("--ignore-working-copy",)


def workspace_path_for_project(project: str) -> Path:
    return paths.project_file(paths.workspaces_dir(), project)


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
        command = ["jj", "--color", "never", *arguments]
        return run_captured(
            command,
            self.path,
            timeout=timeout,
            label=shlex.join(command),
            error=RevisionError,
        )

    def _log(self, revision: str, template: str) -> str:
        """Render *template* for each commit in *revision*; returns jj's stdout."""
        return self._run(["log", "-r", revision, "--no-graph", "-T", template]).stdout

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
        return bool(_lines(result.stdout))

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

    def resolve_revision(self, *, revision: str) -> str:
        output = self._log(revision, 'commit_id ++ "\\n"')
        return _exact_commit(output, revision=revision)

    def has_regular_file(self, *, revision: str, filename: str) -> bool:
        """Whether *filename* at the repository root is a regular file in *revision*.

        Reads without snapshotting the working copy. An absent path and a
        directory both list nothing, so neither counts. Raises RevisionError
        when *revision* names no commit or several.
        """
        listing = self._run(
            [
                *_READ_ONLY,
                "file",
                "list",
                "-r",
                revision,
                "-T",
                'file_type ++ "\\n"',
                f"root-file:{filename}",
            ]
        ).stdout
        return listing.splitlines() == ["file"]

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

    def set_bookmark(
        self, *, bookmark: str, revision: str, allow_backwards: bool = False
    ) -> None:
        """Create or move *bookmark* to *revision*.

        A backwards or sideways move needs *allow_backwards*.
        """
        backwards = ["--allow-backwards"] if allow_backwards else []
        self._run(["bookmark", "set", bookmark, "-r", revision, *backwards])

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

    def fetch(self) -> None:
        """Fetch main from origin."""
        self._run(
            ["git", "fetch", "--remote", "origin", "--branch", "main"], timeout=120
        )

    def push_bookmark(self, *, bookmark: str) -> None:
        self._run(
            ["git", "push", "--bookmark", bookmark, "--remote", "origin"], timeout=120
        )

    def workspace_names(self) -> frozenset[str]:
        result = self._run(["workspace", "list", "-T", 'name ++ "\\n"'])
        return frozenset(_lines(result.stdout))

    def add_workspace(self, *, name: str, path: Path, revision: str) -> None:
        self._run(["workspace", "add", "--name", name, str(path), "-r", revision])

    def forget_workspace(self, *, name: str) -> None:
        self._run(["workspace", "forget", name])
