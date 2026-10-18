import shlex
import subprocess
from pathlib import Path

import pytest

from maintenance_man import vcs
from tests.fakes import FakeCommands
from tests.support.process import completed


@pytest.mark.parametrize("existing", [False, True], ids=["absent", "existing"])
def test_assert_safe_workspace_path_accepts_direct_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
) -> None:
    root = vcs.paths.workspaces_dir()
    root.mkdir(parents=True)
    child = root / "project"
    if existing:
        child.mkdir()

    assert vcs.assert_safe_workspace_path(child) == child.resolve()


@pytest.mark.parametrize("location", ["root", "outside", "nested"])
def test_assert_safe_workspace_path_rejects_unsafe_locations_without_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    root = vcs.paths.workspaces_dir()
    root.mkdir(parents=True)
    targets = {
        "root": root,
        "outside": tmp_path / "outside",
        "nested": root / "project" / "nested",
    }
    target = targets[location]
    target.mkdir(parents=True, exist_ok=True)
    marker = target / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="not a project workspace directly under"):
        vcs.assert_safe_workspace_path(target)

    assert marker.read_text(encoding="utf-8") == "keep"


def _resolve_command(revision: str, *, read_only: bool = False) -> tuple[str, ...]:
    prefix = ("--ignore-working-copy", "--color", "never") if read_only else ()
    return (
        "jj",
        *prefix,
        "log",
        "-r",
        revision,
        "--no-graph",
        "-T",
        'commit_id ++ "\\n"',
    )


def _file_list_command(commit_id: str, filename: str) -> tuple[str, ...]:
    return (
        "jj",
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
    )


def _revision_file_commands(tmp_path: Path, listing: str) -> FakeCommands:
    commands = FakeCommands()
    commands.add(
        _resolve_command("main", read_only=True),
        cwd=tmp_path,
        result=completed(stdout="a" * 40 + "\n"),
    )
    commands.add(
        _file_list_command("a" * 40, "dep.txt"),
        cwd=tmp_path,
        result=completed(stdout=listing),
    )
    return commands


class TestJjRepositoryBoundary:
    def test_command_launch_failure_is_a_revision_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        failure = FileNotFoundError(2, "No such file or directory", "jj")
        error = vcs.RevisionError("Could not run jj")
        error.__cause__ = failure
        commands = FakeCommands()
        commands.add(
            (
                "jj",
                "--ignore-working-copy",
                "--color",
                "never",
                "bookmark",
                "list",
                "-T",
                'if(remote == "origin" || !present, "", name ++ "\\n")',
                "main",
            ),
            cwd=tmp_path,
            result=error,
        )
        monkeypatch.setattr(vcs, "run_captured", commands)
        with pytest.raises(vcs.RevisionError, match="Could not run jj") as caught:
            vcs.JjRepository(tmp_path).bookmark_exists(bookmark="main")
        assert caught.value.__cause__ is failure
        ((actual_argv, cwd, kwargs),) = commands.calls
        assert actual_argv == (
            "jj",
            "--ignore-working-copy",
            "--color",
            "never",
            "bookmark",
            "list",
            "-T",
            'if(remote == "origin" || !present, "", name ++ "\\n")',
            "main",
        )
        assert cwd == tmp_path
        assert kwargs == {
            "timeout": 30,
            "label": shlex.join(actual_argv),
            "error": vcs.RevisionError,
        }

    @pytest.mark.parametrize(
        ("stdout", "message"),
        [
            ("", "exactly one"),
            (f"{'a' * 40}\n{'b' * 40}\n", "exactly one"),
            ("not-a-commit\n", "malformed commit identity"),
            (f"{'A' * 40}\n", "malformed commit identity"),
        ],
    )
    def test_resolve_revision_rejects_invalid_identity(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        stdout: str,
        message: str,
    ):
        commands = FakeCommands()
        commands.add(
            ("jj", "log", "-r", "main", "--no-graph", "-T", 'commit_id ++ "\\n"'),
            cwd=tmp_path,
            result=completed(stdout=stdout),
        )
        monkeypatch.setattr(vcs, "run_captured", commands)
        with pytest.raises(vcs.RevisionError, match=message):
            vcs.JjRepository(tmp_path).resolve_revision(revision="main")

    @pytest.mark.parametrize("listing", ["file\nfile\n", "unknown\n", "\nfile\n"])
    def test_revision_file_rejects_malformed_listing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        listing: str,
    ):
        commands = _revision_file_commands(tmp_path, listing)
        monkeypatch.setattr(vcs, "run_captured", commands)
        with pytest.raises(vcs.RevisionError, match="Unexpected revision file listing"):
            vcs.JjRepository(tmp_path).revision_file(
                revision="main", filename="dep.txt"
            )

    @pytest.mark.parametrize(
        ("listing", "regular"),
        [
            ("", False),
            ("file\n", True),
            ("symlink\n", False),
            ("tree\n", False),
            ("conflict\n", False),
        ],
    )
    def test_revision_file_distinguishes_absence_and_regular_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        listing: str,
        regular: bool,
    ):
        commands = _revision_file_commands(tmp_path, listing)
        monkeypatch.setattr(vcs, "run_captured", commands)
        assert vcs.JjRepository(tmp_path).revision_file(
            revision="main", filename="dep.txt"
        ) == (vcs.RevisionFile(commit_id="a" * 40, is_regular=regular))

    @pytest.mark.parametrize("phase", ["resolve", "list"])
    @pytest.mark.parametrize("failure", ["rejected", "launch", "timeout"])
    def test_revision_file_inspection_failures_are_typed_not_absence(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        phase: str,
        failure: str,
    ):
        raised: BaseException | None = None
        commands = FakeCommands()
        resolve_command = _resolve_command("main", read_only=True)
        list_command = _file_list_command("a" * 40, "local.properties")
        if failure == "rejected":
            failed: subprocess.CompletedProcess[str] | BaseException = (
                vcs.RevisionError("jj file list failed (exit 1): file")
            )
        elif failure == "launch":
            raised = FileNotFoundError(2, "No such file or directory", "jj")
            failed = vcs.RevisionError("Could not run jj")
            failed.__cause__ = raised
        else:
            raised = subprocess.TimeoutExpired(
                list(resolve_command if phase == "resolve" else list_command), 30
            )
            failed = vcs.RevisionError("jj command timed out")
            failed.__cause__ = raised
        commands.add(
            resolve_command,
            cwd=tmp_path,
            result=failed if phase == "resolve" else completed(stdout="a" * 40 + "\n"),
        )
        if phase == "list":
            commands.add(list_command, cwd=tmp_path, result=failed)
        monkeypatch.setattr(vcs, "run_captured", commands)

        with pytest.raises(vcs.RevisionError) as caught:
            vcs.JjRepository(tmp_path).revision_file(
                revision="main", filename="local.properties"
            )

        expected = {
            "rejected": "failed (exit 1): file",
            "launch": "Could not run",
            "timeout": "timed out",
        }
        assert expected[failure] in str(caught.value)
        assert len(commands.calls) == (1 if phase == "resolve" else 2)
        if raised is not None:
            assert caught.value.__cause__ is raised

    @pytest.mark.parametrize(
        ("main_only", "arguments"),
        [
            (False, ["git", "fetch", "--remote", "origin"]),
            (True, ["git", "fetch", "--remote", "origin", "--branch", "main"]),
        ],
    )
    def test_fetch_uses_origin_and_remote_timeout(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        main_only: bool,
        arguments: list[str],
    ):
        repo = vcs.JjRepository(tmp_path)
        calls: list[tuple[list[str], int]] = []

        def run(command: list[str], *, timeout: int = 30):
            calls.append((command, timeout))
            return completed()

        monkeypatch.setattr(repo, "_run", run)
        repo.fetch(main_only=main_only)
        assert calls == [(arguments, 120)]
