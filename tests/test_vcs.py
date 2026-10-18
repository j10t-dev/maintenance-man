from pathlib import Path

import pytest

from maintenance_man import vcs
from tests.fakes import FakeCommands
from tests.support.process import completed


def test_given_jj_missing_from_path_when_inspected_then_revision_error_wraps_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))

    with pytest.raises(vcs.RevisionError) as raised:
        vcs.JjRepository(tmp_path).bookmark_exists(bookmark="main")

    assert isinstance(raised.value.__cause__, OSError)


def test_given_jj_command_when_run_then_timeout_label_and_error_class_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands = FakeCommands()
    argv = ("jj", "log", "-r", "main", "--no-graph", "-T", 'commit_id ++ "\\n"')
    commands.add(argv, cwd=tmp_path, result=completed(stdout=f"{'a' * 40}\n"))
    monkeypatch.setattr(vcs, "run_captured", commands)

    vcs.JjRepository(tmp_path).resolve_revision(revision="main")

    assert commands.calls == [
        (
            argv,
            tmp_path,
            {
                "timeout": 30,
                "label": "jj log -r main --no-graph -T 'commit_id ++ \"\\n\"'",
                "error": vcs.RevisionError,
            },
        )
    ]


class TestJjRepositoryBoundary:
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

    def test_fetch_uses_origin_and_remote_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        repo = vcs.JjRepository(tmp_path)
        calls: list[tuple[list[str], int]] = []

        def run(command: list[str], *, timeout: int = 30):
            calls.append((command, timeout))
            return completed()

        monkeypatch.setattr(repo, "_run", run)
        repo.fetch()
        assert calls == [
            (["git", "fetch", "--remote", "origin", "--branch", "main"], 120)
        ]
