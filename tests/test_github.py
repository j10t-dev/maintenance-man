from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Literal

import pytest

from maintenance_man import github, process
from maintenance_man.github import CodeHostError, GitHubCodeHost


def _completed(
    *, stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


@pytest.mark.parametrize(
    ("state", "stdout"),
    [
        ("merged", "mm/update-dependencies\nfeature/plain\n"),
        ("closed", "mm/resolve-vulnerabilities\nother\n"),
    ],
)
def test_pr_bookmarks_returns_every_head_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: Literal["merged", "closed"],
    stdout: str,
) -> None:
    calls: list[tuple[list[str], Path, dict[str, object]]] = []

    def run(command, cwd, **kwargs):
        calls.append((list(command), Path(cwd), kwargs))
        return _completed(stdout=stdout)

    monkeypatch.setattr(github, "run_captured", run)
    host = GitHubCodeHost(tmp_path)

    assert host.pr_bookmarks(state=state) == frozenset(stdout.splitlines())
    assert calls == [
        (
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
            tmp_path,
            {
                "timeout": 30,
                "label": (
                    f"gh pr list --state {state} --json headRefName "
                    "--jq '.[].headRefName'"
                ),
                "error": CodeHostError,
            },
        )
    ]


@pytest.mark.parametrize(
    "error",
    [
        CodeHostError("rejected status"),
        CodeHostError("launch failed"),
        CodeHostError("timed out"),
    ],
)
def test_pr_bookmarks_propagates_normalized_boundary_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: CodeHostError,
) -> None:
    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(github, "run_captured", fail)
    with pytest.raises(CodeHostError) as caught:
        GitHubCodeHost(tmp_path).pr_bookmarks(state="merged")
    assert caught.value is error


@pytest.mark.parametrize("failure", ["status", "launch", "timeout"])
def test_pr_bookmarks_normalizes_subprocess_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    def run(command, **kwargs):
        if failure == "status":
            return subprocess.CompletedProcess(command, 2, "", "host rejected")
        if failure == "launch":
            raise OSError("cannot launch")
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(process.subprocess, "run", run)

    with pytest.raises(CodeHostError):
        GitHubCodeHost(tmp_path).pr_bookmarks(state="merged")


def test_create_pr_returns_stripped_output_and_uses_guarded_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list[str], Path, dict[str, object]]] = []

    def run(command, cwd, **kwargs):
        calls.append((list(command), Path(cwd), kwargs))
        return _completed(stdout=" https://example.invalid/pr/1 \n")

    monkeypatch.setattr(github, "run_captured", run)

    assert (
        GitHubCodeHost(tmp_path).create_pr(bookmark="mm/update-dependencies")
        == "https://example.invalid/pr/1"
    )
    assert calls == [
        (
            [
                "gh",
                "pr",
                "create",
                "--fill",
                "--head",
                "mm/update-dependencies",
                "--base",
                "main",
            ],
            tmp_path,
            {
                "timeout": 60,
                "label": (
                    "gh pr create --fill --head mm/update-dependencies --base main"
                ),
                "error": CodeHostError,
                "ok_codes": None,
            },
        )
    ]


def test_create_pr_normalizes_existing_pr_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        github,
        "run_captured",
        lambda *_args, **_kwargs: _completed(
            returncode=1, stderr="a pull request already EXISTS for this branch"
        ),
    )

    assert GitHubCodeHost(tmp_path).create_pr(bookmark="mm/update-dependencies") == (
        "PR already exists for mm/update-dependencies"
    )


def test_create_pr_rejects_failed_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        github,
        "run_captured",
        lambda *_args, **_kwargs: _completed(returncode=2, stderr="permission denied"),
    )

    with pytest.raises(CodeHostError, match="permission denied"):
        GitHubCodeHost(tmp_path).create_pr(bookmark="mm/update-dependencies")
