from __future__ import annotations

from pathlib import Path
from typing import Literal

import pytest

from maintenance_man import github
from maintenance_man.github import CodeHostError, GitHubCodeHost
from tests.conftest import completed


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
        return completed(stdout=stdout)

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


def test_create_pr_returns_stripped_output_and_uses_guarded_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list[str], Path, dict[str, object]]] = []

    def run(command, cwd, **kwargs):
        calls.append((list(command), Path(cwd), kwargs))
        return completed(stdout=" https://example.invalid/pr/1 \n")

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
        lambda *_args, **_kwargs: completed(
            returncode=1, stderr="a pull request already EXISTS for this branch"
        ),
    )

    assert GitHubCodeHost(tmp_path).create_pr(bookmark="mm/update-dependencies") == (
        "PR already exists for mm/update-dependencies"
    )


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("permission denied", "gh pr create failed (exit 2): permission denied"),
        ("x" * 500 + "y" * 2000, "gh pr create failed (exit 2): " + "y" * 2000),
    ],
)
def test_given_failed_pr_creation_when_create_pr_runs_then_shared_message_is_raised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stderr: str,
    expected: str,
) -> None:
    monkeypatch.setattr(
        github,
        "run_captured",
        lambda *_args, **_kwargs: completed(returncode=2, stderr=stderr),
    )

    with pytest.raises(CodeHostError) as caught:
        GitHubCodeHost(tmp_path).create_pr(bookmark="mm/update-dependencies")

    assert str(caught.value) == expected
