from __future__ import annotations

import shlex
from pathlib import Path
from typing import Literal, Protocol

from maintenance_man.process import run_captured


class CodeHostError(Exception):
    """A code-host operation could not be completed."""


class CodeHost(Protocol):
    def pr_bookmarks(self, *, state: Literal["merged", "closed"]) -> frozenset[str]: ...

    def create_pr(self, *, bookmark: str) -> str: ...


class GitHubCodeHost:
    """A path-bound GitHub CLI adapter."""

    def __init__(self, path: Path):
        self._path = path

    def pr_bookmarks(self, *, state: Literal["merged", "closed"]) -> frozenset[str]:
        command = [
            "gh",
            "pr",
            "list",
            "--state",
            state,
            "--json",
            "headRefName",
            "--jq",
            ".[].headRefName",
        ]
        completed = run_captured(
            command,
            self._path,
            timeout=30,
            label=shlex.join(command),
            error=CodeHostError,
        )
        return frozenset(
            name.strip() for name in completed.stdout.splitlines() if name.strip()
        )

    def create_pr(self, *, bookmark: str) -> str:
        command = [
            "gh",
            "pr",
            "create",
            "--fill",
            "--head",
            bookmark,
            "--base",
            "main",
        ]
        completed = run_captured(
            command,
            self._path,
            timeout=60,
            label=shlex.join(command),
            error=CodeHostError,
            ok_codes=None,
        )
        if completed.returncode == 0:
            return completed.stdout.strip()
        if "already exists" in completed.stderr.lower():
            return f"PR already exists for {bookmark}"
        detail = completed.stderr.strip() or completed.stdout.strip()
        message = f"gh pr create failed (exit {completed.returncode})"
        raise CodeHostError(f"{message}: {detail}" if detail else message)
