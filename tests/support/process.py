"""Subprocess results and missing-tool responses for command tests."""

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from maintenance_man.process import ToolNotFoundError


def completed(
    argv: str | list[str] | tuple[str, ...] = (),
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    """Build a subprocess result without executing a command."""
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def missing_tool(tool: str) -> Callable[[str, str], Path]:
    """Return a tool lookup that fails only for the named executable."""

    def require(name: str, hint: str) -> Path:
        if name == tool:
            msg = f"{name} is not installed or not on PATH. {hint}"
            raise ToolNotFoundError(msg)
        return Path("/usr/bin") / name

    return require


def refuse_new_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test when anything starts a process; scanning, discovery, native
    preparation, build_command and pushes all need one."""

    def refuse(args, *_, **__):
        msg = f"unexpected process: {args!r}"
        raise AssertionError(msg)

    monkeypatch.setattr(subprocess, "Popen", refuse)
