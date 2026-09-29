"""Run external commands with one set of execution and failure rules."""

import shutil
import subprocess
from collections.abc import Collection, Sequence
from pathlib import Path

from maintenance_man.env import project_env

_DIAGNOSTIC_CHARS = 2000


class ProcessError(Exception):
    """A command could not run, timed out, or exited with a rejected status."""


class ToolNotFoundError(Exception):
    """A required executable is not on the isolated PATH."""


def require_tool(name: str, hint: str) -> Path:
    """Return the executable that isolated commands would run, or raise."""
    found = shutil.which(name, path=project_env().get("PATH"))
    if found is None:
        msg = f"{name} is not installed or not on PATH. {hint}"
        raise ToolNotFoundError(msg)
    return Path(found).absolute()


def _where(cwd: str | Path | None) -> str:
    return f" in {cwd}" if cwd is not None else ""


def run_captured(
    cmd: Sequence[str],
    cwd: str | Path | None,
    *,
    timeout: int,
    label: str,
    error: type[Exception] = ProcessError,
    ok_codes: Collection[int] | None = frozenset({0}),
) -> subprocess.CompletedProcess[str]:
    """Run *cmd* without a shell, capturing text output with stdin closed.

    ``ok_codes=None`` returns every completed status to the caller.
    """
    try:
        completed = subprocess.run(
            list(cmd),
            cwd=cwd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            env=project_env(),
        )
    except subprocess.TimeoutExpired as exc:
        msg = f"{label} timed out after {timeout}s{_where(cwd)}"
        raise error(msg) from exc
    except (OSError, UnicodeDecodeError) as exc:
        msg = f"Could not run {label}{_where(cwd)}: {exc}"
        raise error(msg) from exc
    if ok_codes is not None and completed.returncode not in ok_codes:
        detail = (completed.stderr or "").strip() or (completed.stdout or "").strip()
        message = f"{label} failed (exit {completed.returncode})"
        raise error(f"{message}: {detail[-_DIAGNOSTIC_CHARS:]}" if detail else message)
    return completed


def run_live(
    command: str,
    cwd: str | Path,
    *,
    timeout: int,
    label: str,
    error: type[Exception] = ProcessError,
) -> None:
    """Run a configured command string through Bash with inherited streams."""
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            shell=True,
            executable="/bin/bash",
            timeout=timeout,
            env=project_env(),
        )
    except subprocess.TimeoutExpired as exc:
        msg = f"{label} timed out after {timeout}s{_where(cwd)}"
        raise error(msg) from exc
    except OSError as exc:
        msg = f"Could not run {label}{_where(cwd)}: {exc}"
        raise error(msg) from exc
    if completed.returncode != 0:
        msg = f"{label} failed (exit {completed.returncode})"
        raise error(msg)
