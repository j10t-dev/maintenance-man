"""Run external commands with one set of execution and failure rules."""

import codecs
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Collection, Sequence
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryFile
from typing import BinaryIO

from maintenance_man import output
from maintenance_man.env import project_env

_DIAGNOSTIC_CHARS = 2000
_TERMINATION_GRACE_SECONDS = 2
_LOG_POLL_SECONDS = 0.05


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


def rejected_status_message(
    label: str, completed: subprocess.CompletedProcess[str]
) -> str:
    """Describe a rejected process status with a bounded diagnostic."""
    detail = completed.stderr.strip() or completed.stdout.strip()
    message = f"{label} failed (exit {completed.returncode})"
    return f"{message}: {detail[-_DIAGNOSTIC_CHARS:]}" if detail else message


def run_logged(
    cmd: str | Sequence[str],
    cwd: str | Path,
    *,
    timeout: int,
    label: str,
    error: type[Exception] = ProcessError,
    shell: bool = False,
    stdin: int | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run *cmd* with its logs hidden on success and replayed on stderr on failure.

    When output is verbose the logs stream to stderr while the child runs.  Child
    output never enters the raised error.  ``stdin=None`` inherits mm's stdin.
    Quiet mode writes the child's stdout and stderr to temporary files, so a
    prompt written to either stream stays hidden until the command ends; only a
    prompt that opens ``/dev/tty`` appears.  Ctrl-C still reaches the child.
    Interactive scripts should run with ``--verbose`` or prompt on ``/dev/tty``.
    ``capture=True`` also returns the two streams for the caller to parse.
    """
    with TemporaryFile() as stdout, TemporaryFile() as stderr:
        try:
            child = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=project_env(),
                shell=shell,
                executable="/bin/bash" if shell else None,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
            )
        except OSError as exc:
            msg = f"Could not run {label}{_where(cwd)}: {exc}"
            raise error(msg) from exc
        try:
            returncode = _follow(child, (stdout, stderr), timeout, label, stdin)
        except subprocess.TimeoutExpired as exc:
            msg = f"{label} timed out after {timeout}s{_where(cwd)}"
            raise error(msg) from exc
        captured = (_read(stdout), _read(stderr)) if capture else ("", "")
    if returncode != 0:
        msg = f"{label} failed (exit {returncode})"
        raise error(msg)
    return subprocess.CompletedProcess(cmd, returncode, *captured)


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
        raise error(rejected_status_message(label, completed))
    return completed


def run_live(
    command: str,
    cwd: str | Path,
    *,
    timeout: int,
    label: str,
    error: type[Exception] = ProcessError,
) -> None:
    """Run a configured command string through Bash; see :func:`run_logged`."""
    run_logged(command, cwd, timeout=timeout, label=label, error=error, shell=True)


def _follow(
    child: subprocess.Popen[bytes],
    logs: tuple[BinaryIO, BinaryIO],
    timeout: int,
    label: str,
    stdin: int | None,
) -> int:
    """Wait for the child, forwarding its logs live, or on failure and interruption."""
    verbose = output.is_verbose()
    followed = [_Log(stream) for stream in logs]
    with child:
        interrupted = False
        try:
            with (
                nullcontext()
                if _child_may_prompt(stdin)
                else output.progress(f"Running {label}")
            ):
                _wait(child, timeout, followed if verbose else [])
        except subprocess.TimeoutExpired, KeyboardInterrupt:
            interrupted = True
            _terminate(child)
            raise
        finally:
            if verbose or child.returncode or interrupted:
                for log in followed:
                    log.forward(final=True)
        return child.returncode


def _child_may_prompt(stdin: int | None) -> bool:
    """A spinner would overwrite a prompt the child writes to the terminal."""
    return stdin is None and sys.stdin.isatty()


def _wait(child: subprocess.Popen[bytes], timeout: float, logs: list[_Log]) -> None:
    if not logs:
        child.wait(timeout=timeout)
        return
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        try:
            child.wait(timeout=max(0, min(_LOG_POLL_SECONDS, remaining)))
        except subprocess.TimeoutExpired:
            if remaining <= 0:
                raise subprocess.TimeoutExpired(child.args, timeout) from None
        for log in logs:
            log.forward()
        if child.returncode is not None:
            return


def _terminate(child: subprocess.Popen[bytes]) -> None:
    """Let the running command clean up before escalating to SIGKILL."""
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def _read(stream: BinaryIO) -> str:
    return os.pread(stream.fileno(), os.fstat(stream.fileno()).st_size, 0).decode(
        "utf-8", errors="replace"
    )


class _Log:
    """Read a bounded snapshot without moving the child's shared file offset."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.position = 0
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def forward(self, *, final: bool = False) -> None:
        size = os.fstat(self.stream.fileno()).st_size
        while self.position < size:
            chunk = os.pread(
                self.stream.fileno(), min(65536, size - self.position), self.position
            )
            if not chunk:
                break
            self.position += len(chunk)
            sys.stderr.write(self.decoder.decode(chunk))
        if final:
            sys.stderr.write(self.decoder.decode(b"", final=True))
        sys.stderr.flush()
