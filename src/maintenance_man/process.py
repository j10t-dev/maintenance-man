"""Run maintenance commands with quiet success and single-owner failure logs."""

import codecs
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryFile
from typing import BinaryIO

from maintenance_man import output

_TERMINATION_GRACE_SECONDS = 2
_LOG_POLL_SECONDS = 0.05


def run_logged(
    args: str | Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    env: Mapping[str, str] | None = None,
    shell: bool = False,
    stdin: int | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Follow child logs until command exit; background descendants keep running.

    The child shares mm's terminal and process group, so its prompts, Ctrl-C
    and Ctrl-Z behave as they would for the command run directly.
    """
    verbose = output.is_verbose()
    label = args if isinstance(args, str) else " ".join(args)
    with TemporaryFile() as stdout, TemporaryFile() as stderr:
        logs = [_Log(stdout), _Log(stderr)]
        with subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            shell=shell,
            executable="/bin/bash" if shell else None,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        ) as child:
            interrupted = False
            try:
                with (
                    nullcontext()
                    if _child_may_prompt(stdin)
                    else output.progress(f"Running {label}")
                ):
                    _wait(child, timeout, logs if verbose else [])
            except subprocess.TimeoutExpired, KeyboardInterrupt:
                interrupted = True
                _terminate(child)
                raise
            finally:
                if verbose or child.returncode or interrupted:
                    for log in logs:
                        log.forward(final=True)
            return subprocess.CompletedProcess(
                args,
                child.returncode,
                _read(stdout) if capture else "",
                _read(stderr) if capture else "",
            )


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
