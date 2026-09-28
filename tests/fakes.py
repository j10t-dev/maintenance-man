from __future__ import annotations

import subprocess
from collections import defaultdict, deque
from pathlib import Path
from typing import Any


class FakeCommands:
    """Route command calls to exact, preconfigured command and cwd outcomes."""

    def __init__(self) -> None:
        self._outcomes: dict[
            tuple[tuple[str, ...], Path],
            deque[subprocess.CompletedProcess[str] | BaseException],
        ] = defaultdict(deque)
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, Any]]] = []

    def add(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        result: subprocess.CompletedProcess[str] | BaseException,
    ) -> None:
        self._outcomes[(argv, cwd)].append(result)

    def __call__(
        self, cmd: list[str] | tuple[str, ...], cwd: Path, **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        argv = tuple(cmd)
        key = (argv, cwd)
        self.calls.append((argv, cwd, kwargs))
        outcomes = self._outcomes.get(key)
        if not outcomes:
            raise AssertionError(f"Unconfigured command: {argv!r} in {cwd}")
        result = outcomes.popleft()
        if isinstance(result, BaseException):
            raise result
        return result
