"""Literal terminal records, complete TSV records and stderr diagnostics."""

import os
import shutil
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from threading import Lock, Timer
from typing import Literal, TextIO

from cyclopts.help import HelpPanel, PlainFormatter
from rich.cells import cell_len
from rich.console import Console, ConsoleOptions
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

type Status = Literal["passed", "failed", "blocked", "skipped", "unchanged"]


def set_verbose(verbose: bool) -> None:
    """Set the current invocation's child-log policy."""
    _verbose.set(verbose)
    _last_heading.set(None)
    _consoles.set({})


def is_verbose() -> bool:
    return _verbose.get()


@contextmanager
def progress(message: str) -> Iterator[None]:
    """Show slow operations only on a stderr terminal; erase on completion."""
    if (
        not sys.stderr.isatty()
        or is_verbose()
        or os.environ.get("TERM", "dumb") == "dumb"
    ):
        yield
        return
    status = Live(
        Spinner("dots", text=literal(message), style="dim"),
        console=console(stderr=True),
        transient=True,
        redirect_stdout=False,
        redirect_stderr=False,
    )
    lock = Lock()
    finished = False

    def start() -> None:
        with lock:
            if not finished:
                status.start()

    timer = Timer(_PROGRESS_DELAY_SECONDS, start)
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
        with lock:
            finished = True
            status.stop()


def terminal() -> bool:
    return sys.stdout.isatty()


def console(*, stderr: bool = False) -> Console:
    stream = sys.stderr if stderr else sys.stdout
    cache = _consoles.get()
    if cache is None:
        cache = {}
        _consoles.set(cache)
    if stderr in cache and cache[stderr][0] is stream:
        return cache[stderr][1]
    try:
        size = os.get_terminal_size(stream.fileno())
    except OSError, ValueError:
        size = shutil.get_terminal_size()
    colour = (
        stream.isatty()
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM", "dumb") != "dumb"
    )
    screen = Console(
        file=stream,
        width=size.columns,
        height=size.lines,
        color_system="standard" if colour else None,
        force_terminal=stream.isatty(),
        markup=False,
        highlight=False,
        emoji=False,
    )
    cache[stderr] = (stream, screen)
    return screen


def literal(value: str, style: str = "") -> Text:
    """Render data without interpreting markup or terminal controls."""
    return Text(_escape(value.expandtabs(), backslash=False), style=style)


def heading(name: str, metadata: str = "") -> None:
    if terminal():
        previous = _last_heading.get()
        if previous is not None and previous[0] is sys.stdout:
            if previous[1] == name and not metadata:
                return
            console().print()
        _last_heading.set((sys.stdout, name))
        text = literal(name, "bold")
        if metadata:
            text.append_text(literal(f" · {metadata}", "dim"))
        console().print(text, overflow="ellipsis", no_wrap=True)


def records(
    group: str,
    headers: Sequence[str],
    rows: Sequence[Sequence[str | Text]],
    *,
    pipe_rows: Sequence[Sequence[str]],
    footer: str = "",
) -> None:
    """Terminal omission never changes the independently supplied pipe fields."""
    if not terminal():
        for row in pipe_rows:
            sys.stdout.write(
                "\t".join(_escape(field) for field in (group, *row)) + "\n"
            )
        return
    if not rows:
        return
    cells = [
        [literal(value) if isinstance(value, str) else value.copy() for value in row]
        for row in rows
    ]
    widths = [
        max(
            cell_len(headers[index]) if headers else 0,
            *(row[index].cell_len for row in cells),
        )
        for index in range(len(cells[0]))
    ]
    screen = console()
    budget = max(1, screen.width - 2 - 2 * (len(widths) - 1))
    widths = [min(width, 24) for width in widths[:-1]] + [widths[-1]]
    for index in reversed(range(len(widths))):
        widths[index] = max(1, widths[index] - max(0, sum(widths) - budget))
    if headers:
        cells.insert(0, [literal(header, "dim") for header in headers])
    for row in cells:
        line = Text("  ")
        for index, (cell, width) in enumerate(zip(row, widths, strict=True)):
            cell.truncate(width, overflow="ellipsis", pad=index < len(widths) - 1)
            if index:
                line.append("  ")
            line.append_text(cell)
        screen.print(line, overflow="ellipsis", no_wrap=True)
    if footer:
        screen.print(literal(footer, "dim"))


def project_records(
    headers: Sequence[str],
    rows: Sequence[Sequence[str | Text]],
    pipe_rows: Sequence[Sequence[str]],
    *,
    footer: str = "",
) -> None:
    """Project is already the first field of overview records."""
    if terminal():
        records("", headers, rows, pipe_rows=(), footer=footer)
    else:
        for row in pipe_rows:
            sys.stdout.write("\t".join(_escape(field) for field in row) + "\n")


def outcome(
    project: str,
    operation: str,
    status: Status,
    subject: str,
    *,
    installed: str = "-",
    target: str = "-",
    reason: str = "",
) -> None:
    symbol, style = _STATES[status]
    versions = f"{installed} → {target}" if installed != "-" or target != "-" else ""
    text = Text("  ")
    text.append(f"{symbol} {status:<9}", style=style)
    subject_width = 24 if console().width >= 80 and (versions or reason) else 0
    text.append_text(literal(f"{subject:<{subject_width}}"))
    if versions or reason:
        text.append("  ")
    if versions:
        version_width = 20 if console().width >= 80 and reason else 0
        text.append_text(literal(f"{versions:<{version_width}}"))
        if reason:
            text.append("  ")
    text.append_text(literal(reason, "dim"))
    if terminal():
        console().print(text, overflow="ellipsis", no_wrap=True)
    else:
        records(
            project,
            (),
            (),
            pipe_rows=[(operation, status, subject, installed, target, reason or "-")],
        )


def diagnostic(kind: Literal["error", "warning", "hint"], message: str) -> None:
    style = {"error": "red", "warning": "yellow", "hint": "bold"}[kind]
    text = Text(f"{kind}: ", style=style)
    text.append_text(literal(message, "default"))
    console(stderr=True).print(text, soft_wrap=True)


def notice(message: str) -> None:
    console(stderr=True).print(literal(message, "dim"), soft_wrap=True)


def summary[State: str](counts: Mapping[State, int]) -> None:
    """Print bold totals with plain state words on stderr; totals are status."""
    text = Text()
    for state, count in counts.items():
        if text:
            text.append(" · ", style="dim")
        text.append(str(count), style="bold")
        text.append_text(literal(f" {state}"))
    console(stderr=True).print(text, soft_wrap=True)


def prompt(message: str, *, default: str) -> str:
    console(stderr=True).print(
        literal(f"{message} ({default}): "), end="", soft_wrap=True
    )
    reply = sys.stdin.readline()
    if not reply:
        raise EOFError("Input closed before a selection was made")
    return reply.strip() or default


def timestamp(value: datetime | None) -> str:
    if value is None:
        return "-"
    if not terminal():
        return value.isoformat()
    return relative_time(value)


def relative_time(value: datetime, now: datetime | None = None) -> str:
    """Use short relative timestamps for terminal metadata."""
    seconds = int(((now or datetime.now(timezone.utc)) - value).total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _escape(value: str, *, backslash: bool = True) -> str:
    escapes = {"\t": "\\t", "\n": "\\n", "\r": "\\r"}
    if backslash:
        escapes["\\"] = "\\\\"
    return "".join(
        escapes.get(
            char,
            f"\\x{ord(char):02x}"
            if ord(char) < 32 or 127 <= ord(char) <= 159
            else f"\\u{ord(char):04x}"
            if char in "\u2028\u2029"
            else char,
        )
        for char in value
    )


class HelpFormatter(PlainFormatter):
    """Keep command aliases on the same line as their shared description."""

    def __call__(
        self, console: Console, options: ConsoleOptions, panel: HelpPanel
    ) -> None:
        if panel.format == "command":
            panel = panel.copy(
                entries=[
                    entry.copy(positive_names=(", ".join(entry.positive_names),))
                    if entry.positive_names
                    else entry
                    for entry in panel.entries
                ]
            )
        super().__call__(console, options, panel)


_consoles: ContextVar[dict[bool, tuple[TextIO, Console]] | None] = ContextVar(
    "mm_consoles", default=None
)
_last_heading: ContextVar[tuple[TextIO, str] | None] = ContextVar(
    "mm_heading", default=None
)
_verbose: ContextVar[bool] = ContextVar("mm_verbose", default=False)
_PROGRESS_DELAY_SECONDS = 0.5
_STATES: dict[Status, tuple[str, str]] = {
    "passed": ("✓", "green"),
    "failed": ("✗", "red"),
    "blocked": ("!", "yellow"),
    "skipped": ("○", "dim"),
    "unchanged": ("○", "dim"),
}
