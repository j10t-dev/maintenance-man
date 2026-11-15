"""Literal terminal records, complete TSV records and stderr diagnostics."""

import os
import shutil
import sys
import textwrap
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from threading import Timer
from typing import Literal, TextIO

from cyclopts.help import HelpEntry, HelpPanel, PlainFormatter
from rich.cells import cell_len, set_cell_size
from rich.console import Console, ConsoleOptions
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

from maintenance_man.clock import utc_now
from maintenance_man.models.events import Status

type Cell = str | Text
NARROW_TERMINAL_WIDTH = 70


def reset_invocation_output(*, verbose: bool) -> None:
    """Reset headings and consoles and set the invocation's child-log policy."""
    global _verbose, _last_heading
    _verbose = verbose
    _last_heading = None
    _consoles.clear()


def heading(name: str, metadata: str = "") -> None:
    global _last_heading
    if terminal():
        previous = _last_heading
        if previous is not None and previous[0] is sys.stdout:
            if previous[1] == name and not metadata:
                return
            console().print()
        _last_heading = (sys.stdout, name)
        text = literal(name, "bold")
        if metadata:
            text.append_text(literal(f" · {metadata}", "dim"))
        console().print(text, overflow="ellipsis", no_wrap=True)


def records(
    group: str,
    headers: Sequence[str],
    rows: Sequence[Sequence[Cell]],
    *,
    pipe_rows: Sequence[Sequence[str]],
    footer: str = "",
) -> None:
    """Terminal omission never changes the independently supplied pipe fields."""
    if not terminal():
        for row in pipe_rows:
            sys.stdout.write(_pipe_line((group, *row)))
        return
    if not rows:
        return
    cells = [
        [literal(value) if isinstance(value, str) else value.copy() for value in row]
        for row in rows
    ]
    widths = _column_widths(headers, cells)
    screen = console()
    budget = max(1, screen.width - _table_spacing(len(widths)))
    for index in reversed(range(len(widths))):
        widths[index] = max(1, widths[index] - max(0, sum(widths) - budget))
    if headers:
        cells.insert(0, [literal(header, "dim") for header in headers])
    for row in cells:
        line = Text(_TABLE_INDENT)
        for index, (cell, width) in enumerate(zip(row, widths, strict=True)):
            cell.truncate(width, overflow="ellipsis", pad=index < len(widths) - 1)
            if index:
                line.append(_COLUMN_SEPARATOR)
            line.append_text(cell)
        screen.print(line, overflow="ellipsis", no_wrap=True)
    if footer:
        screen.print(literal(footer, "dim"))


def _column_widths(headers: Sequence[str], rows: Sequence[Sequence[Text]]) -> list[int]:
    widths = [
        max(
            cell_len(headers[index]) if headers else 0,
            *(row[index].cell_len for row in rows),
        )
        for index in range(len(rows[0]))
    ]
    return [min(width, _MAX_FIXED_COLUMN_WIDTH) for width in widths[:-1]] + widths[-1:]


def _table_spacing(columns: int) -> int:
    return len(_TABLE_INDENT) + len(_COLUMN_SEPARATOR) * (columns - 1)


_TABLE_INDENT = "  "
_COLUMN_SEPARATOR = "  "
_MAX_FIXED_COLUMN_WIDTH = 24


def project_records(
    headers: Sequence[str],
    rows: Sequence[Sequence[Cell]],
    pipe_rows: Sequence[Sequence[str]],
    *,
    footer: str = "",
) -> None:
    """Project is already the first field of overview records."""
    if terminal():
        records("", headers, rows, pipe_rows=(), footer=footer)
    else:
        for row in pipe_rows:
            sys.stdout.write(_pipe_line(row))


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
    """Print one outcome; on a terminal it follows the project's heading."""
    if not terminal():
        sys.stdout.write(
            _pipe_line(
                (project, operation, status, subject, installed, target, reason or "-")
            )
        )
        return
    if project:
        heading(project)
    symbol, style = _STATES[status]
    versions = f"{installed} → {target}" if installed != "-" or target != "-" else ""
    text = Text("  ")
    text.append(f"{symbol} {status:<10}", style=style)
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
    console().print(text, overflow="ellipsis", no_wrap=True)


def choices(rows: Sequence[Sequence[str]]) -> None:
    """Print numbered selection rows on stderr; the last column wraps."""
    widths = [
        max(map(cell_len, column)) for column in list(zip(*rows, strict=True))[:-1]
    ]
    screen = console(stderr=True)
    for index, row in enumerate(rows, 1):
        cells = [
            set_cell_size(cell, width) for cell, width in zip(row, widths, strict=False)
        ]
        prefix = "  ".join([f"  {index:>3}", *cells, ""])
        indent = cell_len(prefix)
        wrapped = literal(row[-1]).wrap(screen, max(1, screen.width - indent))
        for number, text in enumerate(wrapped):
            line = literal(prefix if number == 0 else " " * indent)
            line.append_text(text)
            screen.print(line, soft_wrap=True)


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
        console(stderr=True).print()
        msg = "input closed before a selection was made"
        raise EOFError(msg)
    return reply.strip() or default


def is_verbose() -> bool:
    return _verbose


@contextmanager
def progress(message: str) -> Iterator[None]:
    """Show slow operations only on a stderr terminal; erase on completion."""
    if (
        not stderr_terminal()
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
    timer = Timer(_PROGRESS_DELAY_SECONDS, status.start)
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
        timer.join()
        status.stop()


def terminal() -> bool:
    return sys.stdout.isatty()


def stderr_terminal() -> bool:
    return sys.stderr.isatty()


def console(*, stderr: bool = False) -> Console:
    stream = sys.stderr if stderr else sys.stdout
    if stream in _consoles:
        return _consoles[stream]
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
    _consoles[stream] = screen
    return screen


def literal(value: str, style: str = "") -> Text:
    """Render data without interpreting markup or terminal controls."""
    return Text(value.expandtabs().translate(_TERMINAL_ESCAPES), style=style)


def timestamp(value: datetime | None) -> str:
    if value is None:
        return "-"
    if not terminal():
        return value.isoformat()
    return relative_time(value)


def relative_time(value: datetime, now: datetime | None = None) -> str:
    """Use short relative timestamps for terminal metadata."""
    seconds = int(((now or utc_now()) - value).total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _pipe_line(fields: Sequence[str]) -> str:
    return "\t".join(field.translate(_PIPE_ESCAPES) for field in fields) + "\n"


class HelpFormatter(PlainFormatter):
    """Keep command aliases on the same line as their shared description and wrap
    parameter text under a hanging indent."""

    def __call__(
        self, console: Console, options: ConsoleOptions, panel: HelpPanel
    ) -> None:
        if panel.format == "parameter":
            _print_parameter_panel(console, options, panel)
            return
        panel = panel.copy(
            entries=[
                entry.copy(positive_names=(", ".join(entry.positive_names),))
                if entry.positive_names
                else entry
                for entry in panel.entries
            ]
        )
        super().__call__(console, options, panel)


def _print_parameter_panel(
    console: Console, options: ConsoleOptions, panel: HelpPanel
) -> None:
    if not panel.entries:
        return
    if panel.title:
        console.print(literal(f"{panel.title}:"), soft_wrap=True)
    for entry in panel.entries:
        for line in textwrap.wrap(
            _parameter_text(entry, console, options),
            width=console.width,
            initial_indent="  ",
            subsequent_indent="    ",
            break_long_words=False,
        ):
            console.print(literal(line), soft_wrap=True)
    console.print()


def _parameter_text(entry: HelpEntry, console: Console, options: ConsoleOptions) -> str:
    description = "".join(
        segment.text for segment in console.render(entry.description, options)
    )
    tags = []
    if entry.choices:
        tags.append(f"[choices: {', '.join(entry.choices)}]")
    if entry.env_var:
        tags.append(f"[env var: {', '.join(entry.env_var)}]")
    if entry.default is not None:
        tags.append(f"[default: {entry.default}]")
    if entry.required:
        tags.append("[required]")
    labels = ", ".join(entry.display_labels_with_metavar)
    detail = " ".join([*description.split(), *tags])
    return f"{labels}: {detail}" if detail else labels


_consoles: dict[TextIO, Console] = {}
_last_heading: tuple[TextIO, str] | None = None
_verbose = False
_TERMINAL_ESCAPES = {
    **{code: f"\\x{code:02x}" for code in (*range(32), *range(127, 160))},
    ord("\t"): "\\t",
    ord("\n"): "\\n",
    ord("\r"): "\\r",
    0x2028: "\\u2028",
    0x2029: "\\u2029",
}
_PIPE_ESCAPES = {**_TERMINAL_ESCAPES, ord("\\"): "\\\\"}
_PROGRESS_DELAY_SECONDS = 0.5
_STATES: dict[Status, tuple[str, str]] = {
    "passed": ("✓", "green"),
    "failed": ("✗", "red"),
    "blocked": ("!", "yellow"),
    "skipped": ("○", "dim"),
    "unchanged": ("○", "dim"),
}
