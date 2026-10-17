"""Regenerate the CLI output screenshots in this directory.

Run from the repository root with ``uv run python docs/cli-output/capture.py``.
Needs ``rsvg-convert``. Uses a temporary mm home; the real ``~/.mm`` is never read.
"""

import os
import sys
import tempfile
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.text import Text

from maintenance_man import cli, paths
from maintenance_man.exit_codes import ExitCode
from maintenance_man.models.scan import (
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
)
from maintenance_man.process import run_captured


def main() -> None:
    with tempfile.TemporaryDirectory() as scratch:
        paths.MM_HOME = _build_home(Path(scratch))
        _capture("overview", ["list"], expected_exit=ExitCode.OK)
        _capture("findings", ["list", "--detail"], expected_exit=ExitCode.OK)
        _capture("successful-test", ["test", "api-gateway"], expected_exit=ExitCode.OK)


def _build_home(scratch: Path) -> Path:
    home = scratch / ".mm"
    (home / "scan-results").mkdir(parents=True)
    gateway = scratch / "api-gateway"
    reports = scratch / "reports"
    gateway.mkdir()
    reports.mkdir()
    (home / "config.toml").write_text(
        f'[projects.api-gateway]\npath = "{gateway}"\n'
        'package_manager = "uv"\ndeployable = false\ntest_unit = "true"\n\n'
        f'[projects.reports]\npath = "{reports}"\n'
        'package_manager = "uv"\ndeployable = false\n',
        encoding="utf-8",
    )
    scan = ScanResult(
        project="api-gateway",
        scanned_at=datetime.now(tz=UTC),
        trivy_target=".",
        vulnerabilities=[
            VulnFinding(
                vuln_id="CVE-2024-0001",
                pkg_name="requests",
                installed_version="2.31.0",
                fixed_version="2.32.0",
                severity=Severity.HIGH,
                title="Test vuln",
                description="desc",
                status="fixed",
            )
        ],
        updates=[
            UpdateFinding(
                pkg_name="httpx",
                installed_version="0.27.0",
                latest_version="0.27.2",
                semver_tier=SemverTier.PATCH,
            ),
            UpdateFinding(
                pkg_name="pydantic",
                installed_version="1.10.0",
                latest_version="2.0.0",
                semver_tier=SemverTier.MAJOR,
                blocked_reason="needs migration review",
            ),
        ],
    )
    (home / "scan-results" / "api-gateway.json").write_text(
        scan.model_dump_json(), encoding="utf-8"
    )
    return home


def _capture(name: str, argv: list[str], *, expected_exit: ExitCode) -> None:
    ansi = _run_on_terminal(argv, expected_exit)
    svg = HERE / f"{name}.svg"
    png = HERE / f"{name}.png"
    recorder = Console(record=True, width=WIDTH, force_terminal=True, file=StringIO())
    recorder.print(Text.from_ansi(ansi))
    try:
        svg.write_text(_preserve_spaces(recorder.export_svg()), encoding="utf-8")
        run_captured(
            ["rsvg-convert", "-o", str(png), str(svg)],
            HERE,
            timeout=60,
            label="rsvg-convert",
        )
    finally:
        svg.unlink(missing_ok=True)
    print(f"{png.name}: mm {' '.join(argv)}")


def _run_on_terminal(argv: list[str], expected_exit: ExitCode) -> str:
    stream = TerminalStream()
    saved_streams = sys.stdout, sys.stderr
    saved_environment = {key: os.environ.get(key) for key in _TERMINAL_ENVIRONMENT}
    sys.stdout = sys.stderr = stream
    os.environ.update(COLUMNS=str(WIDTH), TERM="xterm")
    os.environ.pop("NO_COLOR", None)
    exit_code = ExitCode.OK
    try:
        cli.main(argv)
    except SystemExit as exc:
        exit_code = _exit_code(exc.code)
    finally:
        sys.stdout, sys.stderr = saved_streams
        for key, value in saved_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    if exit_code != expected_exit:
        message = (
            f"mm {' '.join(argv)} exited {exit_code}, expected {expected_exit}\n"
            f"{stream.getvalue()}"
        )
        raise RuntimeError(message)
    return stream.getvalue()


def _exit_code(code: object) -> int:
    """A bare ``sys.exit()`` carries ``None`` and means success, as in Python."""
    if code is None:
        return ExitCode.OK
    return code if isinstance(code, int) else ExitCode.ERROR


def _preserve_spaces(svg: str) -> str:
    """Stop rsvg-convert dropping the leading spaces that hold columns apart."""
    return svg.replace("&#160;", " ").replace(
        "<svg ", '<svg xml:space="preserve" ', count=1
    )


class TerminalStream(StringIO):
    """An in-memory stream that claims to be a terminal."""

    def isatty(self) -> bool:
        return True


WIDTH = 100
HERE = Path(__file__).resolve().parent
_TERMINAL_ENVIRONMENT = ("COLUMNS", "TERM", "NO_COLOR")


if __name__ == "__main__":
    main()
