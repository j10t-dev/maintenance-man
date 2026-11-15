"""CLI invocation and dependency setup shared by command tests."""

from collections.abc import Callable, Sequence
from copy import deepcopy
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import NoReturn

import pytest

from maintenance_man.cli import main
from maintenance_man.config import load_config
from maintenance_man.models.scan import Failed, ScanResult, Workflow
from maintenance_man.storage import save_scan_results
from maintenance_man.vcs import JjRepository
from tests.fakes import FakeFindingProcessor
from tests.support.findings import make_scan_result, make_update, make_vuln
from tests.support.repository import configure_jj_projects


def run_mm(*argv: str) -> int:
    """Invoke the CLI and return its exit code without ending the test process."""
    try:
        main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def refuse_jj_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test the moment anything runs a jj command."""

    def refuse(cmd: Sequence[str], *_: object, **__: object) -> NoReturn:
        msg = f"unexpected jj command: {cmd!r}"
        raise AssertionError(msg)

    monkeypatch.setattr("maintenance_man.vcs.run_captured", refuse)


class TerminalStream(StringIO):
    """Capture output while reporting terminal capabilities to the renderer."""

    def isatty(self) -> bool:
        """Select terminal rendering for this in-memory stream."""
        return True


def terminal_stdout(
    monkeypatch: pytest.MonkeyPatch, width: int | None = None
) -> TerminalStream:
    """Route stdout to an uncoloured terminal stream, optionally of a given width."""
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("NO_COLOR", "1")
    if width is not None:
        monkeypatch.setenv("COLUMNS", str(width))
    return stream


@dataclass(frozen=True, slots=True)
class CliDeps:
    """The copied project repositories and the mutable scan saved by the test."""

    scan_result: ScanResult
    project_paths: dict[str, Path]
    save_scan: Callable[[], None]


def cli_deps(
    flow: Workflow,
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> CliDeps:
    """Install update or resolve dependencies and seed scans for configured projects."""
    if flow is Workflow.UPDATE:
        scan_result = make_scan_result()
        outcomes = {
            "some-pkg": (True, None),
            "pkg-a": (True, None),
            "pkg-b": (True, None),
            "pkg-c": (True, None),
        }
        processor_path = "maintenance_man.services.update.process_findings"
    else:
        scan_result = make_scan_result(
            vulns=[
                make_vuln(state=Failed(flow=Workflow.RESOLVE, phase="unit")),
            ],
            updates=[
                make_update(state=Failed(flow=Workflow.RESOLVE, phase="unit")),
            ],
        )
        outcomes = {"some-pkg": (True, None), "pkg-a": (True, None)}
        processor_path = "maintenance_man.services.resolve.process_findings"

    project_paths = configure_jj_projects(mm_home, tmp_path)
    if flow is Workflow.RESOLVE:
        JjRepository(project_paths["vulnerable"]).set_bookmark(
            bookmark="mm/resolve-dependencies", revision="@-"
        )

    def save_scan() -> None:
        save_scan_results("vulnerable", scan_result)

    save_scan()
    projects = load_config(mm_home / "config.toml").projects
    for project_name in project_paths:
        if project_name == "vulnerable":
            continue
        project_scan = deepcopy(scan_result)
        project_scan.project_name = project_name
        project_scan.package_manager = projects[project_name].package_manager
        save_scan_results(project_name, project_scan)
    monkeypatch.setattr(processor_path, FakeFindingProcessor(outcomes))
    return CliDeps(scan_result, project_paths, save_scan)
