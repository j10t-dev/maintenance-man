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
from maintenance_man.models.scan import (
    ScanResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.storage import save_scan_results
from maintenance_man.vcs import JjRepository
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeFindingProcessor
from tests.support.findings import make_scan_result, make_update, make_vuln
from tests.support.projects import write_config
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


def configure_fake_vcs(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[FakeJjState, dict[str, Path]]:
    """Redirect projects to fake repositories, sharing duplicate paths."""
    config_path = home / "config.toml"
    configured = load_config(config_path)
    replacements: dict[Path, Path] = {}
    state = FakeJjState()
    for project in configured.projects.values():
        if project.path in replacements:
            continue
        target = tmp_path / "repositories" / f"repo-{len(replacements)}"
        replacements[project.path] = target
        state.seed_repository(target, files={"dep.txt": "version=1\n"})
    text = config_path.read_text(encoding="utf-8")
    for source, target in replacements.items():
        text = text.replace(str(source), str(target))
    write_config(home, text)
    paths_by_name = {
        name: replacements[project.path]
        for name, project in configured.projects.items()
    }
    monkeypatch.setattr("maintenance_man.cli.make_vcs_services", state.services)
    return state, paths_by_name


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
                make_vuln(
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                    failed_phase="unit",
                ),
            ],
            updates=[
                make_update(
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                    failed_phase="unit",
                ),
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
    for project_name in project_paths:
        if project_name == "vulnerable":
            continue
        project_scan = deepcopy(scan_result)
        project_scan.project = project_name
        save_scan_results(project_name, project_scan)
    monkeypatch.setattr(processor_path, FakeFindingProcessor(outcomes))
    return CliDeps(scan_result, project_paths, save_scan)
