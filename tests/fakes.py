import subprocess
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import Emit, Event
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    Failed,
    Ready,
    ScanResult,
    UpdateResult,
    Workflow,
)
from maintenance_man.storage import save_scan_results
from maintenance_man.updater import FindingGroup
from maintenance_man.vcs import JjRepository


@dataclass
class RecordingEmit:
    events: list[Event] = field(default_factory=list)

    def __call__(self, event: Event) -> None:
        copies = {
            item.name: value.model_copy(deep=True)
            for item in fields(event)
            if isinstance(value := getattr(event, item.name), ScanResult)
        }
        self.events.append(replace(event, **copies) if copies else event)

    def of_type[E](self, kind: type[E]) -> list[E]:
        return [event for event in self.events if isinstance(event, kind)]


class FakeFindingProcessor:
    """Deterministic CLI processor that performs real repository transitions."""

    def __init__(self, outcomes: Mapping[str, tuple[bool, str | None]]) -> None:
        self.outcomes = dict(outcomes)

    def __call__(
        self,
        groups: Sequence[FindingGroup],
        project_config: ProjectConfig,
        *,
        flow: Workflow,
        scan_result: ScanResult,
        emit: Emit,
    ) -> list[UpdateResult]:
        del emit
        repo = JjRepository(project_config.path)
        results: list[UpdateResult] = []
        for group in groups:
            assert group.pkg_name in self.outcomes, (
                f"Missing outcome for {group.pkg_name}"
            )
            passed, failed_phase = self.outcomes[group.pkg_name]
            if passed:
                fixture = project_config.path / f"mm-fixture-{group.pkg_name}.txt"
                fixture.write_text(group.target_version, encoding="utf-8")
                repo.commit(message=f"fixture: update {group.pkg_name}")
                repo.set_bookmark(bookmark=WORKFLOW_BOOKMARKS[flow], revision="@-")
                group.record(Ready(flow=flow))
            else:
                assert failed_phase is not None
                group.record(Failed(flow=flow, phase=failed_phase))
            save_scan_results(scan_result.project, scan_result)
            results.append(
                UpdateResult(
                    pkg_name=group.pkg_name,
                    kind=group.kind,
                    passed=passed,
                    failed_phase=failed_phase,
                )
            )
            if not passed and flow is Workflow.RESOLVE:
                break
        return results


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
            msg = f"Unconfigured command: {argv!r} in {cwd}"
            raise AssertionError(msg)
        result = outcomes.popleft()
        if isinstance(result, BaseException):
            raise result
        return result
