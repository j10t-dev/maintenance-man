from __future__ import annotations

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
    ScanResult,
    UpdateFinding,
    UpdateResult,
    UpdateStatus,
    VulnFinding,
    Workflow,
)
from maintenance_man.services.update import FindingChooser
from maintenance_man.storage import save_scan_results
from maintenance_man.updater import Finding
from maintenance_man.vcs_workflow import VcsServices


def pick_findings(*pkg_names: str) -> FindingChooser:
    def choose(
        vulns: list[VulnFinding], updates: list[UpdateFinding]
    ) -> tuple[list[VulnFinding], list[UpdateFinding]]:
        selected_vulns: list[VulnFinding] = []
        selected_updates: list[UpdateFinding] = []
        findings = [*vulns, *updates]
        for pkg_name in pkg_names:
            finding = next(item for item in findings if item.pkg_name == pkg_name)
            if isinstance(finding, VulnFinding):
                selected_vulns.append(finding)
            else:
                selected_updates.append(finding)
        return selected_vulns, selected_updates

    return choose


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
        findings: Sequence[Finding],
        project_config: ProjectConfig,
        *,
        flow: Workflow,
        on_failure: str = "continue",
        scan_result: ScanResult | None = None,
        project_name: str = "",
        vcs: VcsServices | None = None,
        emit: Emit,
    ) -> list[UpdateResult]:
        del emit
        assert vcs is not None, "FakeFindingProcessor requires explicit VcsServices"
        repo = vcs.repository(project_config.path)
        results: list[UpdateResult] = []
        for finding in findings:
            assert finding.pkg_name in self.outcomes, (
                f"Missing outcome for {finding.pkg_name}"
            )
            passed, failed_phase = self.outcomes[finding.pkg_name]
            kind = "update" if isinstance(finding, UpdateFinding) else "vuln"
            if passed:
                fixture = project_config.path / f"mm-fixture-{finding.pkg_name}.txt"
                fixture.write_text(finding.target_version, encoding="utf-8")
                repo.commit(message=f"fixture: update {finding.pkg_name}")
                repo.set_bookmark(bookmark=WORKFLOW_BOOKMARKS[flow], revision="@-")
                finding.update_status = UpdateStatus.READY
                finding.failed_phase = None
            else:
                finding.update_status = UpdateStatus.FAILED
                finding.failed_phase = failed_phase
            finding.flow = flow
            if scan_result is not None:
                save_scan_results(project_name, scan_result)
            results.append(
                UpdateResult(
                    pkg_name=finding.pkg_name,
                    kind=kind,
                    passed=passed,
                    failed_phase=failed_phase,
                )
            )
            if not passed and on_failure == "stop":
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
            raise AssertionError(f"Unconfigured command: {argv!r} in {cwd}")
        result = outcomes.popleft()
        if isinstance(result, BaseException):
            raise result
        return result
