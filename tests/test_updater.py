import dataclasses
import shlex
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict
from unittest.mock import MagicMock

import pytest

from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    validate_gradle_target,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    FindingFailed,
    FindingStepFailed,
    FindingStepKind,
)
from maintenance_man.models.events import (
    TestCommandStarted as CommandStartedEvent,
)
from maintenance_man.models.scan import (
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateStatus,
    Workflow,
)
from maintenance_man.package_managers import package_manager_ops
from maintenance_man.process import ProcessError
from maintenance_man.storage import load_scan_results
from maintenance_man.updater import (
    FindingStep,
    _apply_update,
    consolidate_vulns,
    finding_transition,
    process_findings,
    remove_completed_findings,
    run_test_phases,
    should_discard,
    should_stop,
    sort_updates_by_risk,
)
from maintenance_man.uv_dependencies import (
    UvUngroupedLocation,
    get_uv_dependency_locations,
)
from maintenance_man.vcs_workflow import VcsServices
from tests.conftest import completed, make_gradle_target, make_update, make_vuln
from tests.fake_vcs import FakeJj, FakeJjState
from tests.fakes import RecordingEmit

PASSED = FindingStep(None)
FAILED = FindingStep("unit")
UNSAFE = FindingStep("commit", discardable=False)


@pytest.mark.parametrize(
    "step,on_failure,discard",
    [
        (PASSED, "continue", False),
        (FAILED, "continue", True),
        (FAILED, "stop", False),
        (UNSAFE, "continue", False),
        (UNSAFE, "stop", False),
    ],
)
def test_given_finding_step_when_deciding_to_discard_then_returns_expected_decision(
    step, on_failure, discard
):
    assert should_discard(step, on_failure) is discard


@pytest.mark.parametrize(
    "failed_phase,discardable,on_failure,discarded,expected",
    [
        (None, True, "continue", None, False),
        ("unit", True, "continue", True, False),
        ("unit", True, "continue", False, True),
        ("unit", False, "continue", None, True),
        ("unit", True, "stop", None, True),
    ],
)
def test_given_finding_step_when_deciding_to_stop_then_returns_expected_decision(
    failed_phase, discardable, on_failure, discarded, expected
):
    step = FindingStep(failed_phase, discardable)

    result = should_stop(step, on_failure, discarded)

    assert result is expected


@pytest.mark.parametrize(
    "step,expected",
    [
        (PASSED, (UpdateStatus.READY, None)),
        (FAILED, (UpdateStatus.FAILED, "unit")),
        (UNSAFE, (UpdateStatus.FAILED, "commit")),
    ],
)
def test_finding_transition(step, expected):
    assert finding_transition(step) == expected


def _scan_result_for(
    project_config: ProjectConfig, updates: list[UpdateFinding]
) -> ScanResult:
    return ScanResult(
        project="demo",
        scanned_at=datetime.now(tz=UTC),
        trivy_target=str(project_config.path),
        updates=updates,
    )


# -- Fixtures --


@pytest.fixture()
def project_config(tmp_path: Path) -> ProjectConfig:
    return ProjectConfig(
        path=tmp_path,
        package_manager="bun",
        test_unit="bun test",
    )


class ProcessorDeps(TypedDict):
    state: FakeJjState
    repo: FakeJj
    services: VcsServices
    package: MagicMock
    phase: MagicMock


@pytest.fixture()
def processor_vcs(
    monkeypatch: pytest.MonkeyPatch, project_config: ProjectConfig
) -> ProcessorDeps:
    """Use real repository transitions while substituting package/test commands."""
    path = Path(project_config.path)
    state = FakeJjState()
    repo = state.seed_repository(
        path,
        files={"dep.txt": "version=1\n", "package.json": "{}\n"},
    )

    def run_package(cmd, cwd, **kwargs):
        assert cmd[:2] == ["bun", "add"]
        assert cwd == path
        assert kwargs == {
            "timeout": 300,
            "label": " ".join(cmd),
            "stdin": subprocess.DEVNULL,
        }
        current = (path / "dep.txt").read_text(encoding="utf-8")
        (path / "dep.txt").write_text(f"{current}{cmd[-1]}\n", encoding="utf-8")
        return completed(cmd, returncode=0, stdout="", stderr="")

    def run_phase(command, cwd, **kwargs):
        assert command == "bun test"
        assert cwd == path
        assert kwargs == {"timeout": 600, "label": "unit tests"}

    package = MagicMock(side_effect=run_package)
    phase = MagicMock(side_effect=run_phase)
    monkeypatch.setattr("maintenance_man.updater.run_logged", package)
    monkeypatch.setattr("maintenance_man.updater.run_live", phase)
    return {
        "state": state,
        "repo": repo,
        "services": state.services(),
        "package": package,
        "phase": phase,
    }


class TestGetUvDependencyLocations:
    def test_returns_transitive_when_package_not_in_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["requests>=2.28"]\n', encoding="utf-8"
        )

        result = get_uv_dependency_locations(tmp_path, "urllib3")
        assert result == [UvUngroupedLocation(kind="transitive")]

    def test_returns_transitive_for_optional_dependency(self, tmp_path: Path):
        # project.optional-dependencies are intentionally not scanned for direct deps;
        # packages declared only there fall through to the transitive path.
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = []\n\n"
            "[project.optional-dependencies]\n"
            'cli = ["rich>=14.0"]\n',
            encoding="utf-8",
        )

        result = get_uv_dependency_locations(tmp_path, "rich")
        assert result == [UvUngroupedLocation(kind="transitive")]


class TestApplyUpdate:
    def test_uv_runs_all_matching_commands_in_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["pytest>=8.0"]\n\n'
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0"]\n'
            'lint = ["pytest>=8.0"]\n',
            encoding="utf-8",
        )
        mock_run = MagicMock(
            return_value=completed([], returncode=0, stdout="", stderr="")
        )
        monkeypatch.setattr("maintenance_man.updater.run_logged", mock_run)

        assert (
            _apply_update("uv", "pytest", "9.0.3", tmp_path, emit=RecordingEmit())
            is True
        )
        assert [call.args[0] for call in mock_run.call_args_list] == [
            ["uv", "add", "pytest==9.0.3"],
            ["uv", "add", "--group", "dev", "pytest==9.0.3"],
            ["uv", "add", "--group", "lint", "pytest==9.0.3"],
        ]

    def test_uv_stops_on_first_failing_command(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["pytest>=8.0"]\n\n'
            "[dependency-groups]\n"
            'dev = ["pytest>=8.0"]\n'
            'lint = ["pytest>=8.0"]\n',
            encoding="utf-8",
        )
        mock_run = MagicMock(
            side_effect=[
                completed([], returncode=0, stdout="", stderr=""),
                ProcessError("uv add --group dev pytest==9.0.3 failed (exit 1)"),
                completed([], returncode=0, stdout="", stderr=""),
            ]
        )
        monkeypatch.setattr("maintenance_man.updater.run_logged", mock_run)

        emit = RecordingEmit()
        assert _apply_update("uv", "pytest", "9.0.3", tmp_path, emit=emit) is False
        assert mock_run.call_count == 2
        assert emit.of_type(FindingStepFailed) == [
            FindingStepFailed(
                FindingStepKind.PACKAGE_COMMAND,
                "uv add --group dev pytest==9.0.3 failed (exit 1)",
            )
        ]

    def test_uv_pyproject_read_failure_is_apply_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ):
        mock_run = MagicMock()
        monkeypatch.setattr("maintenance_man.updater.run_logged", mock_run)

        emit = RecordingEmit()
        assert _apply_update("uv", "pytest", "9.0.3", tmp_path, emit=emit) is False
        assert mock_run.call_count == 0
        assert emit.of_type(FindingStepFailed)[0].step is FindingStepKind.PREPARE
        assert "Failed to read" in emit.of_type(FindingStepFailed)[0].error


def test_given_failing_package_command_when_applied_then_error_omits_child_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    command = [sys.executable, "-c", "print('boom'); raise SystemExit(7)"]
    ops = dataclasses.replace(
        package_manager_ops("bun"), update_commands=lambda *args: [command]
    )
    monkeypatch.setattr("maintenance_man.updater.package_manager_ops", lambda _: ops)

    emit = RecordingEmit()
    assert _apply_update("bun", "left-pad", "2.0.0", tmp_path, emit=emit) is False

    assert emit.of_type(FindingStepFailed) == [
        FindingStepFailed(
            FindingStepKind.PACKAGE_COMMAND, f"{shlex.join(command)} failed (exit 7)"
        )
    ]
    assert capsys.readouterr() == ("", "boom\n")


_EXECUTION_FAILURES = [
    "{label} timed out after 300s in {cwd}",
    "Could not run {label} in {cwd}: [Errno 2] No such file or directory",
]


@pytest.mark.parametrize("failure", _EXECUTION_FAILURES)
def test_package_command_execution_failure_stops_the_apply(
    tmp_path, monkeypatch, failure
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["pytest>=8.0"]\n\n'
        "[dependency-groups]\n"
        'dev = ["pytest>=8.0"]\n',
        encoding="utf-8",
    )
    calls = []
    message = failure.format(label="uv add pytest==9.0.3", cwd=tmp_path)

    def run(cmd, cwd, **kwargs):
        calls.append(cmd)
        raise ProcessError(message)

    monkeypatch.setattr("maintenance_man.updater.run_logged", run)
    emit = RecordingEmit()
    assert _apply_update("uv", "pytest", "9.0.3", tmp_path, emit=emit) is False
    assert calls == [["uv", "add", "pytest==9.0.3"]]
    assert emit.of_type(FindingStepFailed) == [
        FindingStepFailed(FindingStepKind.PACKAGE_COMMAND, message)
    ]


@pytest.mark.parametrize("failure", _EXECUTION_FAILURES)
def test_maven_finalisation_execution_failure_is_an_apply_failure(
    tmp_path, monkeypatch, failure
):
    calls = []

    def run(cmd, cwd, **kwargs):
        calls.append((cmd, kwargs["timeout"]))
        if cmd == ["mvn", "versions:commit"]:
            raise ProcessError(failure.format(label="mvn versions:commit", cwd=cwd))
        return completed(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("maintenance_man.updater.run_logged", run)
    assert _apply_update("mvn", "g:a", "2.0", tmp_path, emit=RecordingEmit()) is False
    assert calls == [
        (
            ["mvn", "versions:use-dep-version", "-Dincludes=g:a", "-DdepVersion=2.0"],
            300,
        ),
        (["mvn", "versions:commit"], 300),
    ]


def test_maven_finalisation_does_not_run_after_a_failed_update(tmp_path, monkeypatch):
    calls = []

    def run(cmd, cwd, **kwargs):
        calls.append(cmd)
        msg = f"{kwargs['label']} failed (exit 1)"
        raise ProcessError(msg)

    monkeypatch.setattr("maintenance_man.updater.run_logged", run)
    assert _apply_update("mvn", "g:a", "2.0", tmp_path, emit=RecordingEmit()) is False
    assert calls == [
        ["mvn", "versions:use-dep-version", "-Dincludes=g:a", "-DdepVersion=2.0"]
    ]


def test_package_boundary_failure_is_persisted_as_a_failed_apply(
    processor_vcs, project_config, tmp_path
):
    processor_vcs["package"].side_effect = ProcessError("package command timed out")
    scan_result = ScanResult(
        project="demo",
        scanned_at=datetime.now(UTC),
        trivy_target=str(tmp_path),
        updates=[make_update(SemverTier.PATCH)],
    )
    update = scan_result.updates[0]
    results = process_findings(
        [update],
        project_config,
        flow=Workflow.UPDATE,
        scan_result=scan_result,
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    assert results[0].failed_phase == "apply"
    saved = load_scan_results("demo")
    assert saved.updates[0].update_status == UpdateStatus.FAILED
    assert saved.updates[0].failed_phase == "apply"


# -- run_test_phases --


class TestRunTestPhases:
    def test_all_green(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        mock_run = MagicMock(return_value=None)
        monkeypatch.setattr("maintenance_man.updater.run_live", mock_run)
        tc = ProjectConfig(
            path=tmp_path,
            package_manager="bun",
            test_unit="bun test",
            test_integration="bun run test:integration",
        )
        failed_phase = run_test_phases(tc, tmp_path, emit=RecordingEmit())
        assert failed_phase is None
        assert mock_run.call_count == 2

    def test_unit_fails(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        mock_run = MagicMock(side_effect=ProcessError("unit tests failed (exit 1)"))
        monkeypatch.setattr("maintenance_man.updater.run_live", mock_run)
        tc = ProjectConfig(path=tmp_path, package_manager="bun", test_unit="bun test")
        failed_phase = run_test_phases(tc, tmp_path, emit=RecordingEmit())
        assert failed_phase == "unit"
        assert mock_run.call_count == 1

    def test_integration_fails(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        def side_effect(*args, **kwargs):
            if "integration" in args[0]:
                msg = f"{kwargs['label']} failed (exit 1)"
                raise ProcessError(msg)

        mock_run = MagicMock(side_effect=side_effect)
        monkeypatch.setattr("maintenance_man.updater.run_live", mock_run)
        tc = ProjectConfig(
            path=tmp_path,
            package_manager="bun",
            test_unit="bun test",
            test_integration="bun run test:integration",
        )
        failed_phase = run_test_phases(tc, tmp_path, emit=RecordingEmit())
        assert failed_phase == "integration"

    def test_skips_unconfigured_phases(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        mock_run = MagicMock(return_value=None)
        monkeypatch.setattr("maintenance_man.updater.run_live", mock_run)
        tc = ProjectConfig(
            path=tmp_path, package_manager="bun", test_unit="bun test"
        )  # no integration or component
        failed_phase = run_test_phases(tc, tmp_path, emit=RecordingEmit())
        assert failed_phase is None
        assert mock_run.call_count == 1  # only unit

    def test_blank_phase_is_skipped(self, monkeypatch, tmp_path):
        mock_run = MagicMock(return_value=None)
        monkeypatch.setattr("maintenance_man.updater.run_live", mock_run)
        tc = ProjectConfig(
            path=tmp_path,
            package_manager="bun",
            test_unit="  ",
            test_integration="bun run test:integration",
        )
        assert run_test_phases(tc, tmp_path, emit=RecordingEmit()) is None
        assert [c.args[0] for c in mock_run.call_args_list] == [
            "bun run test:integration"
        ]


def test_test_phases_run_through_bash(tmp_path):
    config = ProjectConfig(
        path=tmp_path,
        package_manager="bun",
        test_unit="printf '%s' 'a b' > out.txt && test \"$(cat out.txt)\" = 'a b'",
    )
    assert run_test_phases(config, tmp_path, emit=RecordingEmit()) is None
    # Under shlex.split printf prints every argument and exits 0; only Bash
    # performs the redirect.
    assert (tmp_path / "out.txt").read_text() == "a b"


def test_first_failed_phase_stops_later_phases(tmp_path):
    config = ProjectConfig(
        path=tmp_path,
        package_manager="bun",
        test_unit="exit 3",
        test_integration="touch integration-ran",
    )
    assert run_test_phases(config, tmp_path, emit=RecordingEmit()) == "unit"
    assert not (tmp_path / "integration-ran").exists()


def test_test_phase_launch_failure_is_a_failed_phase(tmp_path):
    config = ProjectConfig(path=tmp_path, package_manager="bun", test_unit="true")
    emit = RecordingEmit()
    assert run_test_phases(config, tmp_path / "missing", emit=emit) == "unit"
    assert emit.events[0] == CommandStartedEvent("true")
    assert emit.of_type(FindingStepFailed)[0].step is FindingStepKind.TEST
    assert "Could not run unit tests" in emit.of_type(FindingStepFailed)[0].error


# -- sort_updates_by_risk --


class TestSortUpdatesByRisk:
    def test_sorts_patch_minor_major(self):
        updates = [
            make_update(SemverTier.MAJOR),
            make_update(SemverTier.PATCH),
            make_update(SemverTier.MINOR),
        ]
        sorted_u = sort_updates_by_risk(updates)
        assert [u.semver_tier for u in sorted_u] == [
            SemverTier.PATCH,
            SemverTier.MINOR,
            SemverTier.MAJOR,
        ]

    def test_empty_list(self):
        assert sort_updates_by_risk([]) == []

    def test_single_update(self):
        result = sort_updates_by_risk([make_update(SemverTier.MINOR)])
        assert len(result) == 1
        assert result[0].semver_tier == SemverTier.MINOR


# -- consolidate_vulns --


class TestConsolidateVulns:
    def test_same_package_consolidated(self):
        vulns = [
            make_vuln(
                vuln_id="CVE-2023-32681",
                pkg_name="requests",
                fixed_version="2.31.0",
            ),
            make_vuln(
                vuln_id="CVE-2024-35195",
                pkg_name="requests",
                fixed_version="2.32.0",
            ),
            make_vuln(
                vuln_id="CVE-2024-47081",
                pkg_name="requests",
                fixed_version="2.32.4",
            ),
        ]
        result = consolidate_vulns(vulns)
        assert len(result) == 1
        assert result[0].pkg_name == "requests"
        assert result[0].target_version == "2.32.4"
        assert "CVE-2023-32681" in result[0].detail
        assert "CVE-2024-35195" in result[0].detail
        assert "CVE-2024-47081" in result[0].detail

    def test_different_packages_not_consolidated(self):
        vulns = [
            make_vuln(vuln_id="CVE-0001", pkg_name="pkg-a", fixed_version="1.0.1"),
            make_vuln(vuln_id="CVE-0002", pkg_name="pkg-b", fixed_version="2.0.1"),
        ]
        result = consolidate_vulns(vulns)
        assert len(result) == 2
        assert result[0].pkg_name == "pkg-a"
        assert result[1].pkg_name == "pkg-b"

    def test_status_fanout_to_originals(self):
        v1 = make_vuln(vuln_id="CVE-0001", pkg_name="pkg", fixed_version="1.0.1")
        v2 = make_vuln(vuln_id="CVE-0002", pkg_name="pkg", fixed_version="1.0.2")
        consolidated = consolidate_vulns([v1, v2])
        consolidated[0].update_status = UpdateStatus.COMPLETED
        assert v1.update_status == UpdateStatus.COMPLETED
        assert v2.update_status == UpdateStatus.COMPLETED

    def test_lifecycle_fanout_to_originals(self):
        v1 = make_vuln(vuln_id="CVE-0001", pkg_name="pkg", fixed_version="1.0.1")
        v2 = make_vuln(vuln_id="CVE-0002", pkg_name="pkg", fixed_version="1.0.2")
        consolidated = consolidate_vulns([v1, v2])

        consolidated[0].update_status = UpdateStatus.READY
        consolidated[0].failed_phase = "unit"
        consolidated[0].flow = Workflow.RESOLVE

        assert v1.update_status == UpdateStatus.READY
        assert v2.update_status == UpdateStatus.READY
        assert v1.failed_phase == "unit"
        assert v2.failed_phase == "unit"
        assert v1.flow == "resolve"
        assert v2.flow == "resolve"

    def test_initial_lifecycle_state_normalises_across_group(self):
        v1 = make_vuln(vuln_id="CVE-0001", pkg_name="pkg", fixed_version="1.0.1")
        v2 = make_vuln(
            vuln_id="CVE-0002",
            pkg_name="pkg",
            fixed_version="1.0.2",
            update_status=UpdateStatus.FAILED,
            failed_phase="unit",
            flow="resolve",
        )

        consolidated = consolidate_vulns([v1, v2])

        assert consolidated[0].update_status == UpdateStatus.FAILED
        assert consolidated[0].failed_phase == "unit"
        assert consolidated[0].flow == "resolve"
        assert v1.update_status == UpdateStatus.FAILED
        assert v1.failed_phase == "unit"
        assert v1.flow == "resolve"
        assert v2.update_status == UpdateStatus.FAILED
        assert v2.failed_phase == "unit"
        assert v2.flow == "resolve"

    def test_empty_list(self):
        assert consolidate_vulns([]) == []


# -- remove_completed_findings --


class TestRemoveCompletedFindings:
    def test_removes_completed_vulns_and_updates(self):
        vulns = [
            make_vuln(vuln_id="CVE-1", update_status=UpdateStatus.COMPLETED),
            make_vuln(vuln_id="CVE-2", update_status=UpdateStatus.FAILED),
            make_vuln(vuln_id="CVE-3", update_status=None),
        ]
        updates = [
            make_update(SemverTier.PATCH, update_status=UpdateStatus.COMPLETED),
            make_update(SemverTier.MINOR, update_status=UpdateStatus.FAILED),
        ]
        scan = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=UTC),
            trivy_target="/tmp/myapp",
            vulnerabilities=vulns,
            updates=updates,
        )

        remove_completed_findings(scan)

        assert len(scan.vulnerabilities) == 2
        assert all(
            v.update_status != UpdateStatus.COMPLETED for v in scan.vulnerabilities
        )
        assert len(scan.updates) == 1
        assert scan.updates[0].update_status == UpdateStatus.FAILED

    def test_no_completed_is_noop(self):
        scan = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=UTC),
            trivy_target="/tmp/myapp",
            updates=[make_update(SemverTier.PATCH, update_status=UpdateStatus.FAILED)],
        )

        remove_completed_findings(scan)

        assert len(scan.updates) == 1


# -- process_findings --


def _services(bundle: ProcessorDeps) -> VcsServices:
    return bundle["services"]


@pytest.mark.parametrize(
    "flow,bookmark",
    [
        (Workflow.UPDATE, "mm/update-dependencies"),
        (Workflow.RESOLVE, "mm/resolve-dependencies"),
    ],
)
def test_success_commits_and_advances_the_flow_bookmark(
    flow: Workflow,
    bookmark: str,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    update = make_update()

    results = process_findings(
        [update],
        project_config,
        flow=flow,
        scan_result=_scan_result_for(project_config, [update]),
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    state = processor_vcs["state"]
    assert results[0].passed is True
    assert update.update_status == UpdateStatus.READY
    assert update.failed_phase is None
    assert update.flow == flow
    assert [call.method for call in state.effects] == ["commit", "set_bookmark"]
    repo = processor_vcs["repo"]
    assert repo.same_revision(left=bookmark, right="@-")


@pytest.mark.parametrize("flow", [Workflow.UPDATE, Workflow.RESOLVE])
def test_already_applied_is_ready_without_a_commit(
    flow: Workflow,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    processor_vcs["package"].side_effect = lambda cmd, cwd, **kwargs: completed(
        cmd, returncode=0, stdout="", stderr=""
    )
    update = make_update()

    results = process_findings(
        [update],
        project_config,
        flow=flow,
        on_failure="stop" if flow == Workflow.RESOLVE else "continue",
        scan_result=_scan_result_for(project_config, [update]),
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    assert results[0].passed is True
    assert update.update_status == UpdateStatus.READY
    assert update.flow == flow
    assert not any(call.method == "commit" for call in processor_vcs["state"].attempts)


def test_update_failure_discards_then_attempts_the_next_finding(
    processor_vcs: ProcessorDeps, project_config: ProjectConfig
):
    phase = processor_vcs["phase"]
    phase.side_effect = [ProcessError("unit failed"), None]
    findings = [make_update(), make_update(SemverTier.MINOR)]
    emit = RecordingEmit()

    results = process_findings(
        findings,
        project_config,
        flow=Workflow.UPDATE,
        scan_result=_scan_result_for(project_config, findings),
        vcs=_services(processor_vcs),
        emit=emit,
    )

    assert [result.passed for result in results] == [False, True]
    assert findings[0].update_status == UpdateStatus.FAILED
    assert findings[0].failed_phase == "unit"
    assert findings[0].flow == Workflow.UPDATE
    assert processor_vcs["package"].call_count == 2
    assert "discard" in [call.method for call in processor_vcs["state"].effects]
    assert emit.of_type(FindingFailed)[0].phase == "unit"


@pytest.mark.parametrize("flow", [Workflow.UPDATE, Workflow.RESOLVE])
def test_all_successful_findings_commit_without_discard(
    flow: Workflow,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    findings = [make_update(), make_update(SemverTier.MINOR)]

    results = process_findings(
        findings,
        project_config,
        flow=flow,
        on_failure="stop" if flow == Workflow.RESOLVE else "continue",
        scan_result=_scan_result_for(project_config, findings),
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    assert len(results) == 2
    assert all(result.passed for result in results)
    assert processor_vcs["package"].call_count == 2
    assert processor_vcs["phase"].call_count == 2
    methods = [call.method for call in processor_vcs["state"].effects]
    assert methods.count("commit") == 2
    assert "discard" not in methods


def test_update_success_failure_success_sequence_continues_after_discard(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    processor_vcs["phase"].side_effect = [
        None,
        ProcessError("unit failed"),
        None,
    ]
    findings = [
        make_update(),
        make_update(SemverTier.MINOR),
        make_update(SemverTier.MAJOR),
    ]

    results = process_findings(
        findings,
        project_config,
        flow=Workflow.UPDATE,
        scan_result=_scan_result_for(project_config, findings),
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    assert [result.passed for result in results] == [True, False, True]
    methods = [call.method for call in processor_vcs["state"].effects]
    assert methods.count("commit") == 2
    assert methods.count("discard") == 1


@pytest.mark.parametrize("failed_phase", ["unit", "apply", "commit"])
def test_resolve_failure_preserves_changes_and_stops(
    failed_phase: str,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    if failed_phase == "unit":
        processor_vcs["phase"].side_effect = ProcessError("unit failed")
    elif failed_phase == "apply":
        processor_vcs["package"].side_effect = ProcessError("package failed")
    else:
        from maintenance_man.vcs import RevisionError

        processor_vcs["state"].fail(
            "commit", error=RevisionError("injected"), path=project_config.path
        )
    findings = [make_update(), make_update(SemverTier.MINOR)]

    results = process_findings(
        findings,
        project_config,
        flow=Workflow.RESOLVE,
        on_failure="stop",
        scan_result=_scan_result_for(project_config, findings),
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    assert len(results) == 1
    assert results[0].failed_phase == failed_phase
    assert findings[0].update_status == UpdateStatus.FAILED
    assert findings[0].flow == Workflow.RESOLVE
    assert processor_vcs["package"].call_count == 1
    assert findings[1].update_status is None
    assert not any(call.method == "discard" for call in processor_vcs["state"].attempts)


def test_resolve_success_then_failure_leaves_later_finding_unattempted(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    processor_vcs["phase"].side_effect = [None, ProcessError("unit failed")]
    findings = [
        make_update(),
        make_update(SemverTier.MINOR),
        make_update(SemverTier.MAJOR),
    ]

    results = process_findings(
        findings,
        project_config,
        flow=Workflow.RESOLVE,
        on_failure="stop",
        scan_result=_scan_result_for(project_config, findings),
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    assert [result.passed for result in results] == [True, False]
    assert processor_vcs["package"].call_count == 2
    assert findings[2].update_status is None
    methods = [call.method for call in processor_vcs["state"].effects]
    assert methods.count("commit") == 1
    assert "discard" not in methods


@pytest.mark.parametrize("method", ["has_changes", "commit", "set_bookmark"])
def test_repository_failure_never_saves_ready(
    method: str,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    from maintenance_man.vcs import RevisionError

    state = processor_vcs["state"]
    state.fail(method, error=RevisionError("injected"), path=project_config.path)
    finding = make_update()
    second = make_update(SemverTier.MINOR)
    scan = ScanResult(
        project="demo",
        scanned_at=datetime.now(tz=UTC),
        trivy_target=str(project_config.path),
        updates=[finding, second],
    )
    results = process_findings(
        [finding, second],
        project_config,
        flow=Workflow.UPDATE,
        scan_result=scan,
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    saved = load_scan_results("demo")
    assert saved.updates[0].update_status == UpdateStatus.FAILED
    assert saved.updates[0].failed_phase == "commit"
    if method == "has_changes":
        assert len(results) == 1
        assert processor_vcs["package"].call_count == 1
        assert not any(call.method in {"commit", "discard"} for call in state.attempts)
    if method == "commit":
        assert [result.passed for result in results] == [False, True]
        assert processor_vcs["package"].call_count == 2
        assert any(call.method == "discard" for call in state.effects)
    if method == "set_bookmark":
        assert len(results) == 1
        assert processor_vcs["package"].call_count == 1
        assert sum(call.method == "commit" for call in state.effects) == 1
        assert not any(call.method == "discard" for call in state.attempts)


def test_apply_failure_discards_and_continues(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    processor_vcs["package"].side_effect = [
        ProcessError("package failed"),
        completed([], returncode=0, stdout="", stderr=""),
    ]
    findings = [make_update(), make_update(SemverTier.MINOR)]

    results = process_findings(
        findings,
        project_config,
        flow=Workflow.UPDATE,
        scan_result=_scan_result_for(project_config, findings),
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    assert [result.passed for result in results] == [False, True]
    assert results[0].failed_phase == "apply"
    assert any(call.method == "discard" for call in processor_vcs["state"].effects)


@pytest.mark.parametrize("flow", [Workflow.UPDATE, Workflow.RESOLVE])
def test_no_test_config_skips_tests_and_commits(
    flow: Workflow,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    config = project_config.model_copy(update={"test_unit": None})
    update = make_update()

    results = process_findings(
        [update],
        config,
        flow=flow,
        on_failure="stop" if flow == Workflow.RESOLVE else "continue",
        scan_result=_scan_result_for(config, [update]),
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    assert results[0].passed is True
    processor_vcs["phase"].assert_not_called()
    assert any(call.method == "commit" for call in processor_vcs["state"].effects)


def test_empty_findings_have_no_repository_effects(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    assert (
        process_findings(
            [],
            project_config,
            flow=Workflow.UPDATE,
            scan_result=_scan_result_for(project_config, []),
            vcs=_services(processor_vcs),
            emit=RecordingEmit(),
        )
        == []
    )
    assert processor_vcs["state"].effects == []


def test_failed_discard_persists_original_failure_and_stops(
    processor_vcs: ProcessorDeps, project_config: ProjectConfig
):
    from maintenance_man.vcs import RevisionError

    state = processor_vcs["state"]
    processor_vcs["phase"].side_effect = ProcessError("unit failed")
    findings = [make_update(), make_update(SemverTier.MINOR)]
    scan = ScanResult(
        project="demo",
        scanned_at=datetime.now(tz=UTC),
        trivy_target=str(project_config.path),
        updates=findings,
    )

    def assert_persisted_before_discard_failure() -> None:
        saved = load_scan_results("demo")
        assert saved.updates[0].update_status == UpdateStatus.FAILED
        assert saved.updates[0].failed_phase == "unit"
        msg = "cannot discard"
        raise RevisionError(msg)

    state.hook(
        "discard",
        phase="before",
        action=assert_persisted_before_discard_failure,
        path=project_config.path,
    )
    emit = RecordingEmit()
    results = process_findings(
        findings,
        project_config,
        flow=Workflow.UPDATE,
        scan_result=scan,
        vcs=_services(processor_vcs),
        emit=emit,
    )

    assert len(results) == 1
    saved = load_scan_results("demo")
    assert saved.updates[0].failed_phase == "unit"
    assert saved.updates[0].update_status == UpdateStatus.FAILED
    assert emit.of_type(FindingStepFailed)[-1] == FindingStepFailed(
        FindingStepKind.DISCARD, "cannot discard"
    )


def test_update_statuses_are_persisted_after_each_finding(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    findings = [make_update(), make_update(SemverTier.MINOR)]
    scan = ScanResult(
        project="demo",
        scanned_at=datetime.now(tz=UTC),
        trivy_target=str(project_config.path),
        updates=findings,
    )
    inspected_before_second_finding: list[bool] = []
    package_effect = processor_vcs["package"].side_effect
    phase_effect = processor_vcs["phase"].side_effect
    assert callable(package_effect)
    assert callable(phase_effect)

    def run_package(*args: object, **kwargs: object) -> object:
        if processor_vcs["package"].call_count == 2:
            saved = load_scan_results("demo")
            assert [finding.update_status for finding in saved.updates] == [
                UpdateStatus.READY,
                None,
            ]
            inspected_before_second_finding.append(True)
        return package_effect(*args, **kwargs)

    def run_phase(*args: object, **kwargs: object) -> None:
        phase_effect(*args, **kwargs)
        if processor_vcs["phase"].call_count == 2:
            msg = "unit failed"
            raise ProcessError(msg)

    processor_vcs["package"].side_effect = run_package
    processor_vcs["phase"].side_effect = run_phase
    process_findings(
        findings,
        project_config,
        flow=Workflow.UPDATE,
        scan_result=scan,
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    saved = load_scan_results("demo")
    assert [finding.update_status for finding in saved.updates] == [
        UpdateStatus.READY,
        UpdateStatus.FAILED,
    ]
    assert saved.updates[1].failed_phase == "unit"
    assert inspected_before_second_finding == [True]


def test_resolve_failure_status_is_persisted_before_stopping(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    processor_vcs["phase"].side_effect = ProcessError("unit failed")
    finding = make_update(update_status=UpdateStatus.FAILED)
    scan = ScanResult(
        project="demo",
        scanned_at=datetime.now(tz=UTC),
        trivy_target=str(project_config.path),
        updates=[finding],
    )
    process_findings(
        [finding],
        project_config,
        flow=Workflow.RESOLVE,
        on_failure="stop",
        scan_result=scan,
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    saved = load_scan_results("demo")
    assert saved.updates[0].update_status == UpdateStatus.FAILED
    assert saved.updates[0].failed_phase == "unit"
    assert saved.updates[0].flow == Workflow.RESOLVE


@pytest.mark.parametrize(
    ("failure", "passed", "status", "failed_phase"),
    [
        (True, False, UpdateStatus.FAILED, "unit"),
        (False, True, UpdateStatus.READY, None),
    ],
    ids=["failure", "success"],
)
def test_grouped_vulnerability_result_is_persisted_for_every_original(
    failure: bool,
    passed: bool,
    status: UpdateStatus,
    failed_phase: str | None,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    if failure:
        processor_vcs["phase"].side_effect = ProcessError("unit failed")
    vulns = [
        make_vuln(vuln_id="CVE-1", pkg_name="requests", fixed_version="2.31.0"),
        make_vuln(vuln_id="CVE-2", pkg_name="requests", fixed_version="2.32.4"),
    ]
    scan = ScanResult(
        project="demo",
        scanned_at=datetime.now(tz=UTC),
        trivy_target=str(project_config.path),
        vulnerabilities=vulns,
    )

    results = process_findings(
        consolidate_vulns(vulns),
        project_config,
        flow=Workflow.UPDATE,
        scan_result=scan,
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )

    assert [(result.kind, result.passed) for result in results] == [("vuln", passed)]
    saved = load_scan_results("demo")
    assert [
        (finding.update_status, finding.failed_phase, finding.flow)
        for finding in saved.vulnerabilities
    ] == [
        (status, failed_phase, Workflow.UPDATE),
        (status, failed_phase, Workflow.UPDATE),
    ]


def test_process_updates_sorts_by_risk(
    processor_vcs: ProcessorDeps, project_config: ProjectConfig
):
    findings = sort_updates_by_risk(
        [make_update(SemverTier.MAJOR), make_update(SemverTier.PATCH)]
    )
    results = process_findings(
        findings,
        project_config,
        flow=Workflow.UPDATE,
        scan_result=_scan_result_for(project_config, findings),
        vcs=_services(processor_vcs),
        emit=RecordingEmit(),
    )
    assert [result.pkg_name for result in results] == ["pkg-a", "pkg-c"]


def test_gradle_config_records_a_failed_apply_not_a_crash(tmp_path):
    """Unreachable by design; it must still degrade, not unwind the flow."""
    emit = RecordingEmit()
    assert _apply_update("gradle", "room", "2.8.5", tmp_path, emit=emit) is False
    assert emit.of_type(FindingStepFailed)[0].step is FindingStepKind.PREPARE
    assert "Gradle" in emit.of_type(FindingStepFailed)[0].error


def test_a_test_phase_timeout_is_recorded_as_a_failed_phase(
    project_config, monkeypatch
):
    def _timeout(command, cwd, **kwargs):
        msg = "unit tests timed out after 600s"
        raise ProcessError(msg)

    monkeypatch.setattr("maintenance_man.updater.run_live", _timeout)

    assert (
        run_test_phases(project_config, Path(project_config.path), emit=RecordingEmit())
        == "unit"
    )


def test_an_uncommitted_catalogue_edit_blocks_with_a_workspace_hint(
    gradle_project, tmp_path
):
    target = make_gradle_target()
    catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        catalogue.read_text(encoding="utf-8").replace(
            'room = "2.8.4"', 'room = "2.8.6"'
        ),
        encoding="utf-8",
    )

    block = validate_gradle_target(gradle_project, target)

    assert block is not None and block.kind == "stale"
    assert "update workspace" in block.reason


def test_bun_update_without_a_manifest_runs_no_command(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "maintenance_man.updater.run_logged",
        lambda *args, **kwargs: pytest.fail("no command may run"),
    )
    emit = RecordingEmit()
    assert _apply_update("bun", "zod", "4.6.5", tmp_path, emit=emit) is False
    assert emit.of_type(FindingStepFailed)[0].step is FindingStepKind.PREPARE
    assert "package.json" in emit.of_type(FindingStepFailed)[0].error
