import dataclasses
import shlex
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict
from unittest.mock import MagicMock, call

import pytest

from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    FindingFailed,
    FindingsBlocked,
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
    UpdateResult,
    UpdateStatus,
    Workflow,
)
from maintenance_man.package_managers import package_manager_ops
from maintenance_man.process import ProcessError
from maintenance_man.storage import load_scan_results
from maintenance_man.updater import (
    Applied,
    ApplyFailed,
    Blocked,
    FailureStrategy,
    Finding,
    _apply_update,
    apply_finding,
    consolidate_vulns,
    group_findings,
    process_findings,
    remove_completed_findings,
    run_test_phases,
    sort_updates_by_risk,
)
from maintenance_man.uv_dependencies import (
    UvUngroupedLocation,
    get_uv_dependency_locations,
)
from maintenance_man.vcs import JjRepository, RevisionError
from maintenance_man.vcs_workflow import VcsServices, make_vcs_services
from tests.fakes import RecordingEmit
from tests.support.findings import (
    make_gradle_member,
    make_gradle_target,
    make_scan_result,
    make_update,
    make_vuln,
)
from tests.support.gradle import catalogue_apply_runner
from tests.support.process import completed
from tests.support.projects import make_project
from tests.support.repository import (
    MANAGED,
    commit_descriptions,
    commit_to_main,
    copy_jj_repository,
    fail_repository_method,
    operation_id,
    write_file,
)

_ROOM = make_gradle_target()
_KSP = make_gradle_target(
    version_ref="ksp",
    members=[
        make_gradle_member(
            kind="plugin",
            alias="ksp",
            coordinate="com.google.devtools.ksp",
            installed_version="2.3.10",
        )
    ],
    target_version="2.3.12",
)
_DRIFT_REASON = (
    "'room-runtime' is at 2.8.7, expected 2.8.4; the catalogue no longer matches "
    "the scan; note that an uncommitted catalogue edit is not visible in the "
    "update workspace. Rescan required"
)


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
        path=tmp_path / "project", package_manager="bun", test_unit="bun test"
    )


class ProcessorDeps(TypedDict):
    repo: JjRepository
    services: VcsServices
    package: MagicMock
    phase: MagicMock


@pytest.fixture()
def processor_vcs(
    monkeypatch: pytest.MonkeyPatch, project_config: ProjectConfig
) -> ProcessorDeps:
    """Use real repository transitions while substituting package/test commands."""
    repo = copy_jj_repository(Path(project_config.path))
    write_file(repo, "package.json", "{}\n")
    commit_to_main(repo, "add package manifest")

    def run_package(cmd, cwd, **kwargs):
        dep = Path(cwd) / "dep.txt"
        dep.write_text(
            f"{dep.read_text(encoding='utf-8')}{cmd[-1]}\n", encoding="utf-8"
        )
        return completed(cmd, returncode=0, stdout="", stderr="")

    package = MagicMock(side_effect=run_package)
    phase = MagicMock(return_value=None)
    monkeypatch.setattr("maintenance_man.updater.run_logged", package)
    monkeypatch.setattr("maintenance_man.updater.run_shell_command", phase)
    return {
        "repo": repo,
        "services": make_vcs_services(),
        "package": package,
        "phase": phase,
    }


def _process(
    findings: Sequence[Finding],
    project_config: ProjectConfig,
    deps: ProcessorDeps,
    *,
    flow: Workflow = Workflow.UPDATE,
    on_failure: FailureStrategy = "continue",
    scan: ScanResult | None = None,
    emit: RecordingEmit | None = None,
) -> list[UpdateResult]:
    updates = [item for item in findings if isinstance(item, UpdateFinding)]
    return process_findings(
        findings,
        project_config,
        flow=flow,
        on_failure=on_failure,
        scan_result=_scan_result_for(project_config, updates) if scan is None else scan,
        vcs=deps["services"],
        emit=RecordingEmit() if emit is None else emit,
    )


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


@pytest.mark.parametrize(
    ("package_manager", "message"),
    [
        ("uv", "Failed to read"),
        ("gradle", "Gradle updates are applied through the Gradle adapter"),
        ("bun", "package.json is missing"),
    ],
)
def test_given_unpreparable_update_when_applied_then_prepare_failure_and_no_command(
    package_manager: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "maintenance_man.updater.run_logged",
        lambda *args, **kwargs: pytest.fail("no command may run"),
    )
    emit = RecordingEmit()

    applied = _apply_update(package_manager, "pkg", "1.0.0", tmp_path, emit=emit)

    assert applied is False
    failures = emit.of_type(FindingStepFailed)
    assert [failure.step for failure in failures] == [FindingStepKind.PREPARE]
    assert message in failures[0].error


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


# -- run_test_phases --


@pytest.mark.parametrize(
    ("fields", "failing", "expected_phase", "expected_commands"),
    [
        pytest.param(
            {"test_unit": "bun test", "test_integration": "bun run test:integration"},
            None,
            None,
            ["bun test", "bun run test:integration"],
            id="all-green",
        ),
        pytest.param(
            {"test_unit": "bun test"},
            None,
            None,
            ["bun test"],
            id="unconfigured-phases-are-skipped",
        ),
        pytest.param(
            {"test_unit": "  ", "test_integration": "bun run test:integration"},
            None,
            None,
            ["bun run test:integration"],
            id="blank-phase-is-skipped",
        ),
        pytest.param(
            {"test_unit": "bun test"},
            "bun test",
            "unit",
            ["bun test"],
            id="unit-fails",
        ),
        pytest.param(
            {"test_unit": "bun test", "test_integration": "bun run test:integration"},
            "bun run test:integration",
            "integration",
            ["bun test", "bun run test:integration"],
            id="integration-fails",
        ),
        pytest.param(
            {"test_unit": "bun test", "test_integration": "bun run test:integration"},
            "bun test",
            "unit",
            ["bun test"],
            id="first-failure-stops-later-phases",
        ),
    ],
)
def test_given_test_phases_when_run_then_first_failure_stops_later_phases(
    fields: dict[str, str],
    failing: str | None,
    expected_phase: str | None,
    expected_commands: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    commands: list[str] = []

    def run_shell_command(command, cwd, **kwargs):
        commands.append(command)
        if command == failing:
            msg = f"{kwargs['label']} failed (exit 1)"
            raise ProcessError(msg)

    monkeypatch.setattr("maintenance_man.updater.run_shell_command", run_shell_command)
    config = make_project(tmp_path, package_manager="bun", **fields)

    failed_phase = run_test_phases(config, tmp_path, emit=RecordingEmit())

    assert failed_phase == expected_phase
    assert commands == expected_commands


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


def test_test_phase_launch_failure_is_a_failed_phase(tmp_path):
    config = ProjectConfig(path=tmp_path, package_manager="bun", test_unit="true")
    emit = RecordingEmit()
    assert run_test_phases(config, tmp_path / "missing", emit=emit) == "unit"
    assert emit.events[0] == CommandStartedEvent("true")
    assert emit.of_type(FindingStepFailed)[0].step is FindingStepKind.TEST
    assert "Could not run unit tests" in emit.of_type(FindingStepFailed)[0].error


# -- sort_updates_by_risk --


class TestSortUpdatesByRisk:
    @pytest.mark.parametrize(
        ("tiers", "expected"),
        [
            (
                [SemverTier.MAJOR, SemverTier.PATCH, SemverTier.MINOR],
                [SemverTier.PATCH, SemverTier.MINOR, SemverTier.MAJOR],
            ),
            ([SemverTier.MINOR], [SemverTier.MINOR]),
            ([], []),
        ],
    )
    def test_sorts_patch_minor_major(self, tiers, expected):
        updates = [make_update(tier) for tier in tiers]

        assert [u.semver_tier for u in sort_updates_by_risk(updates)] == expected


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


_READY = (UpdateStatus.READY, None)
_FAILED_UNIT = (UpdateStatus.FAILED, "unit")
_FAILED_APPLY = (UpdateStatus.FAILED, "apply")
_FAILED_COMMIT = (UpdateStatus.FAILED, "commit")
_UNPROCESSED = (None, None)
_PATCH_COMMIT = "chore: bump pkg-a 1.0.0 -> 1.0.1 (patch)"
_MINOR_COMMIT = "chore: bump pkg-b 1.0.0 -> 1.1.0 (minor)"
_MAJOR_COMMIT = "chore: bump pkg-c 1.0.0 -> 2.0.0 (major)"


@pytest.mark.parametrize(
    (
        "flow",
        "on_failure",
        "outcomes",
        "expected_passed",
        "expected_saved",
        "expected_descriptions",
        "expected_dep",
    ),
    [
        pytest.param(
            Workflow.UPDATE,
            "continue",
            ["pass", "unit", "pass"],
            [True, False, True],
            [_READY, _FAILED_UNIT, _READY],
            [_PATCH_COMMIT, _MAJOR_COMMIT],
            "version=1\npkg-a@1.0.1\npkg-c@2.0.0\n",
            id="update-discards-the-failed-finding-and-continues",
        ),
        pytest.param(
            Workflow.UPDATE,
            "continue",
            ["apply", "pass"],
            [False, True],
            [_FAILED_APPLY, _READY],
            [_MINOR_COMMIT],
            "version=1\npkg-b@1.1.0\n",
            id="update-continues-after-an-apply-failure",
        ),
        pytest.param(
            Workflow.RESOLVE,
            "stop",
            ["pass", "unit", "pass"],
            [True, False],
            [_READY, _FAILED_UNIT, _UNPROCESSED],
            [_PATCH_COMMIT],
            "version=1\npkg-a@1.0.1\npkg-b@1.1.0\n",
            id="resolve-keeps-the-failed-change-and-stops",
        ),
        pytest.param(
            Workflow.RESOLVE,
            "stop",
            ["apply", "pass"],
            [False],
            [_FAILED_APPLY, _UNPROCESSED],
            [],
            "version=1\npkg-a@1.0.1\n",
            id="resolve-stops-after-an-apply-failure",
        ),
        pytest.param(
            Workflow.RESOLVE,
            "stop",
            ["commit", "pass"],
            [False],
            [_FAILED_COMMIT, _UNPROCESSED],
            [],
            "version=1\npkg-a@1.0.1\n",
            id="resolve-keeps-the-change-after-a-commit-failure",
        ),
    ],
)
def test_given_step_outcome_when_processed_then_status_discard_and_stop_follow_the_flow(
    flow: Workflow,
    on_failure: FailureStrategy,
    outcomes: list[str],
    expected_passed: list[bool],
    expected_saved: list[tuple[UpdateStatus | None, str | None]],
    expected_descriptions: list[str],
    expected_dep: str,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
    monkeypatch: pytest.MonkeyPatch,
):
    repo = processor_vcs["repo"]
    findings = [
        make_update(),
        make_update(SemverTier.MINOR),
        make_update(SemverTier.MAJOR),
    ][: len(outcomes)]
    attempted: list[str] = []
    write_dep = processor_vcs["package"].side_effect

    def run_package(cmd, cwd, **kwargs):
        attempted.append(outcomes[len(attempted)])
        completed_command = write_dep(cmd, cwd, **kwargs)
        if attempted[-1] == "apply":
            msg = "package failed"
            raise ProcessError(msg)
        return completed_command

    def run_phase(command, cwd, **kwargs):
        if attempted[-1] == "unit":
            msg = "unit failed"
            raise ProcessError(msg)

    processor_vcs["package"].side_effect = run_package
    processor_vcs["phase"].side_effect = run_phase
    if "commit" in outcomes:
        fail_repository_method(
            monkeypatch, repo.path, "commit", RevisionError("cannot commit")
        )

    results = _process(
        findings, project_config, processor_vcs, flow=flow, on_failure=on_failure
    )

    assert [result.passed for result in results] == expected_passed
    assert [
        (row.update_status, row.failed_phase)
        for row in load_scan_results("demo").updates
    ] == expected_saved
    assert commit_descriptions(repo, "main..@-") == expected_descriptions
    assert (repo.path / "dep.txt").read_text(encoding="utf-8") == expected_dep


@pytest.mark.parametrize(
    ("flow", "on_failure", "bookmark"),
    [
        (Workflow.UPDATE, "continue", MANAGED),
        (Workflow.RESOLVE, "stop", "mm/resolve-dependencies"),
    ],
)
@pytest.mark.parametrize("count", [1, 2])
def test_given_passing_findings_when_processed_then_each_is_committed_and_bookmarked(
    flow: Workflow,
    on_failure: FailureStrategy,
    bookmark: str,
    count: int,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    findings = [make_update(), make_update(SemverTier.MINOR)][:count]
    project_path = Path(project_config.path)

    results = _process(
        findings, project_config, processor_vcs, flow=flow, on_failure=on_failure
    )

    repo = processor_vcs["repo"]
    package, phase = processor_vcs["package"], processor_vcs["phase"]
    assert [result.passed for result in results] == [True] * count
    assert [(row.update_status, row.failed_phase, row.flow) for row in findings] == [
        (UpdateStatus.READY, None, flow)
    ] * count
    assert (
        commit_descriptions(repo, "main..@-") == [_PATCH_COMMIT, _MINOR_COMMIT][:count]
    )
    assert repo.same_revision(left=bookmark, right="@-")
    assert package.call_count == phase.call_count == count
    assert package.call_args_list[0] == call(
        ["bun", "add", "pkg-a@1.0.1"],
        project_path,
        timeout=300,
        label="bun add pkg-a@1.0.1",
        stdin=subprocess.DEVNULL,
    )
    assert phase.call_args_list[0] == call(
        "bun test", project_path, timeout=600, label="unit tests"
    )


@pytest.mark.parametrize(
    ("flow", "on_failure"),
    [(Workflow.UPDATE, "continue"), (Workflow.RESOLVE, "stop")],
)
def test_already_applied_is_ready_without_a_commit(
    flow: Workflow,
    on_failure: FailureStrategy,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    processor_vcs["package"].side_effect = lambda cmd, cwd, **kwargs: completed(
        cmd, returncode=0, stdout="", stderr=""
    )
    update = make_update()

    results = _process(
        [update], project_config, processor_vcs, flow=flow, on_failure=on_failure
    )

    assert results[0].passed is True
    assert update.update_status == UpdateStatus.READY
    assert update.flow == flow
    assert commit_descriptions(processor_vcs["repo"], "main..@-") == []


@pytest.mark.parametrize(
    ("method", "expected_passed", "expected_descriptions", "expected_dep"),
    [
        pytest.param(
            "has_changes", [False], [], "version=1\npkg-a@1.0.1\n", id="has_changes"
        ),
        pytest.param(
            "commit",
            [False, True],
            [_MINOR_COMMIT],
            "version=1\npkg-b@1.1.0\n",
            id="commit",
        ),
        pytest.param(
            "set_bookmark",
            [False],
            [_PATCH_COMMIT],
            "version=1\npkg-a@1.0.1\n",
            id="set_bookmark",
        ),
    ],
)
def test_repository_failure_never_saves_ready(
    method: str,
    expected_passed: list[bool],
    expected_descriptions: list[str],
    expected_dep: str,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
    monkeypatch: pytest.MonkeyPatch,
):
    repo = processor_vcs["repo"]
    fail_repository_method(monkeypatch, repo.path, method, RevisionError("injected"))

    results = _process(
        [make_update(), make_update(SemverTier.MINOR)], project_config, processor_vcs
    )

    saved = load_scan_results("demo")
    assert saved.updates[0].update_status == UpdateStatus.FAILED
    assert saved.updates[0].failed_phase == "commit"
    assert [result.passed for result in results] == expected_passed
    assert commit_descriptions(repo, "main..@-") == expected_descriptions
    assert (repo.path / "dep.txt").read_text(encoding="utf-8") == expected_dep


def test_given_failing_package_command_when_processed_then_apply_failure_emitted_once(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    processor_vcs["package"].side_effect = ProcessError("package failed")
    emit = RecordingEmit()

    _process([make_update()], project_config, processor_vcs, emit=emit)

    assert emit.events[-2:] == [
        FindingStepFailed(FindingStepKind.PACKAGE_COMMAND, "package failed"),
        FindingFailed("pkg-a", "apply", "1.0.0", "1.0.1"),
    ]
    assert len(emit.of_type(FindingFailed)) == 1


def test_empty_findings_have_no_repository_effects(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    before = operation_id(processor_vcs["repo"])

    assert _process([], project_config, processor_vcs) == []

    assert operation_id(processor_vcs["repo"]) == before


def test_failed_discard_persists_original_failure_and_stops(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
    monkeypatch: pytest.MonkeyPatch,
):
    processor_vcs["phase"].side_effect = ProcessError("unit failed")

    original_discard = JjRepository.discard

    def discard_after_checking_saved_failure(repository: JjRepository) -> None:
        if repository.path.resolve() != processor_vcs["repo"].path.resolve():
            original_discard(repository)
            return
        saved = load_scan_results("demo")
        assert (saved.updates[0].update_status, saved.updates[0].failed_phase) == (
            UpdateStatus.FAILED,
            "unit",
        )
        msg = "cannot discard"
        raise RevisionError(msg)

    monkeypatch.setattr(JjRepository, "discard", discard_after_checking_saved_failure)
    emit = RecordingEmit()

    results = _process(
        [make_update(), make_update(SemverTier.MINOR)],
        project_config,
        processor_vcs,
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
    inspected_before_second_finding: list[bool] = []
    package_effect = processor_vcs["package"].side_effect
    assert callable(package_effect)

    def run_package(*args: object, **kwargs: object) -> object:
        if processor_vcs["package"].call_count == 2:
            saved = load_scan_results("demo")
            assert [finding.update_status for finding in saved.updates] == [
                UpdateStatus.READY,
                None,
            ]
            inspected_before_second_finding.append(True)
        return package_effect(*args, **kwargs)

    processor_vcs["package"].side_effect = run_package
    processor_vcs["phase"].side_effect = [None, ProcessError("unit failed")]

    _process(
        [make_update(), make_update(SemverTier.MINOR)], project_config, processor_vcs
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

    _process(
        [make_update(update_status=UpdateStatus.FAILED)],
        project_config,
        processor_vcs,
        flow=Workflow.RESOLVE,
        on_failure="stop",
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
    scan = _scan_result_for(project_config, [])
    scan.vulnerabilities = vulns

    results = _process(group_findings(vulns), project_config, processor_vcs, scan=scan)

    assert [(result.kind, result.passed) for result in results] == [("vuln", passed)]
    saved = load_scan_results("demo")
    assert [
        (finding.update_status, finding.failed_phase, finding.flow)
        for finding in saved.vulnerabilities
    ] == [
        (status, failed_phase, Workflow.UPDATE),
        (status, failed_phase, Workflow.UPDATE),
    ]


def _group_summary(findings):
    return [
        (f.pkg_name, f.installed_version, f.target_version, f.detail) for f in findings
    ]


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        pytest.param(
            [
                make_vuln(
                    vuln_id="CVE-1",
                    pkg_name="androidx.room:room-runtime",
                    fixed_version="2.8.5",
                    gradle_target=_ROOM,
                ),
                make_update(pkg_name="room", gradle_target=_ROOM),
            ],
            [("room", "2.8.4", "2.8.5", "CVE-1, patch")],
            id="ordinary-and-security-rows-share-a-target",
        ),
        pytest.param(
            [
                make_vuln(vuln_id="CVE-1", gradle_target=_ROOM),
                make_vuln(vuln_id="CVE-2", gradle_target=_ROOM),
            ],
            [("room", "2.8.4", "2.8.5", "CVE-1, CVE-2")],
            id="two-security-rows-share-a-target",
        ),
        pytest.param(
            [
                make_vuln(vuln_id="CVE-1", gradle_target=_ROOM),
                make_vuln(vuln_id="CVE-1", gradle_target=_KSP),
            ],
            [
                ("room", "2.8.4", "2.8.5", "CVE-1"),
                ("ksp", "2.3.10", "2.3.12", "CVE-1"),
            ],
            id="one-advisory-with-two-owner-targets",
        ),
        pytest.param(
            [
                make_update(
                    pkg_name="room",
                    gradle_target=_ROOM,
                    blocked_reason="publication younger than required 7 days",
                )
            ],
            [],
            id="blocked-row",
        ),
        pytest.param([make_vuln(fixed_version=None)], [], id="no-fix-and-no-target"),
        pytest.param(
            [
                make_vuln(
                    fixed_version=None,
                    gradle_target=_ROOM,
                    blocked_reason="no published fix",
                )
            ],
            [],
            id="no-fix-blocked-with-target",
        ),
        pytest.param(
            [
                make_update(SemverTier.MAJOR),
                make_vuln(vuln_id="CVE-1"),
                make_vuln(vuln_id="CVE-2"),
                make_update(),
            ],
            [
                ("some-pkg", "1.0.0", "1.0.1", "CVE-1, CVE-2"),
                ("pkg-a", "1.0.0", "1.0.1", "patch"),
                ("pkg-c", "1.0.0", "2.0.0", "major"),
            ],
            id="native-rows-by-package-then-risk",
        ),
    ],
)
def test_given_saved_rows_when_grouped_then_one_change_per_target_or_package(
    rows, expected
):
    assert _group_summary(group_findings(rows)) == expected


@pytest.mark.parametrize(
    ("catalogue_room", "edits", "returncode", "expected", "commands", "step_failures"),
    [
        pytest.param("2.8.4", None, 0, Applied(), 1, [], id="report-driven-apply"),
        pytest.param("2.8.5", {}, 0, Applied(), 0, [], id="already-applied"),
        pytest.param(
            "2.8.7", {}, 0, Blocked(_DRIFT_REASON), 0, [], id="drifted-catalogue"
        ),
        pytest.param(
            "2.8.4",
            {},
            1,
            ApplyFailed(),
            1,
            [
                FindingStepFailed(
                    FindingStepKind.PACKAGE_COMMAND,
                    "./gradlew versionCatalogApplyUpdates failed (exit 1)",
                )
            ],
            id="gradle-command-fails",
        ),
    ],
)
def test_given_saved_target_when_applied_then_outcome_matches_catalogue_state(
    gradle_project,
    monkeypatch,
    catalogue_room,
    edits,
    returncode,
    expected,
    commands,
    step_failures,
):
    catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        catalogue.read_text(encoding="utf-8").replace(
            'room = "2.8.4"', f'room = "{catalogue_room}"'
        ),
        encoding="utf-8",
    )
    runner = MagicMock(side_effect=catalogue_apply_runner(edits, returncode=returncode))
    monkeypatch.setattr("maintenance_man.gradle.run_logged", runner)
    emit = RecordingEmit()

    outcome = apply_finding(
        gradle_project,
        make_update(pkg_name="room", gradle_target=_ROOM),
        emit=emit,
    )

    assert outcome == expected
    assert runner.call_count == commands
    assert emit.of_type(FindingStepFailed) == step_failures


@pytest.fixture()
def gradle_processor(
    monkeypatch: pytest.MonkeyPatch, gradle_project: ProjectConfig
) -> ProcessorDeps:
    """A copied Gradle repository whose wrapper applies the selected report."""
    repo = copy_jj_repository(Path(gradle_project.path))
    commit_to_main(repo, "gradle project")
    package = MagicMock(side_effect=catalogue_apply_runner())
    phase = MagicMock()
    monkeypatch.setattr("maintenance_man.gradle.run_logged", package)
    monkeypatch.setattr("maintenance_man.updater.run_shell_command", phase)
    return {
        "repo": repo,
        "services": make_vcs_services(),
        "package": package,
        "phase": phase,
    }


def test_given_rows_of_one_target_when_processed_then_one_change_marks_both_ready(
    gradle_processor: ProcessorDeps, gradle_project: ProjectConfig
):
    vuln = make_vuln(
        vuln_id="CVE-1",
        pkg_name="androidx.room:room-runtime",
        fixed_version="2.8.5",
        gradle_target=_ROOM,
    )
    update = make_update(pkg_name="room", gradle_target=_ROOM)
    rows = [vuln, update]
    scan = make_scan_result(vulns=[vuln], updates=[update])
    scan.project = "demo"

    results = _process(
        group_findings(rows), gradle_project, gradle_processor, scan=scan
    )

    repo = gradle_processor["repo"]
    assert results == [UpdateResult("room", "vuln", True)]
    assert gradle_processor["package"].call_count == 1
    assert gradle_processor["phase"].call_count == 1
    assert commit_descriptions(repo, "main..@-") == [
        "fix: upgrade room 2.8.4 -> 2.8.5 for CVE-1, patch"
    ]
    assert repo.same_revision(left=MANAGED, right="@-")
    assert 'room = "2.8.5"' in (
        Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
    ).read_text(encoding="utf-8")
    saved = load_scan_results("demo")
    assert [
        (row.update_status, row.failed_phase, row.flow)
        for row in (*saved.vulnerabilities, *saved.updates)
    ] == [(UpdateStatus.READY, None, Workflow.UPDATE)] * 2


def test_given_two_owner_targets_when_one_fails_then_statuses_stay_independent(
    gradle_processor: ProcessorDeps, gradle_project: ProjectConfig
):
    advisory = make_vuln(
        vuln_id="CVE-1",
        pkg_name="androidx.room:room-runtime",
        installed_version="2.8.4",
        fixed_version="2.8.5",
    )
    rows = [
        advisory.model_copy(update={"gradle_target": _ROOM}),
        advisory.model_copy(update={"gradle_target": _KSP}),
    ]
    gradle_processor["phase"].side_effect = [None, ProcessError("unit failed")]
    scan = make_scan_result(vulns=rows, updates=[])
    scan.project = "demo"

    _process(group_findings(rows), gradle_project, gradle_processor, scan=scan)

    catalogue = (Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH).read_text(
        encoding="utf-8"
    )
    saved = load_scan_results("demo")
    assert gradle_processor["package"].call_count == 2
    assert [(row.update_status, row.failed_phase) for row in saved.vulnerabilities] == [
        (UpdateStatus.READY, None),
        (UpdateStatus.FAILED, "unit"),
    ]
    assert 'room = "2.8.5"' in catalogue
    assert 'ksp = "2.3.10"' in catalogue


def test_given_drifted_target_when_processed_then_rows_are_blocked_without_effects(
    gradle_processor: ProcessorDeps, gradle_project: ProjectConfig
):
    catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        catalogue.read_text(encoding="utf-8").replace(
            'room = "2.8.4"', 'room = "2.8.7"'
        ),
        encoding="utf-8",
    )
    row = make_update(
        pkg_name="room",
        gradle_target=_ROOM,
        update_status=UpdateStatus.FAILED,
        failed_phase="unit",
        flow=Workflow.UPDATE,
    )
    scan = make_scan_result(vulns=[], updates=[row])
    scan.project = "demo"
    emit = RecordingEmit()
    before = operation_id(gradle_processor["repo"])

    results = _process(
        group_findings([row]), gradle_project, gradle_processor, scan=scan, emit=emit
    )

    saved = load_scan_results("demo").updates[0]
    assert results == []
    assert operation_id(gradle_processor["repo"]) == before
    assert gradle_processor["phase"].call_count == 0
    assert (
        saved.blocked_reason,
        saved.update_status,
        saved.failed_phase,
        saved.flow,
    ) == (_DRIFT_REASON, None, None, None)
    assert emit.of_type(FindingsBlocked) == [
        FindingsBlocked((("room", _DRIFT_REASON),))
    ]
