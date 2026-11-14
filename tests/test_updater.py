import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict
from unittest.mock import MagicMock, call

import pytest

from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
)
from maintenance_man.models.config import PackageManager, ProjectConfig
from maintenance_man.models.events import (
    FindingFailed,
    FindingsBlocked,
    FindingStepFailed,
)
from maintenance_man.models.events import (
    TestCommandStarted as CommandStartedEvent,
)
from maintenance_man.models.scan import (
    Failed,
    FindingState,
    GradleBlock,
    Ready,
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateResult,
    VulnFinding,
    Workflow,
)
from maintenance_man.process import ProcessError
from maintenance_man.storage import load_scan_results
from maintenance_man.updater import (
    Applied,
    ApplyFailed,
    Blocked,
    FindingGroup,
    _apply_update,
    apply_finding,
    group_findings,
    process_findings,
    run_test_phases,
)
from maintenance_man.vcs import JjRepository, RevisionError
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
from tests.support.projects import make_project, write_bun_manifest
from tests.support.repository import (
    MANAGED,
    commit_descriptions,
    commit_to_main,
    copy_jj_repository,
    describe,
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
_DRIFT_BLOCK = GradleBlock(kind="stale", reason=_DRIFT_REASON)


def _scan_result_for(
    project_config: ProjectConfig, updates: list[UpdateFinding]
) -> ScanResult:
    return ScanResult(
        project="demo",
        package_manager=project_config.package_manager,
        scanned_at=datetime.now(tz=UTC),
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
    package: MagicMock
    phase: MagicMock


_PROCESSED_VERSIONS = dict.fromkeys(
    ("pkg-a", "pkg-b", "pkg-c", "some-pkg", "requests"), "1.0.0"
)


@pytest.fixture()
def processor_vcs(
    monkeypatch: pytest.MonkeyPatch, project_config: ProjectConfig
) -> ProcessorDeps:
    """Use real repository transitions while substituting package/test commands."""
    repo = copy_jj_repository(Path(project_config.path))
    write_bun_manifest(repo, _PROCESSED_VERSIONS)
    commit_to_main(repo, "add package manifest")
    monkeypatch.setattr(
        "maintenance_man.package_managers.resolved_bun_versions",
        lambda _path: _PROCESSED_VERSIONS,
    )

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
    return {"repo": repo, "package": package, "phase": phase}


def _process(
    findings: Sequence[FindingGroup | VulnFinding | UpdateFinding],
    project_config: ProjectConfig,
    deps: ProcessorDeps,
    *,
    flow: Workflow = Workflow.UPDATE,
    scan: ScanResult | None = None,
    emit: RecordingEmit | None = None,
) -> list[UpdateResult]:
    updates = [item for item in findings if isinstance(item, UpdateFinding)]
    groups = [
        item if isinstance(item, FindingGroup) else group_findings([item])[0]
        for item in findings
    ]
    return process_findings(
        groups,
        project_config,
        flow=flow,
        scan_result=_scan_result_for(project_config, updates) if scan is None else scan,
        emit=RecordingEmit() if emit is None else emit,
    )


_PYTEST_IN_THREE_TABLES = (
    '[project]\ndependencies = ["pytest>=8.0"]\n\n'
    "[dependency-groups]\n"
    'dev = ["pytest>=8.0"]\n'
    'lint = ["pytest>=8.0"]\n'
)


@pytest.mark.parametrize(
    ("manager", "pkg", "version", "failing_call", "expected_calls", "expected_errors"),
    [
        pytest.param(
            "uv",
            "pytest",
            "9.0.3",
            None,
            [
                ["uv", "add", "pytest==9.0.3"],
                ["uv", "add", "--group", "dev", "pytest==9.0.3"],
                ["uv", "add", "--group", "lint", "pytest==9.0.3"],
            ],
            [],
            id="uv-runs-every-declaration-in-order",
        ),
        pytest.param(
            "uv",
            "pytest",
            "9.0.3",
            2,
            [
                ["uv", "add", "pytest==9.0.3"],
                ["uv", "add", "--group", "dev", "pytest==9.0.3"],
            ],
            ["uv add --group dev pytest==9.0.3 failed"],
            id="uv-stops-at-the-first-failure",
        ),
        pytest.param(
            "mvn",
            "g:a",
            "2.0",
            2,
            [
                [
                    "mvn",
                    "versions:use-dep-version",
                    "-Dincludes=g:a",
                    "-DdepVersion=2.0",
                ],
                ["mvn", "versions:commit"],
            ],
            ["mvn versions:commit failed"],
            id="mvn-commit-failure-fails-the-apply",
        ),
        pytest.param(
            "mvn",
            "g:a",
            "2.0",
            1,
            [["mvn", "versions:use-dep-version", "-Dincludes=g:a", "-DdepVersion=2.0"]],
            ["mvn versions:use-dep-version -Dincludes=g:a -DdepVersion=2.0 failed"],
            id="mvn-commit-never-runs-after-a-failed-update",
        ),
    ],
)
def test_given_package_commands_when_applied_then_first_failure_stops_and_is_reported(
    manager: PackageManager,
    pkg: str,
    version: str,
    failing_call: int | None,
    expected_calls: list[list[str]],
    expected_errors: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(_PYTEST_IN_THREE_TABLES, encoding="utf-8")
    calls: list[list[str]] = []

    def run(cmd, cwd, **kwargs):
        calls.append(cmd)
        if len(calls) == failing_call:
            msg = f"{kwargs['label']} failed"
            raise ProcessError(msg)
        return completed(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("maintenance_man.updater.run_logged", run)
    emit = RecordingEmit()

    applied = _apply_update(manager, pkg, "1.0.0", version, tmp_path, emit=emit)

    assert applied is (failing_call is None)
    assert calls == expected_calls
    failures = emit.of_type(FindingStepFailed)
    assert [failure.error for failure in failures] == expected_errors
    assert {failure.step for failure in failures} <= {"package command"}


@pytest.mark.parametrize(
    ("package_manager", "message"),
    [
        ("uv", "Failed to read"),
        ("gradle", "Gradle updates are applied through the Gradle adapter"),
        ("bun", "Failed to read"),
    ],
)
def test_given_unpreparable_update_when_applied_then_prepare_failure_and_no_command(
    package_manager: PackageManager,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setattr(
        "maintenance_man.updater.run_logged",
        lambda *args, **kwargs: pytest.fail("no command may run"),
    )
    emit = RecordingEmit()

    applied = _apply_update(
        package_manager, "pkg", "1.0.0", "1.0.1", tmp_path, emit=emit
    )

    assert applied is False
    failures = emit.of_type(FindingStepFailed)
    assert [failure.step for failure in failures] == ["prepare"]
    assert message in failures[0].error


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


def test_test_phase_launch_failure_is_a_failed_phase(tmp_path):
    config = ProjectConfig(path=tmp_path, package_manager="bun", test_unit="true")
    emit = RecordingEmit()
    assert run_test_phases(config, tmp_path / "missing", emit=emit) == "unit"
    assert emit.events[0] == CommandStartedEvent("true")
    assert emit.of_type(FindingStepFailed)[0].step == "test"
    assert "Could not run unit tests" in emit.of_type(FindingStepFailed)[0].error


# -- process_findings --


_UPDATE_READY = Ready(flow=Workflow.UPDATE)
_UPDATE_FAILED_UNIT = Failed(flow=Workflow.UPDATE, phase="unit")
_UPDATE_FAILED_APPLY = Failed(flow=Workflow.UPDATE, phase="apply")
_RESOLVE_READY = Ready(flow=Workflow.RESOLVE)
_RESOLVE_FAILED_UNIT = Failed(flow=Workflow.RESOLVE, phase="unit")
_RESOLVE_FAILED_APPLY = Failed(flow=Workflow.RESOLVE, phase="apply")
_RESOLVE_FAILED_COMMIT = Failed(flow=Workflow.RESOLVE, phase="commit")
_PATCH_COMMIT = "chore: bump pkg-a 1.0.0 -> 1.0.1 (patch)"
_MINOR_COMMIT = "chore: bump pkg-b 1.0.0 -> 1.1.0 (minor)"
_MAJOR_COMMIT = "chore: bump pkg-c 1.0.0 -> 2.0.0 (major)"


@pytest.mark.parametrize(
    (
        "flow",
        "outcomes",
        "expected_passed",
        "expected_saved",
        "expected_descriptions",
        "expected_dep",
    ),
    [
        pytest.param(
            Workflow.UPDATE,
            ["pass", "unit", "pass"],
            [True, False, True],
            [_UPDATE_READY, _UPDATE_FAILED_UNIT, _UPDATE_READY],
            [_PATCH_COMMIT, _MAJOR_COMMIT],
            "version=1\npkg-a@1.0.1\npkg-c@2.0.0\n",
            id="update-discards-the-failed-finding-and-continues",
        ),
        pytest.param(
            Workflow.UPDATE,
            ["apply", "pass"],
            [False, True],
            [_UPDATE_FAILED_APPLY, _UPDATE_READY],
            [_MINOR_COMMIT],
            "version=1\npkg-b@1.1.0\n",
            id="update-continues-after-an-apply-failure",
        ),
        pytest.param(
            Workflow.RESOLVE,
            ["pass", "unit", "pass"],
            [True, False],
            [_RESOLVE_READY, _RESOLVE_FAILED_UNIT, None],
            [_PATCH_COMMIT],
            "version=1\npkg-a@1.0.1\npkg-b@1.1.0\n",
            id="resolve-keeps-the-failed-change-and-stops",
        ),
        pytest.param(
            Workflow.RESOLVE,
            ["apply", "pass"],
            [False],
            [_RESOLVE_FAILED_APPLY, None],
            [],
            "version=1\npkg-a@1.0.1\n",
            id="resolve-stops-after-an-apply-failure",
        ),
        pytest.param(
            Workflow.RESOLVE,
            ["commit", "pass"],
            [False],
            [_RESOLVE_FAILED_COMMIT, None],
            [],
            "version=1\npkg-a@1.0.1\n",
            id="resolve-keeps-the-change-after-a-commit-failure",
        ),
    ],
)
def test_given_step_outcome_when_processed_then_status_discard_and_stop_follow_the_flow(
    flow: Workflow,
    outcomes: list[str],
    expected_passed: list[bool],
    expected_saved: list[FindingState | None],
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

    results = _process(findings, project_config, processor_vcs, flow=flow)

    assert [result.passed for result in results] == expected_passed
    assert [row.state for row in load_scan_results("demo").updates] == expected_saved
    assert commit_descriptions(repo, "main..@-") == expected_descriptions
    assert (repo.path / "dep.txt").read_text(encoding="utf-8") == expected_dep


@pytest.mark.parametrize(
    ("flow", "bookmark"),
    [
        (Workflow.UPDATE, MANAGED),
        (Workflow.RESOLVE, "mm/resolve-dependencies"),
    ],
)
@pytest.mark.parametrize("count", [1, 2])
def test_given_passing_findings_when_processed_then_each_is_committed_and_bookmarked(
    flow: Workflow,
    bookmark: str,
    count: int,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    findings = [make_update(), make_update(SemverTier.MINOR)][:count]
    project_path = Path(project_config.path)

    results = _process(findings, project_config, processor_vcs, flow=flow)

    repo = processor_vcs["repo"]
    package, phase = processor_vcs["package"], processor_vcs["phase"]
    assert [result.passed for result in results] == [True] * count
    assert [row.state for row in findings] == [Ready(flow=flow)] * count
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
    ("flow", "already_uncommitted", "describes"),
    [
        pytest.param(Workflow.UPDATE, False, False, id="update"),
        pytest.param(Workflow.UPDATE, True, False, id="update-already-uncommitted"),
        pytest.param(Workflow.RESOLVE, False, False, id="resolve"),
        pytest.param(Workflow.RESOLVE, True, False, id="resolve-already-uncommitted"),
        pytest.param(Workflow.UPDATE, False, True, id="update-description-only"),
    ],
)
def test_given_package_commands_changing_no_files_when_processed_then_apply_fails(
    flow: Workflow,
    already_uncommitted: bool,
    describes: bool,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    repo = processor_vcs["repo"]

    def run_package(cmd, cwd, **kwargs):
        if describes:
            describe(repo, "changed by the command")
        return completed(cmd, returncode=0, stdout="", stderr="")

    processor_vcs["package"].side_effect = run_package
    if already_uncommitted:
        write_file(repo, "local.txt", "left by an earlier step\n")
    update = make_update()
    emit = RecordingEmit()

    results = _process([update], project_config, processor_vcs, flow=flow, emit=emit)

    assert results[0].passed is False
    assert results[0].failed_phase == "apply"
    assert update.state == Failed(flow=flow, phase="apply")
    assert emit.of_type(FindingStepFailed) == [
        FindingStepFailed(
            "package command",
            "Package commands for pkg-a changed no files; it may be transitive or "
            "already at 1.0.1. Run mm scan again.",
        )
    ]
    assert processor_vcs["phase"].call_count == 0
    assert commit_descriptions(repo, "main..@-") == []


@pytest.mark.parametrize(
    ("method", "expected_package_calls", "expected_dep"),
    [
        pytest.param("resolve_revision", 0, "version=1\n", id="read-before"),
        pytest.param(
            "has_file_changes_since", 1, "version=1\npkg-a@1.0.1\n", id="comparison"
        ),
    ],
)
def test_given_jj_failure_when_checking_for_file_changes_then_nothing_is_discarded(
    method: str,
    expected_package_calls: int,
    expected_dep: str,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
    monkeypatch: pytest.MonkeyPatch,
):
    repo = processor_vcs["repo"]
    fail_repository_method(monkeypatch, repo.path, method, RevisionError("jj failed"))
    discard = MagicMock()
    monkeypatch.setattr(JjRepository, "discard", discard)
    emit = RecordingEmit()

    results = _process(
        [make_update(), make_update(SemverTier.MINOR)],
        project_config,
        processor_vcs,
        emit=emit,
    )

    assert [(result.passed, result.failed_phase) for result in results] == [
        (False, "apply")
    ]
    assert emit.of_type(FindingStepFailed) == [
        FindingStepFailed("inspect", "jj failed")
    ]
    assert [row.state for row in load_scan_results("demo").updates] == [
        _UPDATE_FAILED_APPLY,
        None,
    ]
    assert discard.call_count == 0
    assert processor_vcs["package"].call_count == expected_package_calls
    assert (repo.path / "dep.txt").read_text(encoding="utf-8") == expected_dep


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
    assert saved.updates[0].state == Failed(flow=Workflow.UPDATE, phase="commit")
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
        FindingStepFailed("package command", "package failed"),
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
        assert saved.updates[0].state == _UPDATE_FAILED_UNIT
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
    assert saved.updates[0].state == _UPDATE_FAILED_UNIT
    assert emit.of_type(FindingStepFailed)[-1] == FindingStepFailed(
        "discard", "cannot discard"
    )


def test_given_two_findings_when_processed_then_each_state_is_saved_before_the_next(
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    inspected_before_second_finding: list[bool] = []
    package_effect = processor_vcs["package"].side_effect
    assert callable(package_effect)

    def run_package(*args: object, **kwargs: object) -> object:
        if processor_vcs["package"].call_count == 2:
            saved = load_scan_results("demo")
            assert [finding.state for finding in saved.updates] == [
                _UPDATE_READY,
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
    assert [finding.state for finding in saved.updates] == [
        _UPDATE_READY,
        _UPDATE_FAILED_UNIT,
    ]
    assert inspected_before_second_finding == [True]


@pytest.mark.parametrize(
    ("failure", "passed", "state"),
    [
        (True, False, _UPDATE_FAILED_UNIT),
        (False, True, _UPDATE_READY),
    ],
    ids=["failure", "success"],
)
def test_grouped_vulnerability_result_is_persisted_for_every_original(
    failure: bool,
    passed: bool,
    state: FindingState,
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    if failure:
        processor_vcs["phase"].side_effect = ProcessError("unit failed")
    vulns = [
        make_vuln(vuln_id="CVE-1", pkg_name="requests", fixed_version="2.32.4"),
        make_vuln(vuln_id="CVE-2", pkg_name="requests", fixed_version="2.32.4"),
    ]
    scan = _scan_result_for(project_config, [])
    scan.vulnerabilities = vulns

    results = _process(group_findings(vulns), project_config, processor_vcs, scan=scan)

    assert [(result.kind, result.passed) for result in results] == [("vuln", passed)]
    saved = load_scan_results("demo")
    assert [finding.state for finding in saved.vulnerabilities] == [state, state]


@pytest.mark.parametrize(
    "selected",
    [(0,), (1,), (2,), (0, 1), (0, 2), (1, 2), (0, 1, 2)],
)
def test_given_selected_advisories_when_processed_then_only_they_are_ready(
    selected: tuple[int, ...],
    processor_vcs: ProcessorDeps,
    project_config: ProjectConfig,
):
    vulns = [
        make_vuln(
            vuln_id=vuln_id,
            pkg_name="requests",
            fixed_version="2.32.4",
            state=_UPDATE_FAILED_UNIT,
        )
        for vuln_id in ("CVE-1", "CVE-2", "CVE-3")
    ]
    scan = _scan_result_for(project_config, [])
    scan.vulnerabilities = vulns

    groups = group_findings([vulns[index] for index in selected])
    _process(groups, project_config, processor_vcs, scan=scan)

    assert [group.target_version for group in groups] == ["2.32.4"]
    assert [finding.state for finding in load_scan_results("demo").vulnerabilities] == [
        _UPDATE_READY if index in selected else _UPDATE_FAILED_UNIT
        for index in range(3)
    ]


def test_given_advisories_of_one_package_with_different_fixes_when_grouped_then_error():
    vulns = [
        make_vuln(vuln_id="CVE-1", fixed_version="1.0.1"),
        make_vuln(vuln_id="CVE-2", fixed_version="1.0.2"),
    ]

    with pytest.raises(
        ValueError,
        match=r"^some-pkg advisories hold different fixes: 1\.0\.1, 1\.0\.2$",
    ):
        group_findings(vulns)


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
                    state=GradleBlock(
                        kind="age", reason="publication younger than required 7 days"
                    ),
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
                    state=GradleBlock(kind="mapping", reason="no published fix"),
                )
            ],
            [],
            id="no-fix-blocked-with-target",
        ),
        pytest.param(
            [
                make_update(SemverTier.MAJOR),
                make_vuln(vuln_id="CVE-1", fixed_version="1.0.2"),
                make_vuln(vuln_id="CVE-2", fixed_version="1.0.2"),
                make_vuln(
                    vuln_id="CVE-3",
                    pkg_name="other-pkg",
                    installed_version="2.0.0",
                    fixed_version="2.0.1",
                ),
                make_update(),
                make_update(SemverTier.MINOR),
            ],
            [
                ("some-pkg", "1.0.0", "1.0.2", "CVE-1, CVE-2"),
                ("other-pkg", "2.0.0", "2.0.1", "CVE-3"),
                ("pkg-a", "1.0.0", "1.0.1", "patch"),
                ("pkg-b", "1.0.0", "1.1.0", "minor"),
                ("pkg-c", "1.0.0", "2.0.0", "major"),
            ],
            id="native-rows-by-package-then-risk",
        ),
        pytest.param([], [], id="no-rows"),
    ],
)
def test_given_saved_rows_when_grouped_then_one_change_per_target_or_package(
    rows, expected
):
    assert _group_summary(group_findings(rows)) == expected


@pytest.mark.parametrize(
    ("rows", "recorded"),
    [
        pytest.param(
            [
                make_vuln(
                    vuln_id="CVE-A", state=Failed(flow=Workflow.UPDATE, phase="unit")
                ),
                make_vuln(vuln_id="CVE-B"),
            ],
            Failed(flow=Workflow.RESOLVE, phase="unit"),
            id="package-group",
        ),
        pytest.param(
            [
                make_vuln(vuln_id="CVE-A", gradle_target=make_gradle_target()),
                make_update(gradle_target=make_gradle_target()),
                make_vuln(
                    vuln_id="CVE-C",
                    gradle_target=make_gradle_target(),
                    state=Ready(flow=Workflow.UPDATE),
                ),
            ],
            Ready(flow=Workflow.UPDATE),
            id="target-group",
        ),
    ],
)
def test_given_rows_when_grouped_then_only_record_writes_their_state(rows, recorded):
    before = [row.model_copy(deep=True) for row in rows]

    groups = group_findings(rows)

    assert len(groups) == 1
    assert rows == before
    groups[0].record(recorded)
    assert [row.state for row in rows] == [recorded] * len(rows)


@pytest.mark.parametrize(
    ("catalogue_room", "edits", "returncode", "expected", "commands", "step_failures"),
    [
        pytest.param("2.8.4", None, 0, Applied(), 1, [], id="report-driven-apply"),
        pytest.param("2.8.5", {}, 0, Applied(), 0, [], id="already-applied"),
        pytest.param(
            "2.8.7", {}, 0, Blocked(_DRIFT_BLOCK), 0, [], id="drifted-catalogue"
        ),
        pytest.param(
            "2.8.4",
            {},
            1,
            ApplyFailed(),
            1,
            [
                FindingStepFailed(
                    "package command",
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

    [group] = group_findings([make_update(pkg_name="room", gradle_target=_ROOM)])

    outcome = apply_finding(
        gradle_project, group, JjRepository(Path(gradle_project.path)), emit=emit
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
    return {"repo": repo, "package": package, "phase": phase}


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
    assert [row.state for row in (*saved.vulnerabilities, *saved.updates)] == [
        _UPDATE_READY
    ] * 2


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
    assert [row.state for row in saved.vulnerabilities] == [
        _UPDATE_READY,
        _UPDATE_FAILED_UNIT,
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
        state=_UPDATE_FAILED_UNIT,
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
    assert saved.state == _DRIFT_BLOCK
    assert emit.of_type(FindingsBlocked) == [
        FindingsBlocked((("room", _DRIFT_REASON),))
    ]
