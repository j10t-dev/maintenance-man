from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.text import Text

from maintenance_man import cli
from maintenance_man import output as maintenance_output
from maintenance_man.models import events
from maintenance_man.models.events import (
    BlockersStillFailing,
    DeployStep,
    DeployStepFailed,
    DeployStepStarted,
    DeployStepSucceeded,
    Event,
    FindingFailed,
    FindingPassed,
    FindingsBlocked,
    FindingsProcessed,
    FindingStarted,
    FindingStepFailed,
    FindingStepKind,
    GradleFlowFailed,
    GradleRunArchived,
    GradleRunReported,
    GradleWithheld,
    HealthChecked,
    HealthcheckUnconfigured,
    MissingTestConfig,
    NoEligibleGradleChanges,
    Operation,
    OperationFailed,
    ProcessingStarted,
    ProjectSkipped,
    ProjectStarted,
    Promoted,
    PullRequestOutput,
    ResolvePaused,
    ScanReported,
    SkipReason,
    SubmissionBlocked,
    SyncCompleted,
)
from maintenance_man.models.gradle import (
    ComparisonContext,
    CompleteResolution,
    GradleRun,
    GradleSnapshot,
    ResolutionReport,
)
from maintenance_man.models.scan import ScanResult, UpdateResult, Workflow
from tests.conftest import TerminalStream, make_scan_result, make_update


def _make_gradle_run() -> GradleRun:
    context = ComparisonContext(
        scanner_version="test",
        loaded_input_digests={},
        selected_scopes=(),
        producer_versions={"gradle": "8", "cyclonedx": "3", "report": "1"},
        scanner_flags=(),
        created_at=datetime(2026, 10, 16, tzinfo=UTC),
        private_cache_path=Path("/tmp/cache"),
        owner_token="owner",
    )
    resolution = CompleteResolution(
        report=ResolutionReport(
            schema_version=1,
            root_project=":",
            producer_versions={"gradle": "8", "cyclonedx": "3", "report": "1"},
            catalogue_digest="catalogue",
            repositories=(),
            selected_scopes=(),
            scopes=(),
        )
    )
    snapshot = GradleSnapshot(
        tree_id="tree",
        resolution=resolution,
        context_identity=context.identity,
        findings=(),
        inventory_digest="inventory",
        inventory_modules=(),
    )
    return GradleRun(
        project="a[b]",
        flow=Workflow.UPDATE,
        base_commit_id="base",
        managed_bookmark="mm/update-dependencies",
        managed_tip_id="tip",
        context=context,
        initial_snapshot=snapshot,
        accepted_snapshot=snapshot,
    )


def _pipe_scan() -> ScanResult:
    scan = make_scan_result(
        updates=[
            make_update(
                pkg_name="pkg",
                installed_version="1.0",
                latest_version="1.1",
                blocked_reason="too young",
            )
        ]
    )
    scan.project = "api"
    return scan


_OPERATION_DIAGNOSTICS = {
    Operation.UPDATE_SETUP: "error: api · update setup · boom",
    Operation.REFRESH: "error: api · workspace refresh · boom",
    Operation.WORKSPACE_CLEANUP: "error: api · workspace cleanup · boom",
    Operation.BOOKMARK_CLEANUP: "error: api · bookmark cleanup · boom",
    Operation.RESOLVE_SETUP: "error: api · resolve setup · boom",
    Operation.SUBMIT: (
        "warning: api · submit failed · keeping mm/resolve-dependencies "
        "for manual recovery · boom"
    ),
    Operation.REMOTE_SYNC: "warning: api · failed to sync remote · boom",
    Operation.SCAN: "error: api · scan · boom",
    Operation.SYNC: "error: api · sync · boom",
}
_STEP_WORDS = [
    (FindingStepKind.PREPARE, "prepare"),
    (FindingStepKind.PACKAGE_COMMAND, "package command"),
    (FindingStepKind.TEST, "test"),
    (FindingStepKind.INSPECT, "inspect"),
    (FindingStepKind.COMMIT, "commit"),
    (FindingStepKind.BOOKMARK, "bookmark"),
    (FindingStepKind.DISCARD, "discard"),
]
_RESOLVE_RECORD = "api\tresolve\tfailed\tpkg\t1.0\t1.1\tcommit failed\n"


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    ("event", "flow", "stdout", "stderr"),
    [
        (FindingStarted("vuln", "pkg", "1.0", "1.1", "CVE-1"), "update", "", ""),
        (events.TestCommandStarted("uv run pytest"), "update", "", ""),
        *[
            (
                FindingStepFailed(step, "boom"),
                "update",
                "",
                f"error: api · {words} · boom\n",
            )
            for step, words in _STEP_WORDS
        ],
        (
            FindingPassed("pkg", False, "1.0", "1.1"),
            "update",
            "api\tupdate\tpassed\tpkg\t1.0\t1.1\t-\n",
            "",
        ),
        (
            FindingPassed("pkg", True, "1.0", "1.1"),
            "update",
            "api\tupdate\tpassed\tpkg\t1.0\t1.1\talready applied\n",
            "",
        ),
        (
            FindingFailed("pkg", "unit", "1.0", "1.1"),
            "update",
            "api\tupdate\tfailed\tpkg\t1.0\t1.1\tunit failed\n",
            "",
        ),
        (
            FindingFailed("pkg", "apply", "1.0", "1.1"),
            "update",
            "api\tupdate\tfailed\tpkg\t1.0\t1.1\tapply failed\n",
            "",
        ),
        (FindingFailed("pkg", "commit", "1.0", "1.1"), "resolve", _RESOLVE_RECORD, ""),
        (
            FindingPassed("pkg[red]", False, "1.0", "1.1"),
            "update",
            "api\tupdate\tpassed\tpkg[red]\t1.0\t1.1\t-\n",
            "",
        ),
        (
            Promoted("mm/update-dependencies"),
            "update",
            "api\tpromotion\tpassed\tlocal main\t-\t-\t-\n",
            "",
        ),
        (
            OperationFailed(Operation.PROMOTE, "api", "conflict"),
            "update",
            "api\tpromotion\tfailed\tlocal main\t-\t-\tconflict\n",
            "",
        ),
        (ProcessingStarted(2, 1), "update", "", ""),
        (ProjectStarted("api"), "update", "", ""),
        (
            MissingTestConfig("api"),
            "update",
            "",
            "warning: api · no test configuration · test phases skipped\n",
        ),
        (
            ResolvePaused("api"),
            "update",
            "",
            "Resolve paused\nhint: mm resolve api --continue\n",
        ),
        (
            FindingsBlocked((("pkg", "no fix"),)),
            "update",
            "api\tresolve\tblocked\tpkg\t-\t-\tno fix\n",
            "",
        ),
        (
            ScanReported(_pipe_scan()),
            "update",
            "api\tupdate\tblocked\tpkg\t1.0\t1.1\ttoo young\n",
            "",
        ),
        (
            SubmissionBlocked("api"),
            "update",
            "",
            "warning: api · blocked findings remain · "
            "rescan or resolve them manually\n",
        ),
        (
            BlockersStillFailing("unit", ("a", "b")),
            "update",
            "",
            "error: unit · still blocking: a, b\n",
        ),
        (
            PullRequestOutput("https://x/pull/1"),
            "resolve",
            "api\tresolve\tpassed\tpull request\t-\t-\thttps://x/pull/1\n",
            "",
        ),
        (
            GradleWithheld("org.x:lib -> 2", "too young"),
            "update",
            "api\tupdate\tblocked\torg.x:lib -> 2\t-\t-\ttoo young\n",
            "",
        ),
        (
            GradleWithheld("org.x:lib -> 2", "too young"),
            "resolve",
            "api\tresolve\tblocked\torg.x:lib -> 2\t-\t-\ttoo young\n",
            "",
        ),
        (
            GradleWithheld("g:[red]lib", "too [new]"),
            "update",
            "api\tupdate\tblocked\tg:[red]lib\t-\t-\ttoo [new]\n",
            "",
        ),
        (
            NoEligibleGradleChanges(),
            "update",
            "",
            "No eligible Gradle changes in api\n",
        ),
        (
            GradleRunArchived(Path("/tmp/run.json")),
            "update",
            "",
            "warning: archived failed Gradle run to /tmp/run.json · "
            "rebuilding candidates from main\n",
        ),
        (
            GradleFlowFailed(Workflow.UPDATE, "bad"),
            "update",
            "",
            "error: cannot complete Gradle update · bad\n",
        ),
    ],
)
def test_given_event_when_rendered_in_pipe_then_records_and_diagnostics_split_by_stream(
    capsys: pytest.CaptureFixture[str],
    batch: bool,
    event: Event,
    flow: cli._Flow,
    stdout: str,
    stderr: str,
) -> None:
    cli._Renderer(batch=batch, project="api", flow=flow)(event)

    captured = capsys.readouterr()
    assert captured.out == stdout
    assert captured.err == stderr


def test_given_step_failure_without_project_when_rendered_then_error_omits_project(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli._Renderer(batch=False)(FindingStepFailed(FindingStepKind.COMMIT, "boom"))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: commit · boom\n"


@pytest.mark.parametrize(
    "operation", [item for item in Operation if item is not Operation.PROMOTE]
)
def test_given_operation_failure_when_rendered_then_diagnostic_goes_to_stderr(
    capsys: pytest.CaptureFixture[str], operation: Operation
) -> None:
    cli._Renderer(batch=False, project="api")(OperationFailed(operation, "api", "boom"))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"{_OPERATION_DIAGNOSTICS[operation]}\n"


@pytest.mark.parametrize(
    ("batch", "expected"),
    [(False, "1 passed · 1 failed · 2 blocked\n"), (True, "")],
    ids=["single", "batch"],
)
def test_given_processed_findings_when_rendered_then_only_single_project_prints_totals(
    capsys: pytest.CaptureFixture[str], batch: bool, expected: str
) -> None:
    results = (
        UpdateResult("a", "update", True),
        UpdateResult("b", "vuln", False, "unit"),
    )

    cli._Renderer(batch=batch, project="api")(FindingsProcessed(results, blocked=2))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == expected


@pytest.mark.parametrize(
    ("results", "blocked", "expected"),
    [
        (
            (UpdateResult("a", "update", True), UpdateResult("b", "update", True)),
            0,
            "2 passed\n",
        ),
        ((UpdateResult("a", "update", False, "unit"),), 0, "1 failed\n"),
        ((), 3, "3 blocked\n"),
        ((), 0, ""),
    ],
    ids=["passed-only", "failed-only", "blocked-only", "none"],
)
def test_given_finding_totals_when_rendered_then_zero_counts_are_omitted(
    capsys: pytest.CaptureFixture[str],
    results: tuple[UpdateResult, ...],
    blocked: int,
    expected: str,
) -> None:
    cli._Renderer(batch=False, project="api")(FindingsProcessed(results, blocked))

    assert capsys.readouterr().err == expected


@pytest.mark.parametrize(
    ("verbose", "expected"), [(False, ""), (True, "$ uv run pytest\n")]
)
def test_given_test_command_when_rendered_then_only_verbose_runs_echo_it(
    capsys: pytest.CaptureFixture[str], verbose: bool, expected: str
) -> None:
    maintenance_output.set_verbose(verbose)

    renderer = cli._Renderer(batch=False, project="api")
    renderer(events.TestCommandStarted("uv run pytest"))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == expected


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (
            FindingPassed("pkg", False, "1.0", "1.1"),
            "api\n  ✓ passed    pkg                       1.0 → 1.1",
        ),
        (
            FindingFailed("pkg", "unit", "1.0", "1.1"),
            "api\n  ✗ failed    pkg                       1.0 → 1.1             "
            "unit failed",
        ),
        (
            FindingsBlocked((("pkg", "no fix"),)),
            "api\n  ! blocked   pkg                       no fix",
        ),
        (Promoted("mm/update-dependencies"), "  ✓ passed    local main"),
        (ProcessingStarted(2, 1), "api · 2 vulnerabilities · 1 updates"),
        (
            PullRequestOutput("https://x/pull/1"),
            "api\n  ✓ passed    pull request              https://x/pull/1",
        ),
    ],
    ids=["passed", "failed", "blocked", "promoted", "processing", "pull-request"],
)
def test_given_event_when_rendered_on_terminal_then_layout_is_aligned(
    monkeypatch: pytest.MonkeyPatch, event: Event, expected: str
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)

    cli._Renderer(batch=False, project="api")(event)

    assert Text.from_ansi(stream.getvalue()).plain == f"{expected}\n"


def test_given_processing_heading_when_finding_rendered_then_heading_is_not_repeated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)

    renderer = cli._Renderer(batch=False, project="api")
    renderer(ProcessingStarted(2, 1))
    renderer(FindingPassed("pkg", False, "1.0", "1.1"))

    assert Text.from_ansi(stream.getvalue()).plain.splitlines() == [
        "api · 2 vulnerabilities · 1 updates",
        "  ✓ passed    pkg                       1.0 → 1.1",
    ]


def test_given_no_project_when_finding_rendered_on_terminal_then_no_heading_prints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)

    cli._Renderer(batch=False)(FindingPassed("pkg", False, "1.0", "1.1"))

    assert Text.from_ansi(stream.getvalue()).plain.splitlines() == [
        "  ✓ passed    pkg                       1.0 → 1.1"
    ]


@pytest.mark.parametrize(
    ("stdout_is_terminal", "stderr_is_terminal", "expected"),
    [
        (False, True, "Updating pkg 1.0 → 2.0\n"),
        (True, True, "Updating pkg 1.0 → 2.0\n"),
        (True, False, ""),
        (False, False, ""),
    ],
    ids=["stderr-terminal", "both-terminals", "stdout-terminal-only", "both-pipes"],
)
def test_given_finding_started_when_rendered_then_only_a_stderr_terminal_shows_progress(
    monkeypatch: pytest.MonkeyPatch,
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
    expected: str,
) -> None:
    stdout = TerminalStream() if stdout_is_terminal else StringIO()
    stderr = TerminalStream() if stderr_is_terminal else StringIO()
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)

    cli._Renderer(batch=False, project="api")(
        FindingStarted("update", "pkg", "1.0", "2.0", "major")
    )

    assert stdout.getvalue() == ""
    assert stderr.getvalue() == expected


def test_given_summary_events_when_rendered_then_exact_payloads_are_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = make_scan_result()
    run = _make_gradle_run()
    print_scan = MagicMock()
    print_gradle = MagicMock()
    monkeypatch.setattr(cli, "_print_scan_result", print_scan)
    monkeypatch.setattr(cli, "_print_gradle_run_summary", print_gradle)

    cli._Renderer(batch=False, flow="scan")(ScanReported(scan, elapsed_s=1.25))
    print_scan.assert_called_once_with(scan, elapsed_s=1.25)
    print_scan.reset_mock()
    cli._Renderer(batch=False)(GradleRunReported(scan, run))
    print_scan.assert_called_once_with(scan)
    print_gradle.assert_called_once_with(run)


def _blocked_scan() -> ScanResult:
    scan = make_scan_result(vulns=[], updates=[])
    scan.project = "api"
    scan.updates = [
        make_update(pkg_name="blocked-pkg", blocked_reason="no publication date"),
        make_update(pkg_name="available-pkg"),
    ]
    return scan


@pytest.mark.parametrize("flow", ["update", "resolve"])
def test_given_blocked_findings_when_saved_scan_reported_in_pipe_then_one_outcome_each(
    flow: cli._Flow, capsys: pytest.CaptureFixture[str]
) -> None:
    cli._Renderer(batch=False, flow=flow)(ScanReported(_blocked_scan()))

    captured = capsys.readouterr()
    assert captured.out == (
        f"api\t{flow}\tblocked\tblocked-pkg\t1.0.0\t1.0.1\tno publication date\n"
    )


def test_given_update_flow_when_saved_scan_reported_on_terminal_then_findings_print(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("NO_COLOR", "1")

    cli._Renderer(batch=False)(ScanReported(_blocked_scan()))

    lines = stream.getvalue().splitlines()
    assert lines[0] == "api · 2 findings"
    assert any("! blocked" in line and "blocked-pkg" in line for line in lines)
    assert any("~ update" in line and "available-pkg" in line for line in lines)


@pytest.mark.parametrize(
    ("batch", "elapsed_s", "expected"),
    [
        (False, 1.25, "No findings in api · scanned in 1.2s\n"),
        (False, None, "No findings in api\n"),
        (True, 1.25, ""),
    ],
    ids=["timed", "untimed", "batch"],
)
def test_given_clean_scan_when_reported_then_notice_depends_on_timing_and_batch(
    batch: bool,
    elapsed_s: float | None,
    expected: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scan = make_scan_result(vulns=[], updates=[])
    scan.project = "api"

    cli._Renderer(batch=batch, flow="scan")(ScanReported(scan, elapsed_s))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == expected


_NO_STDERR = ""
_DEPLOY_RECORD = "api\tdeploy\t{status}\tdeploy\t-\t-\t{reason}\n"
_SKIPPED_AFTER_BUILD = "api\tdeploy\tskipped\tdeploy\t-\t-\tbuild failed\n"


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    ("event", "stdout", "stderr"),
    [
        *[(DeployStepStarted("api", step), "", _NO_STDERR) for step in DeployStep],
        (
            DeployStepSucceeded("api", DeployStep.BUILD),
            "api\tbuild\tpassed\tbuild\t-\t-\t-\n",
            _NO_STDERR,
        ),
        (
            DeployStepSucceeded("api", DeployStep.DEPLOY),
            "api\tdeploy\tpassed\tdeploy\t-\t-\t-\n",
            _NO_STDERR,
        ),
        (
            DeployStepFailed("api", DeployStep.BUILD, "exit 2"),
            "api\tbuild\tfailed\tbuild\t-\t-\texit 2\n" + _SKIPPED_AFTER_BUILD,
            _NO_STDERR,
        ),
        (
            DeployStepFailed("api", DeployStep.DEPLOY, "exit 3"),
            "api\tdeploy\tfailed\tdeploy\t-\t-\texit 3\n",
            _NO_STDERR,
        ),
        (DeployStepSucceeded("api", DeployStep.HEALTH), "", _NO_STDERR),
        (DeployStepFailed("api", DeployStep.HEALTH, "x"), "", _NO_STDERR),
        (
            HealthChecked("api", True, None),
            "api\thealth\tpassed\thealthcheck\t-\t-\t-\n",
            _NO_STDERR,
        ),
        (
            HealthChecked("api", False, "HTTP 503"),
            "api\thealth\tfailed\thealthcheck\t-\t-\tHTTP 503\n",
            _NO_STDERR,
        ),
        (
            HealthChecked("api", False, None),
            "api\thealth\tfailed\thealthcheck\t-\t-\tnot healthy\n",
            _NO_STDERR,
        ),
        (
            HealthChecked("api", False, "bad [state]"),
            "api\thealth\tfailed\thealthcheck\t-\t-\tbad [state]\n",
            _NO_STDERR,
        ),
        (
            HealthcheckUnconfigured(),
            "",
            "--check: no healthcheck_url configured in [defaults]\n",
        ),
        (
            ProjectSkipped("api", SkipReason.NOT_DEPLOYABLE),
            _DEPLOY_RECORD.format(status="skipped", reason="not deployable"),
            _NO_STDERR,
        ),
        (
            ProjectSkipped("api", SkipReason.UNCHANGED),
            _DEPLOY_RECORD.format(
                status="unchanged",
                reason="unchanged since last deploy · use --force to redeploy",
            ),
            _NO_STDERR,
        ),
        (
            ProjectSkipped("api", SkipReason.BLOCKED),
            _DEPLOY_RECORD.format(
                status="blocked",
                reason=(
                    "could not resolve main revision · use --force to deploy anyway"
                ),
            ),
            _NO_STDERR,
        ),
        (
            ProjectSkipped("api", SkipReason.PATH_MISSING, "/x"),
            "",
            "warning: api · path does not exist: /x\n",
        ),
        (
            ProjectSkipped("a[b]", SkipReason.PATH_MISSING, "/tmp/[x]"),
            "",
            "warning: a[b] · path does not exist: /tmp/[x]\n",
        ),
        (
            ProjectSkipped("api", SkipReason.NOTHING_TO_DO, "update"),
            "",
            "Nothing to update in api\n",
        ),
        (
            ProjectSkipped("api", SkipReason.FLOW_CONFLICT, "owned by resolve"),
            "",
            "warning: api · owned by resolve\n",
        ),
        (
            SyncCompleted("api", "already up to date"),
            "api\tsync\tunchanged\tmain\t-\t-\t-\n",
            _NO_STDERR,
        ),
        (
            SyncCompleted("api", "pulled from remote"),
            "api\tsync\tpassed\tmain\t-\t-\tpulled from remote\n",
            _NO_STDERR,
        ),
        (
            SyncCompleted("api", "pushed to remote"),
            "api\tsync\tpassed\tmain\t-\t-\tpushed to remote\n",
            _NO_STDERR,
        ),
        (
            SyncCompleted("a[b]", "already up to date"),
            "a[b]\tsync\tunchanged\tmain\t-\t-\t-\n",
            _NO_STDERR,
        ),
    ],
)
def test_given_deploy_or_sync_event_when_rendered_in_pipe_then_streams_split(
    capsys: pytest.CaptureFixture[str],
    batch: bool,
    event: Event,
    stdout: str,
    stderr: str,
) -> None:
    cli._Renderer(batch=batch, project="api")(event)

    captured = capsys.readouterr()
    assert captured.out == stdout
    assert captured.err == stderr


@pytest.mark.parametrize(
    ("flow", "stdout", "stderr"),
    [
        ("deploy", "api\tdeploy\tfailed\tdeploy\t-\t-\tpath does not exist: /x\n", ""),
        ("update", "", "warning: api · path does not exist: /x\n"),
        ("scan", "", "warning: api · path does not exist: /x\n"),
    ],
)
def test_given_missing_project_path_when_rendered_then_only_deploy_records_a_failure(
    capsys: pytest.CaptureFixture[str], flow: cli._Flow, stdout: str, stderr: str
) -> None:
    cli._Renderer(batch=True, flow=flow)(
        ProjectSkipped("api", SkipReason.PATH_MISSING, "/x")
    )

    captured = capsys.readouterr()
    assert captured.out == stdout
    assert captured.err == stderr


@pytest.mark.parametrize(
    ("batch", "expected"),
    [(False, "No scan results for api\n"), (True, "")],
    ids=["single", "batch"],
)
def test_given_project_without_scan_results_when_skipped_then_only_single_notice(
    capsys: pytest.CaptureFixture[str], batch: bool, expected: str
) -> None:
    cli._Renderer(batch=batch, project="api")(
        ProjectSkipped("api", SkipReason.NO_SCAN_RESULTS)
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == expected


@pytest.mark.parametrize(
    ("steps", "expected"),
    [
        (
            [
                DeployStepStarted("api", DeployStep.BUILD),
                DeployStepSucceeded("api", DeployStep.BUILD),
                DeployStepStarted("api", DeployStep.DEPLOY),
                DeployStepSucceeded("api", DeployStep.DEPLOY),
                DeployStepStarted("api", DeployStep.HEALTH),
                HealthChecked("api", False, "HTTP 503"),
            ],
            [
                "api",
                "  ✓ passed    build",
                "  ✓ passed    deploy",
                "  ✗ failed    healthcheck               HTTP 503",
            ],
        ),
        (
            [
                DeployStepStarted("api", DeployStep.BUILD),
                DeployStepFailed("api", DeployStep.BUILD, "exit 2"),
            ],
            [
                "api",
                "  ✗ failed    build                     exit 2",
                "  ○ skipped   deploy                    build failed",
            ],
        ),
        (
            [
                ProjectSkipped("api", SkipReason.NOT_DEPLOYABLE),
                ProjectSkipped("web", SkipReason.BLOCKED),
            ],
            [
                "api",
                "  ○ skipped   deploy                    not deployable",
                "",
                "web",
                "  ! blocked   deploy                    "
                "could not resolve main revision · use --force to deploy anyway",
            ],
        ),
        (
            [SyncCompleted("api", "pulled from remote")],
            ["api", "  ✓ passed    main                      pulled from remote"],
        ),
    ],
    ids=["deploy-then-health", "failed-build", "two-projects", "sync"],
)
def test_given_project_events_when_rendered_on_terminal_then_one_heading_per_project(
    monkeypatch: pytest.MonkeyPatch,
    steps: list[Event],
    expected: list[str],
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("COLUMNS", "120")

    renderer = cli._Renderer(batch=True)
    for step in steps:
        renderer(step)

    assert Text.from_ansi(stream.getvalue()).plain.splitlines() == expected


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (SyncCompleted("api", "already up to date"), ["api", "  ○ unchanged main"]),
        (
            ProjectSkipped("api", SkipReason.UNCHANGED),
            [
                "api",
                "  ○ unchanged deploy                    "
                "unchanged since last deploy · use --for…",
            ],
        ),
    ],
    ids=["sync", "deploy"],
)
def test_given_unchanged_outcome_when_rendered_on_terminal_then_subject_is_separated(
    monkeypatch: pytest.MonkeyPatch, event: Event, expected: list[str]
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)

    cli._Renderer(batch=True)(event)

    assert Text.from_ansi(stream.getvalue()).plain.splitlines() == expected
