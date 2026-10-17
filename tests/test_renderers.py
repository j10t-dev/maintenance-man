from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.console import Console
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


@pytest.fixture()
def output(monkeypatch):
    buffer = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=buffer, width=220, color_system=None)
    )
    monkeypatch.setattr(
        cli, "_print_scan_result", lambda *args, **kwargs: cli.console.print("SCAN")
    )
    monkeypatch.setattr(
        cli, "_print_gradle_run_summary", lambda *args: cli.console.print("GRADLE")
    )
    return buffer


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    "event, expected",
    [
        (
            ProjectSkipped("a[b]", SkipReason.PATH_MISSING, "/tmp/[x]"),
            "Warning: a[b] — path does not exist: /tmp/[x]\n",
        ),
        (
            SyncCompleted("a[b]", "already [up] to date"),
            "  a[b] — already [up] to date\n",
        ),
        (
            DeployStepStarted("a[b]", DeployStep.BUILD),
            ("Building a[b]\n\n", "  Building...\n"),
        ),
        (
            DeployStepStarted("a[b]", DeployStep.DEPLOY),
            ("Deploying a[b]\n\n", "  Deploying...\n"),
        ),
        (
            DeployStepStarted("a[b]", DeployStep.HEALTH),
            ("\nChecking health of a[b]...\n", ""),
        ),
        (
            DeployStepSucceeded("a[b]", DeployStep.BUILD),
            ("\nBuild succeeded.\n\n", ""),
        ),
        (
            DeployStepSucceeded("a[b]", DeployStep.DEPLOY),
            ("\nDeploy succeeded.\n", ""),
        ),
        (DeployStepSucceeded("a[b]", DeployStep.HEALTH), ""),
        (
            DeployStepFailed("a[b]", DeployStep.BUILD, "bad [state]"),
            ("Error: bad [state]\n", "  Build failed: bad [state]\n"),
        ),
        (
            DeployStepFailed("a[b]", DeployStep.DEPLOY, "bad [state]"),
            ("Error: bad [state]\n", "  Deploy failed: bad [state]\n"),
        ),
        (
            DeployStepFailed("a[b]", DeployStep.HEALTH, "bad [state]"),
            ("Error: bad [state]\n", ""),
        ),
        (
            HealthChecked("a[b]", True, None),
            ("Healthy: a[b] is up\n", "  Healthy: a[b] is up\n"),
        ),
        (
            HealthChecked("a[b]", False, "bad [state]"),
            ("Warning: bad [state]\n", "  Warning: bad [state]\n"),
        ),
        (
            HealthChecked("a[b]", False, None),
            (
                "Warning: a[b] is not healthy\n",
                "  Warning: a[b] is not healthy\n",
            ),
        ),
        (
            HealthcheckUnconfigured(),
            "--check: no healthcheck_url configured in [defaults]\n",
        ),
    ],
)
def test_given_unconverted_event_when_rendered_in_both_modes_then_text_is_printed(
    output, batch, event, expected
):
    cli._Renderer(batch=batch)(event)
    rendered = expected[batch] if isinstance(expected, tuple) else expected
    assert output.getvalue() == rendered


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
                f"error: {words} · boom\n",
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
        (PullRequestOutput("https://x/pull/1"), "update", "", "https://x/pull/1\n"),
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
    flow: str,
    stdout: str,
    stderr: str,
) -> None:
    cli._Renderer(batch=batch, project="api", flow=flow)(event)

    captured = capsys.readouterr()
    assert captured.out == stdout
    assert captured.err == stderr


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
    [(False, "1 passed · 1 failed\n"), (True, "")],
    ids=["single", "batch"],
)
def test_given_processed_findings_when_rendered_then_only_single_project_prints_totals(
    capsys: pytest.CaptureFixture[str], batch: bool, expected: str
) -> None:
    results = (
        UpdateResult("a", "update", True),
        UpdateResult("b", "vuln", False, "unit"),
    )

    cli._Renderer(batch=batch, project="api")(FindingsProcessed(results))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == expected


@pytest.mark.parametrize(
    ("results", "expected"),
    [
        (
            (UpdateResult("a", "update", True), UpdateResult("b", "update", True)),
            "2 passed\n",
        ),
        ((UpdateResult("a", "update", False, "unit"),), "1 failed\n"),
        ((), ""),
    ],
    ids=["passed-only", "failed-only", "none"],
)
def test_given_finding_totals_when_rendered_then_zero_counts_are_omitted(
    capsys: pytest.CaptureFixture[str],
    results: tuple[UpdateResult, ...],
    expected: str,
) -> None:
    cli._Renderer(batch=False, project="api")(FindingsProcessed(results))

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
            "  ✓ passed   pkg                       1.0 → 1.1",
        ),
        (
            FindingFailed("pkg", "unit", "1.0", "1.1"),
            "  ✗ failed   pkg                       1.0 → 1.1             unit failed",
        ),
        (Promoted("mm/update-dependencies"), "  ✓ passed   local main"),
        (ProcessingStarted(2, 1), "api · 2 vulnerabilities · 1 updates"),
    ],
    ids=["passed", "failed", "promoted", "processing"],
)
def test_given_event_when_rendered_on_terminal_then_layout_is_aligned(
    monkeypatch: pytest.MonkeyPatch, event: Event, expected: str
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)

    cli._Renderer(batch=False, project="api")(event)

    assert Text.from_ansi(stream.getvalue()).plain == f"{expected}\n"


@pytest.mark.parametrize("batch", [False, True])
def test_given_pull_request_output_when_rendered_then_stderr_text_is_dim(
    monkeypatch: pytest.MonkeyPatch, batch: bool
) -> None:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stderr", stream)
    monkeypatch.setenv("TERM", "xterm")

    cli._Renderer(batch=batch)(PullRequestOutput("https://x/pull/[1]"))

    rendered = Text.from_ansi(stream.getvalue())
    assert rendered.plain == "https://x/pull/[1]\n"
    assert rendered.spans
    assert all("dim" in str(span.style) for span in rendered.spans)


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
    flow: str, capsys: pytest.CaptureFixture[str]
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


@pytest.mark.parametrize(
    ("reason", "detail", "single", "batch_text"),
    [
        (
            SkipReason.NO_SCAN_RESULTS,
            None,
            "a[b] — no scan results; nothing to do.",
            "",
        ),
        (
            SkipReason.NOTHING_TO_DO,
            "resolve",
            "a[b] — nothing to resolve.",
            "  a[b] — nothing to update",
        ),
        (
            SkipReason.FLOW_CONFLICT,
            "bad [flow]",
            "  Skipped: a[b] — bad [flow]",
            "  Skipped: a[b] — bad [flow]",
        ),
        (
            SkipReason.NOT_DEPLOYABLE,
            None,
            "a[b] — skipped (not deployable)",
            "a[b] — skipped (not deployable)",
        ),
        (
            SkipReason.UNCHANGED,
            None,
            "a[b] unchanged since last deploy (use --force to redeploy).",
            "a[b] — unchanged since last deploy",
        ),
        (
            SkipReason.BLOCKED,
            None,
            "Warning: a[b] — could not resolve main revision; skipping "
            "(use --force to deploy anyway)",
            "Warning: a[b] — could not resolve main revision; skipping "
            "(use --force to deploy anyway)",
        ),
    ],
)
@pytest.mark.parametrize("batch", [False, True])
def test_given_skip_reason_when_rendered_then_mode_specific_literal_is_printed(
    output, reason, detail, single, batch_text, batch
):
    cli._Renderer(batch=batch)(ProjectSkipped("a[b]", reason, detail))
    assert output.getvalue().strip("\n") == (batch_text if batch else single)
