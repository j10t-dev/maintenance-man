from io import StringIO

import pytest
from rich.text import Text

from maintenance_man import cli
from maintenance_man import output as maintenance_output
from maintenance_man.event_renderer import EventRenderer, Flow
from maintenance_man.models import events
from maintenance_man.models.events import (
    BlockersStillFailing,
    DeployStep,
    DeployStepFinished,
    Event,
    FindingFailed,
    FindingPassed,
    FindingsBlocked,
    FindingStarted,
    FindingStepFailed,
    HealthChecked,
    MissingTestConfig,
    OperationFailed,
    ProcessingStarted,
    ProjectSkipped,
    ProjectStarted,
    Promoted,
    PromotionFailed,
    ResolvePaused,
    ScanReported,
    SkipReason,
    SyncCompleted,
)
from maintenance_man.models.scan import GradleBlock, ScanResult, UpdateResult
from tests.support.cli import TerminalStream, terminal_stdout
from tests.support.findings import make_scan_result, make_update


def _pipe_scan() -> ScanResult:
    scan = make_scan_result(
        updates=[
            make_update(
                pkg_name="pkg",
                installed_version="1.0",
                latest_version="1.1",
                state=GradleBlock(kind="age", reason="too young"),
            )
        ]
    )
    scan.project_name = "api"
    return scan


_RESOLVE_RECORD = "api\tresolve\tfailed\tpkg\t1.0\t1.1\tcommit failed\n"
_DEPLOY_RECORD = "api\tdeploy\t{status}\tdeploy\t-\t-\t{reason}\n"
_SKIPPED_AFTER_BUILD = "api\tdeploy\tskipped\tdeploy\t-\t-\tbuild failed\n"


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    ("event", "flow", "stdout", "stderr"),
    [
        (FindingStarted("pkg", "1.0", "1.1"), "update", "", ""),
        (events.TestCommandStarted("uv run pytest"), "update", "", ""),
        (
            FindingStepFailed("prepare", "boom"),
            "update",
            "",
            "error: api · prepare · boom\n",
        ),
        (
            FindingStepFailed("package command", "boom"),
            "update",
            "",
            "error: api · package command · boom\n",
        ),
        (
            OperationFailed("workspace cleanup", "api", "boom"),
            "update",
            "",
            "error: api · workspace cleanup · boom\n",
        ),
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
            FindingFailed("pkg", "commit", "1.0", "1.1"),
            "resolve",
            _RESOLVE_RECORD,
            "",
        ),
        (
            Promoted(),
            "update",
            "api\tpromotion\tpassed\tlocal main\t-\t-\t-\n",
            "",
        ),
        (
            PromotionFailed("api", "conflict"),
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
            "error: api · no test configuration · automatic updates need "
            "test_unit, test_integration or test_component\n",
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
            "api\tupdate\tblocked\tpkg\t-\t-\tno fix\n",
            "",
        ),
        (
            ScanReported(_pipe_scan()),
            "update",
            "api\tupdate\tblocked\tpkg\t1.0\t1.1\ttoo young\n",
            "",
        ),
        (
            BlockersStillFailing("unit", ("a", "b")),
            "update",
            "",
            "error: unit · still blocking: a, b\n",
        ),
        (
            DeployStepFinished("api", DeployStep.BUILD),
            "update",
            "api\tbuild\tpassed\tbuild\t-\t-\t-\n",
            "",
        ),
        (
            DeployStepFinished("api", DeployStep.DEPLOY),
            "update",
            "api\tdeploy\tpassed\tdeploy\t-\t-\t-\n",
            "",
        ),
        (
            DeployStepFinished("api", DeployStep.BUILD, "exit 2"),
            "update",
            "api\tbuild\tfailed\tbuild\t-\t-\texit 2\n" + _SKIPPED_AFTER_BUILD,
            "",
        ),
        (
            DeployStepFinished("api", DeployStep.DEPLOY, "exit 3"),
            "update",
            "api\tdeploy\tfailed\tdeploy\t-\t-\texit 3\n",
            "",
        ),
        (
            HealthChecked("api", True, None),
            "update",
            "api\thealth\tpassed\thealthcheck\t-\t-\t-\n",
            "",
        ),
        (
            HealthChecked("api", False, "HTTP 503"),
            "update",
            "api\thealth\tfailed\thealthcheck\t-\t-\tHTTP 503\n",
            "",
        ),
        (
            HealthChecked("api", False, None),
            "update",
            "api\thealth\tfailed\thealthcheck\t-\t-\tnot healthy\n",
            "",
        ),
        (
            ProjectSkipped("api", SkipReason.NOT_DEPLOYABLE),
            "update",
            _DEPLOY_RECORD.format(status="skipped", reason="not deployable"),
            "",
        ),
        (
            ProjectSkipped("api", SkipReason.UNCHANGED),
            "update",
            _DEPLOY_RECORD.format(
                status="unchanged",
                reason="unchanged since last deploy · use --force to redeploy",
            ),
            "",
        ),
        (
            ProjectSkipped("api", SkipReason.BLOCKED),
            "update",
            _DEPLOY_RECORD.format(
                status="blocked",
                reason="could not resolve main revision · use --force to deploy anyway",
            ),
            "",
        ),
        (
            ProjectSkipped("a[b]", SkipReason.PATH_MISSING, "/tmp/[x]"),
            "update",
            "",
            "warning: a[b] · path does not exist: /tmp/[x]\n",
        ),
        (
            ProjectSkipped("api", SkipReason.NOTHING_TO_DO, "update"),
            "update",
            "",
            "Nothing to update in api\n",
        ),
        (
            ProjectSkipped("api", SkipReason.FLOW_CONFLICT, "owned by resolve"),
            "update",
            "",
            "warning: api · owned by resolve\n",
        ),
        (
            SyncCompleted("api", "already up to date"),
            "update",
            "api\tsync\tunchanged\tmain\t-\t-\t-\n",
            "",
        ),
        (
            SyncCompleted("api", "pulled from remote"),
            "update",
            "api\tsync\tpassed\tmain\t-\t-\tpulled from remote\n",
            "",
        ),
    ],
)
def test_given_event_when_rendered_in_pipe_then_records_and_diagnostics_split_by_stream(
    capsys: pytest.CaptureFixture[str],
    batch: bool,
    event: Event,
    flow: Flow,
    stdout: str,
    stderr: str,
) -> None:
    EventRenderer(batch=batch, project_name="api", flow=flow)(event)

    captured = capsys.readouterr()
    assert captured.out == stdout
    assert captured.err == stderr


def test_given_step_failure_without_project_when_rendered_then_error_omits_project(
    capsys: pytest.CaptureFixture[str],
) -> None:
    EventRenderer(batch=False)(FindingStepFailed("commit", "boom"))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: commit · boom\n"


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
    cli._print_result_totals(results, blocked)

    assert capsys.readouterr().err == expected


@pytest.mark.parametrize(
    ("verbose", "expected"), [(False, ""), (True, "$ uv run pytest\n")]
)
def test_given_test_command_when_rendered_then_only_verbose_runs_echo_it(
    capsys: pytest.CaptureFixture[str], verbose: bool, expected: str
) -> None:
    maintenance_output.reset_invocation_output(verbose=verbose)

    renderer = EventRenderer(batch=False, project_name="api")
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
        (Promoted(), "api\n  ✓ passed    local main"),
        (ProcessingStarted(2, 1), "api · 2 vulnerabilities · 1 updates"),
    ],
    ids=["passed", "failed", "blocked", "promoted", "processing"],
)
def test_given_event_when_rendered_on_terminal_then_layout_is_aligned(
    monkeypatch: pytest.MonkeyPatch, event: Event, expected: str
) -> None:
    stream = terminal_stdout(monkeypatch)

    EventRenderer(batch=False, project_name="api")(event)

    assert Text.from_ansi(stream.getvalue()).plain == f"{expected}\n"


def test_given_processing_heading_when_finding_rendered_then_heading_is_not_repeated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = terminal_stdout(monkeypatch)

    renderer = EventRenderer(batch=False, project_name="api")
    renderer(ProcessingStarted(2, 1))
    renderer(FindingPassed("pkg", False, "1.0", "1.1"))

    assert Text.from_ansi(stream.getvalue()).plain.splitlines() == [
        "api · 2 vulnerabilities · 1 updates",
        "  ✓ passed    pkg                       1.0 → 1.1",
    ]


def test_given_no_project_when_finding_rendered_on_terminal_then_no_heading_prints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = terminal_stdout(monkeypatch)

    EventRenderer(batch=False)(FindingPassed("pkg", False, "1.0", "1.1"))

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

    EventRenderer(batch=False, project_name="api")(FindingStarted("pkg", "1.0", "2.0"))

    assert stdout.getvalue() == ""
    assert stderr.getvalue() == expected


def _clean_scan() -> ScanResult:
    scan = make_scan_result(vulns=[], updates=[])
    scan.project_name = "api"
    return scan


def _blocked_scan() -> ScanResult:
    scan = make_scan_result(vulns=[], updates=[])
    scan.project_name = "api"
    scan.updates = [
        make_update(
            pkg_name="blocked-pkg",
            state=GradleBlock(kind="mapping", reason="no publication date"),
        ),
        make_update(pkg_name="available-pkg"),
    ]
    return scan


@pytest.mark.parametrize("flow", ["update", "resolve"])
def test_given_blocked_findings_when_saved_scan_reported_in_pipe_then_one_outcome_each(
    flow: Flow, capsys: pytest.CaptureFixture[str]
) -> None:
    EventRenderer(batch=False, flow=flow)(ScanReported(_blocked_scan()))

    captured = capsys.readouterr()
    assert captured.out == (
        f"api\t{flow}\tblocked\tblocked-pkg\t1.0.0\t1.0.1\tno publication date\n"
    )


def test_given_update_flow_when_saved_scan_reported_on_terminal_then_findings_print(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = terminal_stdout(monkeypatch)

    EventRenderer(batch=False)(ScanReported(_blocked_scan()))

    lines = stream.getvalue().splitlines()
    assert lines[0] == "api · 2 findings"
    assert any("! blocked" in line and "blocked-pkg" in line for line in lines)
    assert any("~ update" in line and "available-pkg" in line for line in lines)


@pytest.mark.parametrize(
    ("event", "batch", "stderr"),
    [
        (
            ScanReported(_clean_scan(), 1.25),
            False,
            "No findings in api · scanned in 1.2s\n",
        ),
        (ScanReported(_clean_scan()), False, "No findings in api\n"),
        (ScanReported(_clean_scan(), 1.25), True, ""),
        (
            ProjectSkipped("api", SkipReason.NO_SCAN_RESULTS),
            False,
            "No scan results for api\n",
        ),
        (ProjectSkipped("api", SkipReason.NO_SCAN_RESULTS), True, ""),
    ],
    ids=["clean-timed", "clean-untimed", "clean-batch", "no-scan", "no-scan-batch"],
)
def test_given_event_when_rendered_then_only_single_project_runs_print_the_notice(
    capsys: pytest.CaptureFixture[str], event: Event, batch: bool, stderr: str
) -> None:
    EventRenderer(batch=batch, project_name="api", flow="scan")(event)

    captured = capsys.readouterr()
    assert captured.out == ""
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
    capsys: pytest.CaptureFixture[str], flow: Flow, stdout: str, stderr: str
) -> None:
    EventRenderer(batch=True, flow=flow)(
        ProjectSkipped("api", SkipReason.PATH_MISSING, "/x")
    )

    captured = capsys.readouterr()
    assert captured.out == stdout
    assert captured.err == stderr


@pytest.mark.parametrize(
    ("steps", "expected"),
    [
        (
            [
                DeployStepFinished("api", DeployStep.BUILD),
                DeployStepFinished("api", DeployStep.DEPLOY),
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
                DeployStepFinished("api", DeployStep.BUILD, "exit 2"),
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
    stream = terminal_stdout(monkeypatch, width=120)

    renderer = EventRenderer(batch=True)
    for step in steps:
        renderer(step)

    assert Text.from_ansi(stream.getvalue()).plain.splitlines() == expected


@pytest.mark.parametrize(("flow", "expected"), [("deploy", ["api"]), ("update", [])])
def test_given_terminal_when_project_starts_then_only_deploy_prints_heading(
    monkeypatch: pytest.MonkeyPatch, flow: Flow, expected: list[str]
) -> None:
    stream = terminal_stdout(monkeypatch)

    EventRenderer(batch=True, flow=flow)(ProjectStarted("api"))

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
    stream = terminal_stdout(monkeypatch)

    EventRenderer(batch=True)(event)

    assert Text.from_ansi(stream.getvalue()).plain.splitlines() == expected


def test_given_every_event_class_when_rendered_then_a_handler_is_registered():
    registered = set(EventRenderer.__dict__["__call__"].dispatcher.registry)
    event_classes = {
        value
        for value in vars(events).values()
        if isinstance(value, type) and issubclass(value, Event) and value is not Event
    }

    assert event_classes <= registered


def test_given_corrupt_scan_skip_when_rendered_then_warning_names_the_rescan(capsys):
    EventRenderer(batch=True, flow="update")(
        ProjectSkipped("api", SkipReason.CORRUPT_SCAN_RESULTS, "update_status")
    )

    assert capsys.readouterr().err.splitlines() == [
        "warning: api · corrupt scan results; run mm scan api"
    ]
