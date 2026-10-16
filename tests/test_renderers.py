from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from rich.text import Text

from maintenance_man import cli
from maintenance_man.models import events
from maintenance_man.models.events import (
    BlockersStillFailing,
    DeployStep,
    DeployStepFailed,
    DeployStepStarted,
    DeployStepSucceeded,
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
from maintenance_man.models.scan import UpdateResult, Workflow
from tests.conftest import make_scan_result


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
    monkeypatch.setattr(
        cli, "_print_update_summary", lambda *args: cli.console.print("SUMMARY")
    )
    return buffer


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    "event, expected",
    [
        (
            FindingStarted("vuln", "pkg[a]", "1.0", "1.1", "CVE-1"),
            "\n  VULN pkg[a] 1.0 -> 1.1 (CVE-1)\n",
        ),
        (
            FindingStarted("update", "pkg", "1.0", "2.0", "major"),
            "\n  UPDATE pkg 1.0 -> 2.0 (major)\n",
        ),
        (events.TestCommandStarted("uv run pytest"), "  $ uv run pytest\n"),
        (
            FindingStepFailed(FindingStepKind.PACKAGE_COMMAND, "boom"),
            "  FAIL Package manager command failed: boom\n",
        ),
        (
            FindingStepFailed(FindingStepKind.TEST, "unit failed"),
            "  FAIL unit failed\n",
        ),
        (FindingPassed("pkg", False), "  PASS pkg\n"),
        (FindingPassed("pkg", True), "  PASS pkg (already applied)\n"),
        (FindingFailed("pkg", "unit"), "  FAIL pkg — unit failed\n"),
        (ProjectStarted("a[b]"), ("", f"\n{'═' * 40}\na[b]\n{'═' * 40}\n")),
        (
            ProjectSkipped("a[b]", SkipReason.PATH_MISSING, "/tmp/[x]"),
            "Warning: a[b] — path does not exist: /tmp/[x]\n",
        ),
        (
            OperationFailed(Operation.SCAN, "a[b]", "bad [state]"),
            "Error: a[b] — bad [state]\n",
        ),
        (ScanReported(make_scan_result()), "SCAN\n"),
        (
            MissingTestConfig("a[b]"),
            "  Warning: a[b] — no test configuration (test phases will be skipped)\n",
        ),
        (ProcessingStarted(1, 0), "\nProcessing 1 vuln fix(es)...\n"),
        (ProcessingStarted(0, 1), "\nProcessing 1 update(s)...\n"),
        (
            ProcessingStarted(1, 2),
            "\nProcessing 1 vuln fix(es)...\n\nProcessing 2 update(s)...\n",
        ),
        (ProcessingStarted(0, 0), ""),
        (
            FindingsProcessed((UpdateResult("pkg", "update", True),)),
            ("SUMMARY\n", ""),
        ),
        (
            Promoted("mm/update-dependencies"),
            "Promoted mm/update-dependencies to main.\n",
        ),
        (
            ResolvePaused("a[b]"),
            "  Resolve paused. Continue with mm resolve a[b] --continue.\n",
        ),
        (
            FindingsBlocked((("pkg[one]", "reason[two]"),)),
            "  BLOCKED pkg[one] — reason[two]\n",
        ),
        (
            FindingsBlocked((("pkg-one", "reason-one"), ("pkg-two", "reason-two"))),
            "  BLOCKED pkg-one — reason-one\n  BLOCKED pkg-two — reason-two\n",
        ),
        (
            SubmissionBlocked("a[b]"),
            "  Not submitting: blocked findings remain. "
            "Rescan or resolve them manually.\n",
        ),
        (
            BlockersStillFailing("unit", ("pkg[one]", "pkg-two")),
            "  FAIL unit — still blocking: pkg[one], pkg-two\n",
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
        (PullRequestOutput("https://x/pull/[1]"), "  https://x/pull/[1]\n"),
        (
            GradleWithheld("g:[lib]", "too [new]"),
            "Withheld g:[lib]: too [new]\n",
        ),
        (NoEligibleGradleChanges(), "No eligible Gradle changes\n"),
        (
            GradleRunArchived(Path("/tmp/[run].json")),
            "Archived failed Gradle run to /tmp/[run].json; "
            "rebuilding candidates from main\n",
        ),
        (
            GradleFlowFailed(Workflow.UPDATE, "bad [state]"),
            "Cannot complete Gradle update: bad [state]\n",
        ),
        (
            GradleFlowFailed(Workflow.RESOLVE, "bad [state]"),
            "Cannot complete Gradle resolve: bad [state]\n",
        ),
        (
            GradleRunReported(make_scan_result(), _make_gradle_run()),
            "SCAN\nGRADLE\n",
        ),
    ],
)
def test_given_progress_event_when_rendered_in_both_modes_then_expected_text_is_printed(
    output, batch, event, expected
):
    cli._Renderer(batch=batch)(event)
    rendered = expected[batch] if isinstance(expected, tuple) else expected
    assert output.getvalue() == rendered


@pytest.mark.parametrize("batch", [False, True])
def test_given_pull_request_output_when_rendered_then_it_is_indented_and_dim(
    monkeypatch: pytest.MonkeyPatch, batch: bool
) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(
            file=output,
            width=220,
            force_terminal=True,
            color_system="standard",
        ),
    )

    cli._Renderer(batch=batch)(PullRequestOutput("https://x/pull/1"))

    rendered = Text.from_ansi(output.getvalue())
    assert rendered.plain == "  https://x/pull/1\n"
    assert rendered.spans
    assert all("dim" in str(span.style) for span in rendered.spans)


def test_given_summary_events_when_rendered_then_exact_payloads_are_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = make_scan_result()
    results = (UpdateResult("pkg", "update", True),)
    run = _make_gradle_run()
    print_scan = MagicMock()
    print_updates = MagicMock()
    print_gradle = MagicMock()
    monkeypatch.setattr(cli, "_print_scan_result", print_scan)
    monkeypatch.setattr(cli, "_print_update_summary", print_updates)
    monkeypatch.setattr(cli, "_print_gradle_run_summary", print_gradle)

    cli._Renderer(batch=False)(ScanReported(scan, elapsed_s=1.25))
    print_scan.assert_called_once_with(scan, elapsed_s=1.25)
    print_scan.reset_mock()
    cli._Renderer(batch=False)(FindingsProcessed(results))
    print_updates.assert_called_once_with(list(results))
    cli._Renderer(batch=False)(GradleRunReported(scan, run))
    print_scan.assert_called_once_with(scan)
    print_gradle.assert_called_once_with(run)


@pytest.mark.parametrize(
    "step",
    [
        FindingStepKind.PREPARE,
        FindingStepKind.INSPECT,
        FindingStepKind.COMMIT,
        FindingStepKind.BOOKMARK,
        FindingStepKind.DISCARD,
    ],
)
@pytest.mark.parametrize("batch", [False, True])
def test_given_non_package_finding_step_failure_when_rendered_then_error_is_printed(
    output, step, batch
):
    cli._Renderer(batch=batch)(FindingStepFailed(step, "bad [state]"))
    assert output.getvalue().strip("\n") == "  FAIL bad [state]"


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


@pytest.mark.parametrize(
    ("operation", "single", "batch_text"),
    [
        (
            Operation.UPDATE_SETUP,
            "  Error: a[b] — bad [state]",
            "  Error: a[b] — bad [state]",
        ),
        (
            Operation.PROMOTE,
            "Promotion failed: bad [state]",
            "Promotion failed: bad [state]",
        ),
        (
            Operation.REFRESH,
            "Workspace refresh failed: a[b]: bad [state]",
            "Workspace refresh failed: a[b]: bad [state]",
        ),
        (
            Operation.WORKSPACE_CLEANUP,
            "Workspace cleanup failed: bad [state]",
            "  Workspace cleanup failed: bad [state]",
        ),
        (
            Operation.BOOKMARK_CLEANUP,
            "Bookmark cleanup failed: bad [state]",
            "  Bookmark cleanup failed: a[b] — bad [state]",
        ),
        (
            Operation.RESOLVE_SETUP,
            "  Resolve setup failed: bad [state]",
            "  Resolve setup failed: bad [state]",
        ),
        (
            Operation.SUBMIT,
            "  bad [state]\n  Submit failed. Keeping mm/resolve-dependencies "
            "for manual recovery.",
            "  bad [state]\n  Submit failed. Keeping mm/resolve-dependencies "
            "for manual recovery.",
        ),
        (
            Operation.REMOTE_SYNC,
            "Warning: a[b] — failed to sync remote: bad [state]",
            "Warning: a[b] — failed to sync remote: bad [state]",
        ),
        (Operation.SYNC, "  a[b] — bad [state]", "  a[b] — bad [state]"),
    ],
)
@pytest.mark.parametrize("batch", [False, True])
def test_given_operation_failure_when_rendered_then_mode_specific_literal_is_printed(
    output, operation, single, batch_text, batch
):
    cli._Renderer(batch=batch)(OperationFailed(operation, "a[b]", "bad [state]"))
    assert output.getvalue().strip("\n") == (batch_text if batch else single)
