import typing
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from rich.text import Text

from maintenance_man import cli, scanner, vcs_workflow
from maintenance_man.cli import ExitCode, _print_scan_result, _scan_exit_code, app
from maintenance_man.gradle import GradleError
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    Event,
    FindingsBlocked,
    GradleFlowFailed,
    GradleRunArchived,
    GradleWithheld,
    NoEligibleGradleChanges,
    Operation,
    OperationFailed,
    ProjectSkipped,
    PullRequestOutput,
    SkipReason,
    SyncCompleted,
)
from maintenance_man.models.gradle import (
    CandidateWithheld,
    CompleteResolution,
    FailedAttempt,
    GradleCandidate,
    GradleSnapshot,
    ResolutionReport,
    WithheldAttempt,
)
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    VulnFinding,
    Workflow,
)
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.process import ToolNotFoundError
from maintenance_man.services import scan as scan_service
from maintenance_man.services.scan import ScanSummary
from maintenance_man.storage import load_scan_results
from maintenance_man.vcs import RevisionError
from tests.conftest import (
    make_scan_result,
    make_update,
    ops_with_outdated,
    run_mm,
    write_config,
)
from tests.fake_vcs import FakeJjState


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
@pytest.mark.parametrize(
    ("event", "single", "batch_text"),
    [
        (
            ProjectSkipped("a[b]", SkipReason.PATH_MISSING, "/tmp/[path]"),
            "Warning: a[b] — path does not exist: /tmp/[path]",
            "Warning: a[b] — path does not exist: /tmp/[path]",
        ),
        (
            ProjectSkipped("a[b]", SkipReason.NO_SCAN_RESULTS),
            "a[b] — no scan results; nothing to do.",
            "",
        ),
        (
            ProjectSkipped("a[b]", SkipReason.NOTHING_TO_DO, "resolve"),
            "a[b] — nothing to resolve.",
            "  a[b] — nothing to update",
        ),
        (
            ProjectSkipped("a[b]", SkipReason.FLOW_CONFLICT, "bad [projects.x]"),
            "  Skipped: a[b] — bad [projects.x]",
            "  Skipped: a[b] — bad [projects.x]",
        ),
        (
            ProjectSkipped("a[b]", SkipReason.NOT_DEPLOYABLE),
            "a[b] — skipped (not deployable)",
            "a[b] — skipped (not deployable)",
        ),
        (
            ProjectSkipped("a[b]", SkipReason.UNCHANGED),
            "a[b] unchanged since last deploy (use --force to redeploy).",
            "a[b] — unchanged since last deploy",
        ),
        (
            ProjectSkipped("a[b]", SkipReason.BLOCKED),
            "Warning: a[b] — could not resolve main revision; skipping "
            "(use --force to deploy anyway)",
            "Warning: a[b] — could not resolve main revision; skipping "
            "(use --force to deploy anyway)",
        ),
        (
            OperationFailed(Operation.UPDATE_SETUP, "a[b]", "bad [projects.x]"),
            "  Error: a[b] — bad [projects.x]",
            "  Error: a[b] — bad [projects.x]",
        ),
        (
            OperationFailed(Operation.PROMOTE, "a[b]", "bad [projects.x]"),
            "Promotion failed: bad [projects.x]",
            "Promotion failed: bad [projects.x]",
        ),
        (
            OperationFailed(Operation.REFRESH, "a[b]", "bad [projects.x]"),
            "Workspace refresh failed: a[b]: bad [projects.x]",
            "Workspace refresh failed: a[b]: bad [projects.x]",
        ),
        (
            OperationFailed(Operation.WORKSPACE_CLEANUP, "a[b]", "bad [projects.x]"),
            "Workspace cleanup failed: bad [projects.x]",
            "  Workspace cleanup failed: bad [projects.x]",
        ),
        (
            OperationFailed(Operation.BOOKMARK_CLEANUP, "a[b]", "bad [projects.x]"),
            "Bookmark cleanup failed: bad [projects.x]",
            "  Bookmark cleanup failed: a[b] — bad [projects.x]",
        ),
        (
            OperationFailed(Operation.RESOLVE_SETUP, "a[b]", "bad [projects.x]"),
            "  Resolve setup failed: bad [projects.x]",
            "  Resolve setup failed: bad [projects.x]",
        ),
        (
            OperationFailed(Operation.SUBMIT, "a[b]", "bad [projects.x]"),
            "  bad [projects.x]\n  Submit failed. Keeping mm/resolve-dependencies "
            "for manual recovery.",
            "  bad [projects.x]\n  Submit failed. Keeping mm/resolve-dependencies "
            "for manual recovery.",
        ),
        (
            OperationFailed(Operation.REMOTE_SYNC, "a[b]", "bad [projects.x]"),
            "Warning: a[b] — failed to sync remote: bad [projects.x]",
            "Warning: a[b] — failed to sync remote: bad [projects.x]",
        ),
        (
            OperationFailed(Operation.SCAN, "a[b]", "bad [projects.x]"),
            "Error: a[b] — bad [projects.x]",
            "Error: a[b] — bad [projects.x]",
        ),
        (
            OperationFailed(Operation.SYNC, "a[b]", "bad [projects.x]"),
            "  a[b] — bad [projects.x]",
            "  a[b] — bad [projects.x]",
        ),
        (
            SyncCompleted("a[b]", "already [up] to date"),
            "  a[b] — already [up] to date",
            "  a[b] — already [up] to date",
        ),
        (
            GradleWithheld("g:[lib]", "too [new]"),
            "Withheld g:[lib]: too [new]",
            "Withheld g:[lib]: too [new]",
        ),
        (
            NoEligibleGradleChanges(),
            "No eligible Gradle changes",
            "No eligible Gradle changes",
        ),
        (
            GradleRunArchived(Path("/tmp/[history]/run.json")),
            "Archived failed Gradle run to /tmp/[history]/run.json; "
            "rebuilding candidates from main",
            "Archived failed Gradle run to /tmp/[history]/run.json; "
            "rebuilding candidates from main",
        ),
        (
            GradleFlowFailed(Workflow.UPDATE, "bad [projects.x]"),
            "Cannot complete Gradle update: bad [projects.x]",
            "Cannot complete Gradle update: bad [projects.x]",
        ),
    ],
)
def test_event_renderer_preserves_text(
    monkeypatch: pytest.MonkeyPatch,
    event: Event,
    single: str,
    batch_text: str,
    batch: bool,
) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=220, color_system=None)
    )

    cli._Renderer(batch=batch)(event)

    assert output.getvalue().rstrip("\n") == (batch_text if batch else single)


@pytest.mark.parametrize("batch", [False, True])
def test_pull_request_output_is_indented_and_dim(
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


def test_every_event_has_a_renderer() -> None:
    assert set(typing.get_args(Event.__value__)) == set(cli._RENDERERS)


def test_numbered_findings_print_bracketed_values_literally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=220, color_system=None)
    )
    vuln = (
        _make_vulnerable_result()
        .vulnerabilities[0]
        .model_copy(update={"pkg_name": "a[b]", "vuln_id": "CVE-[x]"})
    )
    update = (
        _make_updates_only_result().updates[0].model_copy(update={"pkg_name": "u[p]"})
    )

    cli._print_numbered_findings([vuln], [update])

    assert "a[b]" in output.getvalue()
    assert "CVE-[x]" in output.getvalue()
    assert "u[p]" in output.getvalue()


@pytest.mark.parametrize("failure", ["fetch", "local_bookmarks", "delete_bookmark"])
def test_housekeeping_failure_still_saves_scan(
    mm_home, tmp_path, monkeypatch, capsys, failure
):
    project_path = tmp_path / "project"
    state = FakeJjState()
    repo = state.seed_repository(project_path, files={"dep.txt": "version=1\n"})
    repo.set_bookmark(bookmark="mm/update-dependencies", revision="main")
    state.code_host(project_path).seed_pr(
        bookmark="mm/update-dependencies", state="merged"
    )
    write_config(
        mm_home,
        f'[projects.demo]\npath = "{project_path}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n",
    )
    monkeypatch.setattr(cli, "make_vcs_services", state.services)
    monkeypatch.setattr(
        scan_service, "prune_stale_bookmarks", vcs_workflow.prune_stale_bookmarks
    )
    monkeypatch.setattr(scan_service, "scan_project", scanner.scan_project)
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda path: [])
    monkeypatch.setattr(
        scanner, "package_manager_ops", ops_with_outdated(lambda project: [])
    )
    state.fail(
        failure,
        error=RevisionError(f"{failure} unavailable"),
        path=project_path,
    )

    assert run_mm("scan", "demo") == 0

    assert f"{failure} unavailable" in capsys.readouterr().out
    assert repo.bookmark_exists(bookmark="mm/update-dependencies")
    saved = load_scan_results("demo")
    assert saved.project == "demo"
    assert saved.vulnerabilities == []
    assert saved.updates == []


def _make_vulnerable_result() -> ScanResult:
    return ScanResult(
        project="vulnerable",
        scanned_at=datetime.now(tz=UTC),
        trivy_target="tests/fixtures/vulnerable-project",
        vulnerabilities=[
            VulnFinding(
                vuln_id="CVE-2024-0001",
                pkg_name="some-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.HIGH,
                title="Test vulnerability",
                description="A test vulnerability",
                status="fixed",
            ),
        ],
    )


def _make_clean_result() -> ScanResult:
    return ScanResult(
        project="clean",
        scanned_at=datetime.now(tz=UTC),
        trivy_target="tests/fixtures/clean-project",
    )


def _make_updates_only_result() -> ScanResult:
    return ScanResult(
        project="outdated",
        scanned_at=datetime.now(tz=UTC),
        trivy_target="tests/fixtures/clean-project",
        updates=[
            UpdateFinding(
                pkg_name="axios",
                installed_version="1.6.0",
                latest_version="1.7.2",
                semver_tier=SemverTier.MINOR,
            ),
        ],
    )


@pytest.fixture(autouse=True)
def _mock_trivy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent all CLI tests from calling real Trivy."""
    monkeypatch.setattr(
        "maintenance_man.services.scan.prune_stale_bookmarks", lambda **kwargs: None
    )

    def _fake_scan(
        name: str,
        project_config: object,
        min_version_age_days: int = 7,
        **kwargs: object,
    ) -> ScanResult:
        match name:
            case "vulnerable":
                return _make_vulnerable_result()
            case "clean":
                return _make_clean_result()
            case "outdated":
                return _make_updates_only_result()
            case "no-tests" | "deployable" | "deploy-only" | "no-deploy":
                return _make_clean_result()
            case _:
                msg = f"Unknown project: {name}"
                raise FileNotFoundError(msg)

    monkeypatch.setattr("maintenance_man.services.scan.scan_project", _fake_scan)


def _two_project_config(mm_home, tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "config.toml").write_text(
        f'[projects.first]\npath = "{first}"\npackage_manager = "bun"\n'
        f'[projects.second]\npath = "{second}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n"
    )
    results = mm_home / "scan-results"
    results.mkdir(exist_ok=True)
    (results / "first.json").write_bytes(b"previous first result")
    return results


def _missing(tool):
    def require(name, hint):
        if name == tool:
            msg = f"{name} is not installed or not on PATH. {hint}"
            raise ToolNotFoundError(msg)
        return Path("/usr/bin") / name

    return require


def test_scan_without_trivy_reports_an_empty_config(mm_home, monkeypatch, capsys):
    mm_home.mkdir(parents=True)
    (mm_home / "config.toml").write_text("")
    monkeypatch.setattr("maintenance_man.vcs_workflow.require_tool", _missing("trivy"))
    monkeypatch.setattr("maintenance_man.scanner.require_tool", _missing("trivy"))
    with pytest.raises(SystemExit) as exc:
        app(["scan"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "No projects configured" in output
    assert "trivy" not in output.lower()


def test_scan_without_trivy_reports_an_unknown_project(
    mm_home_with_projects, monkeypatch, capsys
):
    monkeypatch.setattr("maintenance_man.vcs_workflow.require_tool", _missing("trivy"))
    monkeypatch.setattr("maintenance_man.scanner.require_tool", _missing("trivy"))
    with pytest.raises(SystemExit) as exc:
        app(["scan", "nonexistent"])
    assert exc.value.code == 1
    assert "trivy" not in capsys.readouterr().out.lower()


@pytest.mark.parametrize("tool", ["jj", "gh"])
def test_scan_warns_and_continues_without_housekeeping_tools(
    mm_home_with_projects, monkeypatch, capsys, tool
):
    monkeypatch.setattr("maintenance_man.vcs_workflow.require_tool", _missing(tool))
    prune = MagicMock(return_value=True)
    monkeypatch.setattr("maintenance_man.services.scan.prune_stale_bookmarks", prune)
    with pytest.raises(SystemExit) as exc:
        app(["scan", "clean"])
    assert exc.value.code == 0
    prune.assert_not_called()
    assert f"{tool} is not installed" in capsys.readouterr().out


def test_batch_scan_without_trivy_scans_uv_and_exits_error(
    mm_home, tmp_path, monkeypatch
):
    results = _two_project_config(mm_home, tmp_path)
    (results / "first.json").unlink()
    monkeypatch.setattr(
        "maintenance_man.services.scan.scan_project", scanner.scan_project
    )
    monkeypatch.setattr("maintenance_man.vcs_workflow.require_tool", _missing("trivy"))
    monkeypatch.setattr("maintenance_man.scanner.require_tool", _missing("trivy"))
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda path: [])
    monkeypatch.setattr(
        "maintenance_man.scanner.package_manager_ops",
        ops_with_outdated(lambda project: []),
    )
    with pytest.raises(SystemExit) as exc:
        app(["scan"])
    assert exc.value.code == ExitCode.ERROR
    assert not (results / "first.json").exists()
    assert (results / "second.json").is_file()


@pytest.mark.parametrize("failure", ["outdated", "scanner"])
@pytest.mark.parametrize("argv", [["scan"], ["scan", "first"]])
def test_failed_project_scan_keeps_its_result_and_exits_error(
    mm_home, tmp_path, monkeypatch, failure, argv
):
    results = _two_project_config(mm_home, tmp_path)
    monkeypatch.setattr(
        "maintenance_man.services.scan.scan_project", scanner.scan_project
    )
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda path: [])

    def trivy(*args, **kwargs):
        if failure == "scanner":
            msg = "Trivy filesystem scan failed (exit 1): boom"
            raise scanner.ScanError(msg)
        return [], []

    def outdated(project):
        if failure == "outdated" and project.package_manager == "bun":
            msg = "bun outdated failed (exit 1): boom"
            raise OutdatedCheckError(msg)
        return []

    monkeypatch.setattr("maintenance_man.scanner._run_trivy_scan", trivy)
    monkeypatch.setattr(
        "maintenance_man.scanner.package_manager_ops", ops_with_outdated(outdated)
    )
    with pytest.raises(SystemExit) as exc:
        app(argv)
    assert exc.value.code == ExitCode.ERROR
    assert (results / "first.json").read_bytes() == b"previous first result"
    assert (results / "second.json").is_file() is (argv == ["scan"])


def test_scan_warns_and_continues_when_bookmark_pruning_cannot_run(
    mm_home_with_projects, monkeypatch, capsys
):
    def fail(**kwargs):
        msg = "Could not run jj git fetch: missing jj"
        raise RevisionError(msg)

    monkeypatch.setattr("maintenance_man.services.scan.prune_stale_bookmarks", fail)
    with pytest.raises(SystemExit) as exc:
        app(["scan", "clean"])
    assert exc.value.code == 0
    assert "failed to sync remote" in capsys.readouterr().out


class TestScanSingleProject:
    def test_scan_project_with_vulns_exits_2(self, mm_home_with_projects: Path):
        """mm scan vulnerable — has vulns, should exit 2."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "vulnerable"])
        assert exc_info.value.code == 2

    def test_scan_project_with_vulns_shows_findings(
        self, mm_home_with_projects: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Output should contain vulnerability information."""
        with pytest.raises(SystemExit):
            app(["scan", "vulnerable"])
        output = capsys.readouterr().out
        assert "CVE-" in output or "vuln" in output.lower()

    def test_scan_clean_project_exits_0(self, mm_home_with_projects: Path):
        """mm scan clean — clean, should exit 0."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "clean"])
        assert exc_info.value.code == 0

    def test_scan_unknown_project_exits_1(self, mm_home_with_projects: Path):
        """mm scan nonexistent — should exit 1."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "nonexistent"])
        assert exc_info.value.code == 1


class TestScanAllProjects:
    def test_scan_all_exits_worst_case(self, mm_home_with_projects: Path):
        """mm scan (no args) — should exit 2 if any project has vulns."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan"])
        # vulnerable has vulns, so worst case is 2
        assert exc_info.value.code == 2


class TestScanUpdatesExitCodes:
    def test_scan_updates_only_exits_3(self, mm_home_with_projects: Path):
        """mm scan outdated — updates only, no vulns, should exit 3."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "outdated"])
        assert exc_info.value.code == 3

    def test_scan_updates_output_shows_update_rows(
        self, mm_home_with_projects: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Output should contain update information."""
        with pytest.raises(SystemExit):
            app(["scan", "outdated"])
        output = capsys.readouterr().out
        assert "UPDATE" in output or "update" in output.lower()
        assert "axios" in output

    def test_scan_clean_still_exits_0(self, mm_home_with_projects: Path):
        """Clean project (no vulns, no updates) still exits 0."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "clean"])
        assert exc_info.value.code == 0

    def test_scan_vulns_and_updates_exits_2(self, mm_home_with_projects: Path):
        """If project has both vulns and updates, exit 2 (vulns take precedence)."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "vulnerable"])
        assert exc_info.value.code == 2


class TestScanAllWithUpdates:
    def test_scan_all_updates_takes_precedence_over_clean(
        self, mm_home_with_projects: Path
    ):
        """mm scan (all) — worst case includes updates, but vulns override."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan"])
        # vulnerable has vulns → exit 2 takes precedence
        assert exc_info.value.code == 2


def test_blocked_gradle_candidates_are_shown_not_treated_as_clean(capsys):
    result = make_scan_result(
        vulns=[],
        updates=[
            make_update(
                pkg_name="ksp",
                installed_version="2.3.10",
                latest_version="2.3.12",
                blocked_reason=(
                    "no Maven Central publication date for "
                    "com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin "
                    "2.3.12"
                ),
                gradle_block_kind="age",
            )
        ],
    )

    _print_scan_result(result)
    out = capsys.readouterr().out

    assert "clean" not in out
    assert "ksp" in out
    assert "UPDATE" in out
    assert "Blocked" not in out
    assert "publication date" not in out


def test_blocked_update_candidates_still_exit_updates_found():
    """A ScanResult whose only update is blocked must still reach
    UPDATES_FOUND: has_updates counts blocked candidates (they stay in
    ``updates``), and that count is what drives the exit code — not whether
    any update happens to be eligible.
    """
    result = make_scan_result(
        vulns=[],
        updates=[
            make_update(
                pkg_name="ksp",
                installed_version="2.3.10",
                latest_version="2.3.12",
                blocked_reason="no Maven Central publication date",
                gradle_block_kind="age",
            )
        ],
    )

    assert result.has_updates is True
    assert _scan_exit_code(ScanSummary.of(result)) == ExitCode.UPDATES_FOUND


def test_scan_keeps_update_planning_diagnostics_out_of_standard_rows(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=220, color_system=None)
    )
    result = _make_vulnerable_result()
    result.vulnerabilities[0].blocked_reason = "Cannot identify catalogue entry"
    result.vulnerabilities.append(
        result.vulnerabilities[0].model_copy(
            update={
                "pkg_name": "unfixed-pkg",
                "vuln_id": "CVE-2024-0002",
                "fixed_version": None,
                "blocked_reason": "No published fix",
            }
        )
    )
    result.updates = [
        make_update(pkg_name="agp", blocked_reason="Publication lookup timed out"),
        make_update(pkg_name="available"),
    ]

    cli._print_scan_result(result)
    lines = output.getvalue().splitlines()
    for label, package, reason in (
        ("VULN", "some-pkg", "Cannot identify catalogue entry"),
        ("ADV", "unfixed-pkg", "No published fix"),
        ("UPDATE", "agp", "Publication lookup timed out"),
    ):
        rows = [line for line in lines if package in line]
        assert len(rows) == 1
        assert label in rows[0]
        assert reason not in output.getvalue()
    available = next(line for line in lines if "available" in line)
    assert "UPDATE" in available
    assert "timed out" not in available


def test_scan_wraps_long_package_names_without_crowding_out_cves(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=80, color_system=None)
    )
    result = _make_vulnerable_result()
    result.vulnerabilities[0].pkg_name = "org.apache.commons:commons-lang3"
    result.vulnerabilities[
        0
    ].blocked_reason = "cannot identify an unambiguous catalogue entry"

    cli._print_scan_result(result)

    assert "VULN" in output.getvalue()
    assert "CVE-2024-0001" in output.getvalue()
    assert "…" not in output.getvalue()


def test_update_failure_keeps_its_reason_outside_scan_output(capsys):
    cli._Renderer(batch=False)(FindingsBlocked((("example", "apply failed"),)))

    out = capsys.readouterr().out
    assert "BLOCKED example" in out
    assert "apply failed" in out


def test_gradle_scan_failure_exits_error(mm_home_with_gradle, monkeypatch):
    def _boom(name, proj_config, *, minimum_age_days, vcs, emit):
        msg = "./gradlew cyclonedxBom failed (exit 1): boom"
        raise GradleError(msg)

    monkeypatch.setattr("maintenance_man.services.scan.scan_one", _boom)

    with pytest.raises(SystemExit) as exc:
        app(["scan", "android"])

    assert exc.value.code == ExitCode.ERROR


def test_gradle_scan_failure_in_all_project_scan_exits_error_after_others(
    mm_home_with_gradle, monkeypatch, capsys
):
    scanned: list[str] = []

    def _scan(name, proj_config, *, minimum_age_days, vcs, emit):
        scanned.append(name)
        if proj_config.package_manager == "gradle":
            msg = "boom"
            raise GradleError(msg)
        return make_scan_result(vulns=[], updates=[])

    monkeypatch.setattr("maintenance_man.services.scan.scan_one", _scan)

    with pytest.raises(SystemExit) as exc:
        app(["scan"])

    assert exc.value.code == ExitCode.ERROR
    assert "clean" in scanned or len(scanned) > 1
    assert "boom" in capsys.readouterr().out


@pytest.mark.parametrize("all_projects", [False, True])
@pytest.mark.parametrize("with_updates", [False, True])
@pytest.mark.parametrize("manager", ["gradle", "bun"])
@pytest.mark.parametrize("with_vulnerability", [False, True])
def test_scan_blocked_no_fix_vulnerability_exit(
    mm_home,
    tmp_path,
    monkeypatch,
    all_projects,
    with_updates,
    manager,
    with_vulnerability,
):
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "config.toml").write_text(
        f'[projects.sample]\npath = "{tmp_path}"\npackage_manager = "{manager}"\n'
    )
    result = make_scan_result(
        vulns=[
            VulnFinding(
                vuln_id="CVE-no-fix",
                pkg_name="unmapped",
                installed_version="1",
                fixed_version=None,
                severity=Severity.HIGH,
                title="No fix",
                description="No published fix",
                status="affected",
                blocked_reason="no fixed version",
                gradle_block_kind="mapping",
            )
        ]
        if with_vulnerability
        else [],
        updates=[
            make_update(blocked_reason="no publication date", gradle_block_kind="age")
        ]
        if with_updates
        else [],
    )
    assert not result.has_actionable_vulns
    monkeypatch.setattr(
        "maintenance_man.services.scan.scan_project", lambda *args, **kwargs: result
    )
    with pytest.raises(SystemExit) as exc:
        app(["scan"] if all_projects else ["scan", "sample"])
    expected = 3 if with_updates else 0
    assert exc.value.code == expected


def test_all_scan_real_wrapper_launch_error_preserves_results_and_scans_next(
    mm_home, gradle_project, monkeypatch
):
    from maintenance_man.gradle import GRADLE_INVENTORY_RELPATH
    from maintenance_man.scanner import scan_project

    monkeypatch.setattr("maintenance_man.services.scan.scan_project", scan_project)

    root = Path(gradle_project.path)
    (root / "gradlew").write_text("#!/definitely/missing/mm-interpreter\n")
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "config.toml").write_text(
        f'[projects.android]\npath = "{root}"\npackage_manager = "gradle"\n'
        f'[projects.remaining]\npath = "{root}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n"
    )
    results = mm_home / "scan-results"
    results.mkdir()
    (results / "android.json").write_bytes(b"previous scan results\n")
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda *args: [])
    monkeypatch.setattr("maintenance_man.scanner._check_outdated", lambda *args: [])
    with pytest.raises(SystemExit) as exc:
        app(["scan"])
    assert exc.value.code == ExitCode.ERROR
    assert (results / "android.json").read_bytes() == b"previous scan results\n"
    assert (results / "remaining.json").is_file()
    assert not (root / GRADLE_INVENTORY_RELPATH).exists()


_GRADLE_SCAN_CLI_MODULES = [
    ("androidx.room", "room-runtime", "2.8.4"),
    ("androidx.room", "room-compiler", "2.8.4"),
    ("com.squareup.okhttp3", "okhttp", "4.12.0"),
    ("com.google.code.gson", "gson", "2.11.0"),
    ("androidx.compose.ui", "ui", "1.9.0"),
    ("org.jetbrains", "annotations", "23.0.0"),
]


def _gradle_report_json_for_fixture_bom(root: Path) -> str:
    """A resolution report covering every fixtures/gradle/bom.json component.

    mmGradleReport now captures the resolution graph alongside the inventory
    in one combined command, so any test that fakes a real ``bom.json`` must
    also fake a matching ``report.json`` for the adapter's inventory-to-scope
    cross-check to accept it.
    """
    import hashlib
    import json

    from maintenance_man.gradle import GRADLE_CATALOGUE_RELPATH

    components: list[dict[str, object]] = [
        {"id": "root", "kind": "root", "module": None, "variants": []}
    ]
    for index, (group, artifact, version) in enumerate(_GRADLE_SCAN_CLI_MODULES):
        components.append(
            {
                "id": f"c{index}",
                "kind": "module",
                "module": {"group": group, "artifact": artifact, "version": version},
                "variants": ["runtime"],
            }
        )
    scope = {
        "project_path": ":",
        "domain": "project",
        "configuration": "runtimeClasspath",
    }
    return json.dumps(
        {
            "schema_version": 1,
            "root_project": ":",
            "producer_versions": {
                "gradle": "8.14.3",
                "cyclonedx": "3.4.1",
                "report": "1",
            },
            "catalogue_digest": hashlib.sha256(
                (root / GRADLE_CATALOGUE_RELPATH).read_bytes()
            ).hexdigest(),
            "repositories": [],
            "selected_scopes": [scope],
            "scopes": [
                {
                    "scope": scope,
                    "components": components,
                    "edges": [],
                    "unresolved": [],
                }
            ],
            "selection_errors": [],
        }
    )


@pytest.mark.parametrize(
    "phase",
    ["inventory-mkdir", "inventory-marker", "inventory-cleanup", "report-cleanup"],
)
def test_all_scan_owned_filesystem_error_preserves_results_and_processes_remaining(
    mm_home, gradle_project, monkeypatch, phase
):
    from maintenance_man.gradle import (
        GRADLE_INVENTORY_MARKER_RELPATH,
        GRADLE_INVENTORY_RELPATH,
        GRADLE_REPORT_MARKER_RELPATH,
    )
    from maintenance_man.scanner import _check_outdated, scan_project

    monkeypatch.setattr("maintenance_man.services.scan.scan_project", scan_project)
    root = Path(gradle_project.path)
    results = _seed_scan_filesystem_error_config(mm_home, root)
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda *args: [])
    monkeypatch.setattr(
        "maintenance_man.scanner._check_outdated",
        lambda project, *args: (
            [] if project.package_manager == "uv" else _check_outdated(project, *args)
        ),
    )
    _inject_scan_filesystem_failure(monkeypatch, phase, root)
    commands = _prepare_scan_filesystem_error_commands(monkeypatch, phase, root)
    with pytest.raises(SystemExit) as exc:
        app(["scan"])
    assert exc.value.code == ExitCode.ERROR
    assert (results / "android.json").read_bytes() == b"old result bytes"
    assert (results / "remaining.json").is_file()
    if phase == "inventory-cleanup":
        assert (root / GRADLE_INVENTORY_MARKER_RELPATH).is_file()
    else:
        assert not (root / GRADLE_INVENTORY_RELPATH).exists()
    if phase == "report-cleanup":
        assert (root / GRADLE_REPORT_MARKER_RELPATH).is_file()
    elif phase != "inventory-cleanup":
        assert commands == []


def _seed_scan_filesystem_error_config(mm_home: Path, root: Path) -> Path:
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "config.toml").write_text(
        f'[projects.android]\npath = "{root}"\npackage_manager = "gradle"\n'
        "scan_secrets = false\n"
        f'[projects.remaining]\npath = "{root}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n"
    )
    results = mm_home / "scan-results"
    results.mkdir()
    (results / "android.json").write_bytes(b"old result bytes")
    return results


def _inject_scan_filesystem_failure(monkeypatch, phase: str, root: Path) -> None:
    from maintenance_man.gradle import (
        GRADLE_INVENTORY_MARKER_RELPATH,
        GRADLE_INVENTORY_RELPATH,
        GRADLE_UPDATE_REPORT_RELPATH,
    )
    from tests.conftest import GRADLE_FIXTURES

    if phase == "inventory-mkdir":
        mkdir = Path.mkdir

        def fail(path, *args, **kwargs):
            if path == root / GRADLE_INVENTORY_RELPATH:
                msg = "mkdir denied"
                raise PermissionError(msg)
            return mkdir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", fail)
    elif phase == "inventory-marker":
        write = Path.write_bytes

        def fail(path, content):
            if path == root / GRADLE_INVENTORY_MARKER_RELPATH:
                msg = "marker denied"
                raise PermissionError(msg)
            return write(path, content)

        monkeypatch.setattr(Path, "write_bytes", fail)
    elif phase == "inventory-cleanup":

        def fail(*args, **kwargs):
            msg = "inventory cleanup denied"
            raise PermissionError(msg)

        monkeypatch.setattr("maintenance_man.gradle.shutil.rmtree", fail)
    else:
        _inject_report_cleanup_failure(
            monkeypatch, root, GRADLE_UPDATE_REPORT_RELPATH, GRADLE_FIXTURES
        )


def _inject_report_cleanup_failure(monkeypatch, root, report_path, fixtures) -> None:
    from maintenance_man.gradle_resolution import parse_resolution_report

    resolution = parse_resolution_report(
        (fixtures / "resolution/empty.json").read_text()
    )
    monkeypatch.setattr(
        "maintenance_man.scanner.scan_gradle",
        lambda *args: ([], resolution),
    )
    unlink = Path.unlink

    def fail(path, *args, **kwargs):
        if path == root / report_path:
            msg = "cleanup denied"
            raise PermissionError(msg)
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail)


def _prepare_scan_filesystem_error_commands(
    monkeypatch, phase: str, root: Path
) -> list[list[str]]:
    import subprocess

    from maintenance_man.gradle import GRADLE_UPDATE_REPORT_RELPATH
    from tests.conftest import GRADLE_FIXTURES

    commands: list[list[str]] = []

    def run(cmd, **kwargs):
        commands.append(cmd)
        if phase == "inventory-cleanup":
            from maintenance_man.gradle import GRADLE_INVENTORY_BOM_RELPATH

            if cmd[1] == "mmGradleReport":
                (root / GRADLE_INVENTORY_BOM_RELPATH).write_bytes(
                    (GRADLE_FIXTURES / "bom.json").read_bytes()
                )
                (root / GRADLE_INVENTORY_BOM_RELPATH).parent.joinpath(
                    "report.json"
                ).write_text(_gradle_report_json_for_fixture_bom(root))
            else:
                assert cmd[:2] == ["trivy", "sbom"]
                return subprocess.CompletedProcess(
                    cmd, 0, stdout='{"Results": []}', stderr=""
                )
        else:
            assert phase == "report-cleanup"
            assert cmd[1] == "versionCatalogUpdate"
            (root / GRADLE_UPDATE_REPORT_RELPATH).write_bytes(
                (GRADLE_FIXTURES / "updates-clean.toml").read_bytes()
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    return commands


@pytest.mark.parametrize(
    "failure",
    [
        "report-false",
        "trivy-root",
        "trivy-results",
        "trivy-row",
        "trivy-launch",
        "trivy-decode",
        "wrapper-decode",
    ],
)
def test_all_scan_malformed_gradle_output_preserves_results_and_continues(
    mm_home, gradle_project, monkeypatch, failure
):
    import json
    import subprocess

    from maintenance_man.gradle import (
        GRADLE_INVENTORY_BOM_RELPATH,
        GRADLE_INVENTORY_RELPATH,
        GRADLE_REPORT_MARKER_RELPATH,
        GRADLE_UPDATE_REPORT_RELPATH,
    )
    from maintenance_man.scanner import _check_outdated, scan_project
    from tests.conftest import GRADLE_FIXTURES

    root = Path(gradle_project.path)
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "config.toml").write_text(
        f'[projects.android]\npath = "{root}"\npackage_manager = "gradle"\n'
        "scan_secrets = false\n"
        f'[projects.remaining]\npath = "{root}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n"
    )
    results = mm_home / "scan-results"
    results.mkdir()
    (results / "android.json").write_bytes(b"old result bytes")
    monkeypatch.setattr("maintenance_man.services.scan.scan_project", scan_project)
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda *args: [])
    monkeypatch.setattr(
        "maintenance_man.scanner._check_outdated",
        lambda project, *args: (
            [] if project.package_manager == "uv" else _check_outdated(project, *args)
        ),
    )
    if failure == "report-false":
        from maintenance_man.gradle_resolution import parse_resolution_report

        resolution = parse_resolution_report(
            (GRADLE_FIXTURES / "resolution/empty.json").read_text()
        )
        monkeypatch.setattr(
            "maintenance_man.scanner.scan_gradle",
            lambda *args: ([], resolution),
        )

    def run(cmd, **kwargs):
        if cmd[1] == "mmGradleReport":
            if failure == "wrapper-decode":
                msg = "utf8"
                raise UnicodeDecodeError(msg, b"\xff", 0, 1, "invalid")
            (root / GRADLE_INVENTORY_BOM_RELPATH).write_bytes(
                (GRADLE_FIXTURES / "bom.json").read_bytes()
            )
            (root / GRADLE_INVENTORY_BOM_RELPATH).parent.joinpath(
                "report.json"
            ).write_text(_gradle_report_json_for_fixture_bom(root))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[1] == "versionCatalogUpdate":
            assert failure == "report-false"
            (root / GRADLE_UPDATE_REPORT_RELPATH).write_text("libraries = false\n")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        assert cmd[:2] == ["trivy", "sbom"]
        if failure == "trivy-launch":
            msg = "missing interpreter"
            raise FileNotFoundError(msg)
        if failure == "trivy-decode":
            msg = "utf8"
            raise UnicodeDecodeError(msg, b"\xff", 0, 1, "invalid")
        payload = {
            "trivy-root": [],
            "trivy-results": {"Results": False},
            "trivy-row": {"Results": [None]},
        }[failure]
        return subprocess.CompletedProcess(
            cmd, 0, stdout=json.dumps(payload), stderr=""
        )

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(SystemExit) as exc:
        app(["scan"])
    assert exc.value.code == ExitCode.ERROR
    assert (results / "android.json").read_bytes() == b"old result bytes"
    assert (results / "remaining.json").is_file()
    assert not (root / GRADLE_INVENTORY_RELPATH).exists()
    assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
    assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()


@pytest.mark.parametrize("manager", ["gradle", "uv", "bun", "mvn"])
def test_scan_uses_standard_rows_for_each_advisory(monkeypatch, manager, tmp_path):
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=180, color_system=None)
    )
    scope = ":app/project/debugRuntimeClasspath"
    findings = [
        VulnFinding(
            vuln_id=advisory,
            pkg_name="org.example:shared",
            installed_version="1.0",
            fixed_version="1.1" if advisory == "CVE-B" else None,
            severity=severity,
            title=advisory,
            description="",
            status="affected",
            gradle_scopes=(scope,),
        )
        for advisory, severity in (("CVE-A", Severity.LOW), ("CVE-B", Severity.HIGH))
    ]
    result = ScanResult(
        project="android",
        scanned_at=datetime.now(UTC),
        trivy_target="/fixture",
        vulnerabilities=findings,
    )
    state = FakeJjState()
    project_path = tmp_path / "project"
    state.seed_repository(project_path, files={})
    monkeypatch.setattr(scan_service, "scan_project", lambda *args, **kwargs: result)
    scan_service.scan_one(
        "android",
        ProjectConfig(path=project_path, package_manager=manager),
        minimum_age_days=7,
        vcs=state.services(),
        emit=cli._Renderer(batch=False),
    )
    rendered = output.getvalue()
    assert rendered.count("org.example:shared") == 2
    assert "VULN" in rendered
    assert "ADV" in rendered
    assert "Fix" in rendered
    assert "1.1" in rendered
    assert "CVE-A" in rendered
    assert "CVE-B" in rendered
    assert "HIGH" in rendered
    assert [
        row["vuln_id"] for row in result.model_dump(mode="json")["vulnerabilities"]
    ] == ["CVE-A", "CVE-B"]


def test_gradle_advisories_keep_installed_versions_separate(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=180, color_system=None)
    )
    result = ScanResult(
        project="android",
        scanned_at=datetime.now(UTC),
        trivy_target="/fixture",
        vulnerabilities=[
            VulnFinding(
                vuln_id="CVE-A",
                pkg_name="org.example:shared",
                installed_version=version,
                severity=Severity.UNKNOWN,
                title="",
                description="",
                status="affected",
            )
            for version in ("1.0", "2.0")
        ],
    )
    cli._print_scan_result(result)
    assert output.getvalue().count("org.example:shared") == 2


def _summary_run(blocks=(), attempts=(), residuals=()):
    return SimpleNamespace(
        selection_blocks=tuple(blocks),
        attempts=tuple(attempts),
        accepted_snapshot=SimpleNamespace(findings=tuple(residuals)),
    )


def _summary_attempt(state, reference="shared", reason="too young"):
    target = GradleUpdateTarget(
        version_ref=reference,
        target_version="2.0",
        members=[
            GradleMember(
                kind="library",
                alias="shared",
                coordinate="g:shared",
                installed_version="1.0",
            )
        ],
    )
    candidate = GradleCandidate(target=target, origins=frozenset({"ordinary"}))
    if state == "withheld":
        return WithheldAttempt(candidate=candidate, reason=reason)
    if state == "failed":
        baseline = GradleSnapshot(
            tree_id="tree",
            context_identity="context",
            inventory_digest="bom",
            inventory_modules=(),
            findings=(),
            resolution=CompleteResolution(
                report=ResolutionReport(
                    schema_version=1,
                    root_project=":",
                    producer_versions={
                        "gradle": "9.6.1",
                        "cyclonedx": "3.4.1",
                        "report": "1",
                    },
                    catalogue_digest="catalogue",
                    repositories=(),
                    selected_scopes=(),
                    scopes=(),
                )
            ),
        )
        return FailedAttempt(candidate=candidate, reason=reason, baseline=baseline)
    return SimpleNamespace(
        state=state, reason=reason, candidate=SimpleNamespace(target=target)
    )


def test_gradle_retry_summary_renders_persisted_selection_blocks(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=180, color_system=None)
    )
    blocks = [
        CandidateWithheld(
            group_key=group,
            coordinate="g:shared",
            installed_version="1.0",
            reason=reason,
            advisory_ids=frozenset({advisory}),
        )
        for group, reason, advisory in (
            ("ref:first", "too young", "CVE-A"),
            ("ref:first", "too young", "CVE-B"),
            ("ref:second", "too young", "CVE-C"),
            ("ref:first", "unsupported routing", "CVE-D"),
        )
    ]
    # Round-trip selection records to demonstrate the retry needs no preparation output.
    loaded = [
        CandidateWithheld.model_validate_json(block.model_dump_json())
        for block in blocks
    ]
    run = _summary_run(loaded, (_summary_attempt("completed"),), (object(),))
    cli._print_gradle_run_summary(run)
    text = output.getvalue()
    assert "Verified: 1; withheld: 3; failed: 0; residual advisories: 1" in text
    assert text.count("WITHHELD TARGET") == 3
    assert text.count("ref:first") == 2
    assert text.count("ref:second") == 1
    assert text.count("too young") == 2
    assert text.count("unsupported routing") == 1


def test_gradle_summary_keeps_unknown_versions_and_collapses_duplicate_reasons(
    monkeypatch,
):
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=180, color_system=None)
    )
    blocks = [
        CandidateWithheld(
            group_key=None,
            coordinate="g:unowned",
            installed_version=version,
            reason="ambiguous owner",
            advisory_ids=frozenset({advisory}),
        )
        for version, advisory in (("1.0", "CVE-A"), ("1.0", "CVE-B"), ("2.0", "CVE-C"))
    ]
    cli._print_gradle_run_summary(_summary_run(blocks))
    text = output.getvalue()
    assert "withheld: 2" in text
    assert text.count("RESIDUAL PACKAGE") == 2
    assert text.count("g:unowned@1.0") == 1
    assert text.count("g:unowned@2.0") == 1
    assert text.count("ambiguous owner") == 2


def test_gradle_summary_deduplicates_selection_and_attempt_but_retains_failures(
    monkeypatch,
):
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=180, color_system=None)
    )
    block = CandidateWithheld(
        group_key="ref:shared",
        coordinate="g:shared",
        installed_version="1.0",
        reason="too young",
    )
    run = _summary_run(
        (block,),
        (
            _summary_attempt("withheld"),
            _summary_attempt("failed", "broken", "unit tests failed"),
            _summary_attempt("applying", "interrupted"),
            _summary_attempt("ready", "accepted"),
        ),
    )
    cli._print_gradle_run_summary(run)
    text = output.getvalue()
    assert "Verified: 1; withheld: 1; failed: 2; residual advisories: 0" in text
    assert text.count("WITHHELD TARGET") == 1
    assert text.count("too young") == 1
    assert "shared -> 2.0" in text
    assert "FAILED broken -> 2.0" in text
    assert "unit tests failed" in text
