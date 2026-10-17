from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from maintenance_man import cli, scanner
from maintenance_man.cli import ExitCode, _print_scan_result, _scan_exit_code
from maintenance_man.gradle import GradleError
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    FindingsBlocked,
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
)
from maintenance_man.services import scan as scan_service
from maintenance_man.services.scan import ScanSummary
from maintenance_man.vcs import RevisionError
from tests.conftest import (
    TerminalStream,
    make_scan_result,
    make_update,
    missing_tool,
    ops_with_outdated,
    run_mm,
    write_config,
)
from tests.fake_vcs import FakeJjState


def _terminal_stdout(monkeypatch: pytest.MonkeyPatch, width: int = 220) -> StringIO:
    stream = TerminalStream()
    monkeypatch.setattr("sys.stdout", stream)
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setenv("NO_COLOR", "1")
    return stream


@pytest.mark.parametrize(
    ("pkg_name", "reason"),
    [
        ("org.x:lib", "rich version"),
        ("org.x:[lib]", "cannot render [catalogue]"),
    ],
)
def test_given_blocked_update_when_scan_result_printed_then_row_is_literal(
    monkeypatch, pkg_name, reason
):
    stream = _terminal_stdout(monkeypatch)
    blocked = make_update(
        pkg_name=pkg_name,
        installed_version="unknown",
        latest_version="2.0",
        blocked_reason=reason,
    )
    plain = make_update(pkg_name="pkg-a")

    cli._print_scan_result(make_scan_result(vulns=[], updates=[blocked, plain]))

    lines = stream.getvalue().splitlines()
    assert any(
        "! blocked" in line and pkg_name in line and reason in line for line in lines
    )
    assert any("~ update" in line and "pkg-a" in line for line in lines)


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
    write_config(
        mm_home,
        f'[projects.first]\npath = "{first}"\npackage_manager = "bun"\n'
        f'[projects.second]\npath = "{second}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n",
    )
    results = mm_home / "scan-results"
    results.mkdir(exist_ok=True)
    (results / "first.json").write_bytes(b"previous first result")
    return results


def test_given_two_clean_projects_when_batch_scanned_then_one_notice_names_both(
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _two_project_config(mm_home, tmp_path)
    monkeypatch.setattr(
        "maintenance_man.services.scan.prune_stale_bookmarks", lambda **kwargs: None
    )
    monkeypatch.setattr(
        "maintenance_man.services.scan.scan_project",
        lambda name, project, days: ScanResult(
            project=name,
            scanned_at=datetime(2026, 1, 15, 12, tzinfo=UTC),
            trivy_target=".",
        ),
    )

    assert run_mm("scan") == ExitCode.OK

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines()[-1].startswith(
        "2 projects have no findings: first, second · scanned in "
    )


def test_scan_without_trivy_reports_an_empty_config(mm_home, monkeypatch, capsys):
    mm_home.mkdir(parents=True)
    write_config(mm_home, "")
    monkeypatch.setattr(
        "maintenance_man.vcs_workflow.require_tool", missing_tool("trivy")
    )
    monkeypatch.setattr("maintenance_man.scanner.require_tool", missing_tool("trivy"))
    assert run_mm("scan") == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "No projects configured",
        "hint: add projects to ~/.mm/config.toml",
    ]


def test_scan_without_trivy_reports_an_unknown_project(
    mm_home_with_projects, monkeypatch, capsys
):
    monkeypatch.setattr(
        "maintenance_man.vcs_workflow.require_tool", missing_tool("trivy")
    )
    monkeypatch.setattr("maintenance_man.scanner.require_tool", missing_tool("trivy"))
    assert run_mm("scan", "nonexistent") == 1
    assert "trivy" not in capsys.readouterr().out.lower()


def test_given_remote_sync_failure_when_scan_runs_then_exits_zero_with_warning(
    mm_home_with_projects: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_remote_sync(**kwargs) -> None:
        message = "offline"
        raise RevisionError(message)

    monkeypatch.setattr(scan_service, "prune_stale_bookmarks", fail_remote_sync)

    assert run_mm("scan", "clean") == ExitCode.OK
    assert (
        "Warning: clean — failed to sync remote: offline"
        in capsys.readouterr().out.splitlines()
    )


def test_batch_scan_without_trivy_scans_uv_and_exits_error(
    mm_home, tmp_path, monkeypatch
):
    results = _two_project_config(mm_home, tmp_path)
    (results / "first.json").unlink()
    monkeypatch.setattr(
        "maintenance_man.services.scan.scan_project", scanner.scan_project
    )
    monkeypatch.setattr(
        "maintenance_man.vcs_workflow.require_tool", missing_tool("trivy")
    )
    monkeypatch.setattr("maintenance_man.scanner.require_tool", missing_tool("trivy"))
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda path: [])
    monkeypatch.setattr(
        "maintenance_man.scanner.package_manager_ops",
        ops_with_outdated(lambda project: []),
    )
    assert run_mm("scan") == ExitCode.ERROR
    assert not (results / "first.json").exists()
    assert (results / "second.json").is_file()


class TestScanSingleProject:
    def test_scan_project_with_vulns_exits_2(self, mm_home_with_projects: Path):
        """mm scan vulnerable — has vulns, should exit 2."""
        assert run_mm("scan", "vulnerable") == 2

    def test_scan_project_with_vulns_shows_findings(
        self, mm_home_with_projects: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Output should contain vulnerability information."""
        assert run_mm("scan", "vulnerable") == 2
        output = capsys.readouterr().out
        assert "CVE-2024-0001" in output
        assert "some-pkg" in output

    def test_scan_clean_project_exits_0(self, mm_home_with_projects: Path):
        """mm scan clean — clean, should exit 0."""
        assert run_mm("scan", "clean") == 0

    def test_scan_unknown_project_exits_1(self, mm_home_with_projects: Path):
        """mm scan nonexistent — should exit 1."""
        assert run_mm("scan", "nonexistent") == 1


class TestScanAllProjects:
    def test_scan_all_exits_worst_case(self, mm_home_with_projects: Path):
        """mm scan (no args) — should exit 2 if any project has vulns."""
        assert run_mm("scan") == 2


class TestScanUpdatesExitCodes:
    def test_scan_updates_only_exits_3(self, mm_home_with_projects: Path):
        """mm scan outdated — updates only, no vulns, should exit 3."""
        assert run_mm("scan", "outdated") == 3

    def test_scan_updates_output_shows_update_rows(
        self, mm_home_with_projects: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Output should contain update information."""
        assert run_mm("scan", "outdated") == 3
        output = capsys.readouterr().out
        assert "UPDATE" in output or "update" in output.lower()
        assert "axios" in output

    def test_scan_vulns_and_updates_exits_2(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """If project has both vulns and updates, exit 2 (vulns take precedence)."""
        mixed = _make_vulnerable_result().model_copy(
            update={"updates": _make_updates_only_result().updates}
        )
        monkeypatch.setattr(
            "maintenance_man.services.scan.scan_project",
            lambda *args, **kwargs: mixed,
        )
        assert run_mm("scan", "vulnerable") == 2


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
            ),
            make_update(pkg_name="pkg-a"),
        ],
    )

    _print_scan_result(result)
    out = capsys.readouterr().out

    rows = [line.split("\t") for line in out.splitlines()]
    assert [(row[1], row[2], row[8]) for row in rows] == [
        ("update", "ksp", "blocked"),
        ("update", "pkg-a", "available"),
    ]
    assert "publication date" in rows[0][9]


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


def _blocked_mixed_result() -> ScanResult:
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
    return result


def test_given_blocked_scan_when_rendered_then_each_blocked_row_carries_its_reason(
    monkeypatch,
):
    stream = _terminal_stdout(monkeypatch)

    cli._print_scan_result(_blocked_mixed_result())

    lines = stream.getvalue().splitlines()
    for package, reason in (
        ("some-pkg", "Cannot identify catalogue entry"),
        ("unfixed-pkg", "No published fix"),
        ("agp", "Publication lookup timed out"),
    ):
        (row,) = [line for line in lines if package in line]
        assert "! blocked" in row
        assert reason in row
    available = next(line for line in lines if "available" in line)
    assert "~ update" in available
    assert "timed out" not in available


def test_given_blocked_scan_when_piped_then_kind_stays_and_status_is_blocked(capsys):
    cli._print_scan_result(_blocked_mixed_result())

    rows = [line.split("\t") for line in capsys.readouterr().out.splitlines()]
    assert [(row[1], row[2], row[8], row[9]) for row in rows] == [
        ("vuln", "some-pkg", "blocked", "Cannot identify catalogue entry"),
        ("advisory", "unfixed-pkg", "blocked", "No published fix"),
        ("update", "agp", "blocked", "Publication lookup timed out"),
        ("update", "available", "available", "-"),
    ]


def test_given_long_blocked_detail_when_rendered_narrow_then_text_ends_in_ellipsis(
    monkeypatch,
):
    stream = _terminal_stdout(monkeypatch, width=80)
    result = _make_vulnerable_result()
    result.vulnerabilities[0].pkg_name = "org.apache.commons:commons-lang3"
    result.vulnerabilities[
        0
    ].blocked_reason = "cannot identify an unambiguous catalogue entry"

    cli._print_scan_result(result)

    lines = stream.getvalue().splitlines()
    (row,) = [line for line in lines if "! blocked" in line]
    assert "org.apache.commons:commons-lang3" in row
    assert row.endswith("…")
    assert all(len(line) <= 80 for line in lines)


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

    assert run_mm("scan", "android") == ExitCode.ERROR


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

    assert run_mm("scan") == ExitCode.ERROR
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
    write_config(
        mm_home,
        f'[projects.sample]\npath = "{tmp_path}"\npackage_manager = "{manager}"\n',
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
    expected = 3 if with_updates else 0
    argv = ["scan"] if all_projects else ["scan", "sample"]
    assert run_mm(*argv) == expected


@pytest.mark.parametrize("manager", ["gradle", "uv", "bun", "mvn"])
def test_scan_uses_standard_rows_for_each_advisory(monkeypatch, manager, tmp_path):
    stream = _terminal_stdout(monkeypatch, width=180)
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
        emit=cli._Renderer(batch=False, project="android", flow="scan"),
    )
    rendered = stream.getvalue()
    assert rendered.count("org.example:shared") == 2
    assert "! vuln" in rendered
    assert "! advisory" in rendered
    assert "versions" in rendered
    assert "1.0 → 1.1" in rendered
    assert "CVE-A" in rendered
    assert "CVE-B" in rendered
    assert "high" in rendered
    assert [
        row["vuln_id"] for row in result.model_dump(mode="json")["vulnerabilities"]
    ] == ["CVE-A", "CVE-B"]


def test_gradle_advisories_keep_installed_versions_separate(capsys):
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
    rows = [line.split("\t") for line in capsys.readouterr().out.splitlines()]
    assert [(row[2], row[3]) for row in rows] == [
        ("org.example:shared", "1.0"),
        ("org.example:shared", "2.0"),
    ]


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
