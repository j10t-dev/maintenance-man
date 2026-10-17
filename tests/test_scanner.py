import dataclasses
import hashlib
import json
import shutil
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from maintenance_man import dependency_age, paths, scanner
from maintenance_man.clock import utc_now
from maintenance_man.config import load_config
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GRADLE_INVENTORY_BOM_RELPATH,
    GRADLE_INVENTORY_MARKER_RELPATH,
    GRADLE_INVENTORY_RELPATH,
    GRADLE_REPORT_MARKER_RELPATH,
    GRADLE_UPDATE_REPORT_RELPATH,
    GradleError,
)
from maintenance_man.gradle_inventory import (
    CycloneDxInventory,
    load_inventory,
    parse_inventory_text,
)
from maintenance_man.gradle_resolution import (
    GeneratedGradleReport,
    parse_resolution_report,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import Operation, OperationFailed, ScanReported
from maintenance_man.models.gradle import ModuleId
from maintenance_man.models.scan import (
    ScanResult,
    SecretFinding,
    Severity,
    VulnFinding,
)
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.package_managers import PACKAGE_MANAGERS
from maintenance_man.process import ToolNotFoundError
from maintenance_man.scanner import (
    ScanError,
    _parse_gradle_trivy_output,
    _parse_uv_audit_vulns,
    scan_gradle,
    scan_project,
)
from maintenance_man.services import scan as scan_service
from maintenance_man.storage import load_scan_results
from maintenance_man.uv_dependencies import normalise_pkg_name
from tests.conftest import (
    GRADLE_FIXTURES,
    FakeClock,
    completed,
    fixture_runner,
    make_project,
    make_update,
    make_vuln,
    ops_with_outdated,
    write_config,
)
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeCommands, RecordingEmit
from tests.test_dependency_age import _pypi_body, _scan_age_inputs

_OLD = datetime(2024, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Requests", "requests"),
        ("pydantic_core", "pydantic-core"),
        ("zope.interface", "zope-interface"),
        ("Foo-_.Bar", "foo-bar"),
        ("rich", "rich"),
    ],
)
def test_given_package_name_when_normalised_then_pep_503_name_is_returned(
    name, expected
):
    assert normalise_pkg_name(name) == expected


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _batch_scan_dependencies(root: Path) -> tuple[FakeJjState, RecordingEmit]:
    state = FakeJjState()
    state.seed_repository(root, files={})
    return state, RecordingEmit()


def _quiet_uv_scan(monkeypatch):
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda path: [])
    monkeypatch.setattr(scanner, "_check_outdated", lambda *args: [])


def test_scan_project_saves_through_storage(mm_home, tmp_path, monkeypatch):
    _quiet_uv_scan(monkeypatch)
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)
    result = scanner.scan_project("demo", project)
    assert load_scan_results("demo") == result


def test_scan_project_replaces_results_symlink(mm_home, tmp_path, monkeypatch):
    _quiet_uv_scan(monkeypatch)
    results = mm_home / "scan-results"
    results.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text("keep")
    (results / "demo.json").symlink_to(outside)
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)
    scanner.scan_project("demo", project)
    assert not (results / "demo.json").is_symlink()
    assert outside.read_text() == "keep"


@pytest.mark.parametrize(
    "error",
    [
        OutdatedCheckError("uv sync --locked failed (exit 1): lock mismatch"),
        RuntimeError("bug"),
    ],
)
@pytest.mark.parametrize("previous", [b"previous result bytes", None])
def test_outdated_failure_fails_the_scan_and_keeps_the_saved_result(
    mm_home, tmp_path, monkeypatch, error, previous
):
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda path: [])
    monkeypatch.setattr(
        scanner, "package_manager_ops", ops_with_outdated(MagicMock(side_effect=error))
    )
    results = mm_home / "scan-results"
    results.mkdir(parents=True)
    if previous is not None:
        (results / "demo.json").write_bytes(previous)
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)
    with pytest.raises(type(error)):
        scanner.scan_project("demo", project)
    if previous is None:
        assert not (results / "demo.json").exists()
    else:
        assert (results / "demo.json").read_bytes() == previous


def test_given_uv_audit_when_status_has_findings_then_command_contract_accepts_it(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("VIRTUAL_ENV", "/host/venv")
    commands = FakeCommands()
    commands.add(
        ("uv", "audit", "--locked"),
        cwd=tmp_path,
        result=completed(("uv", "audit", "--locked"), returncode=1),
    )
    monkeypatch.setattr(scanner, "run_captured", commands)
    assert scanner._run_uv_audit(tmp_path) == []
    ((cmd, cwd, kwargs),) = commands.calls
    assert cmd == ("uv", "audit", "--locked")
    assert cwd == tmp_path
    assert kwargs == {
        "timeout": 300,
        "label": "uv audit --locked",
        "error": ScanError,
        "ok_codes": {0, 1},
    }


@pytest.mark.parametrize(
    "scan, argv, label",
    [
        (
            lambda path: scanner._run_uv_audit(path),
            ("uv", "audit", "--locked"),
            "uv audit --locked",
        ),
        (
            lambda path: scanner._run_trivy_scan(path, scanners="vuln"),
            ("trivy", "fs", "--format", "json", "--scanners", "vuln", "."),
            "Trivy filesystem scan",
        ),
    ],
)
@pytest.mark.parametrize(
    "raised",
    [
        FileNotFoundError(2, "No such file or directory", "tool"),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    ],
)
def test_given_command_execution_failure_when_scanning_then_scan_error_is_requested(
    tmp_path, monkeypatch, scan, argv, label, raised
):
    commands = FakeCommands()
    error = ScanError(f"Could not run {label} in {tmp_path}: {raised}")
    error.__cause__ = raised
    commands.add(argv, cwd=tmp_path, result=error)
    monkeypatch.setattr(scanner, "run_captured", commands)
    with pytest.raises(ScanError, match=label):
        scan(tmp_path)
    ((actual_argv, cwd, kwargs),) = commands.calls
    assert actual_argv == argv
    assert cwd == tmp_path
    expected = {"timeout": 300, "label": label, "error": ScanError}
    if argv == ("uv", "audit", "--locked"):
        expected["ok_codes"] = {0, 1}
    assert kwargs == expected


@pytest.mark.parametrize(
    "result",
    [
        {"Class": "secret", "Target": None, "Secrets": []},
        {"Class": "secret", "Target": "src/settings.env", "Secrets": 42},
        {
            "Class": "secret",
            "Target": "src/settings.env",
            "Secrets": [{"RuleID": False}],
        },
    ],
    ids=["null-target", "non-list-secrets", "non-string-rule-id"],
)
def test_given_malformed_consumed_secret_fields_when_scanned_then_scan_error(
    tmp_path, monkeypatch, result
):
    monkeypatch.setattr(scanner, "require_tool", lambda *args: None)
    commands = FakeCommands()
    commands.add(
        ("trivy", "fs", "--format", "json", "--scanners", "vuln,secret", "."),
        cwd=tmp_path,
        result=completed(stdout=json.dumps({"Results": [result]})),
    )
    monkeypatch.setattr(scanner, "run_captured", commands)

    with pytest.raises(ScanError, match="Trivy"):
        scanner._run_trivy_scan(tmp_path, scanners="vuln,secret")


def test_stale_comparison_context_is_a_gradle_error(gradle_project, monkeypatch):
    monkeypatch.setattr(scanner, "context_inputs_valid", lambda *args: False)
    with pytest.raises(GradleError, match="Comparison context expired"):
        scanner.capture_gradle_snapshot(
            gradle_project,
            MagicMock(),
            vcs=FakeJjState().services(),
            clock=utc_now,
        )


def test_capture_checks_the_context_at_the_injected_time(gradle_project, monkeypatch):

    clock = FakeClock(datetime(2032, 2, 3, 4, 5, 6, tzinfo=UTC))
    observed = []

    def stale(context, project, now):
        observed.append(now)
        return False

    monkeypatch.setattr(scanner, "context_inputs_valid", stale)
    with pytest.raises(GradleError, match="Comparison context expired"):
        scanner.capture_gradle_snapshot(
            gradle_project, MagicMock(), vcs=FakeJjState().services(), clock=clock
        )
    assert observed == [clock.current]


class TestUvAuditParsing:
    def test_parses_vulnerabilities(self):
        output = (
            "Found 1 known vulnerability and no adverse project statuses in "
            "1 package\n\n"
            "Vulnerabilities:\n\n"
            "setuptools 65.5.0 has 1 known vulnerability:\n\n"
            "- GHSA-r9hx-vwmv-q579: pypa/setuptools vulnerable to Regular "
            "Expression Denial of Service (ReDoS)\n\n"
            "  Fixed in: 65.5.1\n\n"
            "  Advisory information: https://nvd.nist.gov/vuln/detail/"
            "CVE-2022-40897\n"
        )

        vulns = _parse_uv_audit_vulns(output)

        assert len(vulns) == 1
        assert vulns[0].vuln_id == "GHSA-r9hx-vwmv-q579"
        assert vulns[0].pkg_name == "setuptools"
        assert vulns[0].installed_version == "65.5.0"
        assert vulns[0].fixed_version == "65.5.1"
        assert vulns[0].primary_url == "https://nvd.nist.gov/vuln/detail/CVE-2022-40897"

    def test_ignores_non_advisory_bullets_inside_package_section(self):
        output = """setuptools 65.5.0 has 1 known vulnerability:

- GHSA-r9hx-vwmv-q579: real vulnerability

- note: this is not another vulnerability

  Fixed in: 65.5.1
"""

        vulns = _parse_uv_audit_vulns(output)

        assert len(vulns) == 1
        assert vulns[0].vuln_id == "GHSA-r9hx-vwmv-q579"
        assert vulns[0].fixed_version == "65.5.1"


def _missing_trivy(name, hint):
    msg = f"{name} is not installed or not on PATH. {hint}"
    raise ToolNotFoundError(msg)


@pytest.mark.parametrize(
    "manager, secrets, needs_trivy",
    [
        ("uv", False, False),
        ("uv", True, True),
        ("bun", False, True),
        ("mvn", False, True),
    ],
)
def test_scan_requires_trivy_only_for_trivy_work(
    mm_home, tmp_path, monkeypatch, manager, secrets, needs_trivy
):
    monkeypatch.setattr(scanner, "require_tool", _missing_trivy)
    # uv audit is independent; stub it so this test isolates Trivy work.
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda path: [])
    monkeypatch.setattr(
        scanner, "package_manager_ops", ops_with_outdated(lambda project: [])
    )
    monkeypatch.setattr(scanner, "run_captured", FakeCommands())
    project = ProjectConfig(
        path=tmp_path, package_manager=manager, scan_secrets=secrets
    )
    if needs_trivy:
        with pytest.raises(ToolNotFoundError, match="trivy"):
            scanner.scan_project("demo", project)
    else:
        assert scanner.scan_project("demo", project).vulnerabilities == []


def test_gradle_scan_requires_trivy_before_generating_a_report(
    gradle_project, monkeypatch
):
    monkeypatch.setattr(scanner, "require_tool", _missing_trivy)
    monkeypatch.setattr(
        scanner,
        "generate_gradle_report",
        lambda *args: pytest.fail("report without trivy"),
    )
    with pytest.raises(ToolNotFoundError, match="trivy"):
        scanner.scan_gradle(gradle_project)


@pytest.mark.integration
class TestScanProject:
    def test_given_vulnerable_fixture_when_scanned_then_vulnerabilities_are_returned(
        self, scan_results_dir: Path
    ):
        project = make_project(
            FIXTURES_DIR / "vulnerable-project", package_manager="uv"
        )

        result = scan_project("vulnerable", project)

        assert isinstance(result, ScanResult)
        assert result.project == "vulnerable"
        assert result.scanned_at is not None
        assert len(result.vulnerabilities) > 0
        assert result.has_actionable_vulns is True
        for vulnerability in result.vulnerabilities:
            assert vulnerability.vuln_id.startswith(("CVE-", "GHSA-", "PYSEC-"))
            assert vulnerability.pkg_name
            assert vulnerability.installed_version
            assert vulnerability.severity in Severity
            assert vulnerability.title
            assert vulnerability.status

    def test_given_clean_fixture_when_scanned_then_no_vulnerabilities_are_returned(
        self, scan_results_dir: Path
    ):
        project = make_project(FIXTURES_DIR / "clean-project", package_manager="uv")

        result = scan_project("clean", project)

        assert isinstance(result, ScanResult)
        assert result.project == "clean"
        assert result.vulnerabilities == []
        assert result.has_actionable_vulns is False

    def test_given_vulnerable_fixture_when_scanned_then_json_round_trips(
        self, scan_results_dir: Path
    ):
        project = make_project(
            FIXTURES_DIR / "vulnerable-project", package_manager="uv"
        )

        scan_project("vulnerable", project)

        results_file = scan_results_dir / "vulnerable.json"
        assert results_file.is_file()
        data = json.loads(results_file.read_text())
        assert data["project"] == "vulnerable"
        assert "vulnerabilities" in data
        assert "secrets" in data
        assert ScanResult.model_validate(data).project == "vulnerable"

    def test_given_nonexistent_path_when_scanned_then_file_not_found_is_raised(
        self, scan_results_dir: Path
    ):
        project = make_project(Path("/nonexistent/path"), package_manager="uv")

        with pytest.raises(FileNotFoundError):
            scan_project("ghost", project)


def _configure_update_scan(monkeypatch, *, updates, vulnerabilities=()) -> None:
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda _path: list(vulnerabilities))
    monkeypatch.setattr(
        scanner, "package_manager_ops", ops_with_outdated(lambda _project: updates)
    )
    monkeypatch.setattr(
        scanner, "filter_registry_updates_by_age", lambda rows, *args, **kwargs: rows
    )


def test_given_outdated_packages_when_scanned_then_updates_are_returned(
    scan_results_dir, monkeypatch
):
    project = make_project(FIXTURES_DIR / "clean-project", package_manager="uv")
    updates = [make_update(pkg_name="requests")]
    _configure_update_scan(monkeypatch, updates=updates)

    result = scan_project("clean", project)

    assert [update.pkg_name for update in result.updates] == ["requests"]


def test_given_vulnerable_update_when_scanned_then_only_nonvulnerable_update_remains(
    scan_results_dir, monkeypatch
):
    project = make_project(FIXTURES_DIR / "vulnerable-project", package_manager="uv")
    updates = [
        make_update(pkg_name="cryptography"),
        make_update(pkg_name="brand-new-pkg"),
    ]
    _configure_update_scan(
        monkeypatch,
        updates=updates,
        vulnerabilities=[make_vuln(pkg_name="cryptography")],
    )

    result = scan_project("vulnerable", project)

    assert [finding.pkg_name for finding in result.vulnerabilities] == ["cryptography"]
    assert [update.pkg_name for update in result.updates] == ["brand-new-pkg"]


@pytest.mark.parametrize(
    ("secrets", "expected_secrets", "expected_commands"),
    [
        (False, [], [("uv", "audit", "--locked")]),
        (
            True,
            [
                SecretFinding(
                    file="src/settings.env",
                    rule_id="key",
                    title="Token",
                    severity=Severity.HIGH,
                )
            ],
            [
                ("uv", "audit", "--locked"),
                ("trivy", "fs", "--format", "json", "--scanners", "secret", "."),
            ],
        ),
    ],
)
def test_given_uv_project_when_scanned_then_native_audit_and_requested_secrets_run(
    scan_results_dir,
    tmp_path,
    monkeypatch,
    secrets,
    expected_secrets,
    expected_commands,
):
    commands = FakeCommands()
    commands.add(("uv", "audit", "--locked"), cwd=tmp_path, result=completed(stdout=""))
    if secrets:
        payload = {
            "Results": [
                {
                    "Class": "secret",
                    "Target": "src/settings.env",
                    "Secrets": [
                        {"RuleID": "key", "Title": "Token", "Severity": "HIGH"}
                    ],
                }
            ]
        }
        commands.add(
            expected_commands[1],
            cwd=tmp_path,
            result=completed(stdout=json.dumps(payload)),
        )
    monkeypatch.setattr(scanner, "run_captured", commands)
    monkeypatch.setattr(scanner, "package_manager_ops", ops_with_outdated(lambda _: []))
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=secrets)

    result = scan_project("test-proj", project)

    assert result.vulnerabilities == []
    assert result.secrets == expected_secrets
    assert [call[0] for call in commands.calls] == expected_commands


@pytest.mark.parametrize(
    ("project_options", "expected_command"),
    [
        ({}, ("trivy", "fs", "--format", "json", "--scanners", "vuln,secret", ".")),
        (
            {"scan_skip_dirs": ["tests/fixtures", "vendor"]},
            (
                "trivy",
                "fs",
                "--format",
                "json",
                "--scanners",
                "vuln,secret",
                "--skip-dirs",
                "tests/fixtures",
                "--skip-dirs",
                "vendor",
                ".",
            ),
        ),
    ],
)
def test_given_skip_directories_when_scanned_then_trivy_command_contains_them(
    scan_results_dir, tmp_path, monkeypatch, project_options, expected_command
):
    commands = FakeCommands()
    commands.add(
        expected_command, cwd=tmp_path, result=completed(stdout='{"Results": []}')
    )
    monkeypatch.setattr(scanner, "run_captured", commands)
    monkeypatch.setattr(scanner, "package_manager_ops", ops_with_outdated(lambda _: []))
    project = ProjectConfig(path=tmp_path, package_manager="bun", **project_options)

    scan_project("test-proj", project)

    assert [call[0] for call in commands.calls] == [expected_command]


@pytest.fixture
def scoped_publication_scan(tmp_path, monkeypatch, gradle_project, mm_home):

    findings = []
    modules = {}
    for index in range(2):
        module = ModuleId(group="org.example", artifact=f"lib{index}", version="2")
        modules[module.artifact] = module
        finding, project, resolution = _scan_age_inputs(
            gradle_project.path,
            member_specs=(("library", f"lib{index}", module.coordinate),),
            repository_specs=(("library", "https://dl.google.com/dl/android/maven2"),),
        )
        findings.append(
            finding.model_copy(
                update={
                    "pkg_name": module.coordinate,
                    "installed_version": "1",
                    "latest_version": "2",
                }
            )
        )
    state = SimpleNamespace(
        findings=findings,
        vulns=[],
        young=False,
        entered=set(),
        clock=FakeClock(datetime(2026, 9, 18, tzinfo=UTC)),
    )

    def transport(url, repository, suffix, count):
        count()
        artifact = suffix.split("/")[-3]
        state.entered.add(artifact)
        configured_module = modules[artifact]
        module = ModuleId(
            group=configured_module.group,
            artifact=configured_module.artifact,
            version=suffix.split("/")[-2],
        )
        body = (
            f"<project><groupId>{module.group}</groupId>"
            f"<artifactId>{module.artifact}</artifactId>"
            f"<version>{module.version}</version></project>"
        ).encode()
        published = (
            "Thu, 17 Sep 2026 00:00:00 GMT"
            if state.young and artifact == "lib0"
            else "Tue, 01 Sep 2026 00:00:00 GMT"
        )
        return body, {"Last-Modified": published}, url

    monkeypatch.setattr(dependency_age, "_publication_http", transport)
    monkeypatch.setattr(
        scanner, "scan_gradle", lambda project: (state.vulns, resolution)
    )
    monkeypatch.setattr(
        scanner, "discover_gradle_updates", lambda project: state.findings
    )
    state.project = project.model_copy(update={"scan_secrets": False})
    return state


def test_gradle_scan_opens_publications_in_the_shared_cache(
    scoped_publication_scan, monkeypatch
):
    opened = []
    factory = scanner.PublicationLookupContext

    def recording(path, *, clock):
        opened.append(path)
        return factory(path, clock=clock)

    monkeypatch.setattr(scanner, "PublicationLookupContext", recording)
    scan_project(
        "android",
        scoped_publication_scan.project,
        7,
        clock=scoped_publication_scan.clock,
    )
    assert opened == [paths.publications_dir()]


def test_gradle_discovery_failure_is_not_swallowed(
    scoped_publication_scan, monkeypatch
):
    def fail(project):
        msg = "discovery failed"
        raise GradleError(msg)

    monkeypatch.setattr("maintenance_man.scanner.discover_gradle_updates", fail)
    with pytest.raises(GradleError, match="discovery failed"):
        scan_project(
            "android",
            scoped_publication_scan.project,
            7,
            clock=scoped_publication_scan.clock,
        )


def test_gradle_update_findings_are_not_suppressed_by_vuln_package_names(
    scoped_publication_scan,
):
    state = scoped_publication_scan
    state.vulns = [
        make_vuln(
            pkg_name=state.findings[0].pkg_name,
            installed_version="1.0",
            fixed_version="2.0",
        )
    ]
    result = scan_project("android", state.project, 7, clock=state.clock)
    assert [row.pkg_name for row in result.updates] == [
        "org.example:lib0",
        "org.example:lib1",
    ]
    assert result.vulnerabilities[0].gradle_target is None
    assert all(row.blocked_reason is None for row in result.updates)


def test_gradle_scan_reports_unmapped_update_without_planning_diagnostics(
    scoped_publication_scan,
):
    state = scoped_publication_scan
    state.findings.append(make_update(pkg_name="unmapped", gradle_target=None))
    result = scan_project("android", state.project, 7, clock=state.clock)
    assert result.updates[-1].blocked_reason is None
    assert result.updates[-1].gradle_block_kind is None


def test_given_supplied_clock_when_scanned_then_old_update_is_returned_and_persisted(
    scoped_publication_scan,
):
    state = scoped_publication_scan
    state.young = True
    clock = FakeClock(datetime(2026, 9, 18, tzinfo=UTC))

    result = scan_project("android", state.project, 7, clock=clock)

    assert [row.pkg_name for row in result.updates] == ["org.example:lib1"]
    assert load_scan_results("android") == result


_GRADLE_BOM_MODULES = [
    ("androidx.room", "room-runtime", "2.8.4"),
    ("androidx.room", "room-compiler", "2.8.4"),
    ("com.squareup.okhttp3", "okhttp", "4.12.0"),
    ("com.google.code.gson", "gson", "2.11.0"),
    ("androidx.compose.ui", "ui", "1.9.0"),
    ("org.jetbrains", "annotations", "23.0.0"),
]


def _gradle_report_payload(catalogue_digest: str = "a" * 64) -> dict:
    """A resolution report whose scope covers every ``bom.json`` component."""
    components: list[dict[str, object]] = [
        {"id": "root", "kind": "root", "module": None, "variants": []}
    ]
    for index, (group, artifact, version) in enumerate(_GRADLE_BOM_MODULES):
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
    return {
        "schema_version": 1,
        "root_project": ":",
        "producer_versions": {"gradle": "8.14.3", "cyclonedx": "3.4.1", "report": "1"},
        "catalogue_digest": catalogue_digest,
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


def _gradle_resolution_fixture():

    return parse_resolution_report(json.dumps(_gradle_report_payload()))


def _generated(bom, resolution):
    payload, inventory = load_inventory(bom)
    return GeneratedGradleReport(
        bom_path=bom,
        inventory_bytes=payload,
        inventory=inventory,
        resolution=resolution,
    )


def _nested_malformed_inventory() -> tuple[bytes, CycloneDxInventory]:
    """Envelope-valid top level whose nested identity is malformed."""
    text = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "purl": "pkg:maven/g/lib@1",
                    "components": [{"type": "library", "purl": 42}],
                }
            ],
        }
    )
    return text.encode(), parse_inventory_text(text, source="memory-bom")


def _yield_fixture_bom(project):
    @contextmanager
    def _generate(_project):
        bom = Path(project.path) / GRADLE_INVENTORY_BOM_RELPATH
        bom.parent.mkdir(parents=True, exist_ok=True)
        bom.write_text(
            (GRADLE_FIXTURES / "bom.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        try:
            yield _generated(bom, _gradle_resolution_fixture())
        finally:
            shutil.rmtree(bom.parent, ignore_errors=True)

    return _generate


def _trivy_sbom(
    monkeypatch,
    gradle_project: ProjectConfig,
    *,
    returncode: int = 0,
    stdout: str | None = None,
    bom: Path | None = None,
):
    payload = (
        stdout
        if stdout is not None
        else (GRADLE_FIXTURES / "trivy-sbom.json").read_text(encoding="utf-8")
    )

    if bom is None:
        bom = Path(gradle_project.path) / GRADLE_INVENTORY_BOM_RELPATH
    commands = FakeCommands()
    commands.add(
        ("trivy", "sbom", "--format", "json", "--scanners", "vuln", str(bom)),
        cwd=gradle_project.path,
        result=completed(returncode=returncode, stdout=payload),
    )
    monkeypatch.setattr(scanner, "run_captured", commands)


def test_gradle_scan_unreadable_bom_is_gradle_error(gradle_project, monkeypatch):

    def runner(root, args, *, label):
        completed = fixture_runner(root, args, label=label)
        (root / GRADLE_INVENTORY_BOM_RELPATH).unlink()
        return completed

    monkeypatch.setattr("maintenance_man.gradle_resolution.run_gradle", runner)
    monkeypatch.setattr(scanner, "run_captured", FakeCommands())
    with pytest.raises(GradleError, match="cyclonedxBom produced no inventory"):
        scan_gradle(gradle_project)
    assert not (Path(gradle_project.path) / ".mm-gradle-inventory").exists()


def test_gradle_scan_finding_without_resolution_scope_is_error(
    gradle_project, monkeypatch
):

    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_report",
        _yield_fixture_bom(gradle_project),
    )
    unmapped_finding = {
        "VulnerabilityID": "CVE-9999-0000",
        "PkgName": "org.example:unmapped",
        "InstalledVersion": "1.0.0",
        "Severity": "HIGH",
        "Title": "unmapped finding",
        "Description": "not present in any selected resolution scope",
        "Status": "affected",
    }
    _trivy_sbom(
        monkeypatch,
        gradle_project,
        stdout=json.dumps(
            {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [unmapped_finding]}]}
        ),
    )

    with pytest.raises(GradleError, match="no selected resolution scope"):
        scan_gradle(gradle_project)


def _inject_gradle_capture_failure(monkeypatch, root: Path, failure: str) -> None:
    if failure == "incomplete-resolution":
        raw = json.loads((GRADLE_FIXTURES / "resolution/empty.json").read_text())
        raw["scopes"][0]["unresolved"] = ["g:missing:1.0"]
        resolution = parse_resolution_report(json.dumps(raw))

        @contextmanager
        def capture(project):
            payload, inventory = _nested_malformed_inventory()
            yield GeneratedGradleReport(
                root / "bom.json", payload, inventory, resolution
            )

        monkeypatch.setattr(scanner, "generate_gradle_report", capture)
        return

    payloads = {
        "missing-inventory": None,
        "malformed-inventory": "{bad json",
        "empty-inventory": json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        ),
        "command-failure": "{}",
    }
    inventory = json.loads((GRADLE_FIXTURES / "bom.json").read_text())
    inventory["components"] = [
        row for row in inventory["components"] if row["name"] == "gson"
    ]
    payloads["incomplete-inventory"] = json.dumps(inventory)

    def run_gradle(project_root, args, *, label):
        assert (args[0], label) == ("mmGradleReport", "mmGradleReport")
        if payloads[failure] is not None:
            bom = project_root / GRADLE_INVENTORY_BOM_RELPATH
            bom.write_text(payloads[failure], encoding="utf-8")
            if failure == "incomplete-inventory":
                digest = hashlib.sha256(
                    (project_root / GRADLE_CATALOGUE_RELPATH).read_bytes()
                ).hexdigest()
                bom.with_name("report.json").write_text(
                    json.dumps(_gradle_report_payload(digest))
                )
        if failure == "command-failure":
            message = "mmGradleReport failed (exit 1): boom"
            raise GradleError(message)
        return completed(args, stdout="", stderr="boom")

    monkeypatch.setattr("maintenance_man.gradle_resolution.run_gradle", run_gradle)


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("missing-inventory", "produced no inventory"),
        ("malformed-inventory", "malformed CycloneDX inventory"),
        ("empty-inventory", "has no components"),
        ("incomplete-inventory", "resolved module missing from inventory"),
        ("command-failure", "mmGradleReport failed"),
        ("incomplete-resolution", "Incomplete Gradle resolution"),
    ],
)
def test_given_gradle_capture_failure_when_project_scanned_then_saved_bytes_survive(
    mm_home, gradle_project, monkeypatch, failure, message
):
    root = Path(gradle_project.path)
    saved = mm_home / "scan-results/android.json"
    saved.parent.mkdir(parents=True)
    saved.write_bytes(b"previous findings\n")
    commands = FakeCommands()
    monkeypatch.setattr(scanner, "run_captured", commands)
    _inject_gradle_capture_failure(monkeypatch, root, failure)

    with pytest.raises(GradleError, match=message):
        scan_project("android", gradle_project, 7)

    assert saved.read_bytes() == b"previous findings\n"
    assert not (root / GRADLE_INVENTORY_RELPATH).exists()
    assert commands.calls == []


def test_gradle_scan_runs_the_existing_secret_scan_when_enabled(
    gradle_project, monkeypatch, mm_home
):
    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_report",
        _yield_fixture_bom(gradle_project),
    )
    _trivy_sbom(monkeypatch, gradle_project, stdout='{"Results": []}')
    monkeypatch.setattr(
        "maintenance_man.scanner.discover_gradle_updates", lambda project: []
    )
    secret_calls: list[Path] = []
    monkeypatch.setattr(
        "maintenance_man.scanner.scan_secrets",
        lambda path, skip_dirs: (secret_calls.append(path), [])[1],
    )

    scan_project("android", gradle_project, 7)

    assert secret_calls == [Path(gradle_project.path)]


def _gradle_trivy_vulnerability_payload(
    *, changes: dict[str, object] | None = None, omitted: str | None = None
) -> str:
    row: dict[str, object] = {
        "VulnerabilityID": "CVE-example",
        "PkgName": "org.example:library",
        "InstalledVersion": "1",
    }
    row.update(changes or {})
    if omitted is not None:
        del row[omitted]
    return json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [row]}]})


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"Results": False},
        {"Results": None},
        {"Results": ""},
        {"Results": 0},
        {"Results": [None]},
        {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": False}]},
    ],
)
def test_gradle_trivy_malformed_shape_is_scan_error(
    gradle_project, monkeypatch, payload
):

    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_report",
        _yield_fixture_bom(gradle_project),
    )
    _trivy_sbom(monkeypatch, gradle_project, stdout=json.dumps(payload))
    with pytest.raises(ScanError, match="Trivy"):
        scan_gradle(gradle_project)
    assert not (Path(gradle_project.path) / ".mm-gradle-inventory").exists()


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError("interpreter missing"),
        PermissionError("launch denied"),
        UnicodeDecodeError("utf8", b"\xff", 0, 1, "invalid"),
    ],
)
def test_gradle_trivy_launch_or_decode_failure_is_scan_error(
    gradle_project, monkeypatch, failure
):

    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_report",
        _yield_fixture_bom(gradle_project),
    )

    bom = Path(gradle_project.path) / GRADLE_INVENTORY_BOM_RELPATH
    error = ScanError(f"Could not run Trivy SBOM scan: {failure}")
    error.__cause__ = failure
    commands = FakeCommands()
    commands.add(
        ("trivy", "sbom", "--format", "json", "--scanners", "vuln", str(bom)),
        cwd=gradle_project.path,
        result=error,
    )
    monkeypatch.setattr(scanner, "run_captured", commands)
    with pytest.raises(ScanError, match="Trivy"):
        scan_gradle(gradle_project)
    ((actual_argv, cwd, kwargs),) = commands.calls
    assert actual_argv == (
        "trivy",
        "sbom",
        "--format",
        "json",
        "--scanners",
        "vuln",
        str(bom),
    )
    assert cwd == gradle_project.path
    assert kwargs == {
        "timeout": 300,
        "label": "Trivy SBOM scan",
        "error": ScanError,
    }
    assert not (Path(gradle_project.path) / ".mm-gradle-inventory").exists()


@pytest.mark.parametrize(
    "field, value",
    [
        ("VulnerabilityID", None),
        ("VulnerabilityID", ""),
        ("PkgName", 3),
        ("InstalledVersion", False),
        ("Severity", None),
        ("Severity", False),
        ("Severity", []),
        ("PublishedDate", 0),
        ("PublishedDate", {}),
        ("Title", None),
        ("Description", []),
        ("Status", False),
        ("FixedVersion", []),
        ("PrimaryURL", {}),
    ],
)
def test_gradle_trivy_invalid_consumed_vulnerability_field_is_scan_error(field, value):
    payload = _gradle_trivy_vulnerability_payload(changes={field: value})

    with pytest.raises(ScanError, match=field):
        _parse_gradle_trivy_output(payload)


@pytest.mark.parametrize("field", ["VulnerabilityID", "PkgName", "InstalledVersion"])
def test_gradle_trivy_missing_required_vulnerability_field_is_scan_error(field):
    payload = _gradle_trivy_vulnerability_payload(omitted=field)

    with pytest.raises(ScanError, match=field):
        _parse_gradle_trivy_output(payload)


@pytest.mark.parametrize(
    "result",
    [
        {"Class": False},
        {"Class": None, "Target": "x", "Secrets": []},
        {"Class": False, "Target": "x", "Secrets": []},
        {"Class": "lang-pkgs", "Vulnerabilities": ""},
        {"Class": "lang-pkgs", "Vulnerabilities": {}},
        {"Class": "lang-pkgs", "Vulnerabilities": [None]},
    ],
)
def test_gradle_trivy_invalid_result_or_row_container_is_scan_error(result):

    with pytest.raises(ScanError):
        _parse_gradle_trivy_output(json.dumps({"Results": [result]}))


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"Results": []},
        {"Results": [{"Class": "lang-pkgs"}]},
        {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": None}]},
        {
            "Results": [
                {
                    "Class": "os-pkgs",
                    "Target": None,
                    "Secrets": 42,
                    "Vulnerabilities": [{"PkgName": 3}],
                }
            ]
        },
        {
            "Results": [
                {
                    "Class": "secret",
                    "Target": None,
                    "Secrets": 42,
                    "Vulnerabilities": None,
                }
            ]
        },
    ],
)
def test_gradle_trivy_absent_optional_or_null_vulnerabilities_is_clean(payload):

    assert _parse_gradle_trivy_output(json.dumps(payload)) == []


def test_gradle_trivy_unknown_severity_and_bad_string_date_keep_existing_semantics():

    row = {
        "VulnerabilityID": "CVE-example",
        "PkgName": "org.example:library",
        "InstalledVersion": "1",
        "Severity": "new-severity",
        "PublishedDate": "bad-date",
        "FixedVersion": None,
        "PrimaryURL": None,
    }
    findings = _parse_gradle_trivy_output(
        json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [row]}]})
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.UNKNOWN
    assert findings[0].published_date is None
    assert findings[0].fixed_version is None


@pytest.mark.parametrize(
    ("result_fields", "vulnerability_fields"),
    [
        ({}, {}),
        ({}, {"Extra": 1}),
        ({"Target": None, "Secrets": 42}, {}),
    ],
)
def test_given_ignored_vendor_fields_when_trivy_parsed_then_finding_is_retained(
    result_fields, vulnerability_fields
):
    row = {
        "VulnerabilityID": "CVE-example",
        "PkgName": "org.example:library",
        "InstalledVersion": "1",
        **vulnerability_fields,
    }
    payload = {
        "Results": [
            {
                "Class": "lang-pkgs",
                **result_fields,
                "Vulnerabilities": [row],
            }
        ]
    }

    findings = _parse_gradle_trivy_output(json.dumps(payload))

    assert findings == [
        VulnFinding(
            vuln_id="CVE-example",
            pkg_name="org.example:library",
            installed_version="1",
            severity=Severity.UNKNOWN,
            title="",
            description="",
            status="unknown",
        )
    ]


def _prepare_local_provenance_scan(gradle_project, monkeypatch, variant):
    payload = _gradle_report_payload()
    payload["local_projects"] = [
        {
            "project_path": ":",
            "module": {"group": "fixture", "artifact": "app", "version": "unspecified"},
        }
    ]
    purls = {
        "unknown-path": "pkg:maven/fixture/app@unspecified?project_path=%3Aunknown",
        "wrong-coordinate": "pkg:maven/other/app@unspecified?project_path=%3A",
        "unqualified": "pkg:maven/fixture/app@unspecified",
        "duplicate-path": (
            "pkg:maven/fixture/app@unspecified?project_path=%3A&project_path=%3A"
        ),
    }
    purl = purls.get(variant, "pkg:maven/fixture/app@unspecified?project_path=%3A")
    inventory = json.loads((GRADLE_FIXTURES / "bom.json").read_text())
    inventory["components"].append({"type": "library", "purl": purl})
    if variant == "external-mismatch":
        inventory["components"].append(
            {"type": "library", "purl": "pkg:maven/g/missing@1"}
        )

    @contextmanager
    def generate(project):
        bom = Path(project.path) / "fixture-bom.json"
        bom.write_text(json.dumps(inventory))
        try:
            yield _generated(bom, parse_resolution_report(json.dumps(payload)))
        finally:
            bom.unlink()

    monkeypatch.setattr(scanner, "generate_gradle_report", generate)
    bom = Path(gradle_project.path) / "fixture-bom.json"
    if variant == "local-finding":
        trivy = {
            "Results": [
                {
                    "Class": "lang-pkgs",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-local",
                            "PkgName": "fixture:app",
                            "InstalledVersion": "unspecified",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ]
        }
        _trivy_sbom(monkeypatch, gradle_project, stdout=json.dumps(trivy), bom=bom)
    else:
        _trivy_sbom(monkeypatch, gradle_project, bom=bom)


def test_given_bound_local_provenance_when_gradle_scanned_then_scopes_are_recorded(
    gradle_project, monkeypatch
):
    _prepare_local_provenance_scan(gradle_project, monkeypatch, "local")

    findings, _ = scan_gradle(gradle_project)

    assert {finding.gradle_scopes for finding in findings} == {
        (":/project/runtimeClasspath",)
    }


@pytest.mark.parametrize(
    "variant",
    [
        "unknown-path",
        "wrong-coordinate",
        "unqualified",
        "duplicate-path",
        "external-mismatch",
        "local-finding",
    ],
)
def test_given_unbound_local_provenance_when_gradle_scanned_then_scan_is_rejected(
    gradle_project, monkeypatch, variant
):
    _prepare_local_provenance_scan(gradle_project, monkeypatch, variant)

    with pytest.raises(GradleError):
        scan_gradle(gradle_project)


@pytest.mark.parametrize(
    ("manager", "source", "secrets", "expected"),
    [
        ("bun", "uv-audit", False, ["uv-audit"]),
        ("bun", "uv-audit", True, ["uv-audit", "secret"]),
        ("uv", "trivy", False, ["trivy"]),
        ("uv", "trivy", True, ["trivy"]),
    ],
)
def test_scan_steps_follow_the_table_vulnerability_source(
    mm_home, tmp_path, monkeypatch, manager, source, secrets, expected
):
    calls = []

    def uv_audit(path):
        calls.append("uv-audit")
        return []

    def trivy(path, skip_dirs, *, scanners):
        calls.append("trivy")
        return [], []

    def secret(path, skip_dirs):
        calls.append("secret")
        return []

    monkeypatch.setattr(scanner, "_run_uv_audit", uv_audit)
    monkeypatch.setattr(scanner, "_run_trivy_scan", trivy)
    monkeypatch.setattr(scanner, "scan_secrets", secret)
    monkeypatch.setattr(
        scanner,
        "package_manager_ops",
        lambda name: dataclasses.replace(
            PACKAGE_MANAGERS[name],
            vulnerability_source=source,
            outdated=lambda project: [],
        ),
    )
    project = ProjectConfig(
        path=tmp_path, package_manager=manager, scan_secrets=secrets
    )
    scanner.scan_project("demo", project)
    assert calls == expected


def test_scan_dates_bun_updates_with_bun_info_in_the_project(
    mm_home, tmp_path, monkeypatch
):
    monkeypatch.setattr(scanner, "_run_trivy_scan", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(
        scanner,
        "package_manager_ops",
        ops_with_outdated(lambda project: [make_update(pkg_name="zod")]),
    )
    project = ProjectConfig(path=tmp_path, package_manager="bun")
    latest = "1.0.1"
    commands = FakeCommands()
    commands.add(
        ("bun", "info", f"zod@{latest}"),
        cwd=tmp_path,
        result=completed(stdout="zod | MIT\nPublished: 2024-01-01T00:00:00Z\n"),
    )
    monkeypatch.setattr("maintenance_man.dependency_age.run_captured", commands)

    result = scanner.scan_project("demo", project, 7)

    assert [(cmd, cwd) for cmd, cwd, _ in commands.calls] == [
        (("bun", "info", f"zod@{latest}"), tmp_path)
    ]
    assert [u.published_date for u in result.updates] == [_OLD]


@pytest.mark.parametrize(
    "manager, source", [("uv", "pypi"), ("bun", "npm"), ("mvn", "central")]
)
def test_non_gradle_scan_filters_through_one_publication_context(
    mm_home, tmp_path, monkeypatch, manager, source
):
    opened, filtered = [], []
    real = scanner.PublicationLookupContext

    def factory(path, *, clock):
        opened.append(path)
        return real(path, clock=clock)

    def fake_filter(
        updates, publication_source, project_path, *, min_age_days, context
    ):
        filtered.append(
            (publication_source, project_path, min_age_days, isinstance(context, real))
        )
        return updates

    monkeypatch.setattr(scanner, "PublicationLookupContext", factory)
    monkeypatch.setattr(scanner, "filter_registry_updates_by_age", fake_filter)
    monkeypatch.setattr(
        scanner,
        "package_manager_ops",
        ops_with_outdated(lambda project: [make_update()]),
    )
    monkeypatch.setattr(scanner, "_run_trivy_scan", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda *args: [])
    project = ProjectConfig(path=tmp_path, package_manager=manager, scan_secrets=False)
    scanner.scan_project("demo", project, 9)
    assert opened == [paths.publications_dir()]
    assert filtered == [(source, tmp_path, 9, True)]


def test_given_vulnerable_update_when_scanned_then_only_clean_is_looked_up_and_saved(
    mm_home, tmp_path, monkeypatch
):

    vulnerable, _, _ = _scan_age_inputs(tmp_path)
    clean, _, _ = _scan_age_inputs(tmp_path)
    raw_updates = [
        vulnerable.model_copy(
            update={"pkg_name": "pkg-a", "latest_version": "2.0", "gradle_target": None}
        ),
        clean.model_copy(
            update={"pkg_name": "pkg-b", "latest_version": "2.0", "gradle_target": None}
        ),
    ]
    requested = []

    def transport(url, repository, suffix, count):
        count()
        requested.append(suffix)
        return _pypi_body("pkg-b", "2.0"), {}, url

    monkeypatch.setattr(dependency_age, "_publication_http", transport)
    monkeypatch.setattr(
        scanner, "_run_uv_audit", lambda path: [make_vuln(pkg_name="pkg-a")]
    )
    monkeypatch.setattr(
        scanner, "package_manager_ops", ops_with_outdated(lambda project: raw_updates)
    )
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)

    result = scan_project(
        "demo",
        project,
        7,
        clock=FakeClock(datetime(2026, 9, 18, tzinfo=UTC)),
    )

    assert requested == ["pypi/pkg-b/2.0/json"]
    assert [update.pkg_name for update in result.updates] == ["pkg-b"]
    assert load_scan_results("demo").updates == result.updates


def _scan_service_failure_setup(mm_home: Path, root: Path, monkeypatch):
    monkeypatch.setattr("maintenance_man.services.scan.scan_project", scan_project)
    monkeypatch.setattr(
        "maintenance_man.services.scan.prune_stale_bookmarks", lambda **kwargs: None
    )
    mm_home.mkdir(parents=True, exist_ok=True)
    write_config(
        mm_home,
        f'[projects.android]\npath = "{root}"\npackage_manager = "gradle"\n'
        "scan_secrets = false\n"
        f'[projects.remaining]\npath = "{root}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n",
    )
    results = mm_home / "scan-results"
    results.mkdir()
    (results / "android.json").write_bytes(b"old result bytes")
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda *args: [])
    check_outdated = scanner._check_outdated
    monkeypatch.setattr(
        scanner,
        "_check_outdated",
        lambda project, *args: (
            [] if project.package_manager == "uv" else check_outdated(project, *args)
        ),
    )
    state, emit = _batch_scan_dependencies(root)
    return results, state, emit


def _write_gradle_capture(root: Path) -> None:
    bom = root / GRADLE_INVENTORY_BOM_RELPATH
    bom.write_bytes((GRADLE_FIXTURES / "bom.json").read_bytes())
    digest = hashlib.sha256((root / GRADLE_CATALOGUE_RELPATH).read_bytes()).hexdigest()
    bom.with_name("report.json").write_text(json.dumps(_gradle_report_payload(digest)))


def _inject_scan_filesystem_failure(monkeypatch, root: Path, failure: str) -> None:
    if failure == "inventory-mkdir":
        mkdir = Path.mkdir

        def fail_mkdir(path, *args, **kwargs):
            if path == root / GRADLE_INVENTORY_RELPATH:
                message = "mkdir denied"
                raise PermissionError(message)
            return mkdir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", fail_mkdir)
    elif failure == "inventory-marker":
        write_bytes = Path.write_bytes

        def fail_marker(path, content):
            if path == root / GRADLE_INVENTORY_MARKER_RELPATH:
                message = "marker denied"
                raise PermissionError(message)
            return write_bytes(path, content)

        monkeypatch.setattr(Path, "write_bytes", fail_marker)
    elif failure == "inventory-cleanup":
        monkeypatch.setattr(
            "maintenance_man.gradle.shutil.rmtree",
            MagicMock(side_effect=PermissionError("inventory cleanup denied")),
        )


def _inject_report_cleanup_failure(monkeypatch, root: Path) -> None:
    unlink = Path.unlink

    def fail_unlink(path, *args, **kwargs):
        if path == root / GRADLE_UPDATE_REPORT_RELPATH:
            message = "report cleanup denied"
            raise PermissionError(message)
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_unlink)


def _prepare_scan_failure_commands(
    monkeypatch, root: Path, failure: str
) -> list[list[str]]:
    commands: list[list[str]] = []

    def wrapper(cmd, cwd, **kwargs):
        commands.append(cmd)
        if cmd[1] == "mmGradleReport":
            _write_gradle_capture(root)
        else:
            assert cmd[1] == "versionCatalogUpdate"
            report = root / GRADLE_UPDATE_REPORT_RELPATH
            report.write_text(
                "libraries = false\n"
                if failure == "report-false"
                else (GRADLE_FIXTURES / "updates-clean.toml").read_text()
            )
        return completed(cmd)

    def run(cmd, **kwargs):
        commands.append(cmd)
        if failure == "trivy-launch":
            message = "missing interpreter"
            raise FileNotFoundError(message)
        if failure == "trivy-decode":
            message = "utf8"
            raise UnicodeDecodeError(message, b"\xff", 0, 1, "invalid")
        payload = {
            "trivy-root": [],
            "trivy-results": {"Results": False},
            "trivy-row": {"Results": [None]},
        }.get(failure, {"Results": []})
        return completed(cmd, stdout=json.dumps(payload))

    monkeypatch.setattr("maintenance_man.gradle.run_logged", wrapper)
    monkeypatch.setattr(subprocess, "run", run)
    return commands


def _inject_scan_service_failure(monkeypatch, root: Path, failure: str) -> list | None:
    if failure == "wrapper-launch":
        (root / "gradlew").write_text("#!/definitely/missing/mm-interpreter\n")
        return None
    if failure in {"inventory-mkdir", "inventory-marker"}:
        commands = FakeCommands()
        monkeypatch.setattr(subprocess, "run", commands)
        monkeypatch.setattr("maintenance_man.gradle.run_logged", commands)
        _inject_scan_filesystem_failure(monkeypatch, root, failure)
        return commands.calls
    if failure in {"report-false", "report-cleanup"}:
        monkeypatch.setattr(
            scanner, "scan_gradle", lambda *args: ([], _gradle_resolution_fixture())
        )
    if failure == "inventory-cleanup":
        _inject_scan_filesystem_failure(monkeypatch, root, failure)
    elif failure == "report-cleanup":
        _inject_report_cleanup_failure(monkeypatch, root)
    return _prepare_scan_failure_commands(monkeypatch, root, failure)


@pytest.mark.parametrize(
    (
        "failure",
        "inventory_survives",
        "update_report_survives",
        "report_marker_survives",
        "expected_commands",
    ),
    [
        ("wrapper-launch", False, False, False, None),
        ("inventory-mkdir", False, False, False, []),
        ("inventory-marker", False, False, False, []),
        ("inventory-cleanup", True, False, False, None),
        ("report-cleanup", False, True, True, None),
        ("report-false", False, False, False, None),
        ("trivy-root", False, False, False, None),
        ("trivy-results", False, False, False, None),
        ("trivy-row", False, False, False, None),
        ("trivy-launch", False, False, False, None),
        ("trivy-decode", False, False, False, None),
    ],
)
def test_given_gradle_scan_failure_when_scanning_all_then_next_project_is_saved(
    mm_home,
    gradle_project,
    monkeypatch,
    failure,
    inventory_survives,
    update_report_survives,
    report_marker_survives,
    expected_commands,
):
    root = Path(gradle_project.path)
    results, state, emit = _scan_service_failure_setup(mm_home, root, monkeypatch)
    commands = _inject_scan_service_failure(monkeypatch, root, failure)

    summary = scan_service.scan_all(load_config(), vcs=state.services(), emit=emit)

    assert summary.had_error is True
    assert [
        (event.operation, event.project) for event in emit.of_type(OperationFailed)
    ] == [(Operation.SCAN, "android")]
    assert [event.result.project for event in emit.of_type(ScanReported)] == [
        "remaining"
    ]
    assert (results / "android.json").read_bytes() == b"old result bytes"
    assert (results / "remaining.json").is_file()
    assert (root / GRADLE_INVENTORY_RELPATH).exists() is inventory_survives
    assert (root / GRADLE_UPDATE_REPORT_RELPATH).exists() is update_report_survives
    assert (root / GRADLE_REPORT_MARKER_RELPATH).exists() is report_marker_survives
    if failure == "inventory-cleanup":
        assert (root / GRADLE_INVENTORY_MARKER_RELPATH).is_file()
    if expected_commands is not None:
        assert commands == expected_commands
