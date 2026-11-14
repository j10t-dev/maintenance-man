import json
import re
import shutil
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from maintenance_man import bun_dependencies, dependency_age, paths, scanner
from maintenance_man.gradle import GradleError
from maintenance_man.gradle_inventory import inventory_scopes, load_inventory
from maintenance_man.gradle_resolution import (
    ROUTING_UNDECLARED,
    GeneratedGradleReport,
    parse_resolution_report,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    CandidateValidation,
    CandidateWithheld,
    GradleCandidate,
    GradleFixPlan,
    ModuleId,
)
from maintenance_man.models.scan import (
    Failed,
    GradleBlock,
    Ready,
    ScanResult,
    SecretFinding,
    Severity,
    VulnFinding,
    Workflow,
)
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.process import ToolNotFoundError
from maintenance_man.scanner import (
    ScanError,
    _parse_trivy,
    _parse_uv_audit_vulns,
    scan_gradle,
    scan_project,
)
from maintenance_man.storage import load_scan_results, save_scan_results
from tests.fakes import FakeCommands
from tests.support.clock import FakeClock
from tests.support.findings import make_scan_result, make_update, make_vuln
from tests.support.gradle import GRADLE_FIXTURES, fixture_runner, report_directory
from tests.support.process import completed, missing_tool
from tests.support.projects import FIXTURES_DIR, make_project
from tests.support.publication import pypi_body, scan_age_inputs

_OLD = datetime(2024, 1, 1, tzinfo=UTC)


def _quiet_uv_scan(monkeypatch):
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda path: [])
    monkeypatch.setattr(scanner, "_check_outdated", lambda *args: [])


def test_scan_project_saves_through_storage(mm_home, tmp_path, monkeypatch):
    _quiet_uv_scan(monkeypatch)
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)
    result = scanner.scan_project("demo", project)
    assert load_scan_results("demo") == result


@pytest.mark.parametrize("previous", [b"previous result bytes", None])
def test_outdated_failure_fails_the_scan_and_keeps_the_saved_result(
    mm_home, tmp_path, monkeypatch, previous
):
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda path: [])
    error = OutdatedCheckError("uv sync --locked failed (exit 1): lock mismatch")
    _stub_outdated(monkeypatch, MagicMock(side_effect=error))
    results = mm_home / "scan-results"
    results.mkdir(parents=True)
    if previous is not None:
        (results / "demo.json").write_bytes(previous)
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)
    with pytest.raises(OutdatedCheckError):
        scanner.scan_project("demo", project)
    if previous is None:
        assert not (results / "demo.json").exists()
    else:
        assert (results / "demo.json").read_bytes() == previous


def test_given_uv_audit_exiting_one_with_findings_when_run_then_findings_are_returned(
    tmp_path, monkeypatch
):
    output = (
        "setuptools 65.5.0 has 1 known vulnerability:\n\n"
        "- GHSA-r9hx-vwmv-q579: ReDoS\n\n"
        "  Fixed in: 65.5.1\n"
    )
    monkeypatch.setattr(
        "maintenance_man.process.subprocess.run",
        lambda argv, **kwargs: completed(argv, returncode=1, stdout=output),
    )

    findings = scanner._run_uv_audit(tmp_path)

    assert [(f.pkg_name, f.vuln_id, f.fixed_version) for f in findings] == [
        ("setuptools", "GHSA-r9hx-vwmv-q579", "65.5.1")
    ]


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        pytest.param(
            "Found 1 known vulnerability and no adverse project statuses in "
            "1 package\n\n"
            "Vulnerabilities:\n\n"
            "setuptools 65.5.0 has 1 known vulnerability:\n\n"
            "- GHSA-r9hx-vwmv-q579: pypa/setuptools vulnerable to Regular "
            "Expression Denial of Service (ReDoS)\n\n"
            "  Fixed in: 65.5.1\n\n"
            "  Advisory information: https://nvd.nist.gov/vuln/detail/"
            "CVE-2022-40897\n",
            [
                (
                    "setuptools",
                    "65.5.0",
                    "GHSA-r9hx-vwmv-q579",
                    "65.5.1",
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-40897",
                )
            ],
            id="vulnerability",
        ),
        pytest.param(
            "setuptools 65.5.0 has 1 known vulnerability:\n\n"
            "- GHSA-r9hx-vwmv-q579: real vulnerability\n\n"
            "- note: this is not another vulnerability\n\n"
            "  Fixed in: 65.5.1\n",
            [("setuptools", "65.5.0", "GHSA-r9hx-vwmv-q579", "65.5.1", None)],
            id="non-advisory-bullet",
        ),
        pytest.param(
            "- GHSA-xxxx: orphan\n"
            "  Fixed in: 1.0\n"
            "requests 2.0 has 1 known vulnerability:\n"
            "- CVE-1: bad\n",
            [("requests", "2.0", "CVE-1", None, None)],
            id="advisory-before-package",
        ),
    ],
)
def test_given_uv_audit_output_when_parsed_then_advisories_belong_to_their_package(
    output, expected
):
    vulns = _parse_uv_audit_vulns(output)

    assert [
        (v.pkg_name, v.installed_version, v.vuln_id, v.fixed_version, v.primary_url)
        for v in vulns
    ] == expected


_AUDIT_HEADER = "Found 2 known vulnerabilities in 2 packages\n\nVulnerabilities:\n\n"


@pytest.mark.parametrize(
    ("output", "expected_message"),
    [
        pytest.param(
            _AUDIT_HEADER + "setuptools 65.5.0 has 2 known vulnerabilities:\n\n"
            "- GHSA-r9hx-vwmv-q579: ReDoS\n\n  Fixed in: 65.5.1\n",
            "uv audit: setuptools declares 2 advisories, parsed 1",
            id="fewer-parsed-than-declared",
        ),
        pytest.param(
            _AUDIT_HEADER + "requests 2.0.0 has 2 known vulnerabilities:\n\n"
            "- CVE-2026-1: One\n\n  Fixed in: 2.0.1\n\n"
            "urllib3 1.0.0 has 1 known vulnerability:\n\n"
            "- GHSA-x: Two\n\n  Fixed in: 1.0.1\n",
            "uv audit: requests declares 2 advisories, parsed 1",
            id="first-package-mismatch",
        ),
        pytest.param(
            _AUDIT_HEADER + "requests 2.0.0 has 1 known vulnerability:\n\n"
            "- CVE-2026-1: One\n\n  Fixed in: 2.0.1\n\n"
            "urllib3 1.0.0 has 1 known vulnerability:\n\n"
            "- GHSA-x: Two\n- GHSA-y: Three\n\n  Fixed in: 1.0.1\n",
            "uv audit: urllib3 declares 1 advisories, parsed 2",
            id="second-package-mismatch",
        ),
    ],
)
def test_given_uv_audit_text_when_counts_differ_then_scan_error_names_package(
    output, expected_message
):
    with pytest.raises(ScanError, match=f"^{re.escape(expected_message)}$"):
        _parse_uv_audit_vulns(output)


def test_given_uv_audit_advisory_with_unfamiliar_prefix_when_parsed_then_kept():
    output = (
        _AUDIT_HEADER + "left-pad 1.0.0 has 1 known vulnerability:\n\n"
        "- MAL-2026-1: Malicious package\n\n  Fixed in: 1.0.1\n"
    )

    assert _parse_uv_audit_vulns(output) == [
        VulnFinding(
            vuln_id="MAL-2026-1",
            pkg_name="left-pad",
            installed_version="1.0.0",
            fixed_version="1.0.1",
            severity=Severity.UNKNOWN,
            title="Malicious package",
            description="Malicious package",
            status="affected",
        )
    ]


def test_given_uv_audit_advisory_with_fix_versions_when_parsed_then_list_is_stored():
    output = (
        "urllib3 1.26.5 has 1 known vulnerability:\n\n"
        "- GHSA-34jh-p97f-mpxf: Cookie header leaks on redirect\n\n"
        "  Fixed in: 2.0.7, 1.26.18\n"
    )

    assert _parse_uv_audit_vulns(output) == [
        VulnFinding(
            vuln_id="GHSA-34jh-p97f-mpxf",
            pkg_name="urllib3",
            installed_version="1.26.5",
            fixed_version="2.0.7, 1.26.18",
            severity=Severity.UNKNOWN,
            title="Cookie header leaks on redirect",
            description="Cookie header leaks on redirect",
            status="affected",
        )
    ]


def test_gradle_scan_requires_trivy_before_generating_a_report(
    gradle_project, monkeypatch
):
    monkeypatch.setattr(scanner, "require_tool", missing_tool("trivy"))
    monkeypatch.setattr(
        scanner,
        "generate_gradle_report",
        lambda *args: pytest.fail("report without trivy"),
    )
    with pytest.raises(ToolNotFoundError, match="trivy"):
        scanner.scan_gradle(gradle_project)


_SECRET = SecretFinding(
    file="src/settings.env", rule_id="key", title="Token", severity=Severity.HIGH
)
_TRIVY_OUTPUT = json.dumps(
    {
        "Results": [
            {
                "Class": "secret",
                "Target": "src/settings.env",
                "Secrets": [{"RuleID": "key", "Title": "Token", "Severity": "HIGH"}],
            }
        ]
    }
)


_SCAN_COMMAND_OPTIONS = {
    "uv": {
        "timeout": 300,
        "label": "uv audit --locked",
        "error": ScanError,
        "ok_codes": {0, 1},
    },
    "trivy": {
        "timeout": 300,
        "label": "Trivy filesystem scan",
        "error": ScanError,
        "ok_codes": frozenset({0}),
    },
}


@pytest.mark.parametrize(
    ("manager", "scan_secrets", "expected_commands"),
    [
        pytest.param(
            "uv", False, [("uv", "audit", "--locked", "--color", "never")], id="uv"
        ),
        pytest.param(
            "uv",
            True,
            [
                ("uv", "audit", "--locked", "--color", "never"),
                ("trivy", "fs", "--format", "json", "--scanners", "secret", "."),
            ],
            id="uv-with-secrets",
        ),
        pytest.param(
            "bun",
            False,
            [("trivy", "fs", "--format", "json", "--scanners", "vuln", ".")],
            id="bun",
        ),
        pytest.param(
            "mvn",
            True,
            [("trivy", "fs", "--format", "json", "--scanners", "vuln,secret", ".")],
            id="mvn-with-secrets",
        ),
    ],
)
def test_given_manager_when_scanned_then_its_scanners_run(
    mm_home, tmp_path, monkeypatch, manager, scan_secrets, expected_commands
):
    commands = FakeCommands()
    for argv in expected_commands:
        stdout = "" if argv[0] == "uv" else _TRIVY_OUTPUT
        commands.add(argv, cwd=tmp_path, result=completed(stdout=stdout))
    required = []
    monkeypatch.setattr(
        scanner, "require_tool", lambda name, hint: required.append(name)
    )
    monkeypatch.setattr(scanner, "run_captured", commands)
    _stub_outdated(monkeypatch, lambda _project: [])
    project = ProjectConfig(
        path=tmp_path, package_manager=manager, scan_secrets=scan_secrets
    )

    result = scan_project("demo", project)

    assert commands.calls == [
        (argv, tmp_path, _SCAN_COMMAND_OPTIONS[argv[0]]) for argv in expected_commands
    ]
    assert required == ["trivy"] * sum(argv[0] == "trivy" for argv in expected_commands)
    assert result.vulnerabilities == []
    assert result.secrets == ([_SECRET] if scan_secrets else [])
    assert result.package_manager == manager
    assert load_scan_results("demo").package_manager == manager


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

    def test_given_nonexistent_path_when_scanned_then_file_not_found_is_raised(
        self, scan_results_dir: Path
    ):
        project = make_project(Path("/nonexistent/path"), package_manager="uv")

        with pytest.raises(FileNotFoundError):
            scan_project("ghost", project)


def _stub_outdated(monkeypatch, outdated) -> None:
    for name, (_, source) in scanner._OUTDATED.items():
        monkeypatch.setitem(scanner._OUTDATED, name, (outdated, source))


def _configure_update_scan(monkeypatch, *, updates, vulnerabilities=()) -> None:
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda _path: list(vulnerabilities))
    _stub_outdated(monkeypatch, lambda _project: updates)
    monkeypatch.setattr(
        scanner, "filter_registry_updates_by_age", lambda rows, *args, **kwargs: rows
    )


def test_given_pending_statuses_when_scan_succeeds_then_saved_rows_are_fresh(
    scan_results_dir, tmp_path, monkeypatch
):
    save_scan_results(
        "demo",
        make_scan_result(
            vulns=[
                make_vuln(
                    pkg_name="some-pkg",
                    state=Failed(flow=Workflow.UPDATE, phase="unit"),
                )
            ],
            updates=[make_update(pkg_name="pkg-a", state=Ready(flow=Workflow.UPDATE))],
        ).model_copy(update={"resolve_repair_base": "abc"}),
    )
    _configure_update_scan(
        monkeypatch,
        updates=[make_update(pkg_name="pkg-a")],
        vulnerabilities=[make_vuln(pkg_name="some-pkg")],
    )
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)

    scan_project("demo", project)

    saved = load_scan_results("demo")
    assert [(row.pkg_name, row.state) for row in saved.findings] == [
        ("some-pkg", None),
        ("pkg-a", None),
    ]
    assert saved.resolve_repair_base is None


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
    _stub_outdated(monkeypatch, lambda _: [])
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
        finding, project, report = scan_age_inputs(
            gradle_project.path,
            member_specs=(("library", f"lib{index}", module.coordinate),),
            repository_specs=(("library", "https://dl.google.com/dl/android/maven2"),),
        )
        assert finding.gradle_target is not None
        findings.append(
            finding.model_copy(
                update={
                    "pkg_name": module.coordinate,
                    "installed_version": "1",
                    "latest_version": "2",
                    "gradle_target": finding.gradle_target.model_copy(
                        update={"version_ref": f"lib{index}"}
                    ),
                }
            )
        )
    (gradle_project.path / "gradle/libs.versions.toml").write_text(
        '[versions]\nlib0 = "1"\nlib1 = "1"\n[libraries]\n'
        'lib0 = { module = "org.example:lib0", version.ref = "lib0" }\n'
        'lib1 = { module = "org.example:lib1", version.ref = "lib1" }\n',
        encoding="utf-8",
    )
    state = SimpleNamespace(
        findings=findings,
        vulns=[],
        lib0="old",
        entered=set(),
        clock=FakeClock(datetime(2026, 9, 18, tzinfo=UTC)),
    )

    def transport(url, repository, suffix):
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
            if state.lib0 == "young" and artifact == "lib0"
            else "Tue, 01 Sep 2026 00:00:00 GMT"
        )
        return body, {"Last-Modified": published}, url

    def validate(project, candidates, report):
        validations = []
        for candidate in candidates:
            key = candidate.target.group_key
            for member in candidate.target.members:
                request = {
                    "request_id": f"{key}/{member.alias}",
                    "group_key": key,
                    "alias": member.alias,
                    "project_path": ":",
                    "kind": member.kind,
                    "coordinate": member.coordinate,
                    "installed_version": member.installed_version,
                    "candidate_version": candidate.target.target_version,
                }
                result = CandidateValidation(
                    request_id=request["request_id"],
                    selected_version=candidate.target.target_version,
                    implementation=None,
                    reason=None,
                )
                validations.append((request, result))
        return validations

    monkeypatch.setattr(dependency_age, "_publication_http", transport)
    monkeypatch.setattr(
        "maintenance_man.gradle_resolution.validate_gradle_candidates", validate
    )
    monkeypatch.setattr(scanner, "scan_gradle", lambda project: (state.vulns, report))
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
    assert all(row.state is None for row in result.updates)


def test_gradle_scan_reports_unmapped_update_without_planning_diagnostics(
    scoped_publication_scan,
):
    state = scoped_publication_scan
    state.findings.append(make_update(pkg_name="unmapped", gradle_target=None))
    result = scan_project("android", state.project, 7, clock=state.clock)
    assert result.updates[-1].state == GradleBlock(
        kind="mapping", reason="no supported catalogue target"
    )


@pytest.mark.parametrize(
    ("lib0", "routing", "expected_state", "expected_date"),
    [
        ("old", "standard-public", None, datetime(2026, 9, 1, tzinfo=UTC)),
        (
            "young",
            "standard-public",
            GradleBlock(kind="age", reason="publication younger than required 7 days"),
            None,
        ),
        (
            "old",
            None,
            GradleBlock(kind="mapping", reason=ROUTING_UNDECLARED),
            None,
        ),
    ],
)
def test_given_gradle_proposal_when_scanned_then_age_is_fail_closed(
    scoped_publication_scan, lib0, routing, expected_state, expected_date
):
    state = scoped_publication_scan
    state.lib0 = lib0
    project = state.project.model_copy(update={"gradle_repository_routing": routing})

    scan_project("android", project, 7, clock=state.clock)

    saved = {row.pkg_name: row for row in load_scan_results("android").updates}
    first = saved["org.example:lib0"]
    assert (first.state, first.published_date) == (expected_state, expected_date)
    assert (saved["org.example:lib1"].state is None) is (routing == "standard-public")


def test_given_recorded_plan_when_scanned_then_rows_follow_exact_associations(
    scoped_publication_scan, monkeypatch
):
    state = scoped_publication_scan
    first, second = (
        GradleCandidate(target=row.gradle_target, vulnerability_indices=indices)
        for row, indices in zip(state.findings, ((0,), (0, 1, 3)), strict=True)
    )
    unowned = CandidateWithheld(
        group_key=None,
        block=GradleBlock(
            kind="mapping", reason="cannot identify an unambiguous catalogue entry"
        ),
        vulnerability_indices=(2,),
    )
    monkeypatch.setattr(
        scanner,
        "select_gradle_candidates",
        lambda *args: GradleFixPlan(candidates=(first, second), withheld=(unowned,)),
    )
    state.vulns = [make_vuln(vuln_id=f"CVE-{number}") for number in (1, 2, 3)]
    state.vulns.append(make_vuln(vuln_id="CVE-4", fixed_version=None))

    result = scan_project("android", state.project, 7, clock=state.clock)

    saved = load_scan_results("android")
    assert [
        (
            v.vuln_id,
            v.gradle_target.group_key if v.gradle_target else None,
            v.state,
        )
        for v in saved.vulnerabilities
    ] == [
        ("CVE-1", "ref:lib0", None),
        ("CVE-1", "ref:lib1", None),
        ("CVE-2", "ref:lib1", None),
        (
            "CVE-3",
            None,
            GradleBlock(
                kind="mapping", reason="cannot identify an unambiguous catalogue entry"
            ),
        ),
        ("CVE-4", None, GradleBlock(kind="mapping", reason="no published fix")),
    ]
    assert [(u.gradle_target, u.state) for u in saved.updates] == [
        (first.target, None),
        (second.target, None),
    ]
    assert saved == result


_GRADLE_BOM_MODULES = [
    ("androidx.room", "room-runtime", "2.8.4"),
    ("androidx.room", "room-compiler", "2.8.4"),
    ("com.squareup.okhttp3", "okhttp", "4.12.0"),
    ("com.google.code.gson", "gson", "2.11.0"),
    ("androidx.compose.ui", "ui", "1.9.0"),
    ("org.jetbrains", "annotations", "23.0.0"),
]


def _gradle_report_payload() -> dict:
    """A resolution report whose scope covers every ``bom.json`` component."""
    components: list[dict[str, object]] = [
        {"id": "root", "kind": "root", "module": None}
    ]
    for index, (group, artifact, version) in enumerate(_GRADLE_BOM_MODULES):
        components.append(
            {
                "id": f"c{index}",
                "kind": "module",
                "module": {"group": group, "artifact": artifact, "version": version},
            }
        )
    scope = {
        "project_path": ":",
        "domain": "project",
        "configuration": "runtimeClasspath",
    }
    return {
        "schema_version": 1,
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


def _fixture_bom() -> Path:
    return paths.mm_home() / "gradle-report-fixture" / "bom.json"


def _generated(bom, report):
    return GeneratedGradleReport(
        bom_path=bom,
        report=report,
        scopes=inventory_scopes(load_inventory(bom), report),
    )


def _yield_fixture_bom(project):
    @contextmanager
    def _generate(_project):
        bom = _fixture_bom()
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
        bom = _fixture_bom()
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
        (report_directory(args) / "bom.json").unlink()
        return completed

    monkeypatch.setattr("maintenance_man.gradle_resolution.run_gradle", runner)
    monkeypatch.setattr(scanner, "run_captured", FakeCommands())
    with pytest.raises(GradleError, match="cyclonedxBom produced no inventory"):
        scan_gradle(gradle_project)
    assert list(paths.mm_home().glob("gradle-report-*")) == []


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


_NESTED_MALFORMED_BOM = {
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


def _inject_gradle_capture_failure(monkeypatch, failure: str) -> None:
    if failure == "incomplete-resolution":
        report = json.loads((GRADLE_FIXTURES / "resolution/empty.json").read_text())
        report["scopes"][0]["unresolved"] = ["g:missing:1.0"]
        inventory = _NESTED_MALFORMED_BOM
    else:
        report = _gradle_report_payload()
        inventory = json.loads((GRADLE_FIXTURES / "bom.json").read_text())
        inventory["components"] = [
            row for row in inventory["components"] if row["name"] == "gson"
        ]

    def run_gradle(project_root, args, *, label):
        assert (args[0], label) == ("mmGradleReport", "mmGradleReport")
        directory = report_directory(args)
        (directory / "bom.json").write_text(json.dumps(inventory), encoding="utf-8")
        (directory / "report.json").write_text(json.dumps(report), encoding="utf-8")
        return completed(args, stdout="", stderr="boom")

    monkeypatch.setattr("maintenance_man.gradle_resolution.run_gradle", run_gradle)


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("incomplete-inventory", "resolved module missing from inventory"),
        ("incomplete-resolution", "Incomplete Gradle resolution"),
    ],
)
def test_given_gradle_capture_failure_when_project_scanned_then_saved_bytes_survive(
    mm_home, gradle_project, monkeypatch, failure, message
):
    saved = mm_home / "scan-results/android.json"
    saved.parent.mkdir(parents=True)
    saved.write_bytes(b"previous findings\n")
    commands = FakeCommands()
    monkeypatch.setattr(scanner, "run_captured", commands)
    _inject_gradle_capture_failure(monkeypatch, failure)

    with pytest.raises(GradleError, match=message):
        scan_project("android", gradle_project, 7)

    assert saved.read_bytes() == b"previous findings\n"
    assert list(paths.mm_home().glob("gradle-report-*")) == []
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
    findings = _parse_trivy(
        json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [row]}]}),
        "Trivy SBOM",
        secrets=False,
    )[0]
    assert len(findings) == 1
    assert findings[0].severity == Severity.UNKNOWN
    assert findings[0].published_date is None
    assert findings[0].fixed_version is None


_LANGUAGE_ROW = {
    "VulnerabilityID": "CVE-example",
    "PkgName": "org.example:library",
    "InstalledVersion": "1",
}


def _lang_results(vulnerabilities: object) -> dict[str, object]:
    return {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": vulnerabilities}]}


@pytest.mark.parametrize(
    ("payload", "secrets", "message"),
    [
        pytest.param([], False, "Malformed Trivy output", id="not-an-object"),
        pytest.param(
            {"Results": [None]}, False, "Malformed Trivy output", id="null-result"
        ),
        pytest.param(
            {"Results": [{"Class": "secret", "Target": "x", "Secrets": 42}]},
            True,
            r"(?s)Malformed Trivy output.*Secrets",
            id="requested-secrets-not-a-list",
        ),
        pytest.param(
            {"Results": [{"Class": "secret", "Target": None, "Secrets": []}]},
            True,
            r"(?s)Malformed Trivy output.*Target",
            id="requested-secret-null-target",
        ),
        pytest.param(
            {
                "Results": [
                    {"Class": "secret", "Target": "x", "Secrets": [{"RuleID": False}]}
                ]
            },
            True,
            r"(?s)Malformed Trivy output.*RuleID",
            id="requested-secret-non-string-rule-id",
        ),
        *(
            pytest.param(
                _lang_results([{**_LANGUAGE_ROW, field: value}]),
                False,
                rf"(?s)Malformed Trivy output.*{field}",
                id=f"row-{field}-{value!r}",
            )
            for field, value in [
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
            ]
        ),
        *(
            pytest.param(
                _lang_results([{k: v for k, v in _LANGUAGE_ROW.items() if k != field}]),
                False,
                rf"(?s)Malformed Trivy output.*{field}",
                id=f"row-missing-{field}",
            )
            for field in ("VulnerabilityID", "PkgName", "InstalledVersion")
        ),
        *(
            pytest.param(
                payload, False, "Malformed Trivy output", id=f"envelope-{name}"
            )
            for name, payload in [
                ("results-false", {"Results": False}),
                ("results-null", {"Results": None}),
                ("results-string", {"Results": ""}),
                ("results-number", {"Results": 0}),
                ("class-false", {"Results": [{"Class": False}]}),
                (
                    "class-false-with-secrets",
                    {"Results": [{"Class": False, "Target": "x", "Secrets": []}]},
                ),
                (
                    "class-null",
                    {"Results": [{"Class": None, "Target": "x", "Secrets": []}]},
                ),
                ("vulnerabilities-false", _lang_results(False)),
                ("vulnerabilities-string", _lang_results("")),
                ("vulnerabilities-object", _lang_results({})),
                ("vulnerabilities-null-row", _lang_results([None])),
            ]
        ),
    ],
)
def test_given_malformed_consumed_trivy_data_when_parsed_then_scan_error(
    payload, secrets, message
):
    with pytest.raises(ScanError, match=message):
        _parse_trivy(json.dumps(payload), "Trivy", secrets=secrets)


@pytest.mark.parametrize(
    ("payload", "secrets", "expected"),
    [
        pytest.param({}, False, [], id="no-results"),
        pytest.param(
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
            True,
            [],
            id="unconsumed-class",
        ),
        pytest.param(
            {"Results": [{"Class": "secret", "Target": None, "Secrets": 42}]},
            False,
            [],
            id="secrets-not-requested",
        ),
        pytest.param(
            {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": None}]},
            False,
            [],
            id="null-vulnerabilities",
        ),
        pytest.param(
            {
                "Results": [
                    {
                        "Class": "lang-pkgs",
                        "Target": None,
                        "Secrets": 42,
                        "Vulnerabilities": [{**_LANGUAGE_ROW, "Extra": 1}],
                    }
                ]
            },
            False,
            [
                VulnFinding(
                    vuln_id="CVE-example",
                    pkg_name="org.example:library",
                    installed_version="1",
                    severity=Severity.UNKNOWN,
                    title="",
                    description="",
                    status="unknown",
                )
            ],
            id="vendor-fields-ignored",
        ),
    ],
)
def test_given_unconsumed_trivy_data_when_parsed_then_it_is_not_validated(
    payload, secrets, expected
):
    vulns, found = _parse_trivy(json.dumps(payload), "Trivy", secrets=secrets)

    assert (vulns, found) == (expected, [])


def _prepare_bound_local_provenance_scan(gradle_project, monkeypatch):
    payload = _gradle_report_payload()
    payload["local_projects"] = [
        {
            "project_path": ":",
            "module": {"group": "fixture", "artifact": "app", "version": "unspecified"},
        }
    ]
    inventory = json.loads((GRADLE_FIXTURES / "bom.json").read_text())
    inventory["components"].append(
        {
            "type": "library",
            "purl": "pkg:maven/fixture/app@unspecified?project_path=%3A",
        }
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
    _trivy_sbom(monkeypatch, gradle_project, bom=bom)


def test_given_bound_local_provenance_when_gradle_scanned_then_scopes_are_recorded(
    gradle_project, monkeypatch
):
    _prepare_bound_local_provenance_scan(gradle_project, monkeypatch)

    findings, _ = scan_gradle(gradle_project)

    assert {finding.gradle_scopes for finding in findings} == {
        (":/project/runtimeClasspath",)
    }


def test_scan_dates_bun_updates_with_bun_info_in_the_project(
    mm_home, tmp_path, monkeypatch
):
    monkeypatch.setattr(scanner, "_run_trivy_scan", lambda *args, **kwargs: ([], []))
    _stub_outdated(monkeypatch, lambda project: [make_update(pkg_name="zod")])
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


_UV_LIST = ("uv", "pip", "list", "--outdated", "--format", "json")
_MVN_UPDATES = (
    "mvn",
    "-B",
    "-ntp",
    "-Dstyle.color=never",
    "versions:display-dependency-updates",
    "-DprocessDependencyManagement=false",
    "-Dversions.outputLineWidth=1000",
)


@pytest.mark.parametrize(
    ("manager", "source", "outputs"),
    [
        pytest.param(
            "uv", "pypi", [(("uv", "sync", "--locked"), ""), (_UV_LIST, "[]")], id="uv"
        ),
        pytest.param(
            "bun",
            "npm",
            [
                (
                    ("bun", "outdated", "--no-progress"),
                    "bun outdated v1.4.2 (744846f84)\n",
                )
            ],
            id="bun",
        ),
        pytest.param(
            "mvn",
            "central",
            [
                (
                    _MVN_UPDATES,
                    "[INFO] --- versions:2.25.1:display-dependency-updates"
                    " (default-cli) @ demo ---\n"
                    "[INFO] \n",
                )
            ],
            id="mvn",
        ),
    ],
)
def test_non_gradle_scan_filters_through_one_publication_context(
    mm_home, tmp_path, monkeypatch, manager, source, outputs
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = []\n', encoding="utf-8"
    )
    commands = FakeCommands()
    for argv, stdout in outputs:
        commands.add(argv, cwd=tmp_path, result=completed(argv, stdout=stdout))
    monkeypatch.setattr("maintenance_man.outdated.run_captured", commands)
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
    monkeypatch.setattr(scanner, "_run_trivy_scan", lambda *args, **kwargs: ([], []))
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda *args: [])
    project = ProjectConfig(path=tmp_path, package_manager=manager, scan_secrets=False)

    scanner.scan_project("demo", project, 9)

    assert [argv for argv, _, _ in commands.calls] == [argv for argv, _ in outputs]
    assert opened == [paths.publications_dir()]
    assert filtered == [(source, tmp_path, 9, True)]


@pytest.mark.parametrize(
    ("advisory_fix", "expected_updates"),
    [
        pytest.param("1.0.1", ["pkg-b"], id="actionable-advisory-suppresses"),
        pytest.param("0.9", ["pkg-a", "pkg-b"], id="no-fix-above-installed-keeps"),
    ],
)
def test_given_vulnerable_update_when_scanned_then_only_unfixable_ones_are_kept(
    mm_home, tmp_path, monkeypatch, advisory_fix, expected_updates
):
    vulnerable, _, _ = scan_age_inputs(tmp_path)
    clean, _, _ = scan_age_inputs(tmp_path)
    raw_updates = [
        vulnerable.model_copy(
            update={"pkg_name": "pkg-a", "latest_version": "2.0", "gradle_target": None}
        ),
        clean.model_copy(
            update={"pkg_name": "pkg-b", "latest_version": "2.0", "gradle_target": None}
        ),
    ]
    requested = []

    def transport(url, repository, suffix):
        requested.append(suffix)
        return pypi_body(suffix.split("/")[1], "2.0"), {}, url

    monkeypatch.setattr(dependency_age, "_publication_http", transport)
    monkeypatch.setattr(
        scanner,
        "_run_uv_audit",
        lambda path: [make_vuln(pkg_name="pkg-a", fixed_version=advisory_fix)],
    )
    _stub_outdated(monkeypatch, lambda project: raw_updates)
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)

    result = scan_project(
        "demo",
        project,
        7,
        clock=FakeClock(datetime(2026, 9, 18, tzinfo=UTC)),
    )

    assert sorted(requested) == [f"pypi/{name}/2.0/json" for name in expected_updates]
    assert [v.pkg_name for v in result.vulnerabilities] == ["pkg-a"]
    assert [update.pkg_name for update in result.updates] == expected_updates
    assert load_scan_results("demo").updates == result.updates


def _stub_advisories(monkeypatch, vulnerabilities: list[VulnFinding]) -> None:
    monkeypatch.setattr(scanner, "_run_uv_audit", lambda _path: vulnerabilities)
    monkeypatch.setattr(
        scanner, "_run_trivy_scan", lambda *args, **kwargs: (vulnerabilities, [])
    )
    _stub_outdated(monkeypatch, lambda _project: [])


def _bun_project_files(
    monkeypatch, project_path: Path, dependencies: dict[str, str], resolved: str
) -> FakeCommands:
    (project_path / "package.json").write_text(
        json.dumps({"dependencies": dependencies}), encoding="utf-8"
    )
    commands = FakeCommands()
    commands.add(
        ("bun", "pm", "ls"),
        cwd=project_path,
        result=completed(stdout=f"{project_path} node_modules\n└── {resolved}\n"),
    )
    monkeypatch.setattr(bun_dependencies, "run_captured", commands)
    return commands


def _advisories(pkg_name: str, installed: str, *fix_lists: str) -> list[VulnFinding]:
    return [
        make_vuln(
            vuln_id=f"CVE-{index}",
            pkg_name=pkg_name,
            installed_version=installed,
            fixed_version=fix_list,
        )
        for index, fix_list in enumerate(fix_lists, start=1)
    ]


@pytest.mark.parametrize("manager", ["bun", "mvn"])
@pytest.mark.parametrize(
    ("pkg_name", "installed", "fix_lists", "expected_fixes"),
    [
        pytest.param(
            "jackson",
            "2.13.0",
            ("2.12.7.1, 2.13.4.2", "2.13.2.1"),
            ["2.13.4.2", "2.13.4.2"],
            id="list-between-fixes",
        ),
        pytest.param(
            "jackson",
            "2.14.0",
            ("2.12.7.1, 2.13.4.2",),
            [None],
            id="above-every-fix",
        ),
        pytest.param(
            "guava", "31.1-jre", ("32.0.0-android",), [None], id="qualifier-differs"
        ),
        pytest.param(
            "netty",
            "4.1.94.Final",
            ("4.1.100.Final",),
            ["4.1.100.Final"],
            id="qualifier-matches",
        ),
    ],
)
def test_given_trivy_fix_lists_when_scanned_then_one_known_fix_is_saved(
    mm_home,
    tmp_path,
    monkeypatch,
    manager,
    pkg_name,
    installed,
    fix_lists,
    expected_fixes,
):
    _stub_advisories(monkeypatch, _advisories(pkg_name, installed, *fix_lists))
    if manager == "bun":
        _bun_project_files(
            monkeypatch, tmp_path, {pkg_name: installed}, f"{pkg_name}@{installed}"
        )
    project = ProjectConfig(path=tmp_path, package_manager=manager, scan_secrets=False)

    result = scan_project("demo", project)

    assert [v.fixed_version for v in result.vulnerabilities] == expected_fixes


@pytest.mark.parametrize("manager", ["uv", "bun", "mvn"])
def test_given_package_at_two_installed_versions_when_scanned_then_no_fix_is_saved(
    mm_home, tmp_path, monkeypatch, manager
):
    _stub_advisories(
        monkeypatch,
        [
            *_advisories("lodash", "1.0.0", "1.0.1"),
            *_advisories("lodash", "2.0.0", "2.0.1"),
        ],
    )
    if manager == "bun":
        _bun_project_files(monkeypatch, tmp_path, {"lodash": "^3.0.0"}, "lodash@3.0.0")
    project = ProjectConfig(path=tmp_path, package_manager=manager, scan_secrets=False)

    result = scan_project("demo", project)

    assert [v.fixed_version for v in result.vulnerabilities] == [None, None]


@pytest.mark.parametrize(
    ("dependencies", "resolved", "expected_fix"),
    [
        pytest.param({"zod": "^3.0.0"}, "zod@3.0.0", "3.0.1", id="declared"),
        pytest.param({"other": "1.0.0"}, "other@1.0.0", None, id="undeclared"),
        pytest.param({"zod": "file:../zod"}, "zod@3.0.0", None, id="file-source"),
        pytest.param({"zod": "^4.0.0"}, "zod@4.0.0", None, id="nested-copy"),
    ],
)
def test_given_bun_declaration_when_scanned_then_only_registry_direct_fixes_are_kept(
    mm_home, tmp_path, monkeypatch, dependencies, resolved, expected_fix
):
    _stub_advisories(monkeypatch, _advisories("zod", "3.0.0", "3.0.1"))
    _bun_project_files(monkeypatch, tmp_path, dependencies, resolved)
    project = ProjectConfig(path=tmp_path, package_manager="bun", scan_secrets=False)

    result = scan_project("demo", project)

    assert [v.fixed_version for v in result.vulnerabilities] == [expected_fix]


def test_given_bun_direct_and_nested_copies_when_scanned_then_direct_keeps_its_fix(
    mm_home, tmp_path, monkeypatch
):
    _stub_advisories(
        monkeypatch,
        [
            *_advisories("lodash", "1.0.0", "1.0.1"),
            *_advisories("lodash", "2.0.0", "2.0.1"),
        ],
    )
    _bun_project_files(monkeypatch, tmp_path, {"lodash": "^1.0.0"}, "lodash@1.0.0")
    project = ProjectConfig(path=tmp_path, package_manager="bun", scan_secrets=False)

    result = scan_project("demo", project)

    assert [v.fixed_version for v in result.vulnerabilities] == ["1.0.1", None]


def test_given_bun_scan_without_advisories_when_scanned_then_bun_pm_ls_is_not_run(
    mm_home, tmp_path, monkeypatch
):
    _stub_advisories(monkeypatch, [])
    commands = FakeCommands()
    monkeypatch.setattr(bun_dependencies, "run_captured", commands)
    project = ProjectConfig(path=tmp_path, package_manager="bun", scan_secrets=False)

    scan_project("demo", project)

    assert commands.calls == []


def test_given_bun_advisory_without_manifest_when_scanned_then_scan_fails_unsaved(
    mm_home, tmp_path, monkeypatch
):
    _stub_advisories(monkeypatch, _advisories("zod", "3.0.0", "3.0.1"))
    project = ProjectConfig(path=tmp_path, package_manager="bun", scan_secrets=False)

    with pytest.raises(ScanError, match=r"^Failed to read"):
        scan_project("demo", project)

    assert not (mm_home / "scan-results" / "demo.json").exists()


def test_given_uv_fix_lists_when_scanned_then_every_advisory_gets_the_target(
    mm_home, tmp_path, monkeypatch
):
    _stub_advisories(
        monkeypatch,
        _advisories(
            "urllib3",
            "1.24.1",
            "1.24.2",
            "2.0.7, 1.26.18",
            "1.26.19, 2.2.2",
            "2.8.0",
            "1.24.3",
            "1.25.9",
            "2.0.6, 1.26.17",
            "2.5.0",
            "2.6.0",
            "2.6.3",
            "2.7.0",
        ),
    )
    project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)

    result = scan_project("demo", project)

    assert [v.fixed_version for v in result.vulnerabilities] == ["2.8.0"] * 11
