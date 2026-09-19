import hashlib
import json
import shutil
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from unittest.mock import patch

import pytest

from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GRADLE_INVENTORY_BOM_RELPATH,
    GradleError,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
)
from maintenance_man.scanner import (
    TrivyNotFoundError,
    _parse_uv_audit_vulns,
    check_trivy_available,
    scan_project,
)
from tests.conftest import GRADLE_FIXTURES, make_update, make_vuln

_OLD = datetime(2024, 1, 1, tzinfo=timezone.utc)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _make_project(
    path: str | Path, pm: Literal["bun", "uv", "mvn"] = "uv"
) -> ProjectConfig:
    return ProjectConfig(path=Path(path), package_manager=pm)


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


class TestCheckTrivyAvailable:
    def test_trivy_is_available(self):
        # Should not raise — trivy is installed on this machine
        check_trivy_available()

    def test_trivy_not_available(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("PATH", "/nonexistent")
        with pytest.raises(TrivyNotFoundError):
            check_trivy_available()


@pytest.mark.integration
class TestScanProject:
    def test_scan_project_with_vulns(self, scan_results_dir: Path):
        """Scan vulnerable fixture — known to have vulnerabilities."""
        project = _make_project(FIXTURES_DIR / "vulnerable-project")
        result = scan_project("vulnerable", project)

        assert isinstance(result, ScanResult)
        assert result.project == "vulnerable"
        assert result.scanned_at is not None
        assert len(result.vulnerabilities) > 0
        assert result.has_actionable_vulns is True

        # Structural checks on findings
        for v in result.vulnerabilities:
            assert v.vuln_id.startswith(("CVE-", "GHSA-", "PYSEC-"))
            assert v.pkg_name
            assert v.installed_version
            assert v.severity in Severity
            assert v.title
            assert v.status

    def test_scan_project_clean(self, scan_results_dir: Path):
        """Scan clean fixture — expected to have no vulnerabilities."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        result = scan_project("clean", project)

        assert isinstance(result, ScanResult)
        assert result.project == "clean"
        assert len(result.vulnerabilities) == 0
        assert result.has_actionable_vulns is False

    def test_scan_writes_results_file(self, scan_results_dir: Path):
        """Scan should write JSON results to scan-results dir."""
        project = _make_project(FIXTURES_DIR / "vulnerable-project")
        scan_project("vulnerable", project)

        results_file = scan_results_dir / "vulnerable.json"
        assert results_file.exists()

        data = json.loads(results_file.read_text())
        assert data["project"] == "vulnerable"
        assert "vulnerabilities" in data
        assert "secrets" in data

        # Round-trip: the JSON should deserialise back into a ScanResult
        reloaded = ScanResult.model_validate(data)
        assert reloaded.project == "vulnerable"

    def test_scan_nonexistent_path(self, scan_results_dir: Path):
        """Scan a path that doesn't exist — should raise."""
        project = _make_project("/nonexistent/path")
        with pytest.raises(FileNotFoundError):
            scan_project("ghost", project)


class TestScanProjectWithUpdates:
    def test_scan_includes_updates(self, scan_results_dir: Path):
        """When outdated check returns updates, they appear in ScanResult."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        fake_updates = [
            UpdateFinding(
                pkg_name="requests",
                installed_version="2.28.0",
                latest_version="2.31.0",
                semver_tier=SemverTier.MINOR,
            ),
        ]
        with (
            patch("maintenance_man.scanner.get_outdated", return_value=fake_updates),
            patch("maintenance_man.scanner.filter_by_age", return_value=fake_updates),
        ):
            result = scan_project("clean", project)

        assert result.has_updates is True
        assert len(result.updates) == 1
        assert result.updates[0].pkg_name == "requests"

    def test_scan_deduplicates_vuln_and_update(self, scan_results_dir: Path):
        """If a package is both a vuln and an update, only the vuln appears."""
        project = ProjectConfig(
            path=FIXTURES_DIR / "vulnerable-project",
            package_manager="uv",
            scan_secrets=False,
        )
        fake_updates = [
            UpdateFinding(
                pkg_name="cryptography",
                installed_version="42.0.0",
                latest_version="43.0.0",
                semver_tier=SemverTier.MAJOR,
            ),
            UpdateFinding(
                pkg_name="brand-new-pkg",
                installed_version="1.0.0",
                latest_version="2.0.0",
                semver_tier=SemverTier.MAJOR,
            ),
        ]
        audit = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout=(
                "Found 1 known vulnerability and no adverse project statuses in "
                "1 package\n\n"
                "Vulnerabilities:\n\n"
                "cryptography 42.0.0 has 1 known vulnerability:\n\n"
                "- GHSA-test: test vulnerability\n\n"
                "  Fixed in: 43.0.0\n"
            ),
            stderr="",
        )
        with (
            patch("maintenance_man.scanner.subprocess.run", return_value=audit),
            patch("maintenance_man.scanner.get_outdated", return_value=fake_updates),
            patch("maintenance_man.scanner.filter_by_age", return_value=fake_updates),
        ):
            result = scan_project("vulnerable", project)

        vuln_pkg_names = {v.pkg_name for v in result.vulnerabilities}
        update_pkg_names = {u.pkg_name for u in result.updates}
        assert "cryptography" in vuln_pkg_names
        assert "cryptography" not in update_pkg_names
        assert "brand-new-pkg" in update_pkg_names

    def test_scan_outdated_failure_does_not_crash(self, scan_results_dir: Path):
        """If the outdated check fails, scan still returns Trivy results."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        with patch(
            "maintenance_man.scanner.get_outdated",
            side_effect=Exception("bun not found"),
        ):
            result = scan_project("clean", project)

        assert isinstance(result, ScanResult)
        assert result.updates == []

    def test_scan_passes_min_version_age_days(self, scan_results_dir: Path):
        """min_version_age_days parameter is forwarded to filter_by_age."""
        project = _make_project(FIXTURES_DIR / "clean-project")
        with (
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
            patch("maintenance_man.scanner.filter_by_age", return_value=[]) as mock_age,
        ):
            scan_project("clean", project, min_version_age_days=14)

        mock_age.assert_called_once()
        assert mock_age.call_args.kwargs["min_age_days"] == 14


class TestUvNativeScan:
    def test_uv_project_uses_uv_audit_locked_not_trivy_vulns(
        self, scan_results_dir: Path, tmp_path: Path
    ):
        project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=False)
        audit = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Found no known vulnerabilities", stderr=""
        )

        with (
            patch("maintenance_man.scanner.subprocess.run", return_value=audit) as run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            result = scan_project("test-proj", project)

        assert result.vulnerabilities == []
        assert result.secrets == []
        assert run.call_args.args[0] == ["uv", "audit", "--locked"]

    def test_uv_project_scans_secrets_when_enabled(
        self, scan_results_dir: Path, tmp_path: Path
    ):
        project = ProjectConfig(path=tmp_path, package_manager="uv", scan_secrets=True)
        audit = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Found no known vulnerabilities", stderr=""
        )
        trivy = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {
                    "Results": [
                        {
                            "Class": "secret",
                            "Target": "creds/example.json",
                            "Secrets": [
                                {
                                    "RuleID": "secret-rule",
                                    "Title": "Example secret",
                                    "Severity": "HIGH",
                                }
                            ],
                        }
                    ]
                }
            ),
            stderr="",
        )

        with (
            patch(
                "maintenance_man.scanner.subprocess.run", side_effect=[audit, trivy]
            ) as run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            result = scan_project("test-proj", project)

        assert result.vulnerabilities == []
        assert len(result.secrets) == 1
        assert result.secrets[0].file == "creds/example.json"
        assert run.call_args_list[0].args[0] == ["uv", "audit", "--locked"]
        assert run.call_args_list[1].args[0][4:6] == ["--scanners", "secret"]


class TestRunTrivyScanSkipDirs:
    def test_skip_dirs_appended_to_command(
        self, scan_results_dir: Path, tmp_path: Path
    ):
        """scan_skip_dirs entries are forwarded as --skip-dirs flags to trivy."""
        project = ProjectConfig(
            path=tmp_path,
            package_manager="bun",
            scan_skip_dirs=["tests/fixtures", "vendor"],
        )
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Results": []}', stderr=""
        )
        with (
            patch(
                "maintenance_man.scanner.subprocess.run",
                return_value=fake_result,
            ) as mock_run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            scan_project("test-proj", project)

        cmd = mock_run.call_args.args[0]
        assert cmd.count("--skip-dirs") == 2
        dirs_indices = [i for i, v in enumerate(cmd) if v == "--skip-dirs"]
        assert cmd[dirs_indices[0] + 1] == "tests/fixtures"
        assert cmd[dirs_indices[1] + 1] == "vendor"

    def test_no_skip_dirs_by_default(self, scan_results_dir: Path, tmp_path: Path):
        """Without scan_skip_dirs, no --skip-dirs flags are added."""
        project = ProjectConfig(path=tmp_path, package_manager="bun")
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Results": []}', stderr=""
        )
        with (
            patch(
                "maintenance_man.scanner.subprocess.run",
                return_value=fake_result,
            ) as mock_run,
            patch("maintenance_man.scanner.get_outdated", return_value=[]),
        ):
            scan_project("test-proj", project)

        cmd = mock_run.call_args.args[0]
        assert "--skip-dirs" not in cmd


@pytest.fixture
def scoped_publication_scan(tmp_path, monkeypatch, gradle_project, mm_home):
    from threading import Barrier, Lock
    from types import SimpleNamespace

    from maintenance_man import scanner
    from maintenance_man.dependency_age import PublicationLookupContext
    from maintenance_man.models.gradle import (
        CompleteResolution,
        ModuleId,
        PublicationRequest,
        RepositoryDeclaration,
        ResolutionEdge,
        ResolutionReport,
        ResolvedComponent,
        ScopeId,
        ScopeResolution,
    )

    catalogue_path = gradle_project.path / GRADLE_CATALOGUE_RELPATH
    catalogue_path.write_text(
        '[versions]\nlib0 = "1.0"\nlib1 = "1.0"\n[libraries]\n'
        'lib0 = { module = "org.example:lib0", version.ref = "lib0" }\n'
        'lib1 = { module = "org.example:lib1", version.ref = "lib1" }\n'
    )
    findings = []
    modules = {}
    for index in range(2):
        module = ModuleId(group="org.example", artifact=f"lib{index}", version="2.0")
        modules[module.artifact] = module
        target = GradleUpdateTarget(
            version_ref=f"lib{index}",
            target_version="2.0",
            members=[
                GradleMember(
                    kind="library",
                    alias=f"lib{index}",
                    coordinate=module.coordinate,
                    installed_version="1.0",
                )
            ],
        )
        findings.append(
            make_update(
                pkg_name=module.coordinate,
                installed_version="1.0",
                latest_version="2.0",
                gradle_target=target,
            )
        )
    scope = ScopeId(
        project_path=":", domain="project", configuration="runtimeClasspath"
    )
    components = (
        ResolvedComponent(id="root", kind="root", module=None, variants=()),
    ) + tuple(
        ResolvedComponent(
            id=module.artifact,
            kind="module",
            module=ModuleId(
                group=module.group, artifact=module.artifact, version="1.0"
            ),
            variants=("runtime",),
        )
        for module in modules.values()
    )
    edges = tuple(
        ResolutionEdge(
            source="root",
            target=module.artifact,
            requested=f"{module.coordinate}:1.0",
            constraint=False,
        )
        for module in modules.values()
    )
    resolution = CompleteResolution(
        report=ResolutionReport(
            schema_version=1,
            root_project=str(gradle_project.path),
            producer_versions={"gradle": "9.0", "cyclonedx": "3.0.0", "report": "1"},
            catalogue_digest=hashlib.sha256(catalogue_path.read_bytes()).hexdigest(),
            repositories=(
                RepositoryDeclaration(
                    project_path=":",
                    domain="library",
                    url="https://dl.google.com/dl/android/maven2",
                ),
            ),
            selected_scopes=(scope,),
            scopes=(
                ScopeResolution(
                    scope=scope, components=components, edges=edges, unresolved=()
                ),
            ),
        )
    )
    state = SimpleNamespace(
        findings=findings,
        vulns=[],
        unknown=False,
        failure=None,
        overlap=False,
        entered=set(),
    )
    barrier, lock = Barrier(2, timeout=10), Lock()

    def transport(url, repository, suffix, count):
        count()
        artifact = suffix.split("/")[-3]
        with lock:
            state.entered.add(artifact)
        if state.overlap:
            barrier.wait()
        if state.unknown and artifact == "lib1":
            if state.failure:
                raise state.failure
            return None
        module = modules[artifact]
        body = (
            f"<project><groupId>{module.group}</groupId>"
            f"<artifactId>{module.artifact}</artifactId>"
            f"<version>{module.version}</version></project>"
        ).encode()
        return body, {"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"}, url

    now = datetime(2026, 9, 18, tzinfo=timezone.utc)
    monkeypatch.setattr(
        scanner,
        "PublicationLookupContext",
        lambda path: PublicationLookupContext(
            path, transport=transport, now=lambda: now
        ),
    )
    monkeypatch.setattr(
        scanner, "_run_gradle_scan", lambda project: (state.vulns, resolution)
    )
    monkeypatch.setattr(scanner, "get_outdated", lambda project: state.findings)
    monkeypatch.setattr(scanner, "validate_gradle_candidates", lambda *args: object())

    def attach(candidate, resolution, batch):
        requests = tuple(
            PublicationRequest(
                module=modules[member.alias],
                repositories=("google",),
                routing_supported=True,
            )
            for member in candidate.target.members
        )
        return candidate.model_copy(update={"publication_requests": requests})

    monkeypatch.setattr(scanner, "attach_gradle_publications", attach)
    state.project = gradle_project.model_copy(
        update={"scan_secrets": False, "gradle_repository_routing": "standard-public"}
    )
    return state


@pytest.mark.parametrize("failure", [None, TimeoutError("unavailable")])
def test_gradle_scan_overlaps_groups_and_retains_unknown_publications(
    scoped_publication_scan, failure
):
    state = scoped_publication_scan
    state.unknown, state.overlap, state.failure = True, True, failure
    result = scan_project("android", state.project, 7)
    assert state.entered == {"lib0", "lib1"}
    assert len(result.updates) == 2
    assert result.updates[0].blocked_reason is None
    assert result.updates[1].blocked_reason
    assert result.updates[1].gradle_block_kind == "age"


def test_gradle_discovery_failure_is_not_swallowed(
    scoped_publication_scan, monkeypatch
):
    def fail(project):
        raise GradleError("discovery failed")

    monkeypatch.setattr("maintenance_man.scanner.get_outdated", fail)
    with pytest.raises(GradleError, match="discovery failed"):
        scan_project("android", scoped_publication_scan.project, 7)


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
    result = scan_project("android", state.project, 7)
    assert result.updates == state.findings
    assert result.vulnerabilities[0].gradle_target == result.updates[0].gradle_target
    assert all(row.blocked_reason is None for row in result.updates)


def test_gradle_finding_without_target_or_reason_is_blocked_not_eligible(
    scoped_publication_scan,
):
    state = scoped_publication_scan
    state.findings.append(make_update(pkg_name="unmapped", gradle_target=None))
    result = scan_project("android", state.project, 7)
    assert result.updates[-1].blocked_reason == "no supported catalogue target"
    assert result.updates[-1].gradle_block_kind == "mapping"


def test_gradle_block_kind_agrees_between_update_and_vuln_rows_for_withheld_group(
    scoped_publication_scan, monkeypatch
):
    """A group withheld by attach_gradle_publications must report the same
    gradle_block_kind on its update row and its advisory row.  Before the
    fix, the update loop classified this as "mapping" (key not in
    eligible) while the vulnerability loop unconditionally used "age"
    whenever blocked_reason was set.
    """
    from maintenance_man.models.gradle import (
        CandidateWithheld,
        ModuleId,
        PublicationRequest,
    )

    state = scoped_publication_scan
    state.vulns = [
        make_vuln(
            vuln_id="CVE-2030-9999",
            pkg_name="org.example:lib1",
            installed_version="1.0",
            fixed_version="2.0",
        )
    ]

    def attach(candidate, resolution, batch):
        if candidate.target.group_key == "ref:lib1":
            return CandidateWithheld(
                group_key=candidate.target.group_key,
                coordinate=candidate.target.members[0].coordinate,
                installed_version=candidate.target.members[0].installed_version,
                reason="native validation withheld ref:lib1",
                advisory_ids=candidate.requested_advisories,
            )
        requests = tuple(
            PublicationRequest(
                module=ModuleId(
                    group="org.example", artifact=member.alias, version="2.0"
                ),
                repositories=("google",),
                routing_supported=True,
            )
            for member in candidate.target.members
        )
        return candidate.model_copy(update={"publication_requests": requests})

    monkeypatch.setattr("maintenance_man.scanner.attach_gradle_publications", attach)

    result = scan_project("android", state.project, 7)

    def _for_group(rows):
        return next(
            row
            for row in rows
            if row.gradle_target and row.gradle_target.group_key == "ref:lib1"
        )

    update_row = _for_group(result.updates)
    vuln_row = _for_group(result.vulnerabilities)
    assert update_row.blocked_reason == "native validation withheld ref:lib1"
    assert vuln_row.blocked_reason == "native validation withheld ref:lib1"
    assert update_row.gradle_block_kind == vuln_row.gradle_block_kind == "mapping"


def test_gradle_vuln_without_maven_coordinate_is_blocked_with_mapping_kind(
    scoped_publication_scan,
):
    """select_gradle_candidates withholds a finding with no Maven coordinate
    ("finding lacks Maven coordinate"); the scanner must surface it as a
    mapping-kind block, mirroring the equivalent update-row case."""
    state = scoped_publication_scan
    state.vulns = [
        make_vuln(pkg_name="unmapped", installed_version="1.0", fixed_version="2.0")
    ]

    result = scan_project("android", state.project, 7)

    finding = next(v for v in result.vulnerabilities if v.pkg_name == "unmapped")
    assert finding.blocked_reason == "finding lacks Maven coordinate"
    assert finding.gradle_block_kind == "mapping"


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
    from maintenance_man.gradle_resolution import parse_resolution_report

    return parse_resolution_report(json.dumps(_gradle_report_payload()))


def _yield_fixture_bom(project):
    @contextmanager
    def _generate(_project):
        bom = Path(project.path) / GRADLE_INVENTORY_BOM_RELPATH
        bom.parent.mkdir(parents=True, exist_ok=True)
        bom.write_text(
            (GRADLE_FIXTURES / "bom.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        try:
            yield bom, _gradle_resolution_fixture()
        finally:
            shutil.rmtree(bom.parent, ignore_errors=True)

    return _generate


def _trivy_sbom(monkeypatch, *, returncode: int = 0, stdout: str | None = None):
    payload = (
        stdout
        if stdout is not None
        else (GRADLE_FIXTURES / "trivy-sbom.json").read_text(encoding="utf-8")
    )

    def _run(cmd, **kwargs):
        assert cmd[:5] == ["trivy", "sbom", "--format", "json", "--scanners"]
        return subprocess.CompletedProcess(cmd, returncode, stdout=payload, stderr="")

    monkeypatch.setattr("maintenance_man.scanner.subprocess.run", _run)


def test_gradle_scan_inventory_module_without_resolution_identity_is_error(
    gradle_project, monkeypatch
):
    from maintenance_man.scanner import _run_gradle_scan

    payload = _gradle_report_payload()
    payload["scopes"][0]["components"] = [
        component
        for component in payload["scopes"][0]["components"]
        if not (
            component["module"] is not None
            and component["module"]["artifact"] == "gson"
        )
    ]

    @contextmanager
    def _generate(_project):
        from maintenance_man.gradle_resolution import parse_resolution_report

        bom = Path(gradle_project.path) / GRADLE_INVENTORY_BOM_RELPATH
        bom.parent.mkdir(parents=True, exist_ok=True)
        bom.write_text(
            (GRADLE_FIXTURES / "bom.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        resolution = parse_resolution_report(json.dumps(payload))
        try:
            yield bom, resolution
        finally:
            shutil.rmtree(bom.parent, ignore_errors=True)

    monkeypatch.setattr("maintenance_man.scanner.generate_gradle_report", _generate)
    _trivy_sbom(monkeypatch, stdout='{"Results": []}')

    with pytest.raises(GradleError, match="no selected resolution identity"):
        _run_gradle_scan(gradle_project)


def test_gradle_scan_finding_without_resolution_scope_is_error(
    gradle_project, monkeypatch
):
    from maintenance_man.scanner import _run_gradle_scan

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
        stdout=json.dumps(
            {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [unmapped_finding]}]}
        ),
    )

    with pytest.raises(GradleError, match="no selected resolution scope"):
        _run_gradle_scan(gradle_project)


def test_gradle_scan_records_selected_resolution_scopes(gradle_project, monkeypatch):
    """Every finding's gradle_scopes is derived from the selected resolution
    scope(s) that resolved its module — not left at the default empty tuple.

    _gradle_report_payload puts every _GRADLE_BOM_MODULES component under a
    single scope: project_path=":", domain="project",
    configuration="runtimeClasspath". So the expected scope string, computed
    independently of scanner.py, is ":/project/runtimeClasspath".
    """
    from maintenance_man.scanner import _run_gradle_scan

    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_report",
        _yield_fixture_bom(gradle_project),
    )
    _trivy_sbom(monkeypatch)

    findings, _ = _run_gradle_scan(gradle_project)

    assert findings
    assert all(
        finding.gradle_scopes == (":/project/runtimeClasspath",) for finding in findings
    )


def test_gradle_scan_error_leaves_previous_results_intact(
    gradle_project, monkeypatch, mm_home
):
    results_file = mm_home / "scan-results" / "android.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text('{"previous": true}', encoding="utf-8")

    def _boom(project):
        raise GradleError("./gradlew mmGradleReport failed (exit 1): boom")

    monkeypatch.setattr("maintenance_man.scanner.generate_gradle_report", _boom)

    with pytest.raises(GradleError, match="mmGradleReport failed"):
        scan_project("android", gradle_project, 7)

    assert results_file.read_text(encoding="utf-8") == '{"previous": true}'


@pytest.mark.parametrize(
    "payload, returncode",
    [
        (None, 0),
        ("{bad json", 0),
        ('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', 0),
        ("{}", 1),
    ],
)
def test_gradle_inventory_failure_preserves_previous_result_bytes(
    gradle_project, monkeypatch, mm_home, payload, returncode
):
    results_file = mm_home / "scan-results" / "android.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    previous = b'{"previous": true}\n'
    results_file.write_bytes(previous)

    def _run(cmd, **kwargs):
        assert cmd[1] == "mmGradleReport"
        if payload is not None:
            (Path(kwargs["cwd"]) / GRADLE_INVENTORY_BOM_RELPATH).write_text(
                payload, encoding="utf-8"
            )
        return subprocess.CompletedProcess(cmd, returncode, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", _run)
    with pytest.raises(GradleError):
        scan_project("android", gradle_project, 7)
    assert results_file.read_bytes() == previous
    assert not (Path(gradle_project.path) / ".mm-gradle-inventory").exists()


def test_gradle_scan_runs_the_existing_secret_scan_when_enabled(
    gradle_project, monkeypatch, mm_home
):
    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_report",
        _yield_fixture_bom(gradle_project),
    )
    _trivy_sbom(monkeypatch, stdout='{"Results": []}')
    monkeypatch.setattr("maintenance_man.scanner.get_outdated", lambda project: [])
    secret_calls: list[Path] = []
    monkeypatch.setattr(
        "maintenance_man.scanner._run_trivy_secret_scan",
        lambda path, skip_dirs: (secret_calls.append(path), [])[1],
    )

    scan_project("android", gradle_project, 7)

    assert secret_calls == [Path(gradle_project.path)]


def test_gradle_inventory_cleanup_failure_preserves_previous_results(
    gradle_project, monkeypatch, mm_home
):
    results_file = mm_home / "scan-results" / "android.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    previous = b'{"previous": true}\n'
    results_file.write_bytes(previous)

    catalogue_digest = hashlib.sha256(
        (Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH).read_bytes()
    ).hexdigest()

    def _run(cmd, **kwargs):
        if cmd[1] == "mmGradleReport":
            owned = Path(gradle_project.path) / ".mm-gradle-inventory"
            (owned / "bom.json").write_bytes(
                (GRADLE_FIXTURES / "bom.json").read_bytes()
            )
            (owned / "report.json").write_text(
                json.dumps(_gradle_report_payload(catalogue_digest))
            )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout='{"Results": []}', stderr="")

    def _cannot_remove(*args, **kwargs):
        if not kwargs.get("ignore_errors"):
            raise PermissionError("cleanup denied")

    monkeypatch.setattr(subprocess, "run", _run)
    monkeypatch.setattr("maintenance_man.gradle.shutil.rmtree", _cannot_remove)
    monkeypatch.setattr("maintenance_man.scanner.get_outdated", lambda project: [])
    gradle_project = gradle_project.model_copy(update={"scan_secrets": False})
    with pytest.raises(GradleError, match="cleanup denied"):
        scan_project("android", gradle_project, 7)
    assert results_file.read_bytes() == previous


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
    from maintenance_man.scanner import TrivyScanError, _run_gradle_vuln_scan

    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_report",
        _yield_fixture_bom(gradle_project),
    )
    _trivy_sbom(monkeypatch, stdout=json.dumps(payload))
    with pytest.raises(TrivyScanError, match="Trivy"):
        _run_gradle_vuln_scan(gradle_project)
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
    from maintenance_man.scanner import TrivyScanError, _run_gradle_vuln_scan

    monkeypatch.setattr(
        "maintenance_man.scanner.generate_gradle_report",
        _yield_fixture_bom(gradle_project),
    )

    def run(*args, **kwargs):
        raise failure

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(TrivyScanError, match="Trivy"):
        _run_gradle_vuln_scan(gradle_project)
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
    from maintenance_man.scanner import TrivyScanError, _parse_gradle_trivy_output

    row = {
        "VulnerabilityID": "CVE-example",
        "PkgName": "org.example:library",
        "InstalledVersion": "1",
    }
    row[field] = value
    with pytest.raises(TrivyScanError, match=field):
        _parse_gradle_trivy_output(
            json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [row]}]})
        )


@pytest.mark.parametrize("field", ["VulnerabilityID", "PkgName", "InstalledVersion"])
def test_gradle_trivy_missing_required_vulnerability_field_is_scan_error(field):
    from maintenance_man.scanner import TrivyScanError, _parse_gradle_trivy_output

    row = {
        "VulnerabilityID": "CVE-example",
        "PkgName": "org.example:library",
        "InstalledVersion": "1",
    }
    del row[field]
    with pytest.raises(TrivyScanError, match=field):
        _parse_gradle_trivy_output(
            json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [row]}]})
        )


@pytest.mark.parametrize(
    "result",
    [
        {"Class": False},
        {"Class": "lang-pkgs", "Vulnerabilities": ""},
        {"Class": "lang-pkgs", "Vulnerabilities": {}},
        {"Class": "lang-pkgs", "Vulnerabilities": [None]},
    ],
)
def test_gradle_trivy_invalid_result_or_row_container_is_scan_error(result):
    from maintenance_man.scanner import TrivyScanError, _parse_gradle_trivy_output

    with pytest.raises(TrivyScanError):
        _parse_gradle_trivy_output(json.dumps({"Results": [result]}))


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"Results": []},
        {"Results": [{"Class": "lang-pkgs"}]},
        {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": None}]},
    ],
)
def test_gradle_trivy_absent_optional_or_null_vulnerabilities_is_clean(payload):
    from maintenance_man.scanner import _parse_gradle_trivy_output

    assert _parse_gradle_trivy_output(json.dumps(payload)) == []


def test_gradle_trivy_unknown_severity_and_bad_string_date_keep_existing_semantics():
    from maintenance_man.scanner import _parse_gradle_trivy_output

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


def test_gradle_incomplete_capture_preserves_saved_results(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from maintenance_man import scanner
    from maintenance_man.gradle import GradleError
    from maintenance_man.gradle_resolution import parse_resolution_report
    from maintenance_man.models.config import ProjectConfig

    source = Path(__file__).parent / "fixtures/gradle/resolution/empty.json"
    raw = json.loads(source.read_text())
    raw["scopes"][0]["unresolved"] = ["g:missing:1.0"]
    resolution = parse_resolution_report(json.dumps(raw))

    @contextmanager
    def capture(project):
        yield tmp_path / "bom.json", resolution

    monkeypatch.setattr(scanner, "generate_gradle_report", capture)
    monkeypatch.setattr(scanner._config, "MM_HOME", tmp_path / "mm")
    saved = tmp_path / "mm/scan-results/demo.json"
    saved.parent.mkdir(parents=True)
    saved.write_text("previous findings")
    with pytest.raises(GradleError, match="Incomplete"):
        scanner.scan_project(
            "demo", ProjectConfig(path=tmp_path, package_manager="gradle")
        )
    assert saved.read_text() == "previous findings"


@pytest.mark.parametrize(
    "variant",
    [
        "local",
        "unknown-path",
        "wrong-coordinate",
        "unqualified",
        "duplicate-path",
        "external-mismatch",
        "local-finding",
    ],
)
def test_gradle_scan_checks_local_project_provenance(
    gradle_project, monkeypatch, variant
):
    from maintenance_man import scanner
    from maintenance_man.gradle_resolution import parse_resolution_report

    payload = _gradle_report_payload()
    payload["local_projects"] = [
        {
            "project_path": ":",
            "module": {"group": "fixture", "artifact": "app", "version": "unspecified"},
        }
    ]
    purl = "pkg:maven/fixture/app@unspecified?project_path=%3A"
    if variant == "unknown-path":
        purl = "pkg:maven/fixture/app@unspecified?project_path=%3Aunknown"
    elif variant == "wrong-coordinate":
        purl = "pkg:maven/other/app@unspecified?project_path=%3A"
    elif variant == "unqualified":
        purl = "pkg:maven/fixture/app@unspecified"
    elif variant == "duplicate-path":
        purl += "&project_path=%3A"
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
            yield bom, parse_resolution_report(json.dumps(payload))
        finally:
            bom.unlink()

    monkeypatch.setattr(scanner, "generate_gradle_report", generate)
    if variant == "local-finding":
        _trivy_sbom(
            monkeypatch,
            stdout=json.dumps(
                {
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
            ),
        )
    else:
        _trivy_sbom(monkeypatch)
    if variant == "local":
        findings, _ = scanner._run_gradle_scan(gradle_project)
        assert findings
        assert all(f.gradle_scopes == (":/project/runtimeClasspath",) for f in findings)
    else:
        with pytest.raises(GradleError):
            scanner._run_gradle_scan(gradle_project)
