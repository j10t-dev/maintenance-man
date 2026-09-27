import contextlib
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeGuard
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import ValidationError

from maintenance_man import paths
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    filter_by_age,
    filter_gradle_updates_by_age,
)
from maintenance_man.gradle import (
    GradleError,
)
from maintenance_man.gradle_resolution import (
    generate_gradle_report,
)
from maintenance_man.gradle_verification import TRIVY_INSTALL_HINT, context_inputs_valid
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    ComparisonContext,
    CompleteResolution,
    FindingEvidence,
    FindingKey,
    GradleSnapshot,
    IncompleteResolution,
    ModuleId,
    ResolutionReport,
    ScopeId,
)
from maintenance_man.models.scan import (
    ScanResult,
    SecretFinding,
    Severity,
    UpdateFinding,
    VulnFinding,
)
from maintenance_man.outdated import get_outdated
from maintenance_man.process import require_tool, run_captured
from maintenance_man.storage import save_scan_results
from maintenance_man.vcs import revision_tree_id


class ScanError(Exception):
    """Trivy and uv audit execution and response errors."""


def scan_project(
    name: str, project: ProjectConfig, min_version_age_days: int = 7
) -> ScanResult:
    """Run Trivy and outdated checks against a project and return parsed results.

    Also writes the results JSON to ~/.mm/scan-results/<name>.json.

    Raises:
        ScanError: If trivy exits with non-zero status.
        FileNotFoundError: If the project path does not exist.
    """
    project_path = Path(project.path)
    if not project_path.exists():
        raise FileNotFoundError(f"Project path does not exist: {project_path}")
    resolution = None
    if project.package_manager == "uv":
        vulns = _run_uv_audit(project_path)
        secrets = (
            _run_trivy_secret_scan(project_path, project.scan_skip_dirs)
            if project.scan_secrets
            else []
        )
        updates = _check_outdated(project, vulns, min_version_age_days)
    elif project.package_manager == "gradle":
        vulns, resolution = _run_gradle_scan(project)
        updates = get_outdated(project)
        with PublicationLookupContext(paths.gradle_publications_dir()) as context:
            updates = filter_gradle_updates_by_age(
                updates, project, resolution, min_version_age_days, context
            )
        secrets = (
            _run_trivy_secret_scan(project_path, project.scan_skip_dirs)
            if project.scan_secrets
            else []
        )
    else:
        vulns, secrets = _run_trivy_scan(
            project_path, project.scan_secrets, project.scan_skip_dirs
        )
        updates = _check_outdated(project, vulns, min_version_age_days)

    scan_result = ScanResult(
        project=name,
        scanned_at=datetime.now(UTC),
        trivy_target=str(project_path),
        vulnerabilities=vulns,
        secrets=secrets,
        updates=updates,
        gradle_resolution=(
            resolution.report.model_dump(mode="json")
            if resolution is not None
            else None
        ),
    )
    save_scan_results(name, paths.scan_results_dir(), scan_result)
    return scan_result


def _check_outdated(
    project: ProjectConfig,
    vulns: list[VulnFinding],
    min_version_age_days: int,
) -> list[UpdateFinding]:
    """Run non-Gradle outdated checks and return de-duplicated findings."""
    raw_updates = get_outdated(project)
    aged_updates = filter_by_age(
        raw_updates,
        manager=project.package_manager,
        min_age_days=min_version_age_days,
        project_path=project.path,
    )
    vuln_pkgs = {v.pkg_name for v in vulns}
    return [u for u in aged_updates if u.pkg_name not in vuln_pkgs]


def _run_gradle_scan(
    project: ProjectConfig,
) -> tuple[list[VulnFinding], CompleteResolution]:
    """Scan the project's own freshly captured resolution and inventory."""
    require_tool("trivy", TRIVY_INSTALL_HINT)
    with generate_gradle_report(project) as (bom, outcome):
        if isinstance(outcome, IncompleteResolution):
            raise GradleError(
                "Incomplete Gradle resolution: " + "; ".join(outcome.reasons)
            )
        modules = _inventory_modules(_read_inventory(bom), outcome.report)
        module_scopes = _resolution_module_scopes(outcome.report)
        coverage_errors = _inventory_coverage_errors(modules, module_scopes)
        if coverage_errors:
            raise GradleError(
                "Incomplete Gradle inventory: " + "; ".join(coverage_errors)
            )
        cmd = ["trivy", "sbom", "--format", "json", "--scanners", "vuln", str(bom)]
        completed = run_captured(
            cmd,
            project.path,
            timeout=300,
            label="Trivy SBOM scan",
            error=ScanError,
        )
        findings = _parse_gradle_trivy_output(completed.stdout)
        scoped = {
            (module.coordinate, module.version): {
                f"{scope.project_path}/{scope.domain}/{scope.configuration}"
                for scope in scopes
            }
            for module, scopes in module_scopes.items()
        }
        for finding in findings:
            scopes = scoped.get((finding.pkg_name, finding.installed_version))
            if not scopes:
                raise GradleError(
                    f"Security finding has no selected resolution scope: "
                    f"{finding.pkg_name}"
                )
            finding.gradle_scopes = tuple(sorted(scopes))
        return findings, outcome


def _is_trivy_object(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _parse_gradle_trivy_output(payload: str) -> list[VulnFinding]:
    """Validate consumed SBOM response fields before using the common parser."""
    try:
        output: object = json.loads(payload)
    except json.JSONDecodeError as e:
        raise ScanError(f"Failed to parse Trivy SBOM output: {e}") from e
    if not _is_trivy_object(output):
        raise ScanError("Malformed Trivy SBOM output: expected an object")
    results = output.get("Results", [])
    if not isinstance(results, list):
        raise ScanError("Malformed Trivy SBOM Results: expected an array")
    validated_results: list[dict[str, object]] = []
    for index, result in enumerate(results):
        label = f"Trivy SBOM Results[{index}]"
        if not _is_trivy_object(result):
            raise ScanError(f"Malformed {label}: expected an object")
        validated_results.append(result)
        if "Class" in result and not isinstance(result["Class"], str):
            raise ScanError(f"Malformed {label}.Class: expected a string")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise ScanError(f"Malformed {label}.Vulnerabilities: expected an array")
        for row_index, row in enumerate(vulnerabilities):
            row_label = f"{label}.Vulnerabilities[{row_index}]"
            if not _is_trivy_object(row):
                raise ScanError(f"Malformed {row_label}: expected an object")
            if result.get("Class") != "lang-pkgs":
                continue
            for field in ("VulnerabilityID", "PkgName", "InstalledVersion"):
                if not isinstance(row.get(field), str) or not row[field]:
                    raise ScanError(
                        f"Malformed {row_label}.{field}: expected a nonempty string"
                    )
            for field in ("Severity", "Title", "Description", "Status"):
                if field in row and not isinstance(row[field], str):
                    raise ScanError(f"Malformed {row_label}.{field}: expected a string")
            for field in ("FixedVersion", "PrimaryURL", "PublishedDate"):
                if (
                    field in row
                    and row[field] is not None
                    and not isinstance(row[field], str)
                ):
                    raise ScanError(
                        f"Malformed {row_label}.{field}: expected a string or null"
                    )
    try:
        return _parse_vulns(validated_results)
    except ValidationError as e:
        raise ScanError(f"Malformed Trivy SBOM vulnerability fields: {e}") from e


def _run_uv_audit(project_path: Path) -> list[VulnFinding]:
    """Run uv's native lockfile-based audit against a project."""
    cmd = ["uv", "audit", "--locked"]
    completed = run_captured(
        cmd,
        project_path,
        timeout=300,
        label="uv audit --locked",
        error=ScanError,
        ok_codes={0, 1},
    )

    return _parse_uv_audit_vulns(completed.stdout)


@dataclass(frozen=True)
class _UvAuditPackage:
    name: str
    version: str


@dataclass
class _UvAuditAdvisory:
    vuln_id: str
    title: str
    fixed_version: str | None = None
    url: str | None = None


def _parse_uv_audit_vulns(output: str) -> list[VulnFinding]:
    """Parse uv audit's human-readable vulnerability output."""
    findings: list[VulnFinding] = []
    package: _UvAuditPackage | None = None
    advisory: _UvAuditAdvisory | None = None

    for line in output.splitlines():
        if match := _UV_AUDIT_PACKAGE_RE.match(line):
            _append_uv_audit_finding(findings, package, advisory)
            package = _UvAuditPackage(match.group("pkg"), match.group("version"))
            advisory = None
            continue

        if match := _UV_AUDIT_VULN_RE.match(line):
            _append_uv_audit_finding(findings, package, advisory)
            advisory = _UvAuditAdvisory(match.group("id"), match.group("title"))
            continue

        if advisory is None:
            continue

        if match := _UV_AUDIT_FIXED_RE.match(line):
            advisory.fixed_version = match.group("version")
        elif match := _UV_AUDIT_URL_RE.match(line):
            advisory.url = match.group("url")

    _append_uv_audit_finding(findings, package, advisory)
    return findings


def _append_uv_audit_finding(
    findings: list[VulnFinding],
    package: _UvAuditPackage | None,
    advisory: _UvAuditAdvisory | None,
) -> None:
    if package is None or advisory is None:
        return

    findings.append(
        VulnFinding(
            vuln_id=advisory.vuln_id,
            pkg_name=package.name,
            installed_version=package.version,
            fixed_version=advisory.fixed_version,
            severity=Severity.UNKNOWN,
            title=advisory.title or "No summary provided",
            description=advisory.title or "",
            status="affected",
            primary_url=advisory.url,
        )
    )


_UV_AUDIT_PACKAGE_RE = re.compile(
    r"^(?P<pkg>\S+)\s+(?P<version>\S+)\s+has\s+\d+\s+known vulnerabilit(?:y|ies):$"
)
_UV_AUDIT_VULN_RE = re.compile(
    r"^-\s+(?P<id>(?:GHSA|CVE|PYSEC)-[^:]+):\s+(?P<title>.+)$"
)
_UV_AUDIT_FIXED_RE = re.compile(r"^\s+Fixed in:\s+(?P<version>\S+)\s*$")
_UV_AUDIT_URL_RE = re.compile(r"^\s+Advisory information:\s+(?P<url>\S+)\s*$")


def _run_trivy_secret_scan(
    project_path: Path,
    skip_dirs: list[str] | None = None,
) -> list[SecretFinding]:
    """Run Trivy secrets-only scan against *project_path*."""
    _, secrets = _run_trivy_scan(
        project_path, scan_secrets=True, skip_dirs=skip_dirs, scanners="secret"
    )
    return secrets


def _run_trivy_scan(
    project_path: Path,
    scan_secrets: bool,
    skip_dirs: list[str] | None = None,
    scanners: str | None = None,
) -> tuple[list[VulnFinding], list[SecretFinding]]:
    """Run Trivy against *project_path* and return parsed findings."""
    require_tool("trivy", TRIVY_INSTALL_HINT)
    scanners = scanners or ("vuln,secret" if scan_secrets else "vuln")
    cmd = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--scanners",
        scanners,
    ]
    for d in skip_dirs or []:
        cmd.extend(["--skip-dirs", d])
    cmd.append(".")
    completed = run_captured(
        cmd,
        project_path,
        timeout=300,
        label="Trivy filesystem scan",
        error=ScanError,
    )

    try:
        trivy_output = json.loads(completed.stdout)
    except json.JSONDecodeError as e:
        raise ScanError(f"Failed to parse Trivy output: {e}") from e

    results = trivy_output.get("Results", [])
    return _parse_vulns(results), _parse_secrets(results)


def _parse_vulns(results: list[dict]) -> list[VulnFinding]:
    """Extract vulnerability findings from Trivy results."""
    findings: list[VulnFinding] = []
    for result in results:
        if result.get("Class") != "lang-pkgs":
            continue
        for v in result.get("Vulnerabilities") or []:
            severity_raw = v.get("Severity", "UNKNOWN").upper()
            try:
                severity = Severity(severity_raw)
            except ValueError:
                severity = Severity.UNKNOWN

            published = None
            if v.get("PublishedDate"):
                with contextlib.suppress(ValueError):
                    published = datetime.fromisoformat(v["PublishedDate"])

            findings.append(
                VulnFinding(
                    vuln_id=v["VulnerabilityID"],
                    pkg_name=v["PkgName"],
                    installed_version=v["InstalledVersion"],
                    fixed_version=v.get("FixedVersion"),
                    severity=severity,
                    title=v.get("Title", ""),
                    description=v.get("Description", ""),
                    status=v.get("Status", "unknown"),
                    primary_url=v.get("PrimaryURL"),
                    published_date=published,
                )
            )
    return findings


def _parse_secrets(results: list[dict]) -> list[SecretFinding]:
    """Extract secret findings from Trivy results."""
    return [
        SecretFinding(
            file=result.get("Target", ""),
            rule_id=s.get("RuleID", ""),
            title=s.get("Title", ""),
            severity=s.get("Severity", "UNKNOWN"),
        )
        for result in results
        if result.get("Class") == "secret"
        for s in result.get("Secrets") or []
    ]


def _inventory_modules(
    payload: bytes, report: ResolutionReport
) -> tuple[ModuleId, ...]:
    try:
        document = json.loads(payload)
        if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
            raise ValueError("expected CycloneDX object")
        found: set[ModuleId] = set()
        local_projects = {
            project.project_path: project.module for project in report.local_projects
        }

        def visit(rows):
            if not isinstance(rows, list):
                raise ValueError("components must be an array")
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError("component must be an object")
                purl = row.get("purl", "")
                if not isinstance(purl, str):
                    raise ValueError("component purl must be a string")
                if purl.startswith("pkg:maven/"):
                    identity = (
                        purl.removeprefix("pkg:maven/")
                        .split("?", 1)[0]
                        .split("#", 1)[0]
                    )
                    coordinate, separator, version = identity.rpartition("@")
                    group, slash, artifact = coordinate.partition("/")
                    if (
                        not separator
                        or not slash
                        or not group
                        or not artifact
                        or not version
                    ):
                        raise ValueError("malformed Maven purl")
                    module = ModuleId(
                        group=unquote(group),
                        artifact=unquote(artifact),
                        version=unquote(version),
                    )
                    qualifiers = parse_qs(urlsplit(purl).query, keep_blank_values=True)
                    if "project_path" in qualifiers:
                        paths = qualifiers["project_path"]
                        if len(paths) != 1 or local_projects.get(paths[0]) != module:
                            raise ValueError("unverified local project identity")
                    else:
                        found.add(module)
                elif row.get("type") == "library" and not purl:
                    raise ValueError("library component has no package identity")
                visit(row.get("components", []))

        visit(document.get("components", []))
        return tuple(
            sorted(
                found,
                key=lambda module: (module.group, module.artifact, module.version),
            )
        )
    except (ValueError, TypeError, ValidationError) as exc:
        raise GradleError(f"Malformed CycloneDX inventory: {exc}") from exc


def _resolution_module_scopes(report: ResolutionReport) -> dict[ModuleId, set[ScopeId]]:
    scopes: dict[ModuleId, set[ScopeId]] = {}
    for result in report.scopes:
        for component in result.components:
            if component.module is not None:
                scopes.setdefault(component.module, set()).add(result.scope)
    return scopes


def _inventory_coverage_errors(
    modules: tuple[ModuleId, ...], scopes: dict[ModuleId, set[ScopeId]]
) -> tuple[str, ...]:
    inventory = set(modules)
    return tuple(
        f"Inventory module has no selected resolution identity: {module}"
        for module in modules
        if module not in scopes
    ) + tuple(
        f"resolved module missing from inventory: {module}"
        for module in scopes
        if module not in inventory
    )


def _read_inventory(bom: Path) -> bytes:
    try:
        return bom.read_bytes()
    except OSError as exc:
        raise GradleError(f"Could not capture Gradle resolution: {exc}") from exc


def capture_gradle_snapshot(
    project: ProjectConfig, context: ComparisonContext
) -> GradleSnapshot | IncompleteResolution:
    if not context_inputs_valid(context, project, datetime.now(UTC)):
        raise GradleError(
            "Comparison context expired or inputs changed; rebuild baseline and tip"
        )
    with generate_gradle_report(project) as (bom, resolution):
        if isinstance(resolution, IncompleteResolution):
            return resolution
        report = resolution.report
        if (
            set(report.selected_scopes) != set(context.selected_scopes)
            or report.producer_versions != context.producer_versions
        ):
            return IncompleteResolution(
                report=report, reasons=("selected scopes or producer versions changed",)
            )
        inventory = _read_inventory(bom)
        modules = _inventory_modules(inventory, report)
        scopes = _resolution_module_scopes(report)
        coverage_errors = _inventory_coverage_errors(modules, scopes)
        if coverage_errors:
            return IncompleteResolution(
                report=report,
                reasons=coverage_errors,
            )
        binary = next(
            key.removeprefix("binary:")
            for key in context.loaded_input_digests
            if key.startswith("binary:")
        )
        trivy_started = time.monotonic()
        completed = run_captured(
            [binary, *context.scanner_flags, str(bom)],
            project.path,
            timeout=300,
            label="Trivy snapshot",
            error=ScanError,
        )
        logging.getLogger(__name__).info(
            "Gradle Trivy snapshot %.3fs", time.monotonic() - trivy_started
        )
        rows = _parse_gradle_trivy_output(completed.stdout)
        grouped: dict[FindingKey, list[VulnFinding]] = {}
        for row in rows:
            group, separator, artifact = row.pkg_name.partition(":")
            module = ModuleId(
                group=group, artifact=artifact, version=row.installed_version
            )
            if not separator or module not in scopes or module not in modules:
                return IncompleteResolution(
                    report=report,
                    reasons=(
                        f"finding has no exact inventory/graph scope: "
                        f"{row.pkg_name} {row.installed_version}",
                    ),
                )
            for scope in scopes[module]:
                key = FindingKey(
                    advisory_id=row.vuln_id, coordinate=row.pkg_name, scope=scope
                )
                grouped.setdefault(key, []).append(row)
        findings = tuple(
            FindingEvidence(
                key=key,
                affected_versions=frozenset(row.installed_version for row in evidence),
                severity=max(
                    (row.severity for row in evidence),
                    key=lambda severity: severity.rank,
                ),
                has_unknown=any(row.severity == Severity.UNKNOWN for row in evidence),
                rows=tuple(evidence),
            )
            for key, evidence in sorted(
                grouped.items(),
                key=lambda item: (
                    item[0].advisory_id,
                    item[0].coordinate,
                    item[0].scope.project_path,
                    item[0].scope.domain,
                    item[0].scope.configuration,
                ),
            )
        )
    # Generated report/BOM cleanup must precede the jj source-tree snapshot.
    if not context_inputs_valid(context, project, datetime.now(UTC)):
        raise GradleError("Comparison inputs changed during capture")
    return GradleSnapshot(
        tree_id=revision_tree_id(Path(project.path)),
        resolution=resolution,
        context_identity=context.identity,
        findings=findings,
        inventory_digest=hashlib.sha256(inventory).hexdigest(),
        inventory_modules=modules,
    )
