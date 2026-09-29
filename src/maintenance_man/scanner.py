import contextlib
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeGuard, assert_never

from pydantic import ValidationError

from maintenance_man import paths
from maintenance_man.clock import Clock, utc_now
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    filter_by_age,
    filter_gradle_updates_by_age,
)
from maintenance_man.gradle import (
    GradleError,
    discover_gradle_updates,
)
from maintenance_man.gradle_inventory import bind_inventory
from maintenance_man.gradle_resolution import generate_gradle_report
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
)
from maintenance_man.models.scan import (
    ScanResult,
    SecretFinding,
    Severity,
    UpdateFinding,
    VulnFinding,
)
from maintenance_man.package_managers import PackageManagerOps, package_manager_ops
from maintenance_man.process import require_tool, run_captured
from maintenance_man.storage import save_scan_results
from maintenance_man.vcs_workflow import VcsServices, make_vcs_services


class ScanError(Exception):
    """Trivy and uv audit execution and response errors."""


def scan_project(
    name: str,
    project: ProjectConfig,
    min_version_age_days: int = 7,
    *,
    vcs: VcsServices | None = None,
) -> ScanResult:
    """Run Trivy and outdated checks against a project and return parsed results.

    Also writes the results JSON to ~/.mm/scan-results/<name>.json.

    Raises:
        ScanError: If trivy exits with non-zero status.
        FileNotFoundError: If the project path does not exist.
    """
    project_path = Path(project.path)
    if not project_path.exists():
        msg = f"Project path does not exist: {project_path}"
        raise FileNotFoundError(msg)
    resolution = None
    if project.package_manager == "gradle":
        vulns, updates, secrets, resolution = _scan_gradle_project(
            project, min_version_age_days
        )
    else:
        ops = package_manager_ops(project.package_manager)
        match ops.vulnerability_source:
            case "uv-audit":
                vulns = _run_uv_audit(project_path)
                secrets = (
                    scan_secrets(project_path, project.scan_skip_dirs)
                    if project.scan_secrets
                    else []
                )
            case "trivy":
                vulns, secrets = _run_trivy_scan(
                    project_path, project.scan_secrets, project.scan_skip_dirs
                )
            case unreachable:
                assert_never(unreachable)
        updates = _check_outdated(project, ops, vulns, min_version_age_days)

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
    save_scan_results(name, scan_result)
    return scan_result


def _scan_gradle_project(
    project: ProjectConfig, min_version_age_days: int
) -> tuple[
    list[VulnFinding], list[UpdateFinding], list[SecretFinding], CompleteResolution
]:
    vulns, resolution = scan_gradle(project)
    updates = discover_gradle_updates(project)
    with PublicationLookupContext(paths.gradle_publications_dir()) as context:
        updates = filter_gradle_updates_by_age(
            updates, project, resolution, min_version_age_days, context
        )
    secrets = (
        scan_secrets(Path(project.path), project.scan_skip_dirs)
        if project.scan_secrets
        else []
    )
    return vulns, updates, secrets, resolution


def _check_outdated(
    project: ProjectConfig,
    ops: PackageManagerOps,
    vulns: list[VulnFinding],
    min_version_age_days: int,
) -> list[UpdateFinding]:
    """Run the table's outdated check and return aged, de-duplicated findings."""
    raw_updates = ops.outdated(project)
    aged_updates = filter_by_age(
        raw_updates,
        lambda pkg, version: ops.publish_date(pkg, version, project.path),
        min_age_days=min_version_age_days,
    )
    vuln_pkgs = {v.pkg_name for v in vulns}
    return [u for u in aged_updates if u.pkg_name not in vuln_pkgs]


def scan_gradle(
    project: ProjectConfig,
) -> tuple[list[VulnFinding], CompleteResolution]:
    """Scan the project's own freshly captured resolution and inventory."""
    require_tool("trivy", TRIVY_INSTALL_HINT)
    with generate_gradle_report(project) as generated:
        outcome = generated.resolution
        if isinstance(outcome, IncompleteResolution):
            raise GradleError(
                "Incomplete Gradle resolution: " + "; ".join(outcome.reasons)
            )
        coverage = bind_inventory(generated.inventory, outcome.report)
        if coverage.errors:
            raise GradleError(
                "Incomplete Gradle inventory: " + "; ".join(coverage.errors)
            )
        bom = generated.bom_path
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
            for module, scopes in coverage.scopes.items()
        }
        for finding in findings:
            scopes = scoped.get((finding.pkg_name, finding.installed_version))
            if not scopes:
                msg = (
                    f"Security finding has no selected resolution scope: "
                    f"{finding.pkg_name}"
                )
                raise GradleError(msg)
            finding.gradle_scopes = tuple(sorted(scopes))
        return findings, outcome


def _is_trivy_object(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _validate_gradle_trivy_vulnerability(
    row: object, label: str, *, consumed: bool
) -> None:
    if not _is_trivy_object(row):
        msg = f"Malformed {label}: expected an object"
        raise ScanError(msg)
    if not consumed:
        return
    for field in ("VulnerabilityID", "PkgName", "InstalledVersion"):
        if not isinstance(row.get(field), str) or not row[field]:
            msg = f"Malformed {label}.{field}: expected a nonempty string"
            raise ScanError(msg)
    for field in ("Severity", "Title", "Description", "Status"):
        if field in row and not isinstance(row[field], str):
            msg = f"Malformed {label}.{field}: expected a string"
            raise ScanError(msg)
    for field in ("FixedVersion", "PrimaryURL", "PublishedDate"):
        if field in row and row[field] is not None and not isinstance(row[field], str):
            msg = f"Malformed {label}.{field}: expected a string or null"
            raise ScanError(msg)


def _validate_gradle_trivy_result(result: object, index: int) -> dict[str, object]:
    label = f"Trivy SBOM Results[{index}]"
    if not _is_trivy_object(result):
        msg = f"Malformed {label}: expected an object"
        raise ScanError(msg)
    if "Class" in result and not isinstance(result["Class"], str):
        msg = f"Malformed {label}.Class: expected a string"
        raise ScanError(msg)
    vulnerabilities = result.get("Vulnerabilities")
    if vulnerabilities is None:
        return result
    if not isinstance(vulnerabilities, list):
        msg = f"Malformed {label}.Vulnerabilities: expected an array"
        raise ScanError(msg)
    for row_index, row in enumerate(vulnerabilities):
        _validate_gradle_trivy_vulnerability(
            row,
            f"{label}.Vulnerabilities[{row_index}]",
            consumed=result.get("Class") == "lang-pkgs",
        )
    return result


def _parse_gradle_trivy_output(payload: str) -> list[VulnFinding]:
    """Validate consumed SBOM response fields before using the common parser."""
    try:
        output: object = json.loads(payload)
    except json.JSONDecodeError as e:
        msg = f"Failed to parse Trivy SBOM output: {e}"
        raise ScanError(msg) from e
    if not _is_trivy_object(output):
        msg = "Malformed Trivy SBOM output: expected an object"
        raise ScanError(msg)
    results = output.get("Results", [])
    if not isinstance(results, list):
        msg = "Malformed Trivy SBOM Results: expected an array"
        raise ScanError(msg)
    validated_results = [
        _validate_gradle_trivy_result(result, index)
        for index, result in enumerate(results)
    ]
    try:
        return _parse_vulns(validated_results)
    except ValidationError as e:
        msg = f"Malformed Trivy SBOM vulnerability fields: {e}"
        raise ScanError(msg) from e


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


def scan_secrets(
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
        msg = f"Failed to parse Trivy output: {e}"
        raise ScanError(msg) from e

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


def capture_gradle_snapshot(
    project: ProjectConfig,
    context: ComparisonContext,
    *,
    vcs: VcsServices | None = None,
    clock: Clock = utc_now,
) -> GradleSnapshot | IncompleteResolution:
    services = vcs or make_vcs_services()
    if not context_inputs_valid(context, project, clock()):
        msg = "Comparison context expired or inputs changed; rebuild baseline and tip"
        raise GradleError(msg)
    with generate_gradle_report(project) as generated:
        resolution = generated.resolution
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
        coverage = bind_inventory(generated.inventory, report)
        if coverage.errors:
            return IncompleteResolution(report=report, reasons=coverage.errors)
        modules, scopes = coverage.modules, coverage.scopes
        inventory = generated.inventory_bytes
        bom = generated.bom_path
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
    if not context_inputs_valid(context, project, clock()):
        msg = "Comparison inputs changed during capture"
        raise GradleError(msg)
    return GradleSnapshot(
        tree_id=services.repository(Path(project.path)).tree_id(),
        resolution=resolution,
        context_identity=context.identity,
        findings=findings,
        inventory_digest=hashlib.sha256(inventory).hexdigest(),
        inventory_modules=modules,
    )
