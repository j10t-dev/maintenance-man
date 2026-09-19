import hashlib
import json
import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeGuard
from urllib.parse import unquote

from pydantic import ValidationError

from maintenance_man import config as _config
from maintenance_man import sanitise_project_name
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    evaluate_gradle_candidate_age,
    filter_by_age,
)
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GradleError,
    parse_catalogue,
)
from maintenance_man.gradle_resolution import (
    attach_gradle_publications,
    generate_gradle_report,
    gradle_routing_prerequisite,
    select_gradle_candidates,
    validate_gradle_candidates,
)
from maintenance_man.gradle_verification import context_inputs_valid
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    CandidateWithheld,
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
from maintenance_man.outdated import get_outdated
from maintenance_man.vcs import revision_tree_id


class TrivyNotFoundError(Exception):
    pass


class TrivyScanError(Exception):
    pass


def scan_project(
    name: str, project: ProjectConfig, min_version_age_days: int = 7
) -> ScanResult:
    """Run Trivy and outdated checks against a project and return parsed results.

    Also writes the results JSON to ~/.mm/scan-results/<name>.json.

    Raises:
        TrivyScanError: If trivy exits with non-zero status.
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
        updates = _check_outdated(name, project, vulns, min_version_age_days)
    elif project.package_manager == "gradle":
        vulns, resolution = _run_gradle_scan(project)
        updates = get_outdated(project)
        catalogue = parse_catalogue(project_path / GRADLE_CATALOGUE_RELPATH)
        plan = select_gradle_candidates(catalogue, resolution, vulns, updates)
        routing_block = gradle_routing_prerequisite(project)
        blocks = {
            block.group_key: block.reason
            for block in plan.withheld
            if block.group_key is not None
        }
        eligible = {}
        prepared_candidates = []
        with PublicationLookupContext(_config.MM_HOME / "publication-cache") as context:
            if routing_block is not None:
                for candidate in plan.candidates:
                    blocks[candidate.target.group_key] = routing_block.reason
            else:
                batch = validate_gradle_candidates(project, plan.candidates)
                for candidate in plan.candidates:
                    key = candidate.target.group_key
                    prepared = attach_gradle_publications(candidate, resolution, batch)
                    if isinstance(prepared, CandidateWithheld):
                        blocks[key] = prepared.reason
                        continue
                    prepared_candidates.append(prepared)
            context.prefetch(
                request
                for candidate in prepared_candidates
                for request in candidate.publication_requests
            )
            for prepared in prepared_candidates:
                key = prepared.target.group_key
                block = evaluate_gradle_candidate_age(
                    prepared, min_version_age_days, context, datetime.now(timezone.utc)
                )
                if block is not None:
                    blocks[key] = block.reason
                eligible[key] = prepared
        for update in updates:
            if update.gradle_target is None:
                update.blocked_reason = (
                    update.blocked_reason or "no supported catalogue target"
                )
                update.gradle_block_kind = "mapping"
                continue
            key = update.gradle_target.group_key
            if key in blocks:
                update.blocked_reason = blocks[key]
                update.gradle_block_kind = (
                    "age"
                    if key in eligible
                    or (
                        routing_block is not None
                        and any(
                            candidate.target.group_key == key
                            for candidate in plan.candidates
                        )
                    )
                    else "mapping"
                )
            elif key in eligible:
                update.blocked_reason = None
                update.gradle_block_kind = None
        for finding in vulns:
            matches = [
                candidate
                for candidate in plan.candidates
                if finding.vuln_id in candidate.requested_advisories
                and finding.pkg_name in candidate.requested_coordinates
            ]
            if len(matches) == 1:
                candidate = matches[0]
                key = candidate.target.group_key
                finding.gradle_target = candidate.target
                finding.blocked_reason = blocks.get(key)
                if finding.blocked_reason is None:
                    finding.gradle_block_kind = None
                else:
                    finding.gradle_block_kind = (
                        "age"
                        if key in eligible
                        or (
                            routing_block is not None
                            and any(
                                other.target.group_key == key
                                for other in plan.candidates
                            )
                        )
                        else "mapping"
                    )
            else:
                reasons = [
                    block.reason
                    for block in plan.withheld
                    if finding.vuln_id in block.advisory_ids
                    and finding.pkg_name == block.coordinate
                ]
                if reasons:
                    finding.blocked_reason = "; ".join(dict.fromkeys(reasons))
                    finding.gradle_block_kind = "mapping"
        secrets = (
            _run_trivy_secret_scan(project_path, project.scan_skip_dirs)
            if project.scan_secrets
            else []
        )
    else:
        vulns, secrets = _run_trivy_scan(
            project_path, project.scan_secrets, project.scan_skip_dirs
        )
        updates = _check_outdated(name, project, vulns, min_version_age_days)

    scan_result = ScanResult(
        project=name,
        scanned_at=datetime.now(timezone.utc),
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
    results_dir = _config.MM_HOME / "scan-results"
    results_dir.mkdir(parents=True, exist_ok=True)
    safe_name = sanitise_project_name(name)
    results_file = results_dir / f"{safe_name}.json"
    if not results_file.resolve().is_relative_to(results_dir.resolve()):
        raise ValueError(f"Invalid project name for results file: {name!r}")
    temporary = results_file.with_suffix(".json.tmp")
    temporary.write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(results_file)
    return scan_result


def check_trivy_available() -> None:
    """Raise TrivyNotFoundError if trivy is not on PATH."""
    if shutil.which("trivy") is None:
        raise TrivyNotFoundError(
            "Trivy is not installed or not on PATH. Install it from https://trivy.dev/"
        )


def _check_outdated(
    name: str,
    project: ProjectConfig,
    vulns: list[VulnFinding],
    min_version_age_days: int,
) -> list[UpdateFinding]:
    """Run non-Gradle outdated checks and return de-duplicated findings."""
    try:
        raw_updates = get_outdated(project)
        aged_updates = filter_by_age(
            raw_updates,
            manager=project.package_manager,
            min_age_days=min_version_age_days,
            project_path=project.path,
        )
        vuln_pkgs = {v.pkg_name for v in vulns}
        return [u for u in aged_updates if u.pkg_name not in vuln_pkgs]
    except Exception:
        logging.getLogger(__name__).warning(
            "Outdated check failed for %s — skipping update results",
            name,
            exc_info=True,
        )
        return []


def _run_gradle_scan(
    project: ProjectConfig,
) -> tuple[list[VulnFinding], CompleteResolution]:
    """Scan the project's own freshly captured resolution and inventory."""
    with generate_gradle_report(project) as (bom, outcome):
        if isinstance(outcome, IncompleteResolution):
            raise GradleError(
                "Incomplete Gradle resolution: " + "; ".join(outcome.reasons)
            )
        cmd = ["trivy", "sbom", "--format", "json", "--scanners", "vuln", str(bom)]
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=project.path,
                timeout=300,
            )
        except subprocess.TimeoutExpired as e:
            raise TrivyScanError(f"Trivy timed out scanning {bom}") from e
        except (OSError, UnicodeDecodeError) as e:
            raise TrivyScanError(f"Could not run Trivy SBOM scan of {bom}: {e}") from e

        if completed.returncode != 0:
            raise TrivyScanError(
                f"Trivy exited with code {completed.returncode}: "
                f"{completed.stderr.strip()}"
            )
        findings = _parse_gradle_trivy_output(completed.stdout)
        scoped: dict[tuple[str, str], set[str]] = {}
        for scope in outcome.report.scopes:
            for component in scope.components:
                if component.module is not None:
                    module = component.module
                    scoped.setdefault((module.coordinate, module.version), set()).add(
                        f"{scope.scope.project_path}/{scope.scope.domain}/"
                        f"{scope.scope.configuration}"
                    )
        inventory = json.loads(bom.read_text())
        for component in inventory["components"]:
            if not str(component.get("purl", "")).startswith("pkg:maven/"):
                continue
            key = (
                f"{component.get('group', '')}:{component.get('name', '')}",
                component.get("version"),
            )
            if key not in scoped:
                raise GradleError(
                    f"Inventory module has no selected resolution identity: {key}"
                )
        for finding in findings:
            scopes = scoped.get((finding.pkg_name, finding.installed_version))
            if not scopes:
                raise GradleError(
                    f"Security finding has no selected resolution scope: "
                    f"{finding.pkg_name}"
                )
            finding.gradle_scopes = tuple(sorted(scopes))
        return findings, outcome


def _run_gradle_vuln_scan(project: ProjectConfig) -> list[VulnFinding]:
    findings, _ = _run_gradle_scan(project)
    return findings


def _is_trivy_object(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _parse_gradle_trivy_output(payload: str) -> list[VulnFinding]:
    """Validate consumed SBOM response fields before using the common parser."""
    try:
        output: object = json.loads(payload)
    except json.JSONDecodeError as e:
        raise TrivyScanError(f"Failed to parse Trivy SBOM output: {e}") from e
    if not _is_trivy_object(output):
        raise TrivyScanError("Malformed Trivy SBOM output: expected an object")
    results = output.get("Results", [])
    if not isinstance(results, list):
        raise TrivyScanError("Malformed Trivy SBOM Results: expected an array")
    validated_results: list[dict[str, object]] = []
    for index, result in enumerate(results):
        label = f"Trivy SBOM Results[{index}]"
        if not _is_trivy_object(result):
            raise TrivyScanError(f"Malformed {label}: expected an object")
        validated_results.append(result)
        if "Class" in result and not isinstance(result["Class"], str):
            raise TrivyScanError(f"Malformed {label}.Class: expected a string")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise TrivyScanError(
                f"Malformed {label}.Vulnerabilities: expected an array"
            )
        for row_index, row in enumerate(vulnerabilities):
            row_label = f"{label}.Vulnerabilities[{row_index}]"
            if not _is_trivy_object(row):
                raise TrivyScanError(f"Malformed {row_label}: expected an object")
            if result.get("Class") != "lang-pkgs":
                continue
            for field in ("VulnerabilityID", "PkgName", "InstalledVersion"):
                if not isinstance(row.get(field), str) or not row[field]:
                    raise TrivyScanError(
                        f"Malformed {row_label}.{field}: expected a nonempty string"
                    )
            for field in ("Severity", "Title", "Description", "Status"):
                if field in row and not isinstance(row[field], str):
                    raise TrivyScanError(
                        f"Malformed {row_label}.{field}: expected a string"
                    )
            for field in ("FixedVersion", "PrimaryURL", "PublishedDate"):
                if (
                    field in row
                    and row[field] is not None
                    and not isinstance(row[field], str)
                ):
                    raise TrivyScanError(
                        f"Malformed {row_label}.{field}: expected a string or null"
                    )
    try:
        return _parse_vulns(validated_results)
    except ValidationError as e:
        raise TrivyScanError(f"Malformed Trivy SBOM vulnerability fields: {e}") from e


def _run_uv_audit(project_path: Path) -> list[VulnFinding]:
    """Run uv's native lockfile-based audit against a project."""
    cmd = ["uv", "audit", "--locked"]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=project_path,
            timeout=300,
        )
    except subprocess.TimeoutExpired as e:
        raise TrivyScanError(f"uv audit timed out scanning {project_path}") from e

    if completed.returncode not in {0, 1}:
        raise TrivyScanError(
            f"uv audit exited with code {completed.returncode}: "
            f"{completed.stderr.strip()}"
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
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=project_path,
            timeout=300,
        )
    except subprocess.TimeoutExpired as e:
        raise TrivyScanError(f"Trivy timed out scanning {project_path}") from e

    if completed.returncode != 0:
        raise TrivyScanError(
            f"Trivy exited with code {completed.returncode}: {completed.stderr.strip()}"
        )

    try:
        trivy_output = json.loads(completed.stdout)
    except json.JSONDecodeError as e:
        raise TrivyScanError(f"Failed to parse Trivy output: {e}") from e

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
                try:
                    published = datetime.fromisoformat(v["PublishedDate"])
                except ValueError:
                    pass

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


def _inventory_modules(payload: bytes) -> tuple[ModuleId, ...]:
    try:
        document = json.loads(payload)
        if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
            raise ValueError("expected CycloneDX object")
        found: set[ModuleId] = set()

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
                    found.add(
                        ModuleId(
                            group=unquote(group),
                            artifact=unquote(artifact),
                            version=unquote(version),
                        )
                    )
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


def capture_gradle_snapshot(
    project: ProjectConfig, context: ComparisonContext
) -> GradleSnapshot | IncompleteResolution:
    if not context_inputs_valid(context, project, datetime.now(timezone.utc)):
        raise TrivyScanError(
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
        inventory = bom.read_bytes()
        modules = _inventory_modules(inventory)
        scopes: dict[ModuleId, set] = {}
        for result in report.scopes:
            for component in result.components:
                if component.module is not None:
                    scopes.setdefault(component.module, set()).add(result.scope)
        missing = [module for module in modules if module not in scopes]
        omitted = [module for module in scopes if module not in modules]
        if missing or omitted:
            return IncompleteResolution(
                report=report,
                reasons=tuple(
                    f"inventory module has no graph match: {module}"
                    for module in missing
                )
                + tuple(
                    f"resolved module missing from inventory: {module}"
                    for module in omitted
                ),
            )
        binary = next(
            key.removeprefix("binary:")
            for key in context.loaded_input_digests
            if key.startswith("binary:")
        )
        trivy_started = time.monotonic()
        try:
            completed = subprocess.run(
                [binary, *context.scanner_flags, str(bom)],
                cwd=project.path,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired) as exc:
            raise TrivyScanError(f"Trivy snapshot failed: {exc}") from exc
        if completed.returncode != 0:
            raise TrivyScanError(f"Trivy snapshot failed: {completed.stderr.strip()}")
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
        rank = {
            Severity.UNKNOWN: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        findings = tuple(
            FindingEvidence(
                key=key,
                affected_versions=frozenset(row.installed_version for row in evidence),
                severity=max((row.severity for row in evidence), key=rank.__getitem__),
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
    if not context_inputs_valid(context, project, datetime.now(timezone.utc)):
        raise TrivyScanError("Comparison inputs changed during capture")
    return GradleSnapshot(
        tree_id=revision_tree_id(Path(project.path)),
        resolution=resolution,
        context_identity=context.identity,
        findings=findings,
        inventory_digest=hashlib.sha256(inventory).hexdigest(),
        inventory_modules=modules,
    )
