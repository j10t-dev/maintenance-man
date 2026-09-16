import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeGuard

from pydantic import ValidationError

from maintenance_man import config as _config
from maintenance_man import sanitise_project_name
from maintenance_man.dependency_age import evaluate_gradle_group_age, filter_by_age
from maintenance_man.gradle import (
    generate_gradle_inventory,
    resolve_gradle_vulnerability_target,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    GradleBlock,
    ScanResult,
    SecretFinding,
    Severity,
    UpdateFinding,
    VulnFinding,
)
from maintenance_man.outdated import get_outdated


class TrivyNotFoundError(Exception):
    pass


class TrivyScanError(Exception):
    pass


def scan_project(
    name: str,
    project: ProjectConfig,
    min_version_age_days: int = 7,
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

    if project.package_manager == "uv":
        vulns = _run_uv_audit(project_path)
        secrets = (
            _run_trivy_secret_scan(project_path, project.scan_skip_dirs)
            if project.scan_secrets
            else []
        )
    elif project.package_manager == "gradle":
        vulns = _run_gradle_vuln_scan(project)
        _map_gradle_vulns(project, vulns, min_version_age_days)
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
    )

    results_dir = _config.MM_HOME / "scan-results"
    results_dir.mkdir(parents=True, exist_ok=True)
    safe_name = sanitise_project_name(name)
    results_file = results_dir / f"{safe_name}.json"
    if not results_file.resolve().is_relative_to(results_dir.resolve()):
        raise ValueError(f"Invalid project name for results file: {name!r}")
    results_file.write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")

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
    """Run outdated checks and return de-duplicated update findings."""
    if project.package_manager == "gradle":
        return _check_gradle_outdated(project, min_version_age_days)

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


def _check_gradle_outdated(
    project: ProjectConfig, min_version_age_days: int
) -> list[UpdateFinding]:
    """Discover Gradle catalogue updates and record their age eligibility.

    Blocked candidates are retained with their reason rather than filtered out,
    and discovery failures propagate: for Gradle a broken check is an explicit
    scan error, never a silently empty update list.  Package-name suppression
    against vulnerability findings does not apply — Gradle targets are catalogue
    groups, not packages.
    """
    findings = get_outdated(project)
    for finding in findings:
        if finding.blocked_reason is not None:
            continue
        if finding.gradle_target is None:
            # No target attached and no reason set: this combination should
            # not occur, but treat it as blocked rather than as eligible with
            # zero publication evidence.
            finding.blocked_reason = (
                f"{finding.pkg_name} {finding.latest_version} has no catalogue "
                f"target; rescan to refresh this finding"
            )
            finding.gradle_block_kind = "age"
            continue
        block, published = evaluate_gradle_group_age(
            finding.gradle_target, min_version_age_days
        )
        finding.published_date = published
        if block is not None:
            finding.blocked_reason = block.reason
            finding.gradle_block_kind = block.kind
    return findings


def _run_gradle_vuln_scan(project: ProjectConfig) -> list[VulnFinding]:
    """Scan the project's own freshly generated CycloneDX inventory."""
    with generate_gradle_inventory(project) as bom:
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
        return _parse_gradle_trivy_output(completed.stdout)


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


def _map_gradle_vulns(
    project: ProjectConfig, vulns: list[VulnFinding], min_version_age_days: int
) -> None:
    """Attach a catalogue target or a blocking reason to each advisory in place.

    Findings that cannot be mapped to a safe target are preserved and blocked,
    never discarded.
    """
    for vuln in vulns:
        outcome = resolve_gradle_vulnerability_target(project, vuln)
        if isinstance(outcome, GradleBlock):
            vuln.blocked_reason = outcome.reason
            vuln.gradle_block_kind = outcome.kind
            continue
        vuln.gradle_target = outcome
        block, published = evaluate_gradle_group_age(outcome, min_version_age_days)
        vuln.published_date = vuln.published_date or published
        if block is not None:
            vuln.blocked_reason = block.reason
            vuln.gradle_block_kind = block.kind


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
