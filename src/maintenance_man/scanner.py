import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from maintenance_man import config as _config, sanitise_project_name
from maintenance_man.dependency_age import filter_by_age
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    UpdateFinding,
    ScanResult,
    SecretFinding,
    Severity,
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

    vulns, secrets = _run_trivy_scan(project_path, project.scan_secrets)
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
            "Outdated check failed for %s — skipping update results", name,
            exc_info=True,
        )
        return []


def _run_trivy_scan(
    project_path: Path, scan_secrets: bool,
) -> tuple[list[VulnFinding], list[SecretFinding]]:
    """Run Trivy against *project_path* and return parsed vulnerability and secret findings."""
    scanners = "vuln,secret" if scan_secrets else "vuln"
    cmd = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--scanners",
        scanners,
        ".",
    ]
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
