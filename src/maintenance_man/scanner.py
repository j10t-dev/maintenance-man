import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from maintenance_man.config import MM_HOME
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


def check_trivy_available() -> None:
    """Raise TrivyNotFoundError if trivy is not on PATH."""
    if shutil.which("trivy") is None:
        raise TrivyNotFoundError(
            "Trivy is not installed or not on PATH. Install it from https://trivy.dev/"
        )


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
    findings: list[SecretFinding] = []
    for result in results:
        if result.get("Class") != "secret":
            continue
        target = result.get("Target", "")
        for s in result.get("Secrets") or []:
            findings.append(
                SecretFinding(
                    file=target,
                    rule_id=s.get("RuleID", ""),
                    title=s.get("Title", ""),
                    severity=s.get("Severity", "UNKNOWN"),
                )
            )
    return findings


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

    # --- Trivy scan (existing) ---
    scanners = "vuln,secret" if project.scan_secrets else "vuln"
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
    except subprocess.TimeoutExpired:
        raise TrivyScanError(f"Trivy timed out scanning {project_path}")

    if completed.returncode != 0:
        raise TrivyScanError(
            f"Trivy exited with code {completed.returncode}: {completed.stderr.strip()}"
        )

    try:
        trivy_output = json.loads(completed.stdout)
    except json.JSONDecodeError as e:
        raise TrivyScanError(f"Failed to parse Trivy output: {e}") from e
    results = trivy_output.get("Results", [])

    vulns = _parse_vulns(results)
    secrets = _parse_secrets(results)

    # --- Outdated check (new) ---
    updates: list[UpdateFinding] = []
    try:
        raw_updates = get_outdated(project)
        aged_updates = filter_by_age(
            raw_updates,
            manager=project.package_manager,
            min_age_days=min_version_age_days,
        )
        # Dedup: drop updates for packages already flagged as vulns
        vuln_pkgs = {v.pkg_name for v in vulns}
        updates = [u for u in aged_updates if u.pkg_name not in vuln_pkgs]
    except Exception:
        # Outdated check failure is non-fatal — Trivy results still reported
        logging.getLogger(__name__).warning(
            "Outdated check failed for %s — skipping update results", name,
            exc_info=True,
        )

    scan_result = ScanResult(
        project=name,
        scanned_at=datetime.now(timezone.utc),
        trivy_target=str(project_path),
        vulnerabilities=vulns,
        secrets=secrets,
        updates=updates,
    )

    # Write results to disk — sanitise name to prevent path traversal
    results_dir = MM_HOME / "scan-results"
    results_dir.mkdir(parents=True, exist_ok=True)
    safe_name = name.replace("/", "_").replace("\\", "_").replace("..", "_")
    results_file = results_dir / f"{safe_name}.json"
    if not results_file.resolve().is_relative_to(results_dir.resolve()):
        raise ValueError(f"Invalid project name for results file: {name!r}")
    results_file.write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")

    return scan_result
