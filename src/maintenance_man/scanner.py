import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from maintenance_man.config import MM_HOME
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import ScanResult, SecretFinding, Severity, VulnFinding


class TrivyNotFoundError(Exception):
    pass


class TrivyScanError(Exception):
    pass


def check_trivy_available() -> None:
    """Raise TrivyNotFoundError if trivy is not on PATH."""
    if shutil.which("trivy") is None:
        raise TrivyNotFoundError(
            "Trivy is not installed or not on PATH. "
            "Install it from https://trivy.dev/"
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


def scan_project(name: str, project: ProjectConfig) -> ScanResult:
    """Run Trivy against a project and return parsed results.

    Also writes the results JSON to ~/.mm/scan-results/<name>.json.

    Raises:
        TrivyScanError: If trivy exits with non-zero status.
        FileNotFoundError: If the project path does not exist.
    """
    project_path = Path(project.path)
    if not project_path.exists():
        raise FileNotFoundError(f"Project path does not exist: {project_path}")

    scanners = "vuln,secret" if project.scan_secrets else "vuln"
    cmd = [
        "trivy", "fs", "--format", "json",
        "--scanners", scanners, ".",
    ]
    completed = subprocess.run(
        cmd, capture_output=True, text=True, cwd=project_path,
    )

    if completed.returncode != 0:
        raise TrivyScanError(
            f"Trivy exited with code {completed.returncode}: {completed.stderr.strip()}"
        )

    trivy_output = json.loads(completed.stdout)
    results = trivy_output.get("Results", [])

    vulns = _parse_vulns(results)
    secrets = _parse_secrets(results)

    scan_result = ScanResult(
        project=name,
        scanned_at=datetime.now(timezone.utc),
        trivy_target=str(project_path),
        vulnerabilities=vulns,
        secrets=secrets,
    )

    # Write results to disk
    results_dir = MM_HOME / "scan-results"
    results_dir.mkdir(parents=True, exist_ok=True)
    results_file = results_dir / f"{name}.json"
    results_file.write_text(scan_result.model_dump_json(indent=2))

    return scan_result
