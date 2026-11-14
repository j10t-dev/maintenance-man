import contextlib
import re
import subprocess
from collections.abc import Callable, Collection, Iterator
from datetime import datetime
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

from maintenance_man import paths
from maintenance_man.clock import Clock, utc_now
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    PublicationSource,
    filter_registry_updates_by_age,
)
from maintenance_man.fix_versions import select_package_fixes
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GradleError,
    discover_gradle_updates,
    parse_catalogue,
)
from maintenance_man.gradle_resolution import (
    generate_gradle_report,
    prepare_gradle_candidates,
    select_gradle_candidates,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    CandidateWithheld,
    GradleCandidate,
    ResolutionReport,
)
from maintenance_man.models.scan import (
    GradleBlock,
    ScanResult,
    SecretFinding,
    Severity,
    UpdateFinding,
    VulnFinding,
)
from maintenance_man.outdated import bun_outdated, mvn_outdated, uv_outdated
from maintenance_man.process import require_tool, run_captured
from maintenance_man.storage import save_scan_results

TRIVY_INSTALL_HINT = "Install it from https://trivy.dev/"


class ScanError(Exception):
    """Trivy and uv audit execution and response errors."""


def scan_project(
    name: str,
    project: ProjectConfig,
    min_version_age_days: int = 7,
    *,
    clock: Clock = utc_now,
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
    with PublicationLookupContext(paths.publications_dir(), clock=clock) as publication:
        match project.package_manager:
            case "gradle":
                vulns, report = scan_gradle(project)
                vulns, updates = _prepare_gradle_scan_findings(
                    project,
                    vulns,
                    report,
                    discover_gradle_updates(project),
                    min_version_age_days,
                    publication,
                )
                secrets = _requested_secrets(project)
            case "uv":
                vulns = _run_uv_audit(project_path)
                _select_fixes(vulns, project)
                secrets = _requested_secrets(project)
                updates = _check_outdated(
                    project, vulns, min_version_age_days, publication
                )
            case "bun" | "mvn":
                vulns, secrets = _run_trivy_scan(
                    project_path,
                    project.scan_skip_dirs,
                    scanners="vuln,secret" if project.scan_secrets else "vuln",
                )
                _select_fixes(vulns, project)
                updates = _check_outdated(
                    project, vulns, min_version_age_days, publication
                )

    scan_result = ScanResult(
        project=name,
        package_manager=project.package_manager,
        scanned_at=utc_now(),
        vulnerabilities=vulns,
        secrets=secrets,
        updates=updates,
    )
    save_scan_results(name, scan_result)
    return scan_result


def _requested_secrets(project: ProjectConfig) -> list[SecretFinding]:
    """Run the secrets scan only when the project asks for it."""
    if not project.scan_secrets:
        return []
    return scan_secrets(Path(project.path), project.scan_skip_dirs)


def _prepare_gradle_scan_findings(
    project: ProjectConfig,
    vulnerabilities: list[VulnFinding],
    report: ResolutionReport,
    proposals: list[UpdateFinding],
    minimum_age_days: int,
    publication: PublicationLookupContext,
) -> tuple[list[VulnFinding], list[UpdateFinding]]:
    """Save one vulnerability row per exact source/target association, and give
    every Gradle row either its prepared target or the reason it is blocked."""
    catalogue = parse_catalogue(project.path / GRADLE_CATALOGUE_RELPATH)
    plan = select_gradle_candidates(catalogue, report, vulnerabilities, proposals)
    prepared = prepare_gradle_candidates(
        project,
        plan.candidates,
        report,
        publication,
        minimum_age_days,
        clock=publication.clock,
    )
    rows = [
        row
        for index, finding in enumerate(vulnerabilities)
        for row in _vulnerability_rows(index, finding, prepared, plan.withheld)
    ]
    updates = [
        _prepared_update(update, prepared, plan.withheld) for update in proposals
    ]
    return rows, updates


def _vulnerability_rows(
    index: int,
    finding: VulnFinding,
    prepared: tuple[GradleCandidate, ...],
    withheld: tuple[CandidateWithheld, ...],
) -> Iterator[VulnFinding]:
    if finding.fixed_version is None:
        no_fix = GradleBlock(kind="mapping", reason="no published fix")
        yield finding.model_copy(update={"state": no_fix})
        return
    for candidate in prepared:
        if index in candidate.vulnerability_indices:
            yield finding.model_copy(
                update={
                    "gradle_target": candidate.target,
                    "state": candidate.block,
                }
            )
    for entry in withheld:
        if index in entry.vulnerability_indices:
            yield finding.model_copy(update={"state": entry.block})


def _prepared_update(
    update: UpdateFinding,
    prepared: tuple[GradleCandidate, ...],
    withheld: tuple[CandidateWithheld, ...],
) -> UpdateFinding:
    unsupported = GradleBlock(kind="mapping", reason="no supported catalogue target")
    if isinstance(update.state, GradleBlock):
        return update
    if update.gradle_target is None:
        return update.model_copy(update={"state": unsupported})
    key = update.gradle_target.group_key
    for candidate in prepared:
        if candidate.target.group_key == key:
            return update.model_copy(
                update={
                    "gradle_target": candidate.target,
                    "state": candidate.block,
                    "published_date": candidate.published_date,
                }
            )
    block = next((entry.block for entry in withheld if entry.group_key == key), None)
    return update.model_copy(update={"state": block or unsupported})


def _check_outdated(
    project: ProjectConfig,
    vulns: list[VulnFinding],
    min_version_age_days: int,
    publication: PublicationLookupContext,
) -> list[UpdateFinding]:
    """Run the manager's outdated check and return aged, de-duplicated findings."""
    outdated, source = _OUTDATED[project.package_manager]
    vuln_pkgs = {v.pkg_name for v in vulns if v.actionable}
    eligible_updates = [u for u in outdated(project) if u.pkg_name not in vuln_pkgs]
    return filter_registry_updates_by_age(
        eligible_updates,
        source,
        project.path,
        min_age_days=min_version_age_days,
        context=publication,
    )


def _select_fixes(vulns: list[VulnFinding], project: ProjectConfig) -> None:
    """Rewrite each advisory's fix to its package's target, or to none."""
    by_package: dict[str, list[VulnFinding]] = {}
    for vuln in vulns:
        by_package.setdefault(vuln.pkg_name, []).append(vuln)
    for group in by_package.values():
        fixes: list[str | None] = [None] * len(group)
        if len({vuln.installed_version for vuln in group}) == 1:
            fixes = select_package_fixes(
                group[0].installed_version,
                [vuln.fixed_version for vuln in group],
                project.package_manager,
            )
        for vuln, fix in zip(group, fixes, strict=True):
            vuln.fixed_version = fix


_OUTDATED: dict[
    str, tuple[Callable[[ProjectConfig], list[UpdateFinding]], PublicationSource]
] = {
    "uv": (uv_outdated, "pypi"),
    "bun": (bun_outdated, "npm"),
    "mvn": (mvn_outdated, "central"),
}


def scan_gradle(
    project: ProjectConfig,
) -> tuple[list[VulnFinding], ResolutionReport]:
    """Scan the project's own freshly captured resolution and inventory."""
    require_tool("trivy", TRIVY_INSTALL_HINT)
    with generate_gradle_report(project) as generated:
        cmd = [
            "trivy",
            "sbom",
            "--format",
            "json",
            "--scanners",
            "vuln",
            str(generated.bom_path),
        ]
        completed = _run_scan_command(cmd, project.path, "Trivy SBOM scan")
        findings = _parse_trivy(completed.stdout, "Trivy SBOM", secrets=False)[0]
        scoped = {
            (module.coordinate, module.version): {
                f"{scope.project_path}/{scope.domain}/{scope.configuration}"
                for scope in scopes
            }
            for module, scopes in generated.scopes.items()
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
        return findings, generated.report


def _run_scan_command(
    command: list[str],
    cwd: Path,
    label: str,
    *,
    ok_codes: Collection[int] = frozenset({0}),
) -> subprocess.CompletedProcess[str]:
    """Run a scan tool with the scan timeout, raising ScanError on failure."""
    return run_captured(
        command, cwd, timeout=300, label=label, error=ScanError, ok_codes=ok_codes
    )


_NonEmptyString = Annotated[str, Field(strict=True, min_length=1)]


class _TrivyVulnerability(BaseModel):
    vulnerability_id: _NonEmptyString = Field(alias="VulnerabilityID")
    pkg_name: _NonEmptyString = Field(alias="PkgName")
    installed_version: _NonEmptyString = Field(alias="InstalledVersion")
    severity: StrictStr = Field("UNKNOWN", alias="Severity")
    title: StrictStr = Field("", alias="Title")
    description: StrictStr = Field("", alias="Description")
    status: StrictStr = Field("unknown", alias="Status")
    fixed_version: StrictStr | None = Field(None, alias="FixedVersion")
    primary_url: StrictStr | None = Field(None, alias="PrimaryURL")
    published_date: StrictStr | None = Field(None, alias="PublishedDate")


class _TrivySecret(BaseModel):
    rule_id: StrictStr = Field("", alias="RuleID")
    title: StrictStr = Field("", alias="Title")
    severity: Severity = Field(Severity.UNKNOWN, alias="Severity")


class _TrivyResult(BaseModel):
    """One result's class; its other fields are validated only when consumed."""

    model_config = ConfigDict(extra="allow")
    class_: StrictStr = Field("", alias="Class")


class _TrivyLanguageResult(BaseModel):
    vulnerabilities: list[_TrivyVulnerability] | None = Field(
        None, alias="Vulnerabilities"
    )


class _TrivySecretResult(BaseModel):
    target: StrictStr = Field("", alias="Target")
    secrets: list[_TrivySecret] | None = Field(None, alias="Secrets")


class _TrivyResponse(BaseModel):
    results: list[_TrivyResult] = Field(default_factory=list, alias="Results")


def _run_uv_audit(project_path: Path) -> list[VulnFinding]:
    """Run uv's native lockfile-based audit against a project."""
    completed = _run_scan_command(
        ["uv", "audit", "--locked", "--color", "never"],
        project_path,
        "uv audit --locked",
        ok_codes={0, 1},
    )
    return _parse_uv_audit_vulns(completed.stdout)


def _parse_uv_audit_vulns(output: str) -> list[VulnFinding]:
    """Parse uv audit's human-readable vulnerability output.

    Each package header declares its advisory count. A package whose parsed
    advisories differ from that count raises ``ScanError`` instead of
    returning a partial list.
    """
    findings: list[VulnFinding] = []
    package: tuple[str, str] | None = None
    declared = parsed = 0
    current: VulnFinding | None = None

    for line in output.splitlines():
        if match := _UV_AUDIT_PACKAGE_RE.match(line):
            if package is not None:
                _check_declared(package[0], declared, parsed)
            package = (match.group("pkg"), match.group("version"))
            declared, parsed = int(match.group("count")), 0
            current = None
        elif (match := _UV_AUDIT_VULN_RE.match(line)) and package is not None:
            current = VulnFinding(
                vuln_id=match.group("id"),
                pkg_name=package[0],
                installed_version=package[1],
                severity=Severity.UNKNOWN,
                title=match.group("title"),
                description=match.group("title"),
                status="affected",
            )
            findings.append(current)
            parsed += 1
        elif current is None:
            continue
        elif match := _UV_AUDIT_FIXED_RE.match(line):
            current.fixed_version = match.group("versions")
        elif match := _UV_AUDIT_URL_RE.match(line):
            current.primary_url = match.group("url")
    if package is not None:
        _check_declared(package[0], declared, parsed)
    return findings


def _check_declared(package: str, declared: int, parsed: int) -> None:
    if declared != parsed:
        msg = f"uv audit: {package} declares {declared} advisories, parsed {parsed}"
        raise ScanError(msg)


_UV_AUDIT_PACKAGE_RE = re.compile(
    r"^(?P<pkg>\S+)\s+(?P<version>\S+)\s+has\s+(?P<count>\d+)\s+known "
    r"vulnerabilit(?:y|ies):$"
)
_UV_AUDIT_VULN_RE = re.compile(r"^-\s+(?P<id>[A-Z]+-[^:]+):\s+(?P<title>.+)$")
_UV_AUDIT_FIXED_RE = re.compile(r"^\s+Fixed in:\s+(?P<versions>\S+(?:,\s+\S+)*)\s*$")
_UV_AUDIT_URL_RE = re.compile(r"^\s+Advisory information:\s+(?P<url>\S+)\s*$")


def scan_secrets(
    project_path: Path,
    skip_dirs: list[str] | None = None,
) -> list[SecretFinding]:
    """Run Trivy secrets-only scan against *project_path*."""
    _, secrets = _run_trivy_scan(project_path, skip_dirs, scanners="secret")
    return secrets


def _run_trivy_scan(
    project_path: Path,
    skip_dirs: list[str] | None = None,
    *,
    scanners: str,
) -> tuple[list[VulnFinding], list[SecretFinding]]:
    """Run Trivy against *project_path* and return parsed findings."""
    require_tool("trivy", TRIVY_INSTALL_HINT)
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
    completed = _run_scan_command(cmd, project_path, "Trivy filesystem scan")
    return _parse_trivy(completed.stdout, "Trivy", secrets="secret" in scanners)


def _parse_trivy(
    payload: str, label: str, *, secrets: bool
) -> tuple[list[VulnFinding], list[SecretFinding]]:
    """Parse the consumed Trivy result classes; malformed ones are a ScanError."""
    try:
        results = _TrivyResponse.model_validate_json(payload).results
        vulns = _parse_vulns(_consumed(results, "lang-pkgs", _TrivyLanguageResult))
        found = (
            _parse_secrets(_consumed(results, "secret", _TrivySecretResult))
            if secrets
            else []
        )
    except ValidationError as e:
        msg = f"Malformed {label} output: {e}"
        raise ScanError(msg) from e
    return vulns, found


def _consumed[M: BaseModel](
    results: list[_TrivyResult], class_: str, model: type[M]
) -> list[M]:
    return [
        model.model_validate(result.model_extra or {})
        for result in results
        if result.class_ == class_
    ]


def _parse_vulns(results: list[_TrivyLanguageResult]) -> list[VulnFinding]:
    """Extract vulnerability findings from Trivy results."""
    findings: list[VulnFinding] = []
    for result in results:
        for vulnerability in result.vulnerabilities or []:
            raw = vulnerability.severity.upper()
            severity = Severity(raw) if raw in Severity else Severity.UNKNOWN

            published = None
            if vulnerability.published_date:
                with contextlib.suppress(ValueError):
                    published = datetime.fromisoformat(vulnerability.published_date)

            findings.append(
                VulnFinding(
                    vuln_id=vulnerability.vulnerability_id,
                    pkg_name=vulnerability.pkg_name,
                    installed_version=vulnerability.installed_version,
                    fixed_version=vulnerability.fixed_version,
                    severity=severity,
                    title=vulnerability.title,
                    description=vulnerability.description,
                    status=vulnerability.status,
                    primary_url=vulnerability.primary_url,
                    published_date=published,
                )
            )
    return findings


def _parse_secrets(results: list[_TrivySecretResult]) -> list[SecretFinding]:
    """Extract secret findings from Trivy results."""
    return [
        SecretFinding(
            file=result.target,
            rule_id=secret.rule_id,
            title=secret.title,
            severity=secret.severity,
        )
        for result in results
        for secret in result.secrets or []
    ]
