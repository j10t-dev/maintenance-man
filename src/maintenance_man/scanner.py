import contextlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, assert_never

from pydantic import (
    BaseModel,
    Field,
    JsonValue,
    StrictStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from maintenance_man import paths
from maintenance_man.clock import Clock, utc_now
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    filter_registry_updates_by_age,
)
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GradleError,
    discover_gradle_updates,
    parse_catalogue,
)
from maintenance_man.gradle_inventory import bind_inventory
from maintenance_man.gradle_resolution import (
    PreparedCandidate,
    generate_gradle_report,
    prepare_gradle_candidates,
    select_gradle_candidates,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    CandidateWithheld,
    CompleteResolution,
    IncompleteResolution,
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
    resolution = None
    with PublicationLookupContext(paths.publications_dir(), clock=clock) as publication:
        if project.package_manager == "gradle":
            vulns, updates, secrets, resolution = _scan_gradle_project(
                project, min_version_age_days, publication
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
                        project_path,
                        project.scan_skip_dirs,
                        scanners="vuln,secret" if project.scan_secrets else "vuln",
                    )
                case unreachable:
                    assert_never(unreachable)
            updates = _check_outdated(
                project, ops, vulns, min_version_age_days, publication
            )

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
    project: ProjectConfig,
    min_version_age_days: int,
    publication: PublicationLookupContext,
) -> tuple[
    list[VulnFinding], list[UpdateFinding], list[SecretFinding], CompleteResolution
]:
    vulns, resolution = scan_gradle(project)
    updates = discover_gradle_updates(project)
    vulns, updates = _prepare_gradle_scan_findings(
        project, vulns, resolution, updates, min_version_age_days, publication
    )
    secrets = (
        scan_secrets(Path(project.path), project.scan_skip_dirs)
        if project.scan_secrets
        else []
    )
    return vulns, updates, secrets, resolution


def _prepare_gradle_scan_findings(
    project: ProjectConfig,
    vulnerabilities: list[VulnFinding],
    resolution: CompleteResolution,
    proposals: list[UpdateFinding],
    minimum_age_days: int,
    publication: PublicationLookupContext,
) -> tuple[list[VulnFinding], list[UpdateFinding]]:
    """Save one vulnerability row per exact source/target association, and give
    every Gradle row either its prepared target or the reason it is blocked."""
    catalogue = parse_catalogue(project.path / GRADLE_CATALOGUE_RELPATH)
    plan = select_gradle_candidates(catalogue, resolution, vulnerabilities, proposals)
    prepared = prepare_gradle_candidates(
        project,
        plan.candidates,
        resolution,
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
        _prepared_update(update, prepared, plan.withheld, publication)
        for update in proposals
    ]
    return rows, updates


def _vulnerability_rows(
    index: int,
    finding: VulnFinding,
    prepared: tuple[PreparedCandidate, ...],
    withheld: tuple[CandidateWithheld, ...],
) -> Iterator[VulnFinding]:
    if finding.fixed_version is None:
        yield finding.model_copy(update={"blocked_reason": "no published fix"})
        return
    for item in prepared:
        if index in item.candidate.vulnerability_indices:
            yield finding.model_copy(
                update={
                    "gradle_target": item.candidate.target,
                    "blocked_reason": item.withheld_reason,
                }
            )
    for entry in withheld:
        if index in entry.vulnerability_indices:
            yield finding.model_copy(update={"blocked_reason": entry.reason})


def _prepared_update(
    update: UpdateFinding,
    prepared: tuple[PreparedCandidate, ...],
    withheld: tuple[CandidateWithheld, ...],
    publication: PublicationLookupContext,
) -> UpdateFinding:
    unsupported = "no supported catalogue target"
    if update.blocked_reason is not None:
        return update
    if update.gradle_target is None:
        return update.model_copy(update={"blocked_reason": unsupported})
    key = update.gradle_target.group_key
    for item in prepared:
        if item.candidate.target.group_key != key:
            continue
        changes: dict[str, object] = {
            "gradle_target": item.candidate.target,
            "blocked_reason": item.withheld_reason,
        }
        if item.withheld_reason is None:
            changes["published_date"] = max(
                publication.results[request.model_dump_json()].timestamp
                for request in item.candidate.publication_requests
            )
        return update.model_copy(update=changes)
    reason = next((entry.reason for entry in withheld if entry.group_key == key), None)
    return update.model_copy(update={"blocked_reason": reason or unsupported})


def _check_outdated(
    project: ProjectConfig,
    ops: PackageManagerOps,
    vulns: list[VulnFinding],
    min_version_age_days: int,
    publication: PublicationLookupContext,
) -> list[UpdateFinding]:
    """Run the table's outdated check and return aged, de-duplicated findings."""
    raw_updates = ops.outdated(project)
    vuln_pkgs = {v.pkg_name for v in vulns}
    eligible_updates = [u for u in raw_updates if u.pkg_name not in vuln_pkgs]
    return filter_registry_updates_by_age(
        eligible_updates,
        ops.publication_source,
        project.path,
        min_age_days=min_version_age_days,
        context=publication,
    )


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


def _parse_gradle_trivy_output(payload: str) -> list[VulnFinding]:
    """Parse consumed SBOM response fields and return vulnerability findings."""
    response = _parse_trivy_response(payload, "Trivy SBOM", consume_secrets=False)
    try:
        return _parse_vulns(response.results)
    except ValidationError as e:
        msg = f"Malformed Trivy SBOM vulnerability fields: {e}"
        raise ScanError(msg) from e


def _parse_trivy_response(
    payload: str, label: str, *, consume_secrets: bool
) -> _TrivyResponse:
    try:
        return _TrivyResponse.model_validate_json(
            payload, context={"consume_secrets": consume_secrets}
        )
    except ValidationError as e:
        msg = f"Malformed {label} output: {e}"
        raise ScanError(msg) from e


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


class _TrivyLanguageResult(BaseModel):
    class_: Literal["lang-pkgs"] = Field(alias="Class")
    vulnerabilities: list[_TrivyVulnerability] | None = Field(
        None, alias="Vulnerabilities"
    )


class _TrivyNonLanguageResult(BaseModel):
    class_: StrictStr = Field("", alias="Class")
    vulnerabilities: list[dict[str, JsonValue]] | None = Field(
        None, alias="Vulnerabilities"
    )
    target: StrictStr = Field("", alias="Target")
    secrets: list[_TrivySecret] | None = Field(None, alias="Secrets")

    @field_validator("class_")
    @classmethod
    def reject_language_class(cls, value: str) -> str:
        if value == "lang-pkgs":
            msg = "language package results must use the language result schema"
            raise ValueError(msg)
        return value

    @model_validator(mode="before")
    @classmethod
    def normalise_unconsumed_secret_fields(
        cls, value: object, info: ValidationInfo
    ) -> object:
        if not isinstance(value, dict):
            return value
        if (
            value.get("Class") == "secret"
            and info.context is not None
            and info.context["consume_secrets"]
        ):
            return value
        return {**value, "Target": "", "Secrets": None}


type _TrivyResult = _TrivyLanguageResult | _TrivyNonLanguageResult


class _TrivyResponse(BaseModel):
    results: list[_TrivyResult] = Field(default_factory=list, alias="Results")


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
    completed = run_captured(
        cmd,
        project_path,
        timeout=300,
        label="Trivy filesystem scan",
        error=ScanError,
    )

    response = _parse_trivy_response(
        completed.stdout, "Trivy", consume_secrets="secret" in scanners
    )
    try:
        return _parse_vulns(response.results), _parse_secrets(response.results)
    except ValidationError as e:
        msg = f"Malformed Trivy finding fields: {e}"
        raise ScanError(msg) from e


def _parse_vulns(results: list[_TrivyResult]) -> list[VulnFinding]:
    """Extract vulnerability findings from Trivy results."""
    findings: list[VulnFinding] = []
    for result in results:
        if not isinstance(result, _TrivyLanguageResult):
            continue
        for vulnerability in result.vulnerabilities or []:
            severity_raw = vulnerability.severity.upper()
            try:
                severity = Severity(severity_raw)
            except ValueError:
                severity = Severity.UNKNOWN

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


def _parse_secrets(results: list[_TrivyResult]) -> list[SecretFinding]:
    """Extract secret findings from Trivy results."""
    return [
        SecretFinding(
            file=result.target,
            rule_id=secret.rule_id,
            title=secret.title,
            severity=secret.severity,
        )
        for result in results
        if isinstance(result, _TrivyNonLanguageResult) and result.class_ == "secret"
        for secret in result.secrets or []
    ]
