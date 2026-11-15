from maintenance_man import output
from maintenance_man.clock import utc_now
from maintenance_man.models.scan import (
    GradleBlock,
    ScanResult,
    SecretFinding,
    UpdateFinding,
    VulnFinding,
    sort_vulns_by_severity,
)


def print_scan_result(result: ScanResult, elapsed_s: float | None = None) -> None:
    found = [
        *map(_vulnerability_row, sort_vulns_by_severity(result.vulnerabilities)),
        *map(_secret_row, result.secrets),
        *map(_update_row, result.updates),
    ]
    if not found:
        return
    rows, pipe_rows = zip(*found, strict=True)
    output.heading(result.project, f"{len(rows)} findings")
    headers = ["kind", "severity", "versions", "package / detail"]
    visible = (
        [0, 1, 2, 3]
        if output.console().width >= output.NARROW_TERMINAL_WIDTH
        else [0, 3]
    )
    output.records(
        result.project,
        [headers[index] for index in visible],
        [[row[index] for index in visible] for row in rows],
        pipe_rows=pipe_rows,
        footer="hidden: severity, versions · pipe for full records"
        if len(visible) < len(headers)
        else "",
    )
    if elapsed_s is not None:
        output.notice(f"Scanned {result.project} in {elapsed_s:.1f}s")


type _FindingRow = tuple[list[output.Cell], list[str]]


def _vulnerability_row(vuln: VulnFinding) -> _FindingRow:
    kind = "vuln" if vuln.actionable else "advisory"
    blocked = isinstance(vuln.state, GradleBlock)
    reason = vuln.state.reason if blocked else ""
    versions = (
        f"{vuln.installed_version} → {vuln.fixed_version}"
        if vuln.fixed_version
        else "no fix"
    )
    row = [
        output.literal(
            "! blocked" if blocked else f"! {kind}",
            "yellow" if kind == "advisory" or blocked else "red",
        ),
        vuln.severity.value.lower(),
        versions,
        " · ".join(filter(None, [vuln.pkg_name, vuln.vuln_id, reason])),
    ]
    pipe_row = [
        kind,
        vuln.pkg_name,
        vuln.installed_version,
        vuln.fixed_version or "-",
        vuln.severity.value,
        vuln.vuln_id,
        vuln.published_date.isoformat() if vuln.published_date else "-",
        "blocked" if blocked else vuln.status,
        reason or "-",
    ]
    return row, pipe_row


def _secret_row(secret: SecretFinding) -> _FindingRow:
    row = [
        output.literal("! secret", "yellow"),
        secret.severity.value.lower(),
        "-",
        f"{secret.file} · {secret.title}",
    ]
    pipe_row = [
        "secret",
        secret.file,
        "-",
        "-",
        secret.severity.value,
        secret.rule_id,
        "-",
        "found",
        secret.title,
    ]
    return row, pipe_row


def _update_row(update: UpdateFinding) -> _FindingRow:
    blocked = isinstance(update.state, GradleBlock)
    reason = update.state.reason if blocked else ""
    age = (
        f"{(utc_now() - update.published_date).days}d old"
        if update.published_date
        else ""
    )
    row = [
        output.literal(
            "! blocked" if blocked else "~ update", "yellow" if blocked else ""
        ),
        update.semver_tier.value,
        f"{update.installed_version} → {update.latest_version}",
        " · ".join(filter(None, [update.pkg_name, age, reason])),
    ]
    pipe_row = [
        "update",
        update.pkg_name,
        update.installed_version,
        update.latest_version,
        update.semver_tier.value,
        "-",
        update.published_date.isoformat() if update.published_date else "-",
        "blocked" if blocked else "available",
        reason or "-",
    ]
    return row, pipe_row


def print_blocked_findings(result: ScanResult, flow: str) -> None:
    """Piped update and resolve runs record each blocked package once."""
    for finding in result.blocked_findings:
        if not isinstance(finding.state, GradleBlock):
            continue
        target = (
            finding.latest_version
            if isinstance(finding, UpdateFinding)
            else finding.fixed_version or "-"
        )
        output.outcome(
            result.project,
            flow,
            "blocked",
            finding.pkg_name,
            installed=finding.installed_version,
            target=target,
            reason=finding.state.reason,
        )
