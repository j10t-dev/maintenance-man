# Vulnerability Scanning — Design Document

**Backlog item:** #3 — Scan (vulnerability scanning)
**Branch:** `feat/vuln-scanning`
**Depends on:** Config system (completed)

## Overview

`mm scan [project]` shells out to Trivy, parses the JSON output into internal models, writes results to disk, and prints a Rich summary. This task covers CVE detection only — dependency outdated checks are task #4.

## Trivy Integration

**Invocation:** `trivy fs --format json --scanners vuln,secret <project_path>`

- No severity filtering at the Trivy level — fetch everything, filter/classify in our code
- Parse the JSON `Results` array (handle missing `Results` key — known Trivy quirk when clean)
- Process `Class: lang-pkgs` results as vulnerability findings
- Process `Class: secret` results as secret advisories
- Ignore other result classes

**Error handling:**
- Trivy not installed → clear error message, exit 1
- Trivy exits non-zero → capture stderr, report, exit 1
- Project path doesn't exist → caught before Trivy invocation via existing `resolve_project`

## Finding Models

### VulnFinding

| Field | Type | Notes |
|---|---|---|
| `vuln_id` | str | CVE ID |
| `pkg_name` | str | |
| `installed_version` | str | |
| `fixed_version` | str \| None | None = advisory/unfixable |
| `severity` | enum | CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN |
| `title` | str | |
| `description` | str | |
| `status` | str | Trivy's status: fixed, affected, etc. |
| `primary_url` | str \| None | Link to advisory |
| `published_date` | datetime \| None | |

### SecretFinding

| Field | Type | Notes |
|---|---|---|
| `file` | str | Path within project |
| `rule_id` | str | Trivy's secret rule ID |
| `title` | str | |
| `severity` | str | |

### ScanResult (top-level envelope)

| Field | Type | Notes |
|---|---|---|
| `project` | str | Project name |
| `scanned_at` | datetime | |
| `trivy_target` | str | Path that was scanned |
| `vulnerabilities` | list[VulnFinding] | |
| `secrets` | list[SecretFinding] | |

One finding per CVE — stored as Trivy gives it. Grouping by package is a display concern.

## Scan Results Storage

- Written to `~/.mm/scan-results/<project>.json`
- Each scan overwrites the previous file entirely — no state preservation
- Scan results are a snapshot of current reality; if a vuln is fixed, the next scan won't find it

## CLI Behaviour

### `mm scan <project>`

1. Load config, resolve project
2. Check Trivy is available on PATH
3. Run Trivy
4. Parse output into finding models
5. Write ScanResult JSON to `~/.mm/scan-results/<project>.json`
6. Print Rich summary
7. Exit 0 (clean) or 2 (actionable vulns found)

### `mm scan` (no args)

- Iterate all configured projects, scan each
- Print per-project summaries
- Exit code: worst case wins (2 if any project has vulns, else 0)

### Display

Grouped by project, then by category:
- Actionable vulns (has `fixed_version`) listed first
- Advisories (no fix available) visually distinct — informational, alerting user to research mitigation
- Secrets shown at the end

Advisory and secret findings are informational only — they don't contribute to exit code 2.

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Clean, no actionable vulnerabilities |
| 1 | Error (Trivy missing, bad config, etc.) |
| 2 | Actionable vulnerabilities found |

Additional exit codes (e.g. for outdated deps) will be added in task #4.

## Module Structure

| File | Contents |
|---|---|
| `src/maintenance_man/models/scan.py` | VulnFinding, SecretFinding, ScanResult Pydantic models |
| `src/maintenance_man/scanner.py` | Trivy invocation, JSON parsing, results writing |
| `src/maintenance_man/cli.py` | Flesh out existing `scan` stub |

No scanner abstraction layer — Trivy is the only scanner. YAGNI.

## Testing

Integration tests that run `mm scan` against real projects on the local machine.

- `mm scan lifts` → exits 2, writes results JSON, findings have expected structure
- `mm scan feetfax` → exits 0, writes results JSON, empty vulnerabilities
- `mm scan` (no args) → scans all projects, exits with worst-case code
- `mm scan nonexistent` → exits 1, prints error

Assertions are structural, not specific to CVE IDs (which change over time): exit code, file exists, findings have valid fields, severity values are valid enums.

## Trivy Output Reference

Real output from `trivy fs --format json` (schema version 2):

```
Top-level: SchemaVersion, ReportID, CreatedAt, ArtifactName, ArtifactType, Metadata, Results
Result:    Target, Class, Type, Packages, Vulnerabilities (or Secrets)
Vuln:      VulnerabilityID, PkgID, PkgName, PkgIdentifier, InstalledVersion,
           FixedVersion, Status, SeveritySource, PrimaryURL, DataSource,
           Title, Description, Severity, CweIDs, VendorSeverity, CVSS,
           References, PublishedDate, LastModifiedDate
```

Observed `Type` values for our ecosystems: `uv`, `bun`.
Observed `Status` values: `fixed` (has FixedVersion), `affected` (no fix).
Multiple CVEs can exist per package with different fix versions.
