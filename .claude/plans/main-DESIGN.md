# mm (maintenance-man) — Design Document

## Overview

`mm` is a config-driven CLI tool for performing routine maintenance across multiple software projects. It wraps existing tooling (Trivy, native package managers) to provide a consistent workflow for vulnerability scanning, dependency updates, testing, and deployment.

**Stack:** Python + uv + Cyclopts (with Rich output)
**Config format:** TOML (`~/.mm/config.toml`)
**Target user:** Solo developer maintaining multiple projects across languages, deployed to self-hosted infrastructure.

## Principles

- **Local/CLI only** — no servers, no daemons, no web UI. Scriptable, Claude-friendly.
- **Config-driven** — projects are explicitly registered, not discovered.
- **Never modifies main directly** — all updates happen on branches in git worktrees.
- **Native tooling** — mm shells out to existing tools (`trivy`, `bun`, `uv`, `mvn`), it doesn't reimplement them.
- **Interactive by default, automatable** — prompts at each step unless `--auto` is passed.

## Commands

### `mm scan [project]`

Scans registered projects for vulnerabilities and available dependency updates.

- No args = scan all configured projects.
- Uses **Trivy** for vulnerability scanning (local, CLI, JSON output, covers Java/Python/TS).
- Uses **native package manager commands** to check for available updates (e.g. `bun outdated`, `uv lock --check`, `mvn versions:display-dependency-updates`).
- Applies **update policy** to classify findings:
  - Semver tiers: patch, minor, major.
  - Minimum version age gate (default 7 days) — supply chain protection. Vuln fixes bypass this.
- Writes structured JSON results to `~/.mm/scan-results/<project>.json`.
- Each finding has a `status` field: `open`, `resolved`, `failed`.

### `mm update [project]`

Reads scan results from disk. Presents findings and applies selected updates.

- Presents combined view of all findings for the project:
  ```
  feetfax — 3 findings:
    [VULN] lib-A → 2.1.1 (fixes CVE-XXXX, critical)
    [BUMP] lib-B → 1.4.0 (minor, 23 days old)
    [BUMP] lib-C → 3.0.0 (major — flagged for review)

  Apply: [a]ll, [v]ulns only, [s]elect individually, [n]one?
  ```
- For each selected update:
  1. Creates a **git worktree** under `~/.mm/worktrees/<project>/<branch-name>/`.
  2. Creates a branch with descriptive name (see Branch Naming below).
  3. Applies the update via native tooling (`bun update <pkg>`, `uv lock --upgrade-package <pkg>`, `mvn versions:use-dep-version`).
  4. Runs **unit tests**, then **integration tests** (test commands from config).
  5. If tests pass: commits, merges branch to main (fast-forward), cleans up worktree. Updates scan results JSON to mark finding as `resolved`.
  6. If tests fail: leaves branch in place, marks finding as `failed`, reports failure with Cyclopts exit codes. User (or future Claude agent) investigates manually.
- Vuln updates should be isolated — one branch per vulnerability by default. Generic bumps can be combined.

### `mm deploy [project]`

Deploys the current state of main to the target host.

- No gates, no test re-runs. If you run deploy, it deploys.
- Deploy mechanism is per-project configuration — TBD, likely a script path or command list.
- Deployment configuration details to be designed during implementation.

## Branch Naming

Pattern: `<type>/<description>`

- `vuln/lib-A-CVE-2025-1234` — single vulnerability fix
- `vuln/combined-updates` — multiple vulns batched (details in commit message)
- `bump/lib-B` — single dependency bump
- `bump/combined-updates` — multiple bumps batched

Branch prefix is user-configurable. Branches are created in the project's own repo (no project name in branch since it's already scoped).

## Build Isolation

All update work happens in **git worktrees**, not the user's working directory.

- Worktrees live under `~/.mm/worktrees/<project>/<branch-name>/`.
- This prevents mm from interfering with in-progress work in the main checkout.
- Worktrees are cleaned up after successful merge to main.
- Failed worktrees are left in place for manual investigation.

## Home Directory

All mm state lives under `~/.mm/`:

```
~/.mm/
  config.toml              # project registry and defaults
  scan-results/            # per-project scan output (JSON)
    feetfax.json
    lifts.json
  worktrees/               # git worktrees for update branches
    feetfax/
      vuln-lib-A-CVE-XXXX/
    lifts/
      bump-fastapi/
```

Single directory to know about, single directory to nuke if something goes wrong.

## Config Schema (minimal)

```toml
[defaults]
update_policy = "standard"        # patch+minor auto, major flagged
min_version_age_days = 7          # supply chain protection

[projects.feetfax]
path = "/home/glykon/dev/feetfax"
language = "typescript"
package_manager = "bun"

[projects.j10t-web]
path = "/home/glykon/dev/j10t-web"
language = "typescript"
package_manager = "bun"

[projects.lifts]
path = "/home/glykon/dev/lifts"
language = "python"
package_manager = "uv"

[projects.mood-tracker]
path = "/home/glykon/dev/mood-tracker"
language = "typescript"
package_manager = "bun"

[projects.youtube-hipster]
path = "/home/glykon/dev/youtube-hipster"
language = "python"
package_manager = "uv"
```

Config captures what mm needs to know about each project. Deploy configuration, test commands, and other operational details will be designed during implementation — the config schema will grow as needed.

## Update Policy

Semver-based tiers with a time delay for supply chain protection:

| Update type | Default behaviour |
|---|---|
| Patch (1.2.3 → 1.2.4) | Auto-eligible, subject to age gate |
| Minor (1.2.3 → 1.3.0) | Auto-eligible, subject to age gate |
| Major (1.2.3 → 2.0.0) | Flagged for manual review |
| Vuln fix (any) | Always eligible, bypasses age gate |

- **Minimum version age** (default 7 days): applies to **bumps only**. Non-vuln updates are only offered if the target version has been published for at least N days. Protects against supply chain attacks (e.g. xz-utils style). **Vulnerability fixes bypass the age gate entirely** — if Trivy says version X fixes CVE-YYYY, it's offered immediately regardless of publish date.
- Per-project and per-dependency overrides configurable.

## Exit Codes

Cyclopts exit codes for scriptability and Claude integration:

| Code | Meaning |
|---|---|
| 0 | Success, no issues |
| 1 | General failure / error |
| 2 | Scan found vulnerabilities |
| 3 | Scan found available updates (no vulns) |
| 4 | Tests failed during update |

Exact codes TBD during implementation, but the principle is: distinct exit codes for distinct outcomes so callers can branch on results.

## Tooling Choices

- **Vulnerability scanning:** Trivy — local, CLI-first, multi-language, JSON output, broadest single-tool coverage.
- **Dependency updates:** Native package manager commands — `bun update`, `uv lock --upgrade-package`, `mvn versions:use-dep-version`. No Renovate — its local mode is limited and unstable.
- **CLI framework:** Cyclopts with Rich output.
- **Config:** TOML.
- **Build isolation:** Git worktrees.

## Future Extensions (not in scope for POC)

- **Claude agent dispatch** on test failure — automated fix attempts before alerting user.
- **PR/MR workflow** — for projects that benefit from code review (even solo with LLM review).
- **Healthchecker integration** — post-deploy verification via the existing healthchecker project.
- **Scheduled runs** — cron/systemd timer wrapper for weekly sweeps.
- **Additional scanners** — Grype or OSV-Scanner alongside Trivy for broader coverage (~60-65% overlap between tools).

## Research Sources

- [Trivy](https://trivy.dev/) — vulnerability scanner
- [Trivy vs Grype comparison](https://opsdigest.com/digests/trivy-vs-grype-choosing-the-right-vulnerability-scanner/)
- [OWASP dep-scan](https://owasp.org/www-project-dep-scan/) — alternative with reachability analysis
- [Renovate local platform limitations](https://github.com/renovatebot/renovate/discussions/24846)
- [Cyclopts](https://cyclopts.readthedocs.io/) — CLI framework
