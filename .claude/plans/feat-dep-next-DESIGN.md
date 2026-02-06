# mm update — Design Document

## Overview

`mm update <project>` reads scan results, lets the user interactively select
which findings to address, then applies updates using git worktree isolation
via Graphite stacked branches. Vuln fixes are independent branches; bumps are
a risk-ascending stack. Each update is tested through configured test phases
before being committed.

## Finding status tracking

Each `VulnFinding` and `BumpFinding` carries an `update_status` field persisted
in the scan results JSON:

| Status      | Meaning                                    |
|-------------|--------------------------------------------|
| `null`      | Not yet attempted                          |
| `"started"` | Update in progress (useful for crash debug) |
| `"completed"` | Update applied and tests passed          |
| `"failed"`  | Update applied but tests failed            |

- `mm scan` always writes findings with `null` status (clean slate).
- `mm update` writes status back to the scan results file after each finding.
- `--continue` reads `failed` findings to know what needs retesting.

## Flow — fresh run (`mm update <project>`)

### 1. Pre-checks

1. Load config, resolve project via `resolve_project()`.
2. Load scan results from `~/.mm/scan-results/<project>.json` — error if
   missing, tell user to run `mm scan <project>` first.
3. Verify `git status` is clean in the project repo — if dirty, offer to
   reset to main (interactive confirm). Abort if declined.
4. Verify `gt` (Graphite CLI) is available on PATH — abort with install
   instructions if missing.
5. Verify `unit` test command is configured for the project — refuse to
   proceed without it.

### 2. Interactive selection

- Display findings in a Rich-formatted table (reuse existing `_print_scan_result`
  style).
- Number each finding for reference.
- Prompt via `rich.prompt.Prompt.ask()`:
  - `all` — select everything
  - `vulns` — select all vuln fixes only
  - `bumps` — select all bumps only
  - `1,3,5` — comma-separated finding numbers
  - `none` — abort

### 3. Process vulns (Graphite stack)

Vuln fixes are stacked branches, submitted as a single Graphite stack.
Failures are removed from the stack and processing continues.

For each selected vuln:
1. Stack on the previous fix branch (or main for the first).
2. Apply update via package manager command. Mark as `started`.
3. `gt create fix/<pkg> -a -m "fix: upgrade <pkg> <old> → <new> for <CVE-ID>"`.
4. Run test phases: unit → integration (if configured) → component (if configured).
5. **Green:** mark `completed`, continue to next vuln.
6. **Red:** mark `failed`, `gt delete -f fix/<pkg>`, continue to next vuln.

After all vulns: submit the fix stack via `gt submit --stack` from the tip,
then `gt checkout main` to return to main before processing bumps.

### 4. Process bumps (Graphite stack, risk-ascending)

Bumps are sorted by semver tier: patches first, then minors, then majors. This
maximises the number of safe updates that land before a breaking change halts
the stack.

For each selected bump:
1. Apply update via package manager command. Mark as `started`.
2. `gt create bump/<pkg> -a -m "bump: <pkg> <old> → <new> (<tier>)"` — stacks
   on previous.
3. Run test phases: unit → integration → component.
4. **Green:** mark `completed`, continue to next bump.
5. **Red:** mark `failed`, `gt delete -f bump/<pkg>` (removes tip of stack,
   returns to previous good branch), continue with next bump.

The resulting stack contains only passing bumps. Failed bumps are removed from
the stack but remain marked as `failed` in scan results for `--continue`.

### 5. Submit

If all selected findings passed → `gt submit --stack`.
If any failed → report summary, no submit.

### 6. Exit codes

| Code | Meaning                           |
|------|-----------------------------------|
| 0    | All selected updates passed tests |
| 4    | One or more updates failed tests  |

## Flow — continue after fix (`mm update <project> --continue`)

Used after manually fixing a failed update branch.

1. Load scan results, find findings with `failed` status. Error if none found.
2. Detect current git branch, match it to a failed finding by branch name
   (`fix/<pkg>` or `bump/<pkg>`). Error if no match.
3. Re-run test phases against the current working state.
4. **Green:** mark `completed`, write scan results.
   - If no `failed` findings remain → `gt submit --stack`.
   - If `failed` findings remain → report what's outstanding.
5. **Red:** report failure, leave as `failed`.

`--continue` does **not** re-apply the package update — the user has already
fixed the branch manually. It only re-tests and optionally submits.

## Test configuration

Added to `ProjectConfig` via TOML:

```toml
[projects.my-app]
path = "/home/user/my-app"
package_manager = "bun"

[projects.my-app.test]
unit = "bun test"
integration = "bun run test:integration"    # optional
component = "bun run test:component"        # optional
```

### Rules

- `unit` is **required** — `mm update` refuses to proceed without it.
- `integration` and `component` are optional.
- Commands must start with the project's package manager (`bun`, `uv`, `mvn`).
- Exit code 0 = green, non-zero = red.
- Phases run sequentially; first red stops the test run for that update.

## Update commands

| Manager | Command |
|---------|---------|
| bun     | `bun add <pkg>@<version>` |
| uv      | `uv add <pkg>==<version>` |
| mvn     | `mvn versions:use-dep-version -Dincludes=<groupId:artifactId> -DdepVersion=<version>` then `mvn versions:commit` |

The same command shape is used for both vuln fixes (`fixed_version`) and bumps
(`latest_version`).

## Commit messages

**Vulns:**
```
fix: upgrade <pkg> <old> → <new> for <CVE-ID>
```

**Bumps:**
```
bump: <pkg> <old> → <new> (<tier>)
```

## Error handling

| Condition | Behaviour |
|-----------|-----------|
| No scan results | Error: "run `mm scan <project>` first" |
| Dirty git status | Offer reset to main; abort if declined |
| `gt` not installed | Abort with install instructions |
| No `unit` test configured | Refuse to proceed |
| Package manager command fails | Mark update as failed, report |
| Test failure (vuln) | Report, continue to next vuln (independent) |
| Test failure (bump) | Delete branch from stack, continue with remaining bumps |
| `--continue` no failed findings | Error: nothing to continue |
| `--continue` branch mismatch | Error: current branch doesn't match a failed finding |

## Model changes

### `ProjectConfig` — new `test` field

```python
class TestConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unit: str
    integration: str | None = None
    component: str | None = None

class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Path
    package_manager: Literal["bun", "uv", "mvn"]
    scan_secrets: bool = True
    test: TestConfig | None = None
```

`test` is optional at the model level (not all commands need it), but
`mm update` enforces its presence at runtime.

## Dependencies

- **Graphite CLI (`gt`)** — required at runtime for `mm update`, not for other
  commands.
- No new Python package dependencies.
