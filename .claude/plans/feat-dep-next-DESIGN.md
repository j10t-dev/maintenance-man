# mm update — Design Document

## Overview

`mm update <project>` reads scan results, lets the user interactively select
which findings to address, then applies updates using git worktree isolation
via Graphite stacked branches. Vuln fixes are independent branches; bumps are
a risk-ascending stack. Each update is tested through configured test phases
before being committed.

## Flow

### 1. Pre-checks

1. Load config, resolve project via `resolve_project()`.
2. Load scan results from `~/.mm/scan-results/<project>.json` — error if
   missing, tell user to run `mm scan <project>` first.
3. Verify `git status` is clean in the project repo — abort if dirty.
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

### 3. Process vulns (independent branches)

Each vuln fix is an independent branch off main. Failures in one do not block
others.

For each selected vuln:
1. `gt create -m "fix: upgrade <pkg> <old> → <new> for <CVE-ID>"`
2. Apply update via package manager command.
3. Run test phases: unit → integration (if configured) → component (if configured).
4. **Green:** continue to next vuln.
5. **Red:** report failure, continue to next vuln.

After all vulns: `gt checkout main` to return to main before processing bumps.

### 4. Process bumps (Graphite stack, risk-ascending)

Bumps are sorted by semver tier: patches first, then minors, then majors. This
maximises the number of safe updates that land before a breaking change halts
the stack.

For each selected bump:
1. `gt create -m "bump: <pkg> <old> → <new> (<tier>)"` — stacks on previous.
2. Apply update via package manager command.
3. Run test phases: unit → integration → component.
4. **Green:** continue to next bump.
5. **Red:** stop immediately. Report what passed and what was skipped.

### 5. Submit prompt

If any updates passed:
- Prompt: "N updates passed. Submit stack? [y/n]"
- Yes: `gt submit --stack`
- No: leave stack locally for user inspection.

### 6. Exit codes

| Code | Meaning                           |
|------|-----------------------------------|
| 0    | All selected updates passed tests |
| 4    | One or more updates failed tests  |

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
| Dirty git status | Abort before doing anything |
| `gt` not installed | Abort with install instructions |
| No `unit` test configured | Refuse to proceed |
| Package manager command fails | Mark update as failed, report |
| Test failure (vuln) | Report, continue to next vuln (independent) |
| Test failure (bump) | Stop the stack, report passed + skipped |

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
