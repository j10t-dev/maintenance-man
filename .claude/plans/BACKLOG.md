# mm — Implementation Backlog

Each item gets: brainstorm → component design → implementation plan → build.
Reference: [Design Document](main-DESIGN.md)

## 1. Project scaffolding

**Scope:** Bare Python project that produces a working `mm` CLI with no real commands yet.

**Deliverables:**
- `uv init` with appropriate Python version, project metadata
- Cyclopts app entry point with Rich output
- `mm --help` renders correctly
- `mm --version` works
- Stub commands for `scan`, `update`, `deploy` (just print "not implemented" and exit)
- Trivy installed and available on PATH (or documented install step)
- pytest set up with a trivial test passing
- Project structure decisions: src layout vs flat, where commands live, how the package is installed locally (`uv pip install -e .` or similar)

**Open questions:**
- src layout (`src/mm/`) or flat (`mm/`)?
- Entry point via `pyproject.toml` `[project.scripts]` or `__main__.py`?
- Any linting/formatting tooling (ruff?) from the start?

---

## 2. Config system

**Scope:** TOML config loading, validation, and the `~/.mm/` directory structure. The foundation everything else reads from.

**Deliverables:**
- `~/.mm/` directory creation (config, scan-results, worktrees subdirs)
- `~/.mm/config.toml` schema: defaults section + per-project entries
- Config loading with validation (missing fields, bad paths, unknown package managers)
- Pydantic or dataclass models for config
- Possibly `mm add <name> <path>` to register a project (or just hand-edit TOML — TBD)
- Possibly `mm list` to show registered projects
- Error messages when config is missing or malformed

**Open questions:**
- Pydantic vs dataclasses vs plain dicts for config models?
- Do we want `mm init` to create the config interactively, or is hand-editing fine for a power-user tool?
- Should `mm add` auto-detect language/package manager from the project path?
- Config validation: strict (reject unknown keys) or permissive (ignore unknown keys for forward compat)?

**Depends on:** #1

---

## 3. Scan — vulnerability scanning

**Scope:** Trivy integration and the `mm scan [project]` command for CVE detection. Does NOT include dependency outdated checks (that's #4).

**Deliverables:**
- Shell out to `trivy fs --format json` on the project path
- Parse Trivy JSON output into internal finding model
- Finding model: package name, current version, fixed version, CVE ID, severity, source (trivy)
- Scan results JSON schema and file writing to `~/.mm/scan-results/<project>.json`
- `mm scan <project>` runs Trivy, writes results, prints summary via Rich
- `mm scan` (no args) scans all configured projects
- Exit code 0 (clean), 2 (vulns found)
- Handle: Trivy not installed, project path doesn't exist, Trivy finds nothing

**Open questions:**
- Trivy output schema — what fields do we actually need to extract? Need to run Trivy on a real project and examine output.
- How do we map Trivy's "fixed version" to an actionable update? Trivy tells you the CVE and sometimes a fix version, but not always.
- Scan results JSON schema — what's the minimal shape that both scan and update commands need?
- Do we filter by severity? (e.g. ignore low/negligible by default)

**Depends on:** #2

---

## 4. Scan — dependency updates

**Scope:** Checking for available non-vuln dependency updates via native package managers. Merging these with vuln findings from #3 into a unified scan output.

**Deliverables:**
- Package manager abstraction: common interface across bun/uv/mvn for "what's outdated?"
- `bun outdated` parsing (JSON output available?)
- `uv` outdated check — need to determine exact command and output format
- `mvn versions:display-dependency-updates` parsing
- Semver classification: patch / minor / major
- Age gating: check publish date of target version (how? registry APIs?)
- Merge vuln findings + bump findings into unified scan results JSON
- Update `mm scan` to run both Trivy and outdated checks
- Exit code 3 (updates available, no vulns)

**Open questions:**
- How do we get the publish date of a package version? npm registry API for bun packages, PyPI API for Python, Maven Central for Java? This is the age gate mechanism.
- `uv` — does it have an `outdated` command or do we compare `uv.lock` against PyPI?
- Should the package manager abstraction be a proper interface/protocol or just a dict of commands per manager?
- When both vulns and bumps exist, exit code 2 (vulns) takes precedence?

**Depends on:** #3

---

## 5. Update — applying changes

**Scope:** The `mm update <project>` command (project required — no mass updates). Reading scan results, interactive selection, git worktree workflow, applying updates, testing, merging.

**Deliverables:**
- Read scan results from `~/.mm/scan-results/<project>.json`
- Rich interactive display of findings with selection prompt (all / vulns only / select individually / none)
- Git worktree creation under `~/.mm/worktrees/<project>/<branch>/`
- Branch naming: `vuln/<pkg>-<CVE>` or `bump/<pkg>`
- Apply update via native package manager command in worktree
- Run test commands (configured per project) in worktree
- On test pass: commit, fast-forward merge to main, clean up worktree, mark finding as `resolved`
- On test fail: leave worktree, mark finding as `failed`, report with exit code 4
- Handle: no scan results found, all findings already resolved, git dirty state, merge conflicts

**Open questions:**
- Test commands — how are they configured? Per project in TOML? Separate unit vs integration test commands?
- What does the commit message look like? Should it reference the CVE or the bump details?
- If multiple updates are selected, do they each get their own worktree sequentially, or can we batch bumps into one branch?
- How do we handle the case where the project's main branch has diverged since the worktree was created?
- Interactive prompts — Rich prompts, or something else?

**Depends on:** #4

---

## 6. Deploy

**Scope:** `mm deploy <project>` — project required, no mass deploys. Runs a user-configured deploy process.

**Deliverables:**
- Deploy configuration in TOML (script path or command list per project)
- Execute deploy steps, stream output
- Exit code 0 (success) or 1 (failure)
- Handle: no deploy config, deploy script not found, non-zero exit from deploy

**Open questions:**
- What does the deploy config look like? A single script path? A list of shell commands? Both?
- Do we need pre-deploy or post-deploy hooks?
- Should mm verify that main is clean/up-to-date before deploying?
- This is explicitly minimal/bespoke for now — how minimal?

**Depends on:** #5 (logically, though technically independent)
