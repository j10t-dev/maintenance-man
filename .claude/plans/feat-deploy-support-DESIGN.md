# Feature: `mm build` and `mm deploy`

## Purpose

Build artefacts and deploy services to production (Raspberry Pi) by invoking
per-project scripts that live in the service repos. mm orchestrates — the
services own their build/deploy logic.

## Context

All services deploy to a Raspberry Pi via SSH/rsync, managed by systemd.
Bun services compile ARM64 binaries locally before transfer; Python services
need no build step. Each service should have its own `build.sh` and/or
`deploy.sh` script encoding its specific workflow.

## Configuration

```toml
[projects.j10t-web]
build_command = "scripts/build.sh"    # optional — absent for Python services
deploy_command = "scripts/deploy.sh"  # required for deploy

[projects.lifts]
deploy_command = "scripts/deploy.sh"  # no build_command — nothing to compile
```

### Config model changes

`ProjectConfig` gains two optional fields:

- `build_command: str | None = None`
- `deploy_command: str | None = None`

## Commands

### `mm build <project>`

- Required `project` arg, optional `--config` flag.
- Errors if `build_command` is not configured for the project.
- Runs `build_command` via `subprocess.run(shell=True, cwd=project_path)`.
- Streams stdout/stderr live to terminal.
- Exit code: 0 on success, `BUILD_FAILED` on non-zero exit.

### `mm deploy <project> [--build] [--check]`

- Required `project` arg, optional `--config` flag.
- Errors if `deploy_command` is not configured for the project.
- No safeguards — no branch checks, no clean-tree enforcement. The user is in
  control.

**Flags:**

- `--build` — run `build_command` before deploying. If `build_command` is not
  configured, silently skips (not an error). This lets `--build` be safely
  passed for any project without the caller needing to know whether it compiles.
- `--check` — post-deploy health verification via healthchecker (P2, see below).

**Flow:**

1. If `--build` and `build_command` exists: run build. Abort on failure.
2. Run `deploy_command`. Stream output live.
3. If `--check`: poll healthchecker for service status. Report pass/fail.

## Exit codes

Extend the existing `ExitCode` enum:

| Code | Name | Meaning |
|------|------|---------|
| 6 | `BUILD_FAILED` | Build script returned non-zero |
| 7 | `DEPLOY_FAILED` | Deploy script returned non-zero |

## Post-deploy health check (P2)

**Dependency:** Healthchecker needs a query/search API endpoint (e.g.
`GET /api/status?name=<query>`) so mm can look up a service without
maintaining a name mapping.

Once available:

```toml
[defaults]
healthcheck_url = "http://pihost:8080"
```

- `mm deploy <project> --check` polls `healthcheck_url` after deploy.
- Queries healthchecker by project name, checks `is_up` field.
- Retries with backoff up to a configurable timeout.
- Reports healthy/unhealthy to terminal. Does not affect exit code from a
  successful deploy (informational only — TBC).

## Implementation

### 1. `src/maintenance_man/models/config.py`

Add `build_command` and `deploy_command` to `ProjectConfig`.

### 2. `src/maintenance_man/deployer.py` (new module)

- `_project_env()` — returns `os.environ` copy with `VIRTUAL_ENV` removed and
  the venv `bin/` directory scrubbed from `PATH`. Prevents mm's own venv from
  leaking into build/deploy scripts.
- `_run_script(command, project_name, project_path, error_cls)` — shared
  implementation for running a shell command via
  `subprocess.run(shell=True, executable="/bin/bash", timeout=600)`.
  Streams stdout/stderr live (inherited, not captured). Raises `error_cls`
  on non-zero exit.
- `run_build(project_name, build_command, project_path)` — delegates to
  `_run_script` with `BuildError`.
- `run_deploy(project_name, deploy_command, project_path)` — delegates to
  `_run_script` with `DeployError`.

### 2a. `src/maintenance_man/updater.py` (existing — fix `_project_env`)

Update `_project_env()` to also scrub the venv `bin/` directory from `PATH`,
matching the new implementation in `deployer.py`.

### 3. `src/maintenance_man/cli.py`

- New `build` command: load config, resolve project, validate `build_command`
  exists, delegate to `run_build`.
- Flesh out existing `deploy` stub: load config, resolve project, validate
  `deploy_command` exists, handle `--build` flag, delegate to `run_deploy`,
  handle `--check` flag (P2).
- Add `BUILD_FAILED` and `DEPLOY_FAILED` to `ExitCode`.

### 4. Per-service scripts (side quest)

Each service repo needs build/deploy scripts. Only j10t-web currently has one
(`scripts/deploy-pi.sh`). The others need scripts written based on their
existing deployment patterns (rsync + systemctl restart).

## Design notes

- **Working directory:** `cwd=project_path` — build/deploy commands resolve
  relative to the project root. `build_command = "scripts/build.sh"` means
  `<project_path>/scripts/build.sh`.
- **Shell:** Uses `executable="/bin/bash"` so inline commands with bashisms work.
  Scripts with shebangs are unaffected.
- **Signal handling:** If the user Ctrl+C's during a deploy, the subprocess is
  killed. Partial-deploy cleanup (e.g. interrupted rsync) is the deploy script's
  responsibility — scripts should trap signals if they need atomic operations.
- **Timeout:** 600s default on subprocess calls. Generous but prevents infinite
  hangs from broken scripts.
- **No confirmation prompt:** Deliberate. mm is a power-user tool; the user
  typed the command and meant it.

## Not in scope

- Mass/batch deploys (no project arg = error).
- Branch or working-tree validation before deploy.
- Artefact tracking or versioning.
- Rollback support.
- Pre/post-deploy hooks beyond `--build` and `--check`.
- Output logging to disk (future enhancement).
