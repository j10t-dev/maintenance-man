# Mass Deploy — Design

## Problem

User manages multiple projects and wants to deploy them all in one command rather than running `mm deploy <project>` for each one individually.

## Behaviour

`mm deploy` with no project argument deploys all configured projects that have a `deploy_command`. Projects without `deploy_command` are silently skipped.

Build is always run before deploy in mass mode (equivalent to `--build` being implicit). Projects without `build_command` skip the build step and go straight to deploy.

## Flow

For each project (sorted alphabetically, matching `_update_all` pattern):
1. Skip if no `deploy_command` configured
2. Run `build_command` if configured (record activity)
3. Run `deploy_command` (record activity)
4. Run health check if `--check` flag passed and `healthcheck_url` configured
5. On failure at any step, log it and continue to next project

## CLI Changes

The `project` parameter on `mm deploy` becomes optional (currently required). When omitted, mass mode runs. `--build` flag is ignored in mass mode (build always runs). `--check` flag works in both modes.

## Summary Table

Print a cross-project summary at the end, matching the `_print_mass_update_summary` pattern:

| Project | Build | Deploy |
|---------|-------|--------|
| feetfax | PASS  | PASS   |
| lifts   | SKIP  | FAIL   |

"SKIP" when no `build_command` configured. "PASS"/"FAIL" for actual runs.

## Activity Recording

Each build/deploy step records activity via the existing `record_activity` calls already wired into `run_build`/`run_deploy` code paths in the `deploy` command. The mass deploy function should use the same recording pattern.

## Exit Code

`ExitCode.DEPLOY_FAILED` if any project failed at any step, `ExitCode.OK` otherwise.

## What's NOT in Scope

- No "changed since last deploy" filtering
- No interactive project selection
- No parallel deploys
- No `--build` flag behaviour change in single-project mode
