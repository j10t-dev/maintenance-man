# Feature: `mm test <project>`

## Purpose

Run a project's configured test suite (unit, integration, component) as a quick
sanity check during development — e.g. before finishing a branch.

## Behaviour

- Required `project` arg, optional `--config` flag (consistent with existing commands).
- Looks up the project's `PhaseTestConfig`; errors if `test` is not configured.
- Runs defined phases in order: **unit → integration → component**.
- Phases set to `None` are skipped (only `unit` is required by the model).
- Subprocess output streams directly to the terminal (no capture).
- Prints a brief header before each phase (e.g. `Running unit tests...`).
- **Fail fast** — stops on the first non-zero exit code and exits with that code.
- Exits 0 if all phases pass.

## Implementation

### 1. `src/maintenance_man/tester.py` (new module)

- `run_tests(project_name: str, test_config: PhaseTestConfig) -> None`
  - Iterates phases in order: `("unit", config.unit)`, `("integration", config.integration)`, `("component", config.component)`.
  - Skips `None` phases.
  - Prints phase header via `rich.console`.
  - Runs each command string via `subprocess.run(cmd, shell=True, cwd=...)`.
  - On non-zero return code, raises or returns the exit code.

### 2. `src/maintenance_man/cli.py` — new `test` command

- Mirrors the single-project pattern from `scan`:
  - Load config, resolve project, check `test` is configured.
  - Delegate to `run_tests`.
  - `sys.exit` with the result.

## Not in scope

- Multi-project invocation.
- cwd-based project inference.
- Parallel phase execution.
- Coverage reporting.
