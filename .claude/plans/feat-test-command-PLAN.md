# `mm test <project>` Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Add a `test` CLI command that runs a project's configured test phases (unit → integration → component), failing fast on first failure.

**Architecture:** `run_test_phases()` already exists in `updater.py` and handles the subprocess execution + fail-fast logic. We need a thin CLI command in `cli.py` that loads config, resolves the project, validates it has a `test` block, and delegates to `run_test_phases`. One new exit code `TEST_FAILED = 5` for test failures.

**Tech Stack:** Python 3.12+, cyclopts (CLI), rich (output), pytest (tests)

**Skills to Use:**
- test-driven-development
- verification-before-completion

**Required Files:**
- @src/maintenance_man/cli.py
- @src/maintenance_man/updater.py (for `run_test_phases`)
- @src/maintenance_man/config.py (for `load_config`, `resolve_project`)
- @src/maintenance_man/models/config.py (for `PhaseTestConfig`, `ProjectConfig`)
- @tests/conftest.py (for `mm_home_with_projects` fixture)
- @tests/test_cli.py (existing CLI tests for pattern reference)

---

## Task 1: Add `test` CLI command and tests

**Files:**
- Modify: `src/maintenance_man/cli.py` — add `ExitCode.TEST_FAILED`, add `test` command function
- Create: `tests/test_test_cli.py` — tests for the new command
- Modify: `tests/conftest.py` — add fixture for a project with no test config

### Subtask 1.1: Add a project fixture without test config

The existing `mm_home_with_projects` fixture defines projects that all have `test` blocks. We need a project without one to test the error case.

**Step 1:** In `tests/conftest.py`, add a `no-tests` project entry to the `mm_home_with_projects` fixture's config TOML string. Add this after the `[projects.outdated.test]` block:

```toml
[projects.no-tests]
path = "{clean_path}"
package_manager = "uv"
```

This project deliberately has no `[projects.no-tests.test]` section.

### Subtask 1.2: Write failing tests

**Step 1:** Create `tests/test_test_cli.py` with the following tests:

```python
from unittest.mock import patch

import pytest

from maintenance_man.cli import ExitCode, app

INVOKE = app.command  # cyclopts test invocation


class TestTestCommand:
    """Tests for `mm test <project>`."""

    def test_missing_test_config(self, mm_home_with_projects: ...) -> None:
        """Error when project has no test block configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["test", "no-tests"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    @patch("maintenance_man.cli.run_test_phases", return_value=(True, None))
    def test_all_phases_pass(self, mock_run, mm_home_with_projects: ...) -> None:
        """Exit 0 when all test phases pass."""
        with pytest.raises(SystemExit) as exc_info:
            app(["test", "vulnerable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_run.assert_called_once()

    @patch(
        "maintenance_man.cli.run_test_phases",
        return_value=(False, "integration"),
    )
    def test_phase_failure(self, mock_run, mm_home_with_projects: ...) -> None:
        """Exit TEST_FAILED when a phase fails."""
        with pytest.raises(SystemExit) as exc_info:
            app(["test", "vulnerable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.TEST_FAILED

    def test_unknown_project(self, mm_home_with_projects: ...) -> None:
        """Error when project name doesn't exist."""
        with pytest.raises(SystemExit) as exc_info:
            app(["test", "nonexistent"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR
```

**Step 2:** Run to verify they fail:

```
uv run pytest tests/test_test_cli.py -v
```

Expected: failures (ExitCode.TEST_FAILED doesn't exist, `test` command doesn't exist).

### Subtask 1.3: Implement the `test` command

**Step 1:** Add exit code to `ExitCode` in `src/maintenance_man/cli.py`:

```python
TEST_FAILED = 5
```

**Step 2:** Add the `test` command function in `src/maintenance_man/cli.py`. Place it after the `deploy` function. It follows the same pattern as `scan` for config/project resolution:

```python
@app.command
def test(
    project: str,
    *,
    config: Path | None = None,
) -> None:
    """Run a project's test suite.

    Runs configured test phases (unit → integration → component) in order,
    stopping on first failure.

    Parameters
    ----------
    project: str
        Project name to test.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    try:
        cfg = load_config(config_path=config)
    except ConfigError as e:
        _fatal(str(e))

    try:
        proj_config = resolve_project(cfg, project)
    except ProjectNotFoundError as e:
        _fatal(str(e))

    if proj_config.test is None:
        _fatal(f"No test configuration for project '{project}'.")

    console.print(f"[bold]Testing {project}[/]\n")

    passed, failed_phase = run_test_phases(proj_config.test, proj_config.path)

    if passed:
        console.print("\n[bold green]All test phases passed.[/]")
        sys.exit(ExitCode.OK)
    else:
        console.print(f"\n[bold red]Failed:[/] {failed_phase} tests")
        sys.exit(ExitCode.TEST_FAILED)
```

**Step 3:** `run_test_phases` is already imported from `maintenance_man.updater` (check the imports at the top of `cli.py`). No new import needed.

**Step 4:** Run all tests to verify:

```
uv run pytest tests/test_test_cli.py -v
```

Expected: all 4 tests PASS.

**Step 5:** Run the full test suite to check for regressions:

```
uv run pytest -v
```

Expected: all tests PASS.

**Step 6:** Run ruff:

```
uv run ruff check src/maintenance_man/cli.py tests/test_test_cli.py
```

Expected: clean.
