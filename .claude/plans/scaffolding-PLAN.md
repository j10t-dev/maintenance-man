# Project Scaffolding Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use 1337-skills:executing-plans to implement this plan task-by-task.

**Goal:** Scaffold the `maintenance-man` Python project so that `mm --help` works with stub commands.

**Architecture:** Python package `maintenance_man` in `src/` layout, using Typer with Rich for the CLI. Entry point via `pyproject.toml` scripts. uv as package manager. Stub commands for `scan`, `update`, `deploy` that print "Not implemented" and exit 1.

**Tech Stack:** Python 3.12+, uv, Typer (with Rich), pytest, ruff

**Skills to Use:**
- 1337-skills:test-driven-development
- 1337-skills:verification-before-completion

**Required Files:** (executor will auto-read these)
- @.claude/plans/scaffolding-DESIGN.md

---

## Task 1: Scaffold project and implement CLI

This is a single task because every file depends on every other file — `pyproject.toml` defines the package, `cli.py` is the entry point, tests validate both. No parallelism possible.

**Files:**
- Create: `pyproject.toml`
- Create: `src/maintenance_man/__init__.py`
- Create: `src/maintenance_man/cli.py`
- Create: `tests/__init__.py`
- Create: `tests/test_cli.py`
- Create: `.gitignore`

### Subtask 1.1: Initialise the uv project and install dependencies

**Step 1:** Initialise the project with uv.

Run: `uv init --lib --name maintenance-man`

This creates `pyproject.toml`, `src/maintenance_man/__init__.py`, and `.python-version`. The `--lib` flag gives us the `src/` layout.

**Step 2:** Replace the generated `pyproject.toml` with our full configuration.

Write `pyproject.toml`:

```toml
[project]
name = "maintenance-man"
version = "0.1.0"
description = "Config-driven CLI for routine software project maintenance"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "typer[all]>=0.15.0",
]

[project.scripts]
mm = "maintenance_man.cli:app"

[dependency-groups]
dev = [
    "pytest>=8.0",
    "ruff>=0.9.0",
]

[tool.ruff]
line-length = 88

[tool.ruff.lint]
select = ["E", "F", "I", "W"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

**Step 3:** Write the `.gitignore`.

Write `.gitignore`:

```
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.venv/
.eggs/
*.egg
.ruff_cache/
.pytest_cache/
```

**Step 4:** Install dependencies.

Run: `uv sync`

Expected: Dependencies install successfully, `.venv` created.

**Step 5:** Verify the project is set up correctly.

Run: `uv run mm --help`

Expected: This will fail because `cli.py` doesn't exist yet. That's fine — we've confirmed the entry point is wired up (Typer will complain about the missing module, not about a missing script entry).

### Subtask 1.2: Write failing tests for CLI behaviour

**Step 1:** Create the test directory.

Write `tests/__init__.py` (empty file):

```python
```

**Step 2:** Write all CLI smoke tests.

Write `tests/test_cli.py`:

```python
from typer.testing import CliRunner

from maintenance_man.cli import app

runner = CliRunner()


def test_help_exits_zero():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0


def test_help_contains_description():
    result = runner.invoke(app, ["--help"])
    assert "maintenance" in result.output.lower()


def test_version_exits_zero():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0


def test_version_prints_version():
    result = runner.invoke(app, ["--version"])
    assert "0.1.0" in result.output


def test_scan_stub_no_args():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1
    assert "not implemented" in result.output.lower()


def test_scan_stub_with_project():
    result = runner.invoke(app, ["scan", "feetfax"])
    assert result.exit_code == 1
    assert "not implemented" in result.output.lower()


def test_update_requires_project():
    result = runner.invoke(app, ["update"])
    assert result.exit_code != 0


def test_update_stub_with_project():
    result = runner.invoke(app, ["update", "feetfax"])
    assert result.exit_code == 1
    assert "not implemented" in result.output.lower()


def test_deploy_requires_project():
    result = runner.invoke(app, ["deploy"])
    assert result.exit_code != 0


def test_deploy_stub_with_project():
    result = runner.invoke(app, ["deploy", "feetfax"])
    assert result.exit_code == 1
    assert "not implemented" in result.output.lower()
```

**Step 3:** Run the tests to verify they fail.

Run: `uv run pytest tests/test_cli.py -v`

Expected: ALL tests FAIL. Likely `ImportError` because `maintenance_man.cli` doesn't define `app` yet. This is correct — we've written the tests first.

### Subtask 1.3: Implement the CLI to make tests pass

**Step 1:** Write the package init with version.

Write `src/maintenance_man/__init__.py`:

```python
__version__ = "0.1.0"
```

**Step 2:** Write the CLI module.

Write `src/maintenance_man/cli.py`:

```python
from typing import Optional

import typer

from maintenance_man import __version__

app = typer.Typer(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    rich_markup_mode="markdown",
)


def _version_callback(value: bool) -> None:
    if value:
        print(f"mm {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Config-driven CLI for routine software project maintenance."""


@app.command()
def scan(
    project: Optional[str] = typer.Argument(None, help="Project name to scan. Scans all if omitted."),
) -> None:
    """Scan projects for vulnerabilities and available updates."""
    typer.echo("Not implemented.")
    raise typer.Exit(code=1)


@app.command()
def update(
    project: str = typer.Argument(..., help="Project name to update."),
) -> None:
    """Apply updates from scan results to a project."""
    typer.echo("Not implemented.")
    raise typer.Exit(code=1)


@app.command()
def deploy(
    project: str = typer.Argument(..., help="Project name to deploy."),
) -> None:
    """Deploy a project."""
    typer.echo("Not implemented.")
    raise typer.Exit(code=1)
```

**Step 3:** Run all tests.

Run: `uv run pytest tests/test_cli.py -v`

Expected: ALL tests PASS.

**Step 4:** Verify the CLI works end-to-end.

Run these commands and check output:

```
uv run mm --help
uv run mm --version
uv run mm scan
uv run mm scan feetfax
uv run mm update feetfax
uv run mm deploy feetfax
```

Expected:
- `--help` shows description and three commands
- `--version` prints `mm 0.1.0`
- All stub commands print "Not implemented." and exit 1
- `mm update` and `mm deploy` without args show an error about missing argument

**Step 5:** Run ruff to verify code quality.

Run: `uv run ruff check src/ tests/ && uv run ruff format --check src/ tests/`

Expected: No lint errors, no formatting issues. Fix any that appear.

### Subtask 1.4: Final verification

**Step 1:** Run the full test suite one final time.

Run: `uv run pytest tests/ -v`

Expected: All tests pass.

**Step 2:** Check that all expected files exist.

Verify these files exist:
- `pyproject.toml`
- `src/maintenance_man/__init__.py`
- `src/maintenance_man/cli.py`
- `tests/__init__.py`
- `tests/test_cli.py`
- `.gitignore`
