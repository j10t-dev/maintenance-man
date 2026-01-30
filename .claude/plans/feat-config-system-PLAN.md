# Config System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use 1337-skills:executing-plans to implement this plan task-by-task.

**Goal:** Build the config loading system — Pydantic models, TOML parsing, `~/.mm/` directory bootstrap, and `mm list` command.

**Architecture:** Pydantic models in `src/maintenance_man/models/config.py` define the config schema with strict validation. Loading logic in `src/maintenance_man/config.py` handles TOML parsing, directory bootstrap, and project resolution. CLI calls `load_config()` at command entry. All state lives under `~/.mm/`.

**Tech Stack:** Python 3.12, Pydantic, tomllib (stdlib), Typer, Rich

**Skills to Use:**
- 1337-skills:test-driven-development
- 1337-skills:verification-before-completion

**Required Files:** (executor will auto-read these)
- @src/maintenance_man/cli.py
- @src/maintenance_man/__init__.py
- @pyproject.toml
- @tests/test_cli.py
- @.claude/plans/feat-config-system-DESIGN.md

---

## Task 1: Add Pydantic dependency

**Files:**
- Modify: `pyproject.toml`

### Subtask 1.1: Add pydantic to project dependencies

**Step 1:** Add `pydantic` to the `dependencies` list in `pyproject.toml`:

```toml
dependencies = [
    "typer>=0.15.0",
    "pydantic>=2.0",
]
```

**Step 2:** Sync the environment:

Run: `uv sync`
Expected: Resolves and installs pydantic. Exit code 0.

**Step 3:** Verify import works:

Run: `uv run python -c "import pydantic; print(pydantic.__version__)"`
Expected: Prints a version >= 2.0.

---

## Task 2: Pydantic models and config loading with tests

This task creates the models, config loading, and all tests together. The files are tightly coupled — models are validated through loading, and tests exercise both layers.

**Files:**
- Create: `src/maintenance_man/models/__init__.py`
- Create: `src/maintenance_man/models/config.py`
- Create: `src/maintenance_man/config.py`
- Create: `tests/test_config.py`

### Subtask 2.1: Write tests for Pydantic models

Write `tests/test_config.py`. All tests use `tmp_path` and monkeypatch to avoid touching real `~/.mm/`. The file needs a `conftest`-style fixture or inline monkeypatching.

**Step 1:** Create the test file with model validation tests:

```python
import tomllib
from pathlib import Path

import pytest
from pydantic import ValidationError

from maintenance_man.models.config import DefaultsConfig, MmConfig, ProjectConfig


class TestDefaultsConfig:
    def test_defaults_all_optional(self):
        """DefaultsConfig works with no arguments — all fields have defaults."""
        config = DefaultsConfig()
        assert config.min_version_age_days == 7

    def test_defaults_custom_value(self):
        config = DefaultsConfig(min_version_age_days=14)
        assert config.min_version_age_days == 14

    def test_defaults_rejects_unknown_keys(self):
        with pytest.raises(ValidationError, match="extra_field"):
            DefaultsConfig(extra_field="bad")


class TestProjectConfig:
    def test_valid_project(self, tmp_path: Path):
        proj = ProjectConfig(path=tmp_path, package_manager="bun")
        assert proj.path == tmp_path
        assert proj.package_manager == "bun"

    def test_all_package_managers_accepted(self, tmp_path: Path):
        for pm in ("bun", "uv", "mvn"):
            proj = ProjectConfig(path=tmp_path, package_manager=pm)
            assert proj.package_manager == pm

    def test_missing_path_raises(self):
        with pytest.raises(ValidationError, match="path"):
            ProjectConfig(package_manager="bun")

    def test_missing_package_manager_raises(self, tmp_path: Path):
        with pytest.raises(ValidationError, match="package_manager"):
            ProjectConfig(path=tmp_path)

    def test_invalid_package_manager_raises(self, tmp_path: Path):
        with pytest.raises(ValidationError, match="package_manager"):
            ProjectConfig(path=tmp_path, package_manager="npm")

    def test_rejects_unknown_keys(self, tmp_path: Path):
        with pytest.raises(ValidationError, match="language"):
            ProjectConfig(path=tmp_path, package_manager="bun", language="typescript")


class TestMmConfig:
    def test_empty_config_valid(self):
        """MmConfig with no arguments is valid — defaults and empty projects."""
        config = MmConfig()
        assert config.defaults.min_version_age_days == 7
        assert config.projects == {}

    def test_config_with_projects(self, tmp_path: Path):
        config = MmConfig(
            projects={
                "myapp": ProjectConfig(path=tmp_path, package_manager="bun"),
            }
        )
        assert "myapp" in config.projects
        assert config.projects["myapp"].package_manager == "bun"

    def test_full_toml_round_trip(self, tmp_path: Path):
        """Parse a realistic TOML string through the full model."""
        toml_str = f"""
[defaults]
min_version_age_days = 14

[projects.feetfax]
path = "{tmp_path}"
package_manager = "bun"

[projects.lifts]
path = "{tmp_path}"
package_manager = "uv"
"""
        raw = tomllib.loads(toml_str)
        config = MmConfig(**raw)
        assert config.defaults.min_version_age_days == 14
        assert len(config.projects) == 2
        assert config.projects["feetfax"].package_manager == "bun"
        assert config.projects["lifts"].package_manager == "uv"

    def test_toml_missing_defaults_uses_fallback(self, tmp_path: Path):
        """If [defaults] is omitted from TOML, fallback values are used."""
        toml_str = f"""
[projects.myapp]
path = "{tmp_path}"
package_manager = "mvn"
"""
        raw = tomllib.loads(toml_str)
        config = MmConfig(**raw)
        assert config.defaults.min_version_age_days == 7

    def test_toml_unknown_top_level_key_rejected(self):
        toml_str = """
[settings]
foo = "bar"
"""
        raw = tomllib.loads(toml_str)
        with pytest.raises(ValidationError, match="settings"):
            MmConfig(**raw)
```

**Step 2:** Run the tests to verify they fail (modules don't exist yet):

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'maintenance_man.models'`

### Subtask 2.2: Implement Pydantic models

**Step 1:** Create `src/maintenance_man/models/__init__.py` (empty):

```python
```

**Step 2:** Create `src/maintenance_man/models/config.py`:

```python
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict


class DefaultsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_version_age_days: int = 7


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Path
    package_manager: Literal["bun", "uv", "mvn"]


class MmConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaults: DefaultsConfig = DefaultsConfig()
    projects: dict[str, ProjectConfig] = {}
```

**Step 3:** Run the model tests to verify they pass:

Run: `uv run pytest tests/test_config.py -v`
Expected: All tests PASS.

### Subtask 2.3: Write tests for config loading and directory bootstrap

Append to `tests/test_config.py`:

**Step 1:** Add these test classes:

```python
from maintenance_man.config import (
    MM_HOME,
    ensure_mm_home,
    load_config,
    resolve_project,
)


@pytest.fixture()
def mm_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect MM_HOME to a temp directory."""
    home = tmp_path / ".mm"
    monkeypatch.setattr("maintenance_man.config.MM_HOME", home)
    return home


class TestEnsureMmHome:
    def test_creates_directory_structure(self, mm_home: Path):
        assert not mm_home.exists()
        ensure_mm_home()
        assert mm_home.is_dir()
        assert (mm_home / "scan-results").is_dir()
        assert (mm_home / "worktrees").is_dir()
        assert (mm_home / "config.toml").is_file()

    def test_idempotent(self, mm_home: Path):
        ensure_mm_home()
        ensure_mm_home()  # should not raise
        assert mm_home.is_dir()

    def test_skeleton_config_is_valid_toml(self, mm_home: Path):
        ensure_mm_home()
        text = (mm_home / "config.toml").read_text()
        # Should parse without error (comments are valid TOML)
        raw = tomllib.loads(text)
        # Should validate through MmConfig
        config = MmConfig(**raw)
        assert config.defaults.min_version_age_days == 7

    def test_does_not_overwrite_existing_config(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        config_path = mm_home / "config.toml"
        config_path.write_text("[defaults]\nmin_version_age_days = 30\n")
        ensure_mm_home()
        text = config_path.read_text()
        assert "30" in text


class TestLoadConfig:
    def test_loads_valid_config(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text(
            f"[defaults]\nmin_version_age_days = 14\n"
        )
        config = load_config()
        assert config.defaults.min_version_age_days == 14

    def test_loads_skeleton_config_on_first_run(self, mm_home: Path):
        """First run: directory doesn't exist, gets auto-created, skeleton loads."""
        config = load_config()
        assert config.defaults.min_version_age_days == 7
        assert config.projects == {}

    def test_invalid_config_raises_system_exit(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        (mm_home / "config.toml").write_text("[defaults]\nbogus_key = true\n")
        with pytest.raises(SystemExit):
            load_config()


class TestResolveProject:
    def test_resolves_existing_project(self, mm_home: Path):
        project_dir = mm_home.parent / "myproject"
        project_dir.mkdir()
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text(
            f'[projects.myapp]\npath = "{project_dir}"\npackage_manager = "bun"\n'
        )
        config = load_config()
        proj = resolve_project(config, "myapp")
        assert proj.package_manager == "bun"

    def test_unknown_project_raises_system_exit(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text("[defaults]\n")
        config = load_config()
        with pytest.raises(SystemExit):
            resolve_project(config, "nonexistent")

    def test_missing_path_raises_system_exit(self, mm_home: Path):
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text(
            '[projects.myapp]\npath = "/nonexistent/path"\npackage_manager = "bun"\n'
        )
        config = load_config()
        with pytest.raises(SystemExit):
            resolve_project(config, "myapp")
```

**Step 2:** Run to verify the new tests fail:

Run: `uv run pytest tests/test_config.py -v -k "TestEnsureMmHome or TestLoadConfig or TestResolveProject"`
Expected: FAIL — `ImportError: cannot import name 'ensure_mm_home' from 'maintenance_man.config'`

### Subtask 2.4: Implement config loading

**Step 1:** Create `src/maintenance_man/config.py`:

```python
import tomllib
from pathlib import Path

import typer
from rich import print as rprint

from maintenance_man.models.config import MmConfig, ProjectConfig

MM_HOME: Path = Path.home() / ".mm"

_SKELETON_CONFIG = """\
[defaults]
min_version_age_days = 7

# [projects.my-project]
# path = "/home/user/dev/my-project"
# package_manager = "bun"        # bun | uv | mvn
"""


def ensure_mm_home() -> None:
    """Create ~/.mm/ directory structure and skeleton config if missing."""
    MM_HOME.mkdir(parents=True, exist_ok=True)
    (MM_HOME / "scan-results").mkdir(exist_ok=True)
    (MM_HOME / "worktrees").mkdir(exist_ok=True)

    config_path = MM_HOME / "config.toml"
    if not config_path.exists():
        config_path.write_text(_SKELETON_CONFIG)


def load_config() -> MmConfig:
    """Load and validate config from ~/.mm/config.toml."""
    ensure_mm_home()

    config_path = MM_HOME / "config.toml"
    text = config_path.read_text()

    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        rprint(f"[bold red]Config error:[/] Failed to parse {config_path}\n{e}")
        raise typer.Exit(code=1) from e

    try:
        return MmConfig(**raw)
    except Exception as e:
        rprint(f"[bold red]Config error:[/] Invalid config in {config_path}\n{e}")
        raise typer.Exit(code=1) from e


def resolve_project(config: MmConfig, name: str) -> ProjectConfig:
    """Look up a project by name and validate its path exists on disk."""
    if name not in config.projects:
        rprint(
            f"[bold red]Error:[/] Unknown project [bold]{name}[/]. "
            f"Known projects: {', '.join(config.projects) or '(none)'}"
        )
        raise typer.Exit(code=1)

    project = config.projects[name]

    if not project.path.exists():
        rprint(
            f"[bold red]Error:[/] Project [bold]{name}[/] path does not exist: "
            f"{project.path}"
        )
        raise typer.Exit(code=1)

    return project
```

**Step 2:** Run all config tests:

Run: `uv run pytest tests/test_config.py -v`
Expected: All tests PASS.

**Step 3:** Run the full test suite to check nothing is broken:

Run: `uv run pytest -v`
Expected: All tests PASS (both `test_cli.py` and `test_config.py`).

---

## Task 3: `mm list` command and CLI integration

**Files:**
- Modify: `src/maintenance_man/cli.py`
- Create: `tests/test_list.py`

### Subtask 3.1: Write tests for `mm list`

**Step 1:** Create `tests/test_list.py`:

```python
from pathlib import Path

import pytest
from typer.testing import CliRunner

from maintenance_man.cli import app

runner = CliRunner()


@pytest.fixture()
def mm_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect MM_HOME to a temp directory."""
    home = tmp_path / ".mm"
    monkeypatch.setattr("maintenance_man.config.MM_HOME", home)
    return home


class TestListCommand:
    def test_list_no_projects(self, mm_home: Path):
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "no projects" in result.output.lower()

    def test_list_shows_projects(self, mm_home: Path):
        project_dir = mm_home.parent / "myproject"
        project_dir.mkdir()
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text(
            f'[projects.myapp]\npath = "{project_dir}"\npackage_manager = "bun"\n'
        )
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "myapp" in result.output
        assert "bun" in result.output
```

**Step 2:** Run to verify tests fail:

Run: `uv run pytest tests/test_list.py -v`
Expected: FAIL — `No such command 'list'` or similar.

### Subtask 3.2: Implement `mm list`

**Step 1:** Add the `list` command to `src/maintenance_man/cli.py`. Add these imports at the top:

```python
from rich.console import Console
from rich.table import Table

from maintenance_man.config import load_config
```

Then add the command (after the existing `deploy` command):

```python
@app.command(name="list")
def list_projects() -> None:
    """List all configured projects."""
    config = load_config()

    if not config.projects:
        typer.echo("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    console = Console()
    table = Table(title="Configured Projects")
    table.add_column("Name", style="bold")
    table.add_column("Path")
    table.add_column("Package Manager")

    for name, project in sorted(config.projects.items()):
        table.add_row(name, str(project.path), project.package_manager)

    console.print(table)
```

Note: The function is named `list_projects` to avoid shadowing the built-in `list`. The Typer command name is explicitly set to `"list"`.

**Step 2:** Run list tests:

Run: `uv run pytest tests/test_list.py -v`
Expected: All tests PASS.

**Step 3:** Run the full test suite:

Run: `uv run pytest -v`
Expected: All tests PASS.

**Step 4:** Manual smoke test:

Run: `uv run mm list`
Expected: Prints "No projects configured" message (since real `~/.mm/config.toml` likely doesn't exist or has no projects).

Run: `uv run mm --help`
Expected: Shows `list` alongside `scan`, `update`, `deploy`.

---

## Task 4: Lint and final verification

**Files:**
- All new and modified files

### Subtask 4.1: Lint

**Step 1:** Run ruff:

Run: `uv run ruff check src/ tests/`
Expected: No errors.

**Step 2:** Run ruff format check:

Run: `uv run ruff format --check src/ tests/`
Expected: No reformatting needed. If it reports changes needed, run `uv run ruff format src/ tests/` and include the formatted files.

### Subtask 4.2: Full test suite

**Step 1:** Run all tests:

Run: `uv run pytest -v`
Expected: All tests PASS.

### Subtask 4.3: Commit

Commit all changes with message:

```
feat: add config system with Pydantic models and mm list command

- Pydantic models for config schema (strict validation, reject unknown keys)
- TOML config loading with auto-created ~/.mm/ directory structure
- Skeleton config.toml with commented examples on first run
- resolve_project() validates path exists at command time
- mm list command to display configured projects
- Full test coverage for models, loading, and CLI integration
```
