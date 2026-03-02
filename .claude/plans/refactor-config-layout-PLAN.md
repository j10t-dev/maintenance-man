# Flatten Test Config Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Remove `PhaseTestConfig` and promote `test_unit`, `test_integration`, `test_component` as flat optional fields on `ProjectConfig`.

**Architecture:** Delete `PhaseTestConfig` class entirely. Move its three fields (prefixed with `test_`) onto `ProjectConfig` as `str | None = None`. Update all consumers: `run_test_phases` in `updater.py` takes `ProjectConfig` directly, `_require_test_config` in `cli.py` checks the flat fields, call sites drop `.test` indirection.

**Tech Stack:** Python, Pydantic v2, TOML config

**Skills to Use:**
- test-driven-development
- verification-before-completion

**Required Files:**
- @src/maintenance_man/models/config.py
- @src/maintenance_man/models/__init__.py
- @src/maintenance_man/updater.py
- @src/maintenance_man/cli.py
- @tests/test_models_config.py
- @tests/test_updater.py

---

## Task 1: Flatten model and update tests

This is a single task because the model, its consumers, and their tests are tightly coupled — changing the model signature breaks every consumer simultaneously.

**Files:**
- Modify: `src/maintenance_man/models/config.py:12-27`
- Modify: `src/maintenance_man/models/__init__.py` (remove `PhaseTestConfig` if exported)
- Modify: `src/maintenance_man/updater.py:16,37-38,275-301,318-327,379`
- Modify: `src/maintenance_man/cli.py:315,420-425,673`
- Modify: `tests/test_models_config.py` (full rewrite of test classes)
- Modify: `tests/test_updater.py:8,65-71,207-257`

### Subtask 1.1: Update the model

**Step 1:** In `src/maintenance_man/models/config.py`, delete `PhaseTestConfig` (lines 13-18) and replace the `test` field on `ProjectConfig` with three flat fields:

```python
class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Path
    package_manager: Literal["bun", "uv", "mvn"]
    scan_secrets: bool = True
    test_unit: str | None = None
    test_integration: str | None = None
    test_component: str | None = None
```

**Step 2:** In `src/maintenance_man/models/__init__.py`, remove `PhaseTestConfig` from the import — it's not currently exported there, but verify and remove if present.

### Subtask 1.2: Update updater.py

**Step 1:** Remove `PhaseTestConfig` from the import on line 16. It should become:

```python
from maintenance_man.models.config import ProjectConfig
```

**Step 2:** Rename `NoPhaseTestConfigError` to `NoTestConfigError` (line 37-38). Same body.

**Step 3:** Replace `run_test_phases` (lines 275-301) to accept `ProjectConfig` directly:

```python
def run_test_phases(
    project_config: ProjectConfig, project_path: Path
) -> tuple[bool, str | None]:
    """Run configured test phases sequentially. Returns (passed, failed_phase).

    Stops on first failure. Returns (True, None) if all phases pass.
    """
    env = _project_env()
    phases = [
        ("unit", project_config.test_unit),
        ("integration", project_config.test_integration),
        ("component", project_config.test_component),
    ]
    for phase_name, command in phases:
        if command is None:
            continue
        rprint(f"  [dim]$ {command}[/]")
        completed = subprocess.run(
            shlex.split(command),
            cwd=project_path,
            timeout=600,
            text=True,
            env=env,
        )
        if completed.returncode != 0:
            return False, phase_name
    return True, None
```

**Step 4:** In `_process_stack` (around lines 318-327), replace the test-config guard and call site:

Old:
```python
    if project_config.test is None:
        raise NoPhaseTestConfigError(
            f"No test configuration for project at {project_config.path}"
        )
    ...
    test_config = project_config.test
    ...
    passed, failed_phase = run_test_phases(test_config, project_path)
```

New:
```python
    if not _has_test_config(project_config):
        raise NoTestConfigError(
            f"No test configuration for project at {project_config.path}"
        )
    ...
    # Delete the `test_config = project_config.test` line entirely
    ...
    passed, failed_phase = run_test_phases(project_config, project_path)
```

Add a helper near the top of the module (after imports):

```python
def _has_test_config(project_config: ProjectConfig) -> bool:
    """Return True if any test phase is configured."""
    return any([
        project_config.test_unit,
        project_config.test_integration,
        project_config.test_component,
    ])
```

**Step 5:** Find and update any import of `NoPhaseTestConfigError` to `NoTestConfigError`. Check `cli.py` and tests.

### Subtask 1.3: Update cli.py

**Step 1:** Update call sites that pass `proj_config.test` to `run_test_phases`. There are two (lines 315 and 673):

Old: `run_test_phases(proj_config.test, proj_config.path)`
New: `run_test_phases(proj_config, proj_config.path)`

**Step 2:** Replace `_require_test_config` (lines 420-425):

```python
def _require_test_config(project: str, proj_config: ProjectConfig) -> None:
    if not _has_test_config(proj_config):
        _fatal(
            f"No test configuration for [bold]{project}[/]. "
            f"Add test_unit to [projects.{project}] in ~/.mm/config.toml."
        )
```

This requires importing `_has_test_config` from `updater`:

```python
from maintenance_man.updater import (
    ...
    _has_test_config,
    ...
)
```

### Subtask 1.4: Update tests

**Step 1:** Rewrite `tests/test_models_config.py`. Delete `TestPhaseTestConfig` and `TestProjectConfigWithTest`. Replace with:

```python
from pathlib import Path

import pytest
from pydantic import ValidationError

from maintenance_man.models.config import ProjectConfig


class TestProjectConfigTestFields:
    def test_no_test_fields(self):
        pc = ProjectConfig(path=Path("/tmp/x"), package_manager="bun")
        assert pc.test_unit is None
        assert pc.test_integration is None
        assert pc.test_component is None

    def test_unit_only(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"), package_manager="uv", test_unit="uv run pytest"
        )
        assert pc.test_unit == "uv run pytest"
        assert pc.test_integration is None

    def test_all_phases(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="bun",
            test_unit="bun test",
            test_integration="bun run test:integration",
            test_component="bun run test:component",
        )
        assert pc.test_unit == "bun test"
        assert pc.test_integration == "bun run test:integration"
        assert pc.test_component == "bun run test:component"

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError, match="unknown"):
            ProjectConfig(
                path=Path("/tmp/x"), package_manager="bun", unknown="bad"
            )
```

**Step 2:** Update `tests/test_updater.py`:

- Line 8: Change import from `PhaseTestConfig, ProjectConfig` to just `ProjectConfig`
- Lines 65-71: Update `project_config` fixture:
  ```python
  @pytest.fixture()
  def project_config(tmp_path: Path) -> ProjectConfig:
      return ProjectConfig(
          path=tmp_path,
          package_manager="bun",
          test_unit="bun test",
      )
  ```
- Lines 207-212: Update `test_all_green`:
  ```python
  tc = ProjectConfig(
      path=tmp_path,
      package_manager="bun",
      test_unit="bun test",
      test_integration="bun run test:integration",
  )
  passed, failed_phase = run_test_phases(tc, tmp_path)
  ```
- Line 223-224: Update `test_unit_fails`:
  ```python
  tc = ProjectConfig(path=tmp_path, package_manager="bun", test_unit="bun test")
  passed, failed_phase = run_test_phases(tc, tmp_path)
  ```
- Lines 242-243: Update `test_integration_fails`:
  ```python
  tc = ProjectConfig(
      path=tmp_path,
      package_manager="bun",
      test_unit="bun test",
      test_integration="bun run test:integration",
  )
  passed, failed_phase = run_test_phases(tc, tmp_path)
  ```
- Lines 256-257: Update `test_skips_unconfigured_phases`:
  ```python
  tc = ProjectConfig(
      path=tmp_path, package_manager="bun", test_unit="bun test"
  )  # no integration or component
  passed, _ = run_test_phases(tc, tmp_path)
  ```

**Step 3:** Search for any remaining references to `NoPhaseTestConfigError` in tests and update to `NoTestConfigError`.

### Subtask 1.5: Run ruff and full test suite

**Step 1:** Run import sorting:
```
ruff check --fix src/maintenance_man/ tests/
```

**Step 2:** Run full test suite:
```
uv run pytest -v
```

Expected: All tests pass with no import errors or failures.
