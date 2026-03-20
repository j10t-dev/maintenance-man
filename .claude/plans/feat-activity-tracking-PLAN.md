# Activity Tracking Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Track last build/deploy per project and surface it in `mm list`.

**Architecture:** Single `~/.mm/activity.json` file stores latest build/deploy event per project (timestamp, success, branch). Recording is fire-and-forget — never crashes the CLI. `mm list` table updated: Path column removed, "Pkg Mgr" renamed to "Type", new "Built" and "Deployed" columns added.

**Tech Stack:** Python, Pydantic, Rich tables, cyclopts CLI

**Skills to Use:**
- test-driven-development
- verification-before-completion

**Required Files:** (executor will auto-read these)
- @src/maintenance_man/models/scan.py (Pydantic model patterns)
- @src/maintenance_man/config.py (MM_HOME, ensure_mm_home)
- @src/maintenance_man/deployer.py (run_build, run_deploy, BuildError, DeployError)
- @src/maintenance_man/cli.py (build, deploy, list_projects commands)
- @tests/conftest.py (mm_home fixture)
- @tests/test_list.py (existing list tests)
- @tests/test_deploy_cli.py (existing deploy tests)
- @tests/test_build_cli.py (existing build tests)

---

## Task 1: Activity model and persistence layer

Create the Pydantic model and load/save functions for activity data. This is the foundation — other tasks depend on it.

**Files:**
- Create: `src/maintenance_man/models/activity.py`
- Create: `tests/test_activity.py`

### Subtask 1.1: Write activity model tests

**Step 1:** Create `tests/test_activity.py` with tests for the model and persistence:

```python
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from maintenance_man.models.activity import ActivityEvent, ProjectActivity, load_activity, record_activity


_TS = datetime(2026, 3, 20, 14, 32, tzinfo=timezone.utc)


class TestActivityEvent:
    def test_timestamp_truncated_to_minutes(self):
        """Seconds and microseconds stripped from timestamp."""
        event = ActivityEvent(
            timestamp=datetime(2026, 3, 20, 14, 32, 45, 123456, tzinfo=timezone.utc),
            success=True,
            branch="main",
        )
        assert event.timestamp == datetime(2026, 3, 20, 14, 32, tzinfo=timezone.utc)
        assert event.timestamp.second == 0
        assert event.timestamp.microsecond == 0


class TestLoadActivity:
    def test_returns_empty_dict_when_file_missing(self, tmp_path: Path):
        result = load_activity(tmp_path / "activity.json")
        assert result == {}

    def test_returns_empty_dict_when_file_corrupt(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        path.write_text("NOT JSON")
        result = load_activity(path)
        assert result == {}

    def test_loads_valid_activity(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        data = {
            "myapp": {
                "last_build": {
                    "timestamp": "2026-03-20T14:32:00Z",
                    "success": True,
                    "branch": "main",
                },
            },
        }
        path.write_text(json.dumps(data))
        result = load_activity(path)
        assert "myapp" in result
        assert result["myapp"].last_build is not None
        assert result["myapp"].last_build.success is True


class TestRecordActivity:
    def test_records_build_event(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "myapp", "build", success=True, branch="main")
        result = load_activity(path)
        assert result["myapp"].last_build is not None
        assert result["myapp"].last_build.success is True
        assert result["myapp"].last_build.branch == "main"
        assert result["myapp"].last_deploy is None

    def test_records_deploy_event(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "myapp", "deploy", success=False, branch="feat/x")
        result = load_activity(path)
        assert result["myapp"].last_deploy is not None
        assert result["myapp"].last_deploy.success is False
        assert result["myapp"].last_deploy.branch == "feat/x"

    def test_preserves_existing_data(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "myapp", "build", success=True, branch="main")
        record_activity(path, "myapp", "deploy", success=True, branch="main")
        result = load_activity(path)
        assert result["myapp"].last_build is not None
        assert result["myapp"].last_deploy is not None

    def test_preserves_other_projects(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "app-a", "build", success=True, branch="main")
        record_activity(path, "app-b", "deploy", success=True, branch="main")
        result = load_activity(path)
        assert "app-a" in result
        assert "app-b" in result

    def test_overwrites_previous_event(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "myapp", "build", success=True, branch="main")
        record_activity(path, "myapp", "build", success=False, branch="feat/x")
        result = load_activity(path)
        assert result["myapp"].last_build.success is False
        assert result["myapp"].last_build.branch == "feat/x"

    def test_silently_handles_unwritable_path(self, tmp_path: Path):
        """record_activity must not raise even if the file can't be written."""
        path = tmp_path / "nonexistent-dir" / "activity.json"
        # Should not raise
        record_activity(path, "myapp", "build", success=True, branch="main")
```

**Step 2:** Run tests to verify they fail:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_activity.py -v`
Expected: ImportError / ModuleNotFoundError (module doesn't exist yet)

### Subtask 1.2: Implement the activity model

**Step 1:** Create `src/maintenance_man/models/activity.py`:

```python
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, field_validator


class ActivityEvent(BaseModel):
    timestamp: datetime
    success: bool
    branch: str

    @field_validator("timestamp", mode="before")
    @classmethod
    def _truncate_to_minutes(cls, v: datetime) -> datetime:
        if isinstance(v, datetime):
            return v.replace(second=0, microsecond=0)
        return v


class ProjectActivity(BaseModel):
    last_build: ActivityEvent | None = None
    last_deploy: ActivityEvent | None = None


def load_activity(path: Path) -> dict[str, ProjectActivity]:
    """Load activity data from JSON. Returns empty dict on any error."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return {k: ProjectActivity(**v) for k, v in raw.items()}
    except Exception:
        return {}


def record_activity(
    path: Path,
    project: str,
    event_type: Literal["build", "deploy"],
    *,
    success: bool,
    branch: str,
) -> None:
    """Record a build/deploy event. Fire-and-forget — never raises."""
    try:
        activity = load_activity(path)
        proj = activity.get(project, ProjectActivity())
        event = ActivityEvent(
            timestamp=datetime.now(timezone.utc),
            success=success,
            branch=branch,
        )
        if event_type == "build":
            proj.last_build = event
        else:
            proj.last_deploy = event
        activity[project] = proj
        serialised = {
            k: json.loads(v.model_dump_json()) for k, v in activity.items()
        }
        path.write_text(json.dumps(serialised, indent=2), encoding="utf-8")
    except Exception:
        pass
```

**Step 2:** Run tests to verify they pass:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_activity.py -v`
Expected: All PASSED

**Step 3:** Run ruff to fix imports:

Run: `cd /home/glykon/dev/maintenance-man && uv run ruff check --fix src/maintenance_man/models/activity.py tests/test_activity.py`

---

## Task 2: Wire activity recording into build/deploy CLI commands

Hook `record_activity` into the `build` and `deploy` commands. Recording must happen whether the command succeeds or fails, and must never crash the CLI.

**Files:**
- Modify: `src/maintenance_man/cli.py` (build and deploy commands)
- Modify: `tests/test_build_cli.py`
- Modify: `tests/test_deploy_cli.py`

### Subtask 2.1: Write tests for activity recording in build command

**Step 1:** Add tests to `tests/test_build_cli.py`. These test that `record_activity` is called after build succeeds and after build fails:

```python
# Add to existing TestBuildCommand class:

@patch("maintenance_man.cli.record_activity")
@patch("maintenance_man.cli.run_build")
def test_successful_build_records_activity(
    self,
    mock_build: MagicMock,
    mock_record: MagicMock,
    mm_home_with_projects: Path,
) -> None:
    """Successful build records activity event."""
    with pytest.raises(SystemExit):
        app(["build", "deployable"], exit_on_error=False)
    mock_record.assert_called_once()
    _, kwargs = mock_record.call_args
    assert kwargs["success"] is True

@patch("maintenance_man.cli.record_activity")
@patch("maintenance_man.cli.run_build", side_effect=BuildError("build failed"))
def test_failed_build_records_activity(
    self,
    mock_build: MagicMock,
    mock_record: MagicMock,
    mm_home_with_projects: Path,
) -> None:
    """Failed build still records activity event with success=False."""
    with pytest.raises(SystemExit):
        app(["build", "deployable"], exit_on_error=False)
    mock_record.assert_called_once()
    _, kwargs = mock_record.call_args
    assert kwargs["success"] is False
```

**Step 2:** Run to verify they fail:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_build_cli.py -v -k "records_activity"`
Expected: FAIL (record_activity not imported/called yet)

### Subtask 2.2: Write tests for activity recording in deploy command

**Step 1:** Add tests to `tests/test_deploy_cli.py`. Add to existing `TestDeployCommand` class:

```python
# Add to existing TestDeployCommand class:

@patch("maintenance_man.cli.record_activity")
@patch("maintenance_man.cli.run_deploy")
def test_successful_deploy_records_activity(
    self,
    mock_deploy: MagicMock,
    mock_record: MagicMock,
    mm_home_with_projects: Path,
) -> None:
    """Successful deploy records activity event."""
    with pytest.raises(SystemExit):
        app(["deploy", "deployable"], exit_on_error=False)
    mock_record.assert_called_once()
    _, kwargs = mock_record.call_args
    assert kwargs["success"] is True

@patch("maintenance_man.cli.record_activity")
@patch("maintenance_man.cli.run_deploy", side_effect=DeployError("deploy failed"))
def test_failed_deploy_records_activity(
    self,
    mock_deploy: MagicMock,
    mock_record: MagicMock,
    mm_home_with_projects: Path,
) -> None:
    """Failed deploy still records activity event with success=False."""
    with pytest.raises(SystemExit):
        app(["deploy", "deployable"], exit_on_error=False)
    mock_record.assert_called_once()
    _, kwargs = mock_record.call_args
    assert kwargs["success"] is False

@patch("maintenance_man.cli.record_activity")
@patch("maintenance_man.cli.run_deploy")
@patch("maintenance_man.cli.run_build")
def test_deploy_with_build_records_both(
    self,
    mock_build: MagicMock,
    mock_deploy: MagicMock,
    mock_record: MagicMock,
    mm_home_with_projects: Path,
) -> None:
    """--build records both build and deploy events."""
    with pytest.raises(SystemExit):
        app(["deploy", "deployable", "--build"], exit_on_error=False)
    assert mock_record.call_count == 2
    calls = mock_record.call_args_list
    # First call is build, second is deploy
    assert calls[0].args[2] == "build"
    assert calls[1].args[2] == "deploy"
```

**Step 2:** Run to verify they fail:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_deploy_cli.py -v -k "records_activity or records_both"`
Expected: FAIL

### Subtask 2.3: Implement activity recording in CLI

**Step 1:** In `src/maintenance_man/cli.py`, add import:

```python
from maintenance_man.models.activity import record_activity
```

**Step 2:** Add a helper to get branch safely:

```python
def _safe_branch(project_path: Path) -> str:
    """Get current branch, returning 'unknown' on any failure."""
    try:
        return get_current_branch(project_path)
    except Exception:
        return "unknown"
```

**Step 3:** Modify the `build` command (around line 607-639). Replace the try/except block so activity is recorded on both success and failure:

Current code:
```python
    try:
        run_build(project, proj_config.build_command, proj_config.path)
    except BuildError as e:
        _fatal(str(e), code=ExitCode.BUILD_FAILED)

    console.print("\n[bold green]Build succeeded.[/]")
    sys.exit(ExitCode.OK)
```

New code:
```python
    activity_path = _config.MM_HOME / "activity.json"
    success = True
    try:
        run_build(project, proj_config.build_command, proj_config.path)
    except BuildError as e:
        success = False
        record_activity(activity_path, project, "build", success=False, branch=_safe_branch(proj_config.path))
        _fatal(str(e), code=ExitCode.BUILD_FAILED)

    record_activity(activity_path, project, "build", success=True, branch=_safe_branch(proj_config.path))
    console.print("\n[bold green]Build succeeded.[/]")
    sys.exit(ExitCode.OK)
```

**Step 4:** Modify the `deploy` command (around line 507-570). Apply the same pattern to both the build step (when `--build` is used) and the deploy step:

For the build step within deploy (around line 538-544):
```python
    if build and proj_config.build_command:
        console.print(f"[bold]Building {project}[/]\n")
        activity_path = _config.MM_HOME / "activity.json"
        try:
            run_build(project, proj_config.build_command, proj_config.path)
        except BuildError as e:
            record_activity(activity_path, project, "build", success=False, branch=_safe_branch(proj_config.path))
            _fatal(str(e), code=ExitCode.BUILD_FAILED)
        record_activity(activity_path, project, "build", success=True, branch=_safe_branch(proj_config.path))
        console.print("\n[bold green]Build succeeded.[/]\n")
```

For the deploy step (around line 546-553):
```python
    console.print(f"[bold]Deploying {project}[/]\n")
    activity_path = _config.MM_HOME / "activity.json"

    try:
        run_deploy(project, proj_config.deploy_command, proj_config.path)
    except DeployError as e:
        record_activity(activity_path, project, "deploy", success=False, branch=_safe_branch(proj_config.path))
        _fatal(str(e), code=ExitCode.DEPLOY_FAILED)

    record_activity(activity_path, project, "deploy", success=True, branch=_safe_branch(proj_config.path))
    console.print("\n[bold green]Deploy succeeded.[/]")
```

Note: `activity_path` may be assigned twice if `--build` is used — that's fine, it's the same value. If you prefer, hoist it to the top of the function body just after resolving `proj_config`.

**Step 5:** Run tests:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_build_cli.py tests/test_deploy_cli.py -v`
Expected: All PASSED

**Step 6:** Run ruff:

Run: `cd /home/glykon/dev/maintenance-man && uv run ruff check --fix src/maintenance_man/cli.py`

---

## Task 3: Update `mm list` table

Remove Path column, rename "Pkg Mgr" to "Type", add "Built" and "Deployed" columns with relative times and failure markers.

**Files:**
- Modify: `src/maintenance_man/cli.py` (list_projects command, around line 645-714)
- Modify: `tests/test_list.py`

### Subtask 3.1: Write tests for updated list table

**Step 1:** Add tests to `tests/test_list.py`. Import `record_activity`:

```python
from maintenance_man.models.activity import record_activity
```

Add a new test class:

```python
class TestListActivity:
    def test_shows_dash_when_never_built(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Projects with no activity show dash in Built/Deployed columns."""
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "Built" in output
        assert "Deployed" in output

    def test_shows_relative_time_for_build(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Build activity shows relative time."""
        activity_path = list_project_home / "activity.json"
        record_activity(activity_path, "myapp", "build", success=True, branch="main")
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "just now" in output.lower() or "0m ago" in output or "1m ago" in output

    def test_shows_failure_marker(
        self,
        list_project_home: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        """Failed build/deploy shows [F] marker."""
        activity_path = list_project_home / "activity.json"
        record_activity(activity_path, "myapp", "build", success=False, branch="main")
        with pytest.raises(SystemExit) as exc_info:
            app(["list"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "[F]" in output
```

**Step 2:** Update existing tests that check for removed/renamed columns.

In `TestListCommand.test_list_shows_projects` (line 90-98): the test currently asserts `"uv" in output` which will still pass. But it also might check for "Pkg Mgr" text indirectly. Review and update if needed — the column header is now "Type" instead of "Pkg Mgr".

In `TestListFindings.test_shows_never_for_unscanned_projects` (line 102-115): the regex `r"\│\s+never\s+\│"` may need updating since column positions changed. The "never" text in the Scanned column is still present so this should still work, but verify.

**Step 3:** Run to verify new tests fail:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_list.py -v`
Expected: New tests FAIL, existing tests may also fail if they rely on "Path" or "Pkg Mgr" column headers

### Subtask 3.2: Implement list table changes

**Step 1:** In `src/maintenance_man/cli.py`, add import at the top with the other activity import (should already be there from Task 2):

```python
from maintenance_man.models.activity import load_activity, record_activity
```

**Step 2:** Modify the `list_projects` function (around line 645-714). The key changes to the column definitions (around line 678-687):

Replace:
```python
    for col, kw in [
        ("Name", {"style": "bold"}),
        ("Path", {}),
        ("Pkg Mgr", {}),
        ("Vulns", {"justify": "right"}),
        ("Updates", {"justify": "right"}),
        ("Secrets", {"justify": "right"}),
        ("Scanned", {}),
    ]:
        table.add_column(col, **kw)
```

With:
```python
    for col, kw in [
        ("Name", {"style": "bold"}),
        ("Type", {}),
        ("Vulns", {"justify": "right"}),
        ("Updates", {"justify": "right"}),
        ("Secrets", {"justify": "right"}),
        ("Scanned", {}),
        ("Built", {}),
        ("Deployed", {}),
    ]:
        table.add_column(col, **kw)
```

**Step 3:** Load activity data before the table loop. Add after `scan_results` loading (around line 677):

```python
    activity = load_activity(_config.MM_HOME / "activity.json")
```

**Step 4:** Add a helper function to format activity events (place near `_relative_time`):

```python
def _format_activity(event: ActivityEvent | None, now: datetime | None = None) -> str:
    """Format an activity event as relative time with optional failure marker."""
    if event is None:
        return _NO_DATA
    time_str = _relative_time(event.timestamp, now)
    if not event.success:
        return f"{time_str} [red]\\[F][/]"
    return time_str
```

Add the import for `ActivityEvent` at the top:
```python
from maintenance_man.models.activity import ActivityEvent, load_activity, record_activity
```

**Step 5:** Update the `table.add_row` call in the loop (around line 690-707). Replace:

```python
        table.add_row(
            name,
            str(project.path),
            project.package_manager,
            *counts,
        )
```

With:
```python
        proj_activity = activity.get(name)
        table.add_row(
            name,
            project.package_manager,
            *counts,
            _format_activity(proj_activity.last_build if proj_activity else None),
            _format_activity(proj_activity.last_deploy if proj_activity else None),
        )
```

**Step 6:** Run all tests:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_list.py tests/test_build_cli.py tests/test_deploy_cli.py tests/test_activity.py -v`
Expected: All PASSED

**Step 7:** Run ruff:

Run: `cd /home/glykon/dev/maintenance-man && uv run ruff check --fix src/maintenance_man/cli.py tests/test_list.py`

**Step 8:** Run full test suite to catch any regressions:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All PASSED
