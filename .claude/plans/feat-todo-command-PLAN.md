# `mm todo` Command Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Add a `mm todo` CLI command that displays TODO.md content across configured projects.

**Architecture:** Single new `@app.command` in `cli.py` that reads `TODO.md` from each project's `path`. Three display states: content present, file empty, file missing. No new modules, models, or config changes. Uses `rich.text.Text` to avoid Rich markup interpretation of TODO content.

**Tech Stack:** cyclopts, Rich, pytest

**Skills to Use:**
- test-driven-development
- verification-before-completion

**Required Files:**
- @src/maintenance_man/cli.py
- @tests/test_cli.py
- @tests/conftest.py

---

## Task 1: Add `mm todo` command with tests

This is a single task — the implementation is small and all changes are tightly coupled (one function in cli.py + its tests).

**Files:**
- Modify: `tests/test_cli.py` (append new test class)
- Modify: `src/maintenance_man/cli.py` (add `todo` command after the `list_projects` function, before the helpers section)

### Subtask 1.1: Write failing tests

**Step 1:** Append the following test class to `tests/test_cli.py`:

```python
class TestTodoCommand:
    """Tests for mm todo."""

    @pytest.fixture()
    def mm_home_with_todos(self, mm_home: Path) -> Path:
        """mm_home with two projects: 'alpha' has a TODO.md, 'beta' does not."""
        alpha_dir = mm_home.parent / "alpha"
        alpha_dir.mkdir()
        (alpha_dir / "TODO.md").write_text("- Fix the widget\n- Refactor utils\n")

        beta_dir = mm_home.parent / "beta"
        beta_dir.mkdir()

        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text(
            f'[projects.alpha]\npath = "{alpha_dir}"\npackage_manager = "uv"\n\n'
            f'[projects.beta]\npath = "{beta_dir}"\npackage_manager = "uv"\n'
        )
        return mm_home

    def test_todo_all_shows_content(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo shows TODO.md content for projects that have one."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "alpha" in output
        assert "Fix the widget" in output

    def test_todo_all_shows_no_file_message(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo shows 'no TODO.md' for projects without the file."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "beta" in output
        assert "no TODO.md" in output

    def test_todo_all_shows_empty_message(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo shows 'empty' for projects with blank TODO.md."""
        alpha_dir = mm_home_with_todos.parent / "alpha"
        (alpha_dir / "TODO.md").write_text("   \n\n  ")
        with pytest.raises(SystemExit) as exc_info:
            app(["todo"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "alpha" in output
        assert "empty" in output

    def test_todo_single_project_shows_content(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo <project> shows that project's TODO.md."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo", "alpha"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "alpha" in output
        assert "Fix the widget" in output
        assert "beta" not in output

    def test_todo_single_project_no_file(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo <project> with no TODO.md logs missing file, exits 0."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo", "beta"])
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "no TODO.md" in output

    def test_todo_unknown_project_exits_error(self, mm_home_with_todos: Path):
        """mm todo <unknown> exits with error (config error, not missing file)."""
        with pytest.raises(SystemExit) as exc_info:
            app(["todo", "nonexistent"])
        assert exc_info.value.code == 1

    def test_todo_no_projects_configured(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo with no projects configured prints message and exits 0."""
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")
        with pytest.raises(SystemExit) as exc_info:
            app(["todo"])
        assert exc_info.value.code == 0
        assert "no projects" in capsys.readouterr().out.lower()
```

**Step 2:** Run the tests to verify they fail:

Run: `uv run pytest tests/test_cli.py::TestTodoCommand -v`
Expected: FAIL — cyclopts doesn't recognise the `todo` command yet.

### Subtask 1.2: Implement the `todo` command

**Step 1:** Add `Text` to the existing `rich.text` import, or add a new import line:

```python
from rich.text import Text
```

**Step 2:** Add the following function to `src/maintenance_man/cli.py`, after the `list_projects` function (line ~948) and before the `# -- Helpers --` comment:

```python
@app.command
def todo(
    project: str | None = None,
    *,
    config: Path | None = None,
) -> None:
    """Show TODO.md items for projects.

    Parameters
    ----------
    project: str | None
        Project name. Shows all projects if omitted.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)

    if project:
        proj_config = _resolve_proj(cfg, project)
        _print_project_todo(project, proj_config.path)
        return

    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    for name in sorted(cfg.projects):
        _print_project_todo(name, cfg.projects[name].path)
```

**Step 3:** Add the following helper inside the helpers section:

```python
def _print_project_todo(name: str, project_path: Path) -> None:
    """Print a single project's TODO.md content with header."""
    todo_path = project_path / "TODO.md"
    console.print(f"\n[bold]{name}[/]")
    if not todo_path.exists():
        console.print("  [dim]no TODO.md[/]")
        return
    content = todo_path.read_text().strip()
    if not content:
        console.print("  [dim]empty[/]")
        return
    console.print(Text(content))
```

**Step 4:** Run the tests to verify they pass:

Run: `uv run pytest tests/test_cli.py::TestTodoCommand -v`
Expected: All 8 tests PASS.

### Subtask 1.3: Verify full test suite

**Step 1:** Run the entire test suite to check for regressions:

Run: `uv run pytest -v`
Expected: All existing tests still pass.
