# Mass Update Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Allow `mm update` with no project argument to update all configured projects sequentially, auto-selecting all findings.

**Architecture:** The existing `update` command gets its `project` parameter made optional. When omitted, we loop over all projects (like `scan` does), skip those without scan results or actionable findings, and call `_update_one` for each. A cross-project summary table is printed at the end.

**Tech Stack:** Python, cyclopts, Rich tables

**Skills to Use:**
- test-driven-development
- verification-before-completion

**Required Files:**
- @src/maintenance_man/cli.py
- @tests/test_update_cli.py
- @tests/conftest.py

---

## Task 1: Tests for mass-update behaviour

All tests go in `tests/test_update_cli.py`. The existing test infrastructure (`mm_home_with_projects`, `_mock_updater`, `_make_scan_result`) provides 4 projects: `vulnerable`, `clean`, `outdated`, `no-tests`.

**Files:**
- Modify: `tests/test_update_cli.py`

### Subtask 1.1: Test --continue without project errors

**Step 1:** Add a test to the `TestUpdateContinue` class:

```python
def test_continue_without_project_exits_1(
    self,
    mm_home_with_projects: Path,
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        app(["update", "--continue"])
    assert exc_info.value.code == 1
```

**Step 2:** Run test to confirm it fails (update currently requires project):

Run: `uv run pytest tests/test_update_cli.py::TestUpdateContinue::test_continue_without_project_exits_1 -v`
Expected: FAIL (cyclopts will error because project is required)

### Subtask 1.2: Test update-all skips projects without scan results

**Step 1:** Add a new test class `TestUpdateAll`:

```python
class TestUpdateAll:
    """Tests for `mm update` with no project argument (batch mode)."""

    def test_skips_projects_without_scan_results(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Projects with no scan data are skipped silently."""
        # Override the autouse _mock_updater's load_scan_results to raise for all
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("No results")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code == 0
```

Note: will need to add `NoScanResultsError` to the imports at the top of the test file:
```python
from maintenance_man.updater import NoScanResultsError, UpdateResult
```

**Step 2:** Run test to confirm it fails:

Run: `uv run pytest tests/test_update_cli.py::TestUpdateAll::test_skips_projects_without_scan_results -v`
Expected: FAIL

### Subtask 1.3: Test update-all processes projects and shows summary

**Step 1:** Add test for the happy path — all projects processed:

```python
def test_processes_all_projects(
    self,
    mm_home_with_projects: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """All projects with scan results get processed; summary table printed."""
    mock_vulns = MagicMock(
        return_value=[UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)]
    )
    mock_updates = MagicMock(
        return_value=[UpdateResult(pkg_name="pkg-a", kind="update", passed=True)]
    )
    monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
    monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)

    with pytest.raises(SystemExit) as exc_info:
        app(["update"])
    assert exc_info.value.code == 0
```

**Step 2:** Run test to confirm it fails:

Run: `uv run pytest tests/test_update_cli.py::TestUpdateAll::test_processes_all_projects -v`
Expected: FAIL

### Subtask 1.4: Test update-all with failures exits 4

**Step 1:** Add test for mixed pass/fail across projects:

```python
def test_any_failure_exits_4(
    self,
    mm_home_with_projects: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_vulns = MagicMock(
        return_value=[
            UpdateResult(
                pkg_name="some-pkg",
                kind="vuln",
                passed=False,
                failed_phase="test_unit",
            )
        ]
    )
    mock_updates = MagicMock(
        return_value=[UpdateResult(pkg_name="pkg-a", kind="update", passed=True)]
    )
    monkeypatch.setattr("maintenance_man.cli.process_vulns", mock_vulns)
    monkeypatch.setattr("maintenance_man.cli.process_updates", mock_updates)

    with pytest.raises(SystemExit) as exc_info:
        app(["update"])
    assert exc_info.value.code == 4
```

**Step 2:** Run test:

Run: `uv run pytest tests/test_update_cli.py::TestUpdateAll::test_any_failure_exits_4 -v`
Expected: FAIL

### Subtask 1.5: Test that single-project mode still works unchanged

**Step 1:** Run the existing test suite to confirm nothing is broken as a baseline:

Run: `uv run pytest tests/test_update_cli.py -v`
Expected: All existing tests PASS

---

## Task 2: Implement mass-update in CLI

**Files:**
- Modify: `src/maintenance_man/cli.py`

### Subtask 2.1: Extract `_update_one` from `update`

Extract the per-project processing logic (lines ~160–260 of `update`) into a helper function. This function handles: loading scan results, collecting actionable findings, calling process_vulns/process_updates, and returning results. It does NOT handle interactive selection (that stays in single-project mode only).

**Step 1:** Add the `_update_one` function after the `update` function (it's a private helper):

```python
def _update_one(
    project: str,
    proj_config: ProjectConfig,
    results_dir: Path,
) -> list[UpdateResult]:
    """Process all actionable findings for a single project.

    Returns the list of update results (may be empty if nothing to do).
    Handles repo clean check, graphite sync, scan result loading internally.
    """
    try:
        check_repo_clean(proj_config.path)
    except RepoDirtyError as e:
        console.print(f"[bold yellow]Warning:[/] {project} — {e}")
        if Confirm.ask("  Discard changes and reset to main?", default=False):
            reset_to_main(proj_config.path)
        else:
            console.print(f"  [dim]Skipping {project}[/]")
            return []

    if not sync_graphite(proj_config.path):
        console.print(f"  [bold red]Error:[/] {project} — failed to sync trunk")
        return []

    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError:
        return []

    if not _has_test_config(proj_config):
        console.print(
            f"  [dim]Skipping {project} — no test configuration[/]"
        )
        return []

    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    updates = scan_result.updates

    if not actionable_vulns and not updates:
        console.print(f"  [dim]{project} — nothing to update[/]")
        return []

    _print_scan_result(scan_result)

    vuln_results: list[UpdateResult] = []
    if actionable_vulns:
        console.print(f"\n[bold]Processing {len(actionable_vulns)} vuln fix(es)...[/]")
        vuln_results = process_vulns(
            actionable_vulns,
            proj_config,
            scan_result=scan_result,
            project_name=project,
            results_dir=results_dir,
        )

    update_results: list[UpdateResult] = []
    if updates:
        console.print(f"\n[bold]Processing {len(updates)} update(s)...[/]")
        update_results = process_updates(
            updates,
            proj_config,
            scan_result=scan_result,
            project_name=project,
            results_dir=results_dir,
        )

    return vuln_results + update_results
```

Note: you'll need to import `_has_test_config` from `updater` — check if it's already imported, if not add it. Actually, looking at `_require_test_config` in cli.py, it calls `_has_test_config` from updater. The import for `_has_test_config` may need to be added.

Check the import: look for `_has_test_config` in the imports at the top of cli.py. If missing, add it to the updater import block.

### Subtask 2.2: Modify `update` command signature and add batch path

**Step 1:** Change the `update` function signature and add the all-projects branch:

```python
@app.command
def update(
    project: str | None = None,
    *,
    continue_: Annotated[bool, cyclopts.Parameter(name="--continue")] = False,
    config: Path | None = None,
) -> None:
    """Apply updates from scan results to a project.

    Parameters
    ----------
    project: str | None
        Project name to update. Updates all projects if omitted.
    continue_: bool
        Re-test a manually fixed failed finding on the current branch.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)

    if continue_ and not project:
        _fatal("--continue requires a project name.")

    try:
        check_graphite_available()
    except GraphiteNotFoundError as e:
        _fatal(str(e))

    if project:
        # --- Single-project mode (existing behaviour) ---
        _update_single(cfg, project, continue_=continue_, config=config)
    else:
        # --- All-projects mode ---
        _update_all(cfg)
```

### Subtask 2.3: Rename existing single-project logic into `_update_single`

Move the existing single-project body (everything after the graphite check in the current `update` function) into `_update_single(cfg, project, *, continue_, config)`. This preserves interactive selection and --continue support exactly as-is. The function signature:

```python
def _update_single(
    cfg: MmConfig,
    project: str,
    *,
    continue_: bool = False,
    config: Path | None = None,
) -> NoReturn:
```

This is a pure extract — the body is the existing code from `update` starting from `proj_config = _resolve_proj(cfg, project)` through `sys.exit(...)`. No logic changes.

### Subtask 2.4: Implement `_update_all`

```python
def _update_all(cfg: MmConfig) -> NoReturn:
    """Update all configured projects, auto-selecting all findings."""
    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        sys.exit(ExitCode.OK)

    results_dir = _config.MM_HOME / "scan-results"
    all_project_results: list[tuple[str, list[UpdateResult]]] = []

    for name, proj_config in sorted(cfg.projects.items()):
        if not proj_config.path.exists():
            console.print(
                f"[bold yellow]Warning:[/] {name} — "
                f"path does not exist: {proj_config.path}"
            )
            continue

        console.print(f"\n{'═' * 40}")
        console.print(f"[bold]{name}[/]")
        console.print("═" * 40)

        results = _update_one(name, proj_config, results_dir)
        if results:
            all_project_results.append((name, results))

    # Cross-project summary
    _print_mass_update_summary(all_project_results)

    any_failed = any(
        not r.passed for _, results in all_project_results for r in results
    )
    sys.exit(ExitCode.UPDATE_FAILED if any_failed else ExitCode.OK)
```

### Subtask 2.5: Implement `_print_mass_update_summary`

```python
def _print_mass_update_summary(
    project_results: list[tuple[str, list[UpdateResult]]],
) -> None:
    """Print a cross-project summary table."""
    if not project_results:
        console.print("\n[dim]No projects had actionable findings.[/]")
        return

    table = Table(title="Update Summary")
    table.add_column("Project", style="bold")
    table.add_column("Package")
    table.add_column("Kind")
    table.add_column("Result")

    for proj_name, results in project_results:
        for r in results:
            status = "[green]PASS[/]" if r.passed else f"[red]FAIL ({r.failed_phase})[/]"
            table.add_row(proj_name, r.pkg_name, r.kind, status)

    console.print()
    console.print(table)
```

### Subtask 2.6: Run all tests

Run: `uv run pytest tests/test_update_cli.py -v`
Expected: All tests PASS (both existing single-project tests and new mass-update tests)

Run: `uv run pytest tests/ -v`
Expected: Full suite PASS

### Subtask 2.7: Lint

Run: `ruff check --fix src/maintenance_man/cli.py`
Run: `ruff check tests/test_update_cli.py`
