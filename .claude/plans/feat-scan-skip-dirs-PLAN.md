# Scan Skip Dirs — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Allow projects to exclude directories from trivy scans via `scan_skip_dirs` config.

**Architecture:** Add `scan_skip_dirs: list[str]` to `ProjectConfig`, thread it through `scan_project()` → `_run_trivy_scan()`, and append `--skip-dirs` flags to the trivy command.

**Tech Stack:** Python, Pydantic, subprocess, pytest

**Skills to Use:**
- test-driven-development
- verification-before-completion

**Required Files:**
- @src/maintenance_man/models/config.py
- @src/maintenance_man/scanner.py
- @tests/test_models_config.py
- @tests/test_scanner.py

---

## Task 1: Add `scan_skip_dirs` to `ProjectConfig` and thread through scanner

All changes are tightly coupled (model → scanner signature → trivy command) and touch related files, so this is a single task.

### Subtask 1.1: Write failing tests

**Step 1:** Add model test in `tests/test_models_config.py`

Add a new test class at the end of the file:

```python
class TestProjectConfigScanSkipDirs:
    def test_defaults_to_empty_list(self):
        pc = ProjectConfig(path=Path("/tmp/x"), package_manager="uv")
        assert pc.scan_skip_dirs == []

    def test_accepts_skip_dirs(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="uv",
            scan_skip_dirs=["tests/fixtures", "vendor"],
        )
        assert pc.scan_skip_dirs == ["tests/fixtures", "vendor"]
```

**Step 2:** Add scanner unit test in `tests/test_scanner.py`

Add a new test class at the end of the file. This patches `subprocess.run` to capture the trivy command and verify `--skip-dirs` flags are included:

```python
class TestRunTrivyScanSkipDirs:
    def test_skip_dirs_appended_to_command(self, scan_results_dir: Path, tmp_path: Path):
        """scan_skip_dirs entries are forwarded as --skip-dirs flags to trivy."""
        project = ProjectConfig(
            path=tmp_path,
            package_manager="uv",
            scan_skip_dirs=["tests/fixtures", "vendor"],
        )
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Results": []}', stderr=""
        )
        with patch("maintenance_man.scanner.subprocess.run", return_value=fake_result) as mock_run:
            scan_project("test-proj", project)

        cmd = mock_run.call_args.args[0]
        # Each skip-dirs entry should produce a --skip-dirs flag
        assert cmd.count("--skip-dirs") == 2
        dirs_indices = [i for i, v in enumerate(cmd) if v == "--skip-dirs"]
        assert cmd[dirs_indices[0] + 1] == "tests/fixtures"
        assert cmd[dirs_indices[1] + 1] == "vendor"

    def test_no_skip_dirs_by_default(self, scan_results_dir: Path, tmp_path: Path):
        """Without scan_skip_dirs, no --skip-dirs flags are added."""
        project = ProjectConfig(path=tmp_path, package_manager="uv")
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"Results": []}', stderr=""
        )
        with patch("maintenance_man.scanner.subprocess.run", return_value=fake_result) as mock_run:
            scan_project("test-proj", project)

        cmd = mock_run.call_args.args[0]
        assert "--skip-dirs" not in cmd
```

Note: add `import subprocess` to the top of `tests/test_scanner.py`.

**Step 3:** Run tests to verify they fail

Run: `uv run pytest tests/test_models_config.py::TestProjectConfigScanSkipDirs tests/test_scanner.py::TestRunTrivyScanSkipDirs -v`
Expected: FAIL — `scan_skip_dirs` field doesn't exist yet, and `scan_project`/`_run_trivy_scan` don't accept it.

### Subtask 1.2: Add `scan_skip_dirs` field to `ProjectConfig`

**Step 1:** In `src/maintenance_man/models/config.py`, add to `ProjectConfig`:

```python
scan_skip_dirs: list[str] = []
```

Place it after the `scan_secrets` field (line 17), before the `test_*` fields.

**Step 2:** Run model tests to verify they pass

Run: `uv run pytest tests/test_models_config.py -v`
Expected: PASS

### Subtask 1.3: Thread `scan_skip_dirs` through `scanner.py`

**Step 1:** Update `_run_trivy_scan` signature to accept `skip_dirs: list[str]`

In `src/maintenance_man/scanner.py`, change the function signature:

```python
def _run_trivy_scan(
    project_path: Path,
    scan_secrets: bool,
    skip_dirs: list[str] | None = None,
) -> tuple[list[VulnFinding], list[SecretFinding]]:
```

**Step 2:** Build `--skip-dirs` flags into the command

After the existing `cmd` list construction (after the `"."` entry), add:

```python
    for d in skip_dirs or []:
        cmd.extend(["--skip-dirs", d])
```

**Step 3:** Pass `scan_skip_dirs` from `scan_project` to `_run_trivy_scan`

In `scan_project`, change the call on line ~46 from:

```python
vulns, secrets = _run_trivy_scan(project_path, project.scan_secrets)
```

to:

```python
vulns, secrets = _run_trivy_scan(project_path, project.scan_secrets, project.scan_skip_dirs)
```

**Step 4:** Run all tests

Run: `uv run pytest tests/test_models_config.py tests/test_scanner.py -v`
Expected: ALL PASS

**Step 5:** Run full suite

Run: `uv run pytest`
Expected: ALL PASS (no regressions)

### Subtask 1.4: Lint

Run: `ruff check --fix src/maintenance_man/models/config.py src/maintenance_man/scanner.py tests/test_models_config.py tests/test_scanner.py`
Expected: Clean or auto-fixed
