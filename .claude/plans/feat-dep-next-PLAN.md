# mm update — Recovery & Continuation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use 1337-skills:executing-plans to implement this plan task-by-task.

**Goal:** Add update status tracking to scan results, skip-and-continue for failed bumps, and a `--continue` flag to re-test manually fixed branches.

**Architecture:** Scan results become both input and output — each finding gains an `update_status` field (`null | started | completed | failed`). `mm scan` writes `null`; `mm update` writes status back after each finding. Bumps that fail tests have their branch deleted from the Graphite stack (`gt delete -f`) and processing continues with remaining bumps. `--continue` re-tests the current branch against a `failed` finding and optionally submits the stack when all failures are resolved.

**Tech Stack:** Python 3.12, Pydantic v2, cyclopts, Rich, Graphite CLI

**Skills to Use:**
- 1337-skills:test-driven-development
- 1337-skills:verification-before-completion

**Required Files:** (executor will auto-read these)
- @src/maintenance_man/models/scan.py
- @src/maintenance_man/updater.py
- @src/maintenance_man/cli.py
- @src/maintenance_man/scanner.py
- @src/maintenance_man/models/config.py
- @tests/test_updater.py
- @tests/test_update_cli.py
- @tests/conftest.py
- @.claude/plans/feat-dep-next-DESIGN.md

---

## Task 1: Add `update_status` field to finding models

The model field, serialisation default, and scan-writer behaviour must be consistent. Existing scan results JSON that lacks the field will deserialise fine via Pydantic defaults.

**Files:**
- Modify: `src/maintenance_man/models/scan.py`
- Create: `tests/test_models.py`

### Subtask 1.1: Write failing tests for `update_status` field

**Step 1:** Create `tests/test_models.py`:

```python
from maintenance_man.models.scan import (
    BumpFinding,
    SemverTier,
    Severity,
    UpdateStatus,
    VulnFinding,
)


class TestUpdateStatus:
    def test_vuln_finding_default_status_is_none(self):
        v = VulnFinding(
            vuln_id="CVE-2024-0001",
            pkg_name="some-pkg",
            installed_version="1.0.0",
            fixed_version="1.0.1",
            severity=Severity.HIGH,
            title="Test vuln",
            description="desc",
            status="fixed",
        )
        assert v.update_status is None

    def test_bump_finding_default_status_is_none(self):
        b = BumpFinding(
            pkg_name="pkg-a",
            installed_version="1.0.0",
            latest_version="1.0.1",
            semver_tier=SemverTier.PATCH,
        )
        assert b.update_status is None

    def test_vuln_finding_accepts_all_statuses(self):
        for status in UpdateStatus:
            v = VulnFinding(
                vuln_id="CVE-2024-0001",
                pkg_name="some-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.HIGH,
                title="Test vuln",
                description="desc",
                status="fixed",
                update_status=status,
            )
            assert v.update_status == status

    def test_bump_finding_serialises_null_status(self):
        b = BumpFinding(
            pkg_name="pkg-a",
            installed_version="1.0.0",
            latest_version="1.0.1",
            semver_tier=SemverTier.PATCH,
        )
        data = b.model_dump()
        assert "update_status" in data
        assert data["update_status"] is None
```

**Step 2:** Run tests to verify they fail:

Run: `uv run pytest tests/test_models.py -v`
Expected: FAIL — `UpdateStatus` does not exist, `update_status` field not on models.

### Subtask 1.2: Implement `UpdateStatus` and add field to models

**Step 1:** In `src/maintenance_man/models/scan.py`, add this enum after the existing `SemverTier` class:

```python
class UpdateStatus(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
```

**Step 2:** Add `update_status: UpdateStatus | None = None` field to `VulnFinding` (after `published_date`).

**Step 3:** Add the same field to `BumpFinding` (after `published_date`).

**Step 4:** Run tests:

Run: `uv run pytest tests/test_models.py -v`
Expected: PASS

**Step 5:** Run full test suite to check nothing broke:

Run: `uv run pytest -v`
Expected: All existing tests pass. The new field defaults to `None`, so existing test fixtures and scan result JSON deserialise fine.

---

## Task 2: Add `save_scan_results`, `_gt_delete`, and update processors

This task adds the persistence function, branch deletion, and changes both `process_vulns` and `process_bumps` to: (a) skip failures instead of halting, (b) delete failed branches, and (c) remove the `skipped` concept.

**Files:**
- Modify: `src/maintenance_man/updater.py`
- Modify: `src/maintenance_man/cli.py` (remove `skipped` references from summary)
- Modify: `tests/test_updater.py`
- Modify: `tests/test_update_cli.py`

### Subtask 2.1: Write failing tests for `save_scan_results`

**Step 1:** Add to `tests/test_updater.py`. Import `save_scan_results` at the top (alongside existing updater imports). Add:

```python
class TestSaveScanResults:
    def test_writes_json_to_disk(self, scan_results_dir: Path, scan_result: ScanResult):
        save_scan_results("myapp", scan_results_dir, scan_result)
        import json
        data = json.loads(
            (scan_results_dir / "myapp.json").read_text(encoding="utf-8")
        )
        assert data["project"] == "myapp"

    def test_preserves_update_status(self, scan_results_dir: Path):
        from maintenance_man.models.scan import UpdateStatus
        result = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
            bumps=[
                BumpFinding(
                    pkg_name="pkg-a",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    semver_tier=SemverTier.PATCH,
                    update_status=UpdateStatus.COMPLETED,
                ),
            ],
        )
        save_scan_results("myapp", scan_results_dir, result)
        import json
        data = json.loads(
            (scan_results_dir / "myapp.json").read_text(encoding="utf-8")
        )
        assert data["bumps"][0]["update_status"] == "completed"
```

**Step 2:** Run to verify failure:

Run: `uv run pytest tests/test_updater.py::TestSaveScanResults -v`
Expected: FAIL — `save_scan_results` does not exist.

### Subtask 2.2: Implement `save_scan_results`

**Step 1:** Add to `src/maintenance_man/updater.py`, after `load_scan_results`:

```python
def save_scan_results(
    project_name: str, results_dir: Path, scan_result: ScanResult
) -> None:
    """Write scan results (with update statuses) back to disk."""
    safe_name = project_name.replace("/", "_").replace("\\", "_").replace("..", "_")
    results_file = results_dir / f"{safe_name}.json"
    results_file.write_text(
        scan_result.model_dump_json(indent=2), encoding="utf-8"
    )
```

**Step 2:** Run:

Run: `uv run pytest tests/test_updater.py::TestSaveScanResults -v`
Expected: PASS

### Subtask 2.3: Write failing tests for `_gt_delete` and updated `process_bumps`

**Step 1:** Replace `TestProcessBumps.test_bump_failure_stops_stack` in `tests/test_updater.py` with:

```python
    @patch("maintenance_man.updater._gt_delete")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases")
    def test_bump_failure_skips_and_continues(
        self, mock_test, mock_apply, mock_gt, mock_delete,
        project_config: ProjectConfig,
    ):
        # Patch passes, minor fails, major passes
        mock_test.side_effect = [(True, None), (False, "unit"), (True, None)]
        bumps = [BUMP_PATCH, BUMP_MINOR, BUMP_MAJOR]
        results = process_bumps(bumps, project_config)

        assert len(results) == 3
        assert results[0].passed is True   # patch passed
        assert results[1].passed is False  # minor failed
        assert results[1].failed_phase == "unit"
        assert results[2].passed is True   # major still attempted and passed
        mock_delete.assert_called_once()  # failed branch deleted
```

**Step 2:** Run to verify failure:

Run: `uv run pytest tests/test_updater.py::TestProcessBumps::test_bump_failure_skips_and_continues -v`
Expected: FAIL — `_gt_delete` does not exist, current `process_bumps` stops on failure.

### Subtask 2.4: Implement `_gt_delete` and update `process_bumps`

**Step 1:** Add `_gt_delete` to `src/maintenance_man/updater.py`, after `_gt_create`:

```python
def _gt_delete(branch_name: str, project_path: Path) -> bool:
    """Delete a Graphite branch. Returns True on success."""
    completed = subprocess.run(
        ["gt", "delete", "-f", branch_name],
        cwd=project_path,
        timeout=30,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        rprint(
            f"  [bold yellow]Warning:[/] gt delete {branch_name} failed: "
            f"{completed.stderr.strip()}"
        )
        return False
    return True
```

**Step 2:** Update `process_bumps` — remove the `failed` flag and `skipped` early-continue. On test failure, call `_gt_delete(f"bump/{b.pkg_name}", project_path)` and continue. The full updated function:

```python
def process_bumps(
    bumps: list[BumpFinding],
    project_config: ProjectConfig,
) -> list[UpdateResult]:
    """Process bumps as a Graphite stack, risk-ascending.

    Failures are deleted from the stack and processing continues.
    """
    if project_config.test is None:
        raise NoPhaseTestConfigError(
            f"No test configuration for project at {project_config.path}"
        )

    results: list[UpdateResult] = []
    project_path = Path(project_config.path)
    test_config = project_config.test
    sorted_bumps = sort_bumps_by_risk(bumps)

    for b in sorted_bumps:
        rprint(
            f"\n  [bold cyan]BUMP[/] {b.pkg_name} {b.installed_version} "
            f"-> {b.latest_version} ({b.semver_tier.value})"
        )

        if not _apply_update(
            project_config.package_manager,
            b.pkg_name,
            b.latest_version,
            project_path,
        ):
            results.append(
                UpdateResult(
                    pkg_name=b.pkg_name,
                    kind="bump",
                    passed=False,
                    failed_phase="apply",
                )
            )
            continue

        msg = (
            f"bump: {b.pkg_name} "
            f"{b.installed_version} -> {b.latest_version} "
            f"({b.semver_tier.value})"
        )
        if not _gt_create(msg, f"bump/{b.pkg_name}", project_path):
            results.append(
                UpdateResult(
                    pkg_name=b.pkg_name,
                    kind="bump",
                    passed=False,
                    failed_phase="gt-create",
                )
            )
            continue

        passed, failed_phase = run_test_phases(test_config, project_path)
        if passed:
            rprint(f"  [bold green]PASS[/] {b.pkg_name}")
        else:
            rprint(
                f"  [bold red]FAIL[/] {b.pkg_name} — {failed_phase} failed"
            )
            _gt_delete(f"bump/{b.pkg_name}", project_path)

        results.append(
            UpdateResult(
                pkg_name=b.pkg_name,
                kind="bump",
                passed=passed,
                failed_phase=failed_phase,
            )
        )

    return results
```

**Step 3:** Remove `skipped` from `UpdateResult`:

```python
@dataclass
class UpdateResult:
    """Tracks the outcome of a single update attempt."""

    pkg_name: str
    kind: str  # "vuln" or "bump"
    passed: bool
    failed_phase: str | None = None
```

**Step 4:** Run:

Run: `uv run pytest tests/test_updater.py::TestProcessBumps -v`
Expected: PASS

### Subtask 2.5: Update `process_vulns` to delete failed branches

**Step 1:** Update `test_vuln_test_fails_continues` in `tests/test_updater.py` to mock `_gt_delete` and assert it's called:

```python
    @patch("maintenance_man.updater._gt_delete")
    @patch("maintenance_man.updater._gt_checkout_main")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch(
        "maintenance_man.updater.run_test_phases",
        return_value=(False, "unit"),
    )
    def test_vuln_test_fails_continues(
        self, mock_test, mock_apply, mock_gt, mock_checkout, mock_delete,
        project_config: ProjectConfig,
    ):
        vuln2 = VULN_FINDING.model_copy(
            update={"vuln_id": "CVE-2024-0002", "pkg_name": "other-pkg"}
        )
        results = process_vulns([VULN_FINDING, vuln2], project_config)
        assert len(results) == 2
        assert results[0].passed is False
        assert results[1].passed is False
        assert mock_apply.call_count == 2
        assert mock_delete.call_count == 2  # both failed branches deleted
```

**Step 2:** In `src/maintenance_man/updater.py`, in `process_vulns`, add `_gt_delete(f"fix/{v.pkg_name}", project_path)` after the test failure `rprint`.

**Step 3:** Run:

Run: `uv run pytest tests/test_updater.py::TestProcessVulns -v`
Expected: PASS

### Subtask 2.6: Update CLI summary — remove `skipped` references

**Step 1:** In `src/maintenance_man/cli.py`, replace the summary section (around lines 374-395):

Replace:
```python
    passed = [r for r in all_results if r.passed]
    failed = [r for r in all_results if not r.passed and not r.skipped]
    skipped = [r for r in all_results if r.skipped]

    rprint("\n[bold]Summary:[/]")
    if passed:
        rprint(f"  [green]{len(passed)} passed[/]")
    if failed:
        rprint(f"  [red]{len(failed)} failed[/]")
    if skipped:
        rprint(f"  [dim]{len(skipped)} skipped[/]")
```

With:
```python
    passed = [r for r in all_results if r.passed]
    failed = [r for r in all_results if not r.passed]

    rprint("\n[bold]Summary:[/]")
    if passed:
        rprint(f"  [green]{len(passed)} passed[/]")
    if failed:
        rprint(f"  [red]{len(failed)} failed[/]")
```

Replace:
```python
    has_failures = any(not r.passed and not r.skipped for r in all_results)
```

With:
```python
    has_failures = any(not r.passed for r in all_results)
```

**Step 2:** Run full test suite:

Run: `uv run pytest -v`
Expected: All tests pass.

---

## Task 3: Wire status tracking into processors

Now the processors need to update `update_status` on each finding and persist via `save_scan_results` after each one. The processor signatures gain optional kwargs for tracking context.

**Files:**
- Modify: `src/maintenance_man/updater.py`
- Modify: `src/maintenance_man/cli.py` (pass tracking args to processors)
- Modify: `tests/test_updater.py`

### Subtask 3.1: Write failing tests for status tracking

**Step 1:** Add to `tests/test_updater.py`:

```python
class TestStatusTracking:
    @patch("maintenance_man.updater.save_scan_results")
    @patch("maintenance_man.updater._gt_checkout_main")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_vuln_pass_sets_completed(
        self, mock_test, mock_apply, mock_gt, mock_checkout, mock_save,
        project_config: ProjectConfig, scan_result: ScanResult,
    ):
        from maintenance_man.models.scan import UpdateStatus
        process_vulns(
            scan_result.vulnerabilities, project_config,
            scan_result=scan_result, project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.COMPLETED
        mock_save.assert_called()

    @patch("maintenance_man.updater.save_scan_results")
    @patch("maintenance_man.updater._gt_delete")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(False, "unit"))
    def test_bump_fail_sets_failed(
        self, mock_test, mock_apply, mock_gt, mock_delete, mock_save,
        project_config: ProjectConfig, scan_result: ScanResult,
    ):
        from maintenance_man.models.scan import UpdateStatus
        process_bumps(
            scan_result.bumps, project_config,
            scan_result=scan_result, project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        statuses = [b.update_status for b in scan_result.bumps]
        assert UpdateStatus.FAILED in statuses
        mock_save.assert_called()

    @patch("maintenance_man.updater.save_scan_results")
    @patch("maintenance_man.updater._gt_delete")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases")
    def test_started_set_before_processing(
        self, mock_test, mock_apply, mock_gt, mock_delete, mock_save,
        project_config: ProjectConfig, scan_result: ScanResult,
    ):
        """Verify 'started' is set before test execution."""
        from maintenance_man.models.scan import UpdateStatus

        statuses_during_test = []

        def capture_status(*args, **kwargs):
            # Capture bump statuses at the time tests run
            statuses_during_test.extend(
                [b.update_status for b in scan_result.bumps]
            )
            return (True, None)

        mock_test.side_effect = capture_status
        process_bumps(
            scan_result.bumps[:1], project_config,
            scan_result=scan_result, project_name="myapp",
            results_dir=Path("/tmp/fake"),
        )
        assert UpdateStatus.STARTED in statuses_during_test
```

**Step 2:** Run to verify failure:

Run: `uv run pytest tests/test_updater.py::TestStatusTracking -v`
Expected: FAIL — `process_vulns` and `process_bumps` don't accept tracking kwargs.

### Subtask 3.2: Update processor signatures and wire in status tracking

**Step 1:** Add a helper to `src/maintenance_man/updater.py`:

```python
def _persist_status(
    scan_result: ScanResult | None,
    project_name: str,
    results_dir: Path | None,
) -> None:
    """Save scan results if tracking args are provided."""
    if scan_result is not None and results_dir is not None:
        save_scan_results(project_name, results_dir, scan_result)
```

**Step 2:** Update `process_vulns` signature to accept optional tracking kwargs:

```python
def process_vulns(
    vulns: list[VulnFinding],
    project_config: ProjectConfig,
    *,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
```

In the loop, for each vuln `v`:
- Before processing: `v.update_status = UpdateStatus.STARTED; _persist_status(scan_result, project_name, results_dir)`
- On pass: `v.update_status = UpdateStatus.COMPLETED; _persist_status(...)`
- On fail (test or apply or gt-create): `v.update_status = UpdateStatus.FAILED; _persist_status(...)`

Import `UpdateStatus` at the top of `updater.py`:
```python
from maintenance_man.models.scan import (
    ...,
    UpdateStatus,
)
```

**Step 3:** Apply the same pattern to `process_bumps` — same keyword-only args, same `started`/`completed`/`failed` tracking.

**Step 4:** Update `cli.py` to pass tracking args. Change:
```python
        vuln_results = process_vulns(selected_vulns, proj_config)
```
to:
```python
        vuln_results = process_vulns(
            selected_vulns, proj_config,
            scan_result=scan_result, project_name=project,
            results_dir=results_dir,
        )
```
Same for `process_bumps`.

**Step 5:** Run:

Run: `uv run pytest -v`
Expected: All tests pass. Existing tests that don't pass tracking kwargs still work (defaults to `None`, no persistence).

---

## Task 4: Implement `--continue` flag

**Files:**
- Modify: `src/maintenance_man/updater.py` (add `get_current_branch`)
- Modify: `src/maintenance_man/cli.py` (add `--continue` flag and handler)
- Modify: `tests/test_updater.py`
- Modify: `tests/test_update_cli.py`

### Subtask 4.1: Write failing tests for `get_current_branch`

**Step 1:** Add to `tests/test_updater.py`. Import `get_current_branch` at top alongside other updater imports:

```python
class TestGetCurrentBranch:
    @patch("maintenance_man.updater.subprocess.run")
    def test_returns_branch_name(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="bump/pkg-a\n", stderr=""
        )
        assert get_current_branch(tmp_path) == "bump/pkg-a"

    @patch("maintenance_man.updater.subprocess.run")
    def test_strips_whitespace(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="  fix/some-pkg  \n", stderr=""
        )
        assert get_current_branch(tmp_path) == "fix/some-pkg"
```

**Step 2:** Run to verify failure:

Run: `uv run pytest tests/test_updater.py::TestGetCurrentBranch -v`
Expected: FAIL — `get_current_branch` does not exist.

### Subtask 4.2: Implement `get_current_branch`

**Step 1:** Add to `src/maintenance_man/updater.py`, after `check_repo_clean`:

```python
def get_current_branch(project_path: Path) -> str:
    """Return the current git branch name."""
    completed = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=project_path,
        timeout=30,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()
```

**Step 2:** Run:

Run: `uv run pytest tests/test_updater.py::TestGetCurrentBranch -v`
Expected: PASS

### Subtask 4.3: Write failing tests for `--continue` CLI flow

**Step 1:** Add to `tests/test_update_cli.py`. Add these imports at the top if not present:

```python
from maintenance_man.updater import UpdateResult
```

Add the test class:

```python
class TestUpdateContinue:
    def test_continue_no_failures_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue with no failed findings should error."""
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 1

    @patch("maintenance_man.cli.get_current_branch", return_value="bump/pkg-a")
    @patch("maintenance_man.cli.run_test_phases", return_value=(True, None))
    @patch("maintenance_man.cli.save_scan_results")
    @patch("maintenance_man.cli.submit_stack", return_value=True)
    def test_continue_passes_and_submits(
        self, mock_submit, mock_save, mock_test, mock_branch,
        mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue on matching failed branch, tests pass, no other failures -> submit."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        scan_result.bumps[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 0
        mock_test.assert_called_once()
        mock_submit.assert_called_once()

    @patch("maintenance_man.cli.get_current_branch", return_value="bump/pkg-a")
    @patch("maintenance_man.cli.run_test_phases", return_value=(False, "unit"))
    @patch("maintenance_man.cli.save_scan_results")
    def test_continue_fails_again_exits_4(
        self, mock_save, mock_test, mock_branch,
        mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue that fails again should exit 4."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        scan_result.bumps[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 4

    @patch("maintenance_man.cli.get_current_branch", return_value="main")
    def test_continue_branch_mismatch_exits_1(
        self, mock_branch,
        mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue on wrong branch should error."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        scan_result.bumps[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 1

    @patch("maintenance_man.cli.get_current_branch", return_value="fix/some-pkg")
    @patch("maintenance_man.cli.run_test_phases", return_value=(True, None))
    @patch("maintenance_man.cli.save_scan_results")
    @patch("maintenance_man.cli.submit_stack", return_value=True)
    def test_continue_with_remaining_failures_no_submit(
        self, mock_submit, mock_save, mock_test, mock_branch,
        mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """--continue that passes but other failures remain -> no submit, exit 4."""
        from maintenance_man.models.scan import UpdateStatus
        scan_result = _make_scan_result()
        # Vuln is failed (matching current branch), bump is also failed
        scan_result.vulnerabilities[0].update_status = UpdateStatus.FAILED
        scan_result.bumps[0].update_status = UpdateStatus.FAILED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            lambda name, d: scan_result,
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable", "--continue"])
        assert exc_info.value.code == 4
        mock_submit.assert_not_called()
```

**Step 2:** Run to verify failure:

Run: `uv run pytest tests/test_update_cli.py::TestUpdateContinue -v`
Expected: FAIL — `--continue` flag not recognised.

### Subtask 4.4: Implement `--continue` flag

**Step 1:** Update the `update` command signature in `src/maintenance_man/cli.py`. cyclopts uses `Annotated` for parameter customisation. Add to imports:

```python
from typing import Annotated
```

Update the signature:

```python
@app.command
def update(
    project: str,
    *,
    continue_: Annotated[bool, cyclopts.Parameter(name="--continue")] = False,
) -> None:
```

Note: Check cyclopts docs for exact syntax — may differ. The key requirement is that `--continue` maps to the `continue_` parameter.

**Step 2:** Add imports to `cli.py`:

```python
from maintenance_man.updater import (
    ...existing imports...,
    get_current_branch,
    run_test_phases,
    save_scan_results,
)
from maintenance_man.models.scan import UpdateStatus
```

**Step 3:** Add the `--continue` branch early in the `update` function, after loading scan results and the test config check, before interactive selection:

```python
    if continue_:
        # Find failed findings
        failed_vulns = [
            v for v in scan_result.vulnerabilities
            if v.update_status == UpdateStatus.FAILED
        ]
        failed_bumps = [
            b for b in scan_result.bumps
            if b.update_status == UpdateStatus.FAILED
        ]
        if not failed_vulns and not failed_bumps:
            rprint("[bold red]Error:[/] No failed findings to continue.")
            sys.exit(1)

        # Match current branch to a failed finding
        branch = get_current_branch(proj_config.path)
        finding = None
        for v in failed_vulns:
            if branch == f"fix/{v.pkg_name}":
                finding = v
                break
        if finding is None:
            for b in failed_bumps:
                if branch == f"bump/{b.pkg_name}":
                    finding = b
                    break
        if finding is None:
            rprint(
                f"[bold red]Error:[/] Current branch '{branch}' does not "
                f"match any failed finding."
            )
            sys.exit(1)

        # Re-test
        rprint(f"\n[bold]Re-testing {finding.pkg_name} on {branch}...[/]")
        passed, failed_phase = run_test_phases(proj_config.test, proj_config.path)

        if passed:
            finding.update_status = UpdateStatus.COMPLETED
            save_scan_results(project, results_dir, scan_result)
            rprint(f"  [bold green]PASS[/] {finding.pkg_name}")

            # Check remaining failures
            remaining = [
                v for v in scan_result.vulnerabilities
                if v.update_status == UpdateStatus.FAILED
            ] + [
                b for b in scan_result.bumps
                if b.update_status == UpdateStatus.FAILED
            ]
            if not remaining:
                if submit_stack(proj_config.path):
                    rprint("  [bold green]Stack submitted.[/]")
                else:
                    rprint("  [bold red]Submit failed.[/]")
                sys.exit(0)
            else:
                pkg_names = [f.pkg_name for f in remaining]
                rprint(f"\n  [dim]Still failed: {', '.join(pkg_names)}[/]")
                sys.exit(4)
        else:
            rprint(
                f"  [bold red]FAIL[/] {finding.pkg_name} — {failed_phase} failed"
            )
            sys.exit(4)
```

**Step 4:** Run:

Run: `uv run pytest tests/test_update_cli.py::TestUpdateContinue -v`
Expected: PASS

**Step 5:** Run full suite:

Run: `uv run pytest -v`
Expected: All tests pass.

---

## Task 5: Auto-submit when all pass (fresh run)

Currently the fresh run prompts with `Confirm.ask` before submitting. Per design, it should auto-submit when all passed and skip submission when any failed.

**Files:**
- Modify: `src/maintenance_man/cli.py`
- Modify: `tests/test_update_cli.py`

### Subtask 5.1: Write failing tests for auto-submit

**Step 1:** Add to `tests/test_update_cli.py`:

```python
class TestUpdateAutoSubmit:
    @patch("maintenance_man.cli.submit_stack", return_value=True)
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ],
    )
    @patch(
        "maintenance_man.cli.process_bumps",
        return_value=[
            UpdateResult(pkg_name="pkg-a", kind="bump", passed=True)
        ],
    )
    @patch("maintenance_man.cli.Prompt.ask", return_value="all")
    def test_all_pass_auto_submits(
        self, mock_ask, mock_bumps, mock_vulns, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_submit.assert_called_once()

    @patch("maintenance_man.cli.submit_stack")
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(
                pkg_name="some-pkg", kind="vuln", passed=False,
                failed_phase="unit",
            )
        ],
    )
    @patch("maintenance_man.cli.process_bumps", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="all")
    def test_any_failure_no_submit(
        self, mock_ask, mock_bumps, mock_vulns, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4
        mock_submit.assert_not_called()
```

**Step 2:** Run to verify failure:

Run: `uv run pytest tests/test_update_cli.py::TestUpdateAutoSubmit -v`
Expected: Likely FAIL — current code uses `Confirm.ask` before submit.

### Subtask 5.2: Implement auto-submit

**Step 1:** In `src/maintenance_man/cli.py`, replace the submit prompt:

Replace:
```python
    # Submit prompt
    if passed and Confirm.ask("\n  Submit stack?", default=False):
        if submit_stack(proj_config.path):
            rprint("  [bold green]Stack submitted.[/]")
        else:
            rprint("  [bold red]Submit failed.[/]")
```

With:
```python
    # Auto-submit if all passed
    if passed and not failed:
        if submit_stack(proj_config.path):
            rprint("  [bold green]Stack submitted.[/]")
        else:
            rprint("  [bold red]Submit failed.[/]")
```

**Step 2:** Clean up: if `Confirm` is no longer imported elsewhere in `cli.py` (check the dirty-repo prompt — it still uses `Confirm.ask`), keep the import. Otherwise remove it.

**Step 3:** Update existing tests in `TestUpdateSelection` and `TestUpdateExitCodes` that mock `Confirm.ask` for the submit prompt — remove those mocks since the confirm is gone. The dirty-repo test still needs `Confirm.ask` mocked.

**Step 4:** Run:

Run: `uv run pytest -v`
Expected: All tests pass.

Run: `uv run ruff check src/ tests/`
Expected: No lint errors.

---

## Verification

After all tasks are complete:

Run: `uv run pytest -v`
Expected: All tests pass, zero failures.

Run: `uv run ruff check src/ tests/`
Expected: No lint errors.
