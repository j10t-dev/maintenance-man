# mm update — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use 1337-skills:executing-plans to implement this plan task-by-task.

**Goal:** Implement `mm update <project>` — load scan results, interactive selection, apply updates via Graphite stacked branches, run test phases, optionally submit.

**Architecture:** Scan results are loaded from `~/.mm/scan-results/<project>.json`. Vuln fixes get independent branches off main via `gt create`. Bumps are stacked in risk-ascending order (patch → minor → major). Each update runs the project's configured test phases (unit required, integration/component optional). On bump failure the stack stops; vuln failures are independent. The user is prompted to submit via `gt submit --stack` at the end.

**Tech Stack:** Python 3.12, Pydantic v2, Cyclopts, Rich, subprocess (gt, bun/uv/mvn)

**Skills to Use:**
- 1337-skills:test-driven-development
- 1337-skills:verification-before-completion

**Required Files:** (executor will auto-read these)
- @src/maintenance_man/models/config.py
- @src/maintenance_man/models/scan.py
- @src/maintenance_man/config.py
- @src/maintenance_man/cli.py
- @src/maintenance_man/scanner.py
- @src/maintenance_man/outdated.py
- @tests/conftest.py
- @tests/test_cli.py
- @tests/test_scan_cli.py
- @pyproject.toml
- @.claude/plans/feat-dep-next-DESIGN.md

---

## Task 1: Add TestConfig model and update ProjectConfig

Extend the config models to support per-project test command configuration.

**Files:**
- Modify: `src/maintenance_man/models/config.py`
- Create: `tests/test_models_config.py`
- Modify: `tests/conftest.py`

### Subtask 1.1: Write failing tests for TestConfig

**Step 1:** Create `tests/test_models_config.py`:

```python
from pathlib import Path

import pytest
from pydantic import ValidationError

from maintenance_man.models.config import ProjectConfig, TestConfig


class TestTestConfig:
    def test_unit_only(self):
        tc = TestConfig(unit="uv run pytest")
        assert tc.unit == "uv run pytest"
        assert tc.integration is None
        assert tc.component is None

    def test_all_phases(self):
        tc = TestConfig(
            unit="bun test",
            integration="bun run test:integration",
            component="bun run test:component",
        )
        assert tc.unit == "bun test"
        assert tc.integration == "bun run test:integration"
        assert tc.component == "bun run test:component"

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError):
            TestConfig(unit="bun test", unknown="bad")


class TestProjectConfigWithTest:
    def test_project_without_test_config(self):
        pc = ProjectConfig(path=Path("/tmp/x"), package_manager="bun")
        assert pc.test is None

    def test_project_with_test_config(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="bun",
            test=TestConfig(unit="bun test"),
        )
        assert pc.test is not None
        assert pc.test.unit == "bun test"
```

**Step 2:** Run to verify failure:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_models_config.py -v`
Expected: FAIL — `ImportError: cannot import name 'TestConfig'`

### Subtask 1.2: Implement TestConfig

**Step 1:** Add `TestConfig` to `src/maintenance_man/models/config.py`. Insert it before `ProjectConfig`:

```python
class TestConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unit: str
    integration: str | None = None
    component: str | None = None
```

**Step 2:** Add `test: TestConfig | None = None` field to `ProjectConfig`:

The updated `ProjectConfig` should be:
```python
class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Path
    package_manager: Literal["bun", "uv", "mvn"]
    scan_secrets: bool = True
    test: TestConfig | None = None
```

**Step 3:** Run tests:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_models_config.py -v`
Expected: All 5 tests PASS.

**Step 4:** Run full suite to check nothing broke:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All tests PASS.

### Subtask 1.3: Update conftest fixture to include test config

**Step 1:** Update the `mm_home_with_projects` fixture in `tests/conftest.py`. The config TOML needs a `[projects.vulnerable.test]` section. Update the `config_text` variable:

```python
    config_text = f"""\
[defaults]
min_version_age_days = 7

[projects.vulnerable]
path = "{vuln_path}"
package_manager = "uv"

[projects.vulnerable.test]
unit = "uv run pytest"

[projects.clean]
path = "{clean_path}"
package_manager = "uv"

[projects.clean.test]
unit = "uv run pytest"

[projects.outdated]
path = "{clean_path}"
package_manager = "bun"

[projects.outdated.test]
unit = "bun test"
"""
```

**Step 2:** Run full suite:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All tests PASS (config still loads correctly with the new optional field).

---

## Task 2: Updater module — pre-checks and package manager commands

Create the core update logic: pre-flight checks, package manager update commands, test runner, and Graphite integration.

**Files:**
- Create: `src/maintenance_man/updater.py`
- Create: `tests/test_updater.py`

### Subtask 2.1: Write failing tests for pre-checks and helpers

**Step 1:** Create `tests/test_updater.py`. These tests mock all subprocess calls — no real git/gt/package managers needed.

```python
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from maintenance_man.models.config import ProjectConfig, TestConfig
from maintenance_man.models.scan import (
    BumpFinding,
    ScanResult,
    SemverTier,
    Severity,
    VulnFinding,
)
from maintenance_man.updater import (
    GraphiteNotFoundError,
    NoScanResultsError,
    NoTestConfigError,
    RepoDirtyError,
    UpdateResult,
    check_graphite_available,
    check_repo_clean,
    get_update_command,
    load_scan_results,
    run_test_phases,
)


# -- Fixtures --

VULN_FINDING = VulnFinding(
    vuln_id="CVE-2024-0001",
    pkg_name="some-pkg",
    installed_version="1.0.0",
    fixed_version="1.0.1",
    severity=Severity.HIGH,
    title="Test vuln",
    description="desc",
    status="fixed",
)

BUMP_PATCH = BumpFinding(
    pkg_name="pkg-a",
    installed_version="1.0.0",
    latest_version="1.0.1",
    semver_tier=SemverTier.PATCH,
)

BUMP_MINOR = BumpFinding(
    pkg_name="pkg-b",
    installed_version="1.0.0",
    latest_version="1.1.0",
    semver_tier=SemverTier.MINOR,
)

BUMP_MAJOR = BumpFinding(
    pkg_name="pkg-c",
    installed_version="1.0.0",
    latest_version="2.0.0",
    semver_tier=SemverTier.MAJOR,
)


@pytest.fixture()
def project_config(tmp_path: Path) -> ProjectConfig:
    return ProjectConfig(
        path=tmp_path,
        package_manager="bun",
        test=TestConfig(unit="bun test"),
    )


@pytest.fixture()
def scan_result() -> ScanResult:
    return ScanResult(
        project="myapp",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="/tmp/myapp",
        vulnerabilities=[VULN_FINDING],
        bumps=[BUMP_MAJOR, BUMP_PATCH, BUMP_MINOR],
    )


# -- check_graphite_available --

class TestCheckGraphiteAvailable:
    def test_gt_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/gt" if cmd == "gt" else None)
        check_graphite_available()  # should not raise

    def test_gt_not_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        with pytest.raises(GraphiteNotFoundError):
            check_graphite_available()


# -- check_repo_clean --

class TestCheckRepoClean:
    @patch("maintenance_man.updater.subprocess.run")
    def test_clean_repo(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        check_repo_clean(tmp_path)  # should not raise

    @patch("maintenance_man.updater.subprocess.run")
    def test_dirty_repo(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=" M src/file.py\n", stderr=""
        )
        with pytest.raises(RepoDirtyError):
            check_repo_clean(tmp_path)


# -- load_scan_results --

class TestLoadScanResults:
    def test_load_existing(self, scan_results_dir: Path):
        result = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="/tmp/myapp",
        )
        (scan_results_dir / "myapp.json").write_text(
            result.model_dump_json(indent=2), encoding="utf-8"
        )
        loaded = load_scan_results("myapp", scan_results_dir)
        assert loaded.project == "myapp"

    def test_load_missing(self, scan_results_dir: Path):
        with pytest.raises(NoScanResultsError):
            load_scan_results("nonexistent", scan_results_dir)


# -- get_update_command --

class TestGetUpdateCommand:
    def test_bun(self):
        cmd = get_update_command("bun", "axios", "1.7.0")
        assert cmd == ["bun", "add", "axios@1.7.0"]

    def test_uv(self):
        cmd = get_update_command("uv", "requests", "2.32.0")
        assert cmd == ["uv", "add", "requests==2.32.0"]

    def test_mvn(self):
        cmds = get_update_command("mvn", "org.example:lib", "3.0.0")
        assert cmds == [
            "mvn", "versions:use-dep-version",
            "-Dincludes=org.example:lib",
            "-DdepVersion=3.0.0",
        ]


# -- run_test_phases --

class TestRunTestPhases:
    @patch("maintenance_man.updater.subprocess.run")
    def test_all_green(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        tc = TestConfig(
            unit="bun test",
            integration="bun run test:integration",
        )
        passed, failed_phase = run_test_phases(tc, tmp_path)
        assert passed is True
        assert failed_phase is None
        assert mock_run.call_count == 2

    @patch("maintenance_man.updater.subprocess.run")
    def test_unit_fails(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="FAIL", stderr=""
        )
        tc = TestConfig(unit="bun test")
        passed, failed_phase = run_test_phases(tc, tmp_path)
        assert passed is False
        assert failed_phase == "unit"
        assert mock_run.call_count == 1

    @patch("maintenance_man.updater.subprocess.run")
    def test_integration_fails(self, mock_run: MagicMock, tmp_path: Path):
        def side_effect(*args, **kwargs):
            cmd_str = " ".join(args[0])
            if "integration" in cmd_str:
                return subprocess.CompletedProcess(
                    args=[], returncode=1, stdout="", stderr=""
                )
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )

        mock_run.side_effect = side_effect
        tc = TestConfig(unit="bun test", integration="bun run test:integration")
        passed, failed_phase = run_test_phases(tc, tmp_path)
        assert passed is False
        assert failed_phase == "integration"

    @patch("maintenance_man.updater.subprocess.run")
    def test_skips_unconfigured_phases(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        tc = TestConfig(unit="bun test")  # no integration or component
        passed, _ = run_test_phases(tc, tmp_path)
        assert passed is True
        assert mock_run.call_count == 1  # only unit
```

**Step 2:** Run to verify failure:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_updater.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'maintenance_man.updater'`

### Subtask 2.2: Implement the updater module

**Step 1:** Create `src/maintenance_man/updater.py`:

```python
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from rich import print as rprint

from maintenance_man.models.config import ProjectConfig, TestConfig
from maintenance_man.models.scan import (
    BumpFinding,
    ScanResult,
    SemverTier,
    VulnFinding,
)


class GraphiteNotFoundError(Exception):
    pass


class RepoDirtyError(Exception):
    pass


class NoScanResultsError(Exception):
    pass


class NoTestConfigError(Exception):
    pass


@dataclass
class UpdateResult:
    """Tracks the outcome of a single update attempt."""

    pkg_name: str
    kind: str  # "vuln" or "bump"
    passed: bool
    failed_phase: str | None = None
    skipped: bool = False


def check_graphite_available() -> None:
    """Raise GraphiteNotFoundError if gt is not on PATH."""
    if shutil.which("gt") is None:
        raise GraphiteNotFoundError(
            "Graphite CLI (gt) is not installed or not on PATH. "
            "Install it from https://graphite.dev/docs/installing-the-cli"
        )


def check_repo_clean(project_path: Path) -> None:
    """Raise RepoDirtyError if the git repo has uncommitted changes."""
    completed = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        cwd=project_path,
        timeout=30,
    )
    if completed.stdout.strip():
        raise RepoDirtyError(
            f"Repository has uncommitted changes:\n{completed.stdout.strip()}"
        )


def load_scan_results(project_name: str, results_dir: Path) -> ScanResult:
    """Load scan results JSON for a project. Raises NoScanResultsError if missing."""
    safe_name = project_name.replace("/", "_").replace("\\", "_").replace("..", "_")
    results_file = results_dir / f"{safe_name}.json"
    if not results_file.exists():
        raise NoScanResultsError(
            f"No scan results found for '{project_name}'. "
            f"Run 'mm scan {project_name}' first."
        )
    data = json.loads(results_file.read_text(encoding="utf-8"))
    return ScanResult.model_validate(data)


def get_update_command(
    package_manager: str, pkg_name: str, version: str
) -> list[str]:
    """Return the shell command to update a package to a specific version."""
    if package_manager == "bun":
        return ["bun", "add", f"{pkg_name}@{version}"]
    elif package_manager == "uv":
        return ["uv", "add", f"{pkg_name}=={version}"]
    elif package_manager == "mvn":
        return [
            "mvn",
            "versions:use-dep-version",
            f"-Dincludes={pkg_name}",
            f"-DdepVersion={version}",
        ]
    else:
        raise ValueError(f"Unsupported package manager: {package_manager}")


def run_test_phases(
    test_config: TestConfig, project_path: Path
) -> tuple[bool, str | None]:
    """Run configured test phases sequentially. Returns (passed, failed_phase).

    Stops on first failure. Returns (True, None) if all phases pass.
    """
    phases = [
        ("unit", test_config.unit),
        ("integration", test_config.integration),
        ("component", test_config.component),
    ]
    for phase_name, command in phases:
        if command is None:
            continue
        completed = subprocess.run(
            command.split(),
            cwd=project_path,
            timeout=600,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            return False, phase_name
    return True, None


def _apply_update(
    package_manager: str, pkg_name: str, version: str, project_path: Path
) -> bool:
    """Apply a single package update. Returns True on success."""
    cmd = get_update_command(package_manager, pkg_name, version)
    completed = subprocess.run(
        cmd,
        cwd=project_path,
        timeout=300,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        rprint(
            f"  [bold red]FAIL[/] Package manager command failed: "
            f"{' '.join(cmd)}\n  {completed.stderr.strip()}"
        )
        return False

    # Maven needs a second command to finalise
    if package_manager == "mvn":
        commit = subprocess.run(
            ["mvn", "versions:commit"],
            cwd=project_path,
            timeout=120,
            capture_output=True,
            text=True,
        )
        if commit.returncode != 0:
            rprint(
                f"  [bold red]FAIL[/] mvn versions:commit failed: "
                f"{commit.stderr.strip()}"
            )
            return False
    return True


def _gt_create(message: str, project_path: Path) -> bool:
    """Create a Graphite branch. Returns True on success."""
    completed = subprocess.run(
        ["gt", "create", "-a", "-m", message],
        cwd=project_path,
        timeout=60,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        rprint(
            f"  [bold red]FAIL[/] gt create failed: {completed.stderr.strip()}"
        )
        return False
    return True


def _gt_checkout_main(project_path: Path) -> None:
    """Return to main branch."""
    subprocess.run(
        ["gt", "checkout", "main"],
        cwd=project_path,
        timeout=30,
        capture_output=True,
        text=True,
    )


def sort_bumps_by_risk(bumps: list[BumpFinding]) -> list[BumpFinding]:
    """Sort bumps risk-ascending: PATCH < MINOR < MAJOR < UNKNOWN."""
    order = {
        SemverTier.PATCH: 0,
        SemverTier.MINOR: 1,
        SemverTier.MAJOR: 2,
        SemverTier.UNKNOWN: 3,
    }
    return sorted(bumps, key=lambda b: order.get(b.semver_tier, 99))


def process_vulns(
    vulns: list[VulnFinding],
    project_config: ProjectConfig,
) -> list[UpdateResult]:
    """Process vuln fixes as independent branches off main.

    Each vuln gets its own branch. Failures don't block other vulns.
    """
    results: list[UpdateResult] = []
    project_path = Path(project_config.path)
    test_config = project_config.test

    for v in vulns:
        if not v.actionable:
            continue

        rprint(
            f"\n  [bold red]VULN[/] {v.pkg_name} {v.installed_version} "
            f"-> {v.fixed_version} ({v.vuln_id})"
        )

        # Return to main before each vuln (independent branches)
        _gt_checkout_main(project_path)

        msg = (
            f"fix: upgrade {v.pkg_name} "
            f"{v.installed_version} -> {v.fixed_version} "
            f"for {v.vuln_id}"
        )

        if not _apply_update(
            project_config.package_manager,
            v.pkg_name,
            v.fixed_version,
            project_path,
        ):
            results.append(
                UpdateResult(
                    pkg_name=v.pkg_name,
                    kind="vuln",
                    passed=False,
                    failed_phase="apply",
                )
            )
            continue

        if not _gt_create(msg, project_path):
            results.append(
                UpdateResult(
                    pkg_name=v.pkg_name,
                    kind="vuln",
                    passed=False,
                    failed_phase="gt-create",
                )
            )
            continue

        passed, failed_phase = run_test_phases(test_config, project_path)
        if passed:
            rprint(f"  [bold green]PASS[/] {v.pkg_name}")
        else:
            rprint(f"  [bold red]FAIL[/] {v.pkg_name} — {failed_phase} failed")

        results.append(
            UpdateResult(
                pkg_name=v.pkg_name,
                kind="vuln",
                passed=passed,
                failed_phase=failed_phase,
            )
        )

    # Return to main after all vulns
    _gt_checkout_main(project_path)
    return results


def process_bumps(
    bumps: list[BumpFinding],
    project_config: ProjectConfig,
) -> list[UpdateResult]:
    """Process bumps as a Graphite stack, risk-ascending.

    Stops on first failure. Remaining bumps are marked as skipped.
    """
    results: list[UpdateResult] = []
    project_path = Path(project_config.path)
    test_config = project_config.test
    sorted_bumps = sort_bumps_by_risk(bumps)
    failed = False

    for b in sorted_bumps:
        if failed:
            results.append(
                UpdateResult(
                    pkg_name=b.pkg_name, kind="bump", passed=False, skipped=True
                )
            )
            continue

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
            failed = True
            continue

        msg = (
            f"bump: {b.pkg_name} "
            f"{b.installed_version} -> {b.latest_version} "
            f"({b.semver_tier.value})"
        )
        if not _gt_create(msg, project_path):
            results.append(
                UpdateResult(
                    pkg_name=b.pkg_name,
                    kind="bump",
                    passed=False,
                    failed_phase="gt-create",
                )
            )
            failed = True
            continue

        passed, failed_phase = run_test_phases(test_config, project_path)
        if passed:
            rprint(f"  [bold green]PASS[/] {b.pkg_name}")
        else:
            rprint(
                f"  [bold red]FAIL[/] {b.pkg_name} — {failed_phase} failed"
            )
            failed = True

        results.append(
            UpdateResult(
                pkg_name=b.pkg_name,
                kind="bump",
                passed=passed,
                failed_phase=failed_phase,
            )
        )

    return results


def submit_stack(project_path: Path) -> bool:
    """Run gt submit --stack. Returns True on success."""
    completed = subprocess.run(
        ["gt", "submit", "--stack"],
        cwd=project_path,
        timeout=120,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0
```

**Step 2:** Run tests:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_updater.py -v`
Expected: All tests PASS.

**Step 3:** Run full suite:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All tests PASS.

---

## Task 3: Tests for process_vulns, process_bumps, and sort_bumps_by_risk

Add tests for the higher-level orchestration functions. These mock subprocess calls and gt commands.

**Files:**
- Modify: `tests/test_updater.py`

### Subtask 3.1: Write tests for sort_bumps_by_risk

**Step 1:** Append to `tests/test_updater.py`:

```python
from maintenance_man.updater import sort_bumps_by_risk


class TestSortBumpsByRisk:
    def test_sorts_patch_minor_major(self):
        bumps = [BUMP_MAJOR, BUMP_PATCH, BUMP_MINOR]
        sorted_b = sort_bumps_by_risk(bumps)
        assert [b.semver_tier for b in sorted_b] == [
            SemverTier.PATCH,
            SemverTier.MINOR,
            SemverTier.MAJOR,
        ]

    def test_empty_list(self):
        assert sort_bumps_by_risk([]) == []

    def test_single_bump(self):
        result = sort_bumps_by_risk([BUMP_MINOR])
        assert len(result) == 1
        assert result[0].semver_tier == SemverTier.MINOR
```

**Step 2:** Run:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_updater.py::TestSortBumpsByRisk -v`
Expected: All 3 tests PASS.

### Subtask 3.2: Write tests for process_vulns

**Step 1:** Append to `tests/test_updater.py`:

```python
from maintenance_man.updater import process_vulns


class TestProcessVulns:
    @patch("maintenance_man.updater._gt_checkout_main")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_single_vuln_passes(
        self, mock_test, mock_apply, mock_gt, mock_checkout,
        project_config: ProjectConfig,
    ):
        results = process_vulns([VULN_FINDING], project_config)
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].kind == "vuln"

    @patch("maintenance_man.updater._gt_checkout_main")
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch(
        "maintenance_man.updater.run_test_phases",
        return_value=(False, "unit"),
    )
    def test_vuln_test_fails_continues(
        self, mock_test, mock_apply, mock_gt, mock_checkout,
        project_config: ProjectConfig,
    ):
        vuln2 = VULN_FINDING.model_copy(
            update={"vuln_id": "CVE-2024-0002", "pkg_name": "other-pkg"}
        )
        results = process_vulns([VULN_FINDING, vuln2], project_config)
        assert len(results) == 2
        assert results[0].passed is False
        assert results[1].passed is False  # both fail, but both attempted
        assert mock_apply.call_count == 2  # both were attempted

    @patch("maintenance_man.updater._gt_checkout_main")
    @patch("maintenance_man.updater._apply_update", return_value=False)
    def test_vuln_apply_fails(
        self, mock_apply, mock_checkout, project_config: ProjectConfig,
    ):
        results = process_vulns([VULN_FINDING], project_config)
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].failed_phase == "apply"
```

**Step 2:** Run:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_updater.py::TestProcessVulns -v`
Expected: All 3 tests PASS.

### Subtask 3.3: Write tests for process_bumps

**Step 1:** Append to `tests/test_updater.py`:

```python
from maintenance_man.updater import process_bumps


class TestProcessBumps:
    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_all_bumps_pass(
        self, mock_test, mock_apply, mock_gt, project_config: ProjectConfig,
    ):
        bumps = [BUMP_MAJOR, BUMP_PATCH, BUMP_MINOR]
        results = process_bumps(bumps, project_config)
        # All 3 pass, sorted as patch -> minor -> major
        assert len(results) == 3
        assert all(r.passed for r in results)
        # Verify sort order via call order
        names = [r.pkg_name for r in results]
        assert names == ["pkg-a", "pkg-b", "pkg-c"]  # patch, minor, major

    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases")
    def test_bump_failure_stops_stack(
        self, mock_test, mock_apply, mock_gt, project_config: ProjectConfig,
    ):
        # Patch passes, minor fails
        mock_test.side_effect = [(True, None), (False, "unit")]
        bumps = [BUMP_PATCH, BUMP_MINOR, BUMP_MAJOR]
        results = process_bumps(bumps, project_config)

        assert len(results) == 3
        assert results[0].passed is True  # patch passed
        assert results[1].passed is False  # minor failed
        assert results[1].failed_phase == "unit"
        assert results[2].skipped is True  # major skipped

    @patch("maintenance_man.updater._gt_create", return_value=True)
    @patch("maintenance_man.updater._apply_update", return_value=True)
    @patch("maintenance_man.updater.run_test_phases", return_value=(True, None))
    def test_empty_bumps(
        self, mock_test, mock_apply, mock_gt, project_config: ProjectConfig,
    ):
        results = process_bumps([], project_config)
        assert results == []
```

**Step 2:** Run:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_updater.py::TestProcessBumps -v`
Expected: All 3 tests PASS.

**Step 3:** Run full suite:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All tests PASS.

---

## Task 4: CLI integration — wire up `mm update`

Replace the stub `update` command with the real implementation using the updater module. Add interactive selection via Rich prompts.

**Files:**
- Modify: `src/maintenance_man/cli.py`
- Create: `tests/test_update_cli.py`
- Modify: `tests/test_cli.py` (remove update stub tests)

### Subtask 4.1: Write failing tests for the update CLI command

**Step 1:** Create `tests/test_update_cli.py`. These tests mock the updater module functions — no real git/gt/package managers.

```python
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.cli import app
from maintenance_man.models.scan import (
    BumpFinding,
    ScanResult,
    SemverTier,
    Severity,
    VulnFinding,
)
from maintenance_man.updater import UpdateResult


def _make_scan_result() -> ScanResult:
    return ScanResult(
        project="vulnerable",
        scanned_at=datetime.now(tz=timezone.utc),
        trivy_target="tests/fixtures/vulnerable-project",
        vulnerabilities=[
            VulnFinding(
                vuln_id="CVE-2024-0001",
                pkg_name="some-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.HIGH,
                title="Test vuln",
                description="desc",
                status="fixed",
            ),
        ],
        bumps=[
            BumpFinding(
                pkg_name="pkg-a",
                installed_version="1.0.0",
                latest_version="1.0.1",
                semver_tier=SemverTier.PATCH,
            ),
        ],
    )


@pytest.fixture(autouse=True)
def _mock_updater(monkeypatch: pytest.MonkeyPatch):
    """Mock all updater pre-checks to pass by default."""
    monkeypatch.setattr(
        "maintenance_man.cli.check_graphite_available", lambda: None
    )
    monkeypatch.setattr(
        "maintenance_man.cli.check_repo_clean", lambda p: None
    )
    monkeypatch.setattr(
        "maintenance_man.cli.load_scan_results",
        lambda name, d: _make_scan_result(),
    )


class TestUpdatePreChecks:
    def test_no_scan_results_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.updater import NoScanResultsError
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results",
            MagicMock(side_effect=NoScanResultsError("No results")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1

    def test_dirty_repo_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.updater import RepoDirtyError
        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            MagicMock(side_effect=RepoDirtyError("dirty")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1

    def test_no_gt_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        from maintenance_man.updater import GraphiteNotFoundError
        monkeypatch.setattr(
            "maintenance_man.cli.check_graphite_available",
            MagicMock(side_effect=GraphiteNotFoundError("no gt")),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1

    def test_no_test_config_exits_1(
        self, mm_home_with_projects: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """Project without test config should refuse to proceed."""
        from maintenance_man.models.config import ProjectConfig
        monkeypatch.setattr(
            "maintenance_man.cli.resolve_project",
            MagicMock(return_value=ProjectConfig(
                path=Path("/tmp/x"), package_manager="bun", test=None
            )),
        )
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 1


class TestUpdateSelection:
    @patch("maintenance_man.cli.process_vulns", return_value=[])
    @patch("maintenance_man.cli.process_bumps", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="none")
    def test_none_selection_exits_0(
        self, mock_ask, mock_bumps, mock_vulns,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_not_called()
        mock_bumps.assert_not_called()

    @patch("maintenance_man.cli.submit_stack")
    @patch("maintenance_man.cli.Confirm.ask", return_value=False)
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ],
    )
    @patch("maintenance_man.cli.process_bumps", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="vulns")
    def test_vulns_selection(
        self, mock_ask, mock_bumps, mock_vulns, mock_confirm, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        mock_vulns.assert_called_once()
        mock_bumps.assert_not_called()


class TestUpdateExitCodes:
    @patch("maintenance_man.cli.submit_stack")
    @patch("maintenance_man.cli.Confirm.ask", return_value=False)
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
    def test_all_pass_exits_0(
        self, mock_ask, mock_bumps, mock_vulns, mock_confirm, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0

    @patch("maintenance_man.cli.submit_stack")
    @patch("maintenance_man.cli.Confirm.ask", return_value=False)
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
    def test_any_failure_exits_4(
        self, mock_ask, mock_bumps, mock_vulns, mock_confirm, mock_submit,
        mm_home_with_projects: Path,
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 4
```

**Step 2:** Run to verify failure:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_update_cli.py -v`
Expected: FAIL — the update command still prints "Not implemented."

### Subtask 4.2: Implement the update CLI command

**Step 1:** Update `src/maintenance_man/cli.py`. Replace the `update` stub function. Add the necessary imports at the top of the file:

Add these imports (alongside existing ones):
```python
from rich.prompt import Confirm, Prompt
```

And from the updater module:
```python
from maintenance_man.updater import (
    GraphiteNotFoundError,
    NoScanResultsError,
    NoTestConfigError,
    RepoDirtyError,
    check_graphite_available,
    check_repo_clean,
    load_scan_results,
    process_bumps,
    process_vulns,
    submit_stack,
)
```

Replace the `update` function body with:

```python
@app.command
def update(
    project: str,
) -> None:
    """Apply updates from scan results to a project.

    Parameters
    ----------
    project: str
        Project name to update.
    """
    config = load_config()
    proj_config = resolve_project(config, project)

    # Pre-checks
    try:
        check_graphite_available()
    except GraphiteNotFoundError as e:
        rprint(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    try:
        check_repo_clean(proj_config.path)
    except RepoDirtyError as e:
        rprint(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    results_dir = MM_HOME / "scan-results"
    try:
        scan_result = load_scan_results(project, results_dir)
    except NoScanResultsError as e:
        rprint(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    if proj_config.test is None:
        rprint(
            f"[bold red]Error:[/] No test configuration for [bold]{project}[/]. "
            f"Add a [projects.{project}.test] section to ~/.mm/config.toml."
        )
        sys.exit(1)

    # Collect actionable findings
    actionable_vulns = [v for v in scan_result.vulnerabilities if v.actionable]
    bumps = scan_result.bumps

    if not actionable_vulns and not bumps:
        rprint(f"[bold green]{project}[/] — nothing to update.")
        sys.exit(0)

    # Display findings with numbers
    _print_scan_result(scan_result)

    # Interactive selection
    choices = "all"
    if actionable_vulns and bumps:
        choices = "all/vulns/bumps/none"
    elif actionable_vulns:
        choices = "all/vulns/none"
    elif bumps:
        choices = "all/bumps/none"

    selection = Prompt.ask(
        f"\n  Select updates [{choices}]",
        default="all",
    )

    selected_vulns: list = []
    selected_bumps: list = []

    if selection == "none":
        sys.exit(0)
    elif selection == "all":
        selected_vulns = actionable_vulns
        selected_bumps = bumps
    elif selection == "vulns":
        selected_vulns = actionable_vulns
    elif selection == "bumps":
        selected_bumps = bumps

    # Process vulns (independent branches)
    vuln_results = []
    if selected_vulns:
        rprint(f"\n[bold]Processing {len(selected_vulns)} vuln fix(es)...[/]")
        vuln_results = process_vulns(selected_vulns, proj_config)

    # Process bumps (stacked, risk-ascending)
    bump_results = []
    if selected_bumps:
        rprint(f"\n[bold]Processing {len(selected_bumps)} bump(s)...[/]")
        bump_results = process_bumps(selected_bumps, proj_config)

    # Summary
    all_results = vuln_results + bump_results
    passed = [r for r in all_results if r.passed]
    failed = [r for r in all_results if not r.passed and not r.skipped]
    skipped = [r for r in all_results if r.skipped]

    rprint(f"\n[bold]Summary:[/]")
    if passed:
        rprint(f"  [green]{len(passed)} passed[/]")
    if failed:
        rprint(f"  [red]{len(failed)} failed[/]")
    if skipped:
        rprint(f"  [dim]{len(skipped)} skipped[/]")

    # Submit prompt
    if passed and Confirm.ask("\n  Submit stack?", default=False):
        if submit_stack(Path(proj_config.path)):
            rprint("  [bold green]Stack submitted.[/]")
        else:
            rprint("  [bold red]Submit failed.[/]")

    has_failures = any(not r.passed and not r.skipped for r in all_results)
    sys.exit(4 if has_failures else 0)
```

Also add this import at the top of `cli.py`:
```python
from maintenance_man.config import MM_HOME, load_config, resolve_project
```

(Update the existing import from `maintenance_man.config` to include `MM_HOME`.)

**Step 2:** Remove the update stub tests from `tests/test_cli.py`. Delete the entire `TestUpdateStub` class.

**Step 3:** Run the new update CLI tests:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_update_cli.py -v`
Expected: All tests PASS.

**Step 4:** Run full suite:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All tests PASS.

**Step 5:** Run linter:

Run: `cd /home/glykon/dev/maintenance-man && uv run ruff check src/ tests/`
Expected: No errors.

---

## Task 5: Numbered selection and integration polish

Add support for comma-separated number selection (e.g. `1,3,5`) and end-to-end integration test.

**Files:**
- Modify: `src/maintenance_man/cli.py`
- Modify: `tests/test_update_cli.py`

### Subtask 5.1: Write failing test for numbered selection

**Step 1:** Add to `tests/test_update_cli.py`:

```python
class TestUpdateNumberedSelection:
    @patch("maintenance_man.cli.submit_stack")
    @patch("maintenance_man.cli.Confirm.ask", return_value=False)
    @patch(
        "maintenance_man.cli.process_vulns",
        return_value=[
            UpdateResult(pkg_name="some-pkg", kind="vuln", passed=True)
        ],
    )
    @patch("maintenance_man.cli.process_bumps", return_value=[])
    @patch("maintenance_man.cli.Prompt.ask", return_value="1")
    def test_select_by_number(
        self, mock_ask, mock_bumps, mock_vulns, mock_confirm, mock_submit,
        mm_home_with_projects: Path,
    ):
        """Selecting '1' should pick the first finding."""
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "vulnerable"])
        assert exc_info.value.code == 0
        # Should have called process_vulns with the first vuln
        mock_vulns.assert_called_once()
```

**Step 2:** Run to verify it fails (current code doesn't handle numeric input):

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_update_cli.py::TestUpdateNumberedSelection -v`
Expected: FAIL or unexpected behaviour.

### Subtask 5.2: Implement numbered selection

**Step 1:** Update the selection logic in the `update` function in `src/maintenance_man/cli.py`. After printing scan results and before the `Prompt.ask`, number each finding. Then parse numeric input.

Add a helper function before the `update` command:

```python
def _print_numbered_findings(
    vulns: list[VulnFinding], bumps: list[BumpFinding]
) -> list[tuple[str, VulnFinding | BumpFinding]]:
    """Print numbered list of findings. Returns ordered list of (kind, finding)."""
    numbered: list[tuple[str, VulnFinding | BumpFinding]] = []
    idx = 1
    for v in vulns:
        rprint(
            f"  [dim]{idx:>3}.[/] [bold red]VULN[/] {v.pkg_name} "
            f"{v.installed_version} -> {v.fixed_version} ({v.vuln_id})"
        )
        numbered.append(("vuln", v))
        idx += 1
    for b in bumps:
        rprint(
            f"  [dim]{idx:>3}.[/] [bold cyan]BUMP[/] {b.pkg_name} "
            f"{b.installed_version} -> {b.latest_version} ({b.semver_tier.value})"
        )
        numbered.append(("bump", b))
        idx += 1
    return numbered


def _parse_selection(
    selection: str,
    numbered: list[tuple[str, VulnFinding | BumpFinding]],
    actionable_vulns: list[VulnFinding],
    bumps: list[BumpFinding],
) -> tuple[list[VulnFinding], list[BumpFinding]]:
    """Parse user selection string into vuln and bump lists."""
    if selection == "none":
        return [], []
    if selection == "all":
        return actionable_vulns, bumps
    if selection == "vulns":
        return actionable_vulns, []
    if selection == "bumps":
        return [], bumps

    # Try comma-separated numbers
    selected_vulns: list[VulnFinding] = []
    selected_bumps: list[BumpFinding] = []
    try:
        indices = [int(s.strip()) for s in selection.split(",")]
    except ValueError:
        return actionable_vulns, bumps  # fallback to all

    for i in indices:
        if 1 <= i <= len(numbered):
            kind, finding = numbered[i - 1]
            if kind == "vuln":
                selected_vulns.append(finding)
            else:
                selected_bumps.append(finding)

    return selected_vulns, selected_bumps
```

Then update the `update` command to use these helpers: replace the section after `_print_scan_result(scan_result)` with calls to `_print_numbered_findings` and `_parse_selection`.

**Step 2:** Run tests:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_update_cli.py -v`
Expected: All tests PASS.

**Step 3:** Run full suite:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All tests PASS.

**Step 4:** Run linter:

Run: `cd /home/glykon/dev/maintenance-man && uv run ruff check src/ tests/`
Expected: No errors.
