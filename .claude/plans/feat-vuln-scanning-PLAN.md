# Vulnerability Scanning Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use 1337-skills:executing-plans to implement this plan task-by-task.

**Goal:** Implement `mm scan [project]` — shell out to Trivy, parse JSON output, write results to disk, print Rich summary.

**Architecture:** Trivy is invoked as a subprocess. Its JSON output is parsed into Pydantic models (`VulnFinding`, `SecretFinding`, `ScanResult`) and written to `~/.mm/scan-results/<project>.json`. The CLI loads config, resolves projects, calls the scanner module, displays results via Rich, and exits with appropriate codes.

**Tech Stack:** Python 3.12, Pydantic v2, Cyclopts, Rich, subprocess (Trivy)

**Skills to Use:**
- 1337-skills:test-driven-development
- 1337-skills:verification-before-completion

**Required Files:** (executor will auto-read these)
- @src/maintenance_man/models/config.py
- @src/maintenance_man/config.py
- @src/maintenance_man/cli.py
- @src/maintenance_man/models/__init__.py
- @src/maintenance_man/__init__.py
- @tests/conftest.py
- @tests/test_cli.py
- @pyproject.toml
- @.claude/plans/feat-vuln-scanning-DESIGN.md

---

## Task 1: Scan Models

Create the Pydantic models for scan findings and results.

**Files:**
- Create: `src/maintenance_man/models/scan.py`
- Modify: `src/maintenance_man/models/__init__.py`
- Create: `tests/test_models_scan.py`

### Subtask 1.1: Write failing tests for scan models

**Step 1:** Create `tests/test_models_scan.py` with model validation tests.

```python
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from maintenance_man.models.scan import (
    ScanResult,
    SecretFinding,
    Severity,
    VulnFinding,
)


def test_vuln_finding_with_fix():
    finding = VulnFinding(
        vuln_id="CVE-2026-23490",
        pkg_name="pyasn1",
        installed_version="0.6.1",
        fixed_version="0.6.2",
        severity=Severity.HIGH,
        title="pyasn1: DoS via malformed RELATIVE-OID",
        description="Memory exhaustion from malformed RELATIVE-OID.",
        status="fixed",
        primary_url="https://avd.aquasec.com/nvd/cve-2026-23490",
        published_date=datetime(2026, 1, 16, tzinfo=timezone.utc),
    )
    assert finding.vuln_id == "CVE-2026-23490"
    assert finding.fixed_version == "0.6.2"
    assert finding.actionable is True


def test_vuln_finding_advisory_no_fix():
    finding = VulnFinding(
        vuln_id="CVE-2025-99999",
        pkg_name="somelib",
        installed_version="1.0.0",
        fixed_version=None,
        severity=Severity.HIGH,
        title="somelib: advisory only",
        description="No fix available.",
        status="affected",
    )
    assert finding.fixed_version is None
    assert finding.actionable is False


def test_vuln_finding_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        VulnFinding(
            vuln_id="CVE-2025-00001",
            pkg_name="pkg",
            installed_version="1.0",
            severity="BOGUS",
            title="t",
            description="d",
            status="fixed",
        )


def test_secret_finding():
    finding = SecretFinding(
        file="creds/service.json",
        rule_id="gcp-service-account",
        title="Google (GCP) Service-account",
        severity="CRITICAL",
    )
    assert finding.rule_id == "gcp-service-account"


def test_scan_result_empty():
    result = ScanResult(
        project="feetfax",
        scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
        trivy_target="/home/user/dev/feetfax",
        vulnerabilities=[],
        secrets=[],
    )
    assert result.has_actionable_vulns is False


def test_scan_result_with_vulns():
    vuln = VulnFinding(
        vuln_id="CVE-2026-23490",
        pkg_name="pyasn1",
        installed_version="0.6.1",
        fixed_version="0.6.2",
        severity=Severity.HIGH,
        title="t",
        description="d",
        status="fixed",
    )
    result = ScanResult(
        project="lifts",
        scanned_at=datetime(2026, 1, 30, tzinfo=timezone.utc),
        trivy_target="/home/user/dev/lifts",
        vulnerabilities=[vuln],
        secrets=[],
    )
    assert result.has_actionable_vulns is True
```

**Step 2:** Run the tests to verify they fail.

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_models_scan.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'maintenance_man.models.scan'`

### Subtask 1.2: Implement scan models

**Step 1:** Create `src/maintenance_man/models/scan.py`:

```python
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class VulnFinding(BaseModel):
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str | None = None
    severity: Severity
    title: str
    description: str
    status: str
    primary_url: str | None = None
    published_date: datetime | None = None

    @property
    def actionable(self) -> bool:
        return self.fixed_version is not None


class SecretFinding(BaseModel):
    file: str
    rule_id: str
    title: str
    severity: str


class ScanResult(BaseModel):
    project: str
    scanned_at: datetime
    trivy_target: str
    vulnerabilities: list[VulnFinding] = []
    secrets: list[SecretFinding] = []

    @property
    def has_actionable_vulns(self) -> bool:
        return any(v.actionable for v in self.vulnerabilities)
```

**Step 2:** Update `src/maintenance_man/models/__init__.py` to export the new models:

```python
from maintenance_man.models.config import DefaultsConfig, MmConfig, ProjectConfig
from maintenance_man.models.scan import ScanResult, SecretFinding, Severity, VulnFinding

__all__ = [
    "DefaultsConfig",
    "MmConfig",
    "ProjectConfig",
    "ScanResult",
    "SecretFinding",
    "Severity",
    "VulnFinding",
]
```

**Step 3:** Run tests to verify they pass.

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_models_scan.py -v`
Expected: All 6 tests PASS.

**Step 4:** Run full test suite to check nothing is broken.

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All tests PASS.

---

## Task 2: Scanner Module

Implement the Trivy invocation, JSON parsing, and results file writing.

**Files:**
- Create: `src/maintenance_man/scanner.py`
- Create: `tests/test_scanner.py`

**Context:** The scanner module has one main public function: `scan_project(name, project_config) -> ScanResult`. It runs `trivy fs --format json --scanners vuln,secret <path>`, parses the JSON, and writes the result to `~/.mm/scan-results/<name>.json`. It also provides `check_trivy_available()` which verifies Trivy is on PATH.

### Subtask 2.1: Write failing integration tests

**Step 1:** Create `tests/test_scanner.py`. These tests run real Trivy against real projects. They assert structural properties, not specific CVE IDs.

```python
import json
from pathlib import Path

import pytest

from maintenance_man.config import MM_HOME
from maintenance_man.models.scan import ScanResult, Severity
from maintenance_man.scanner import TrivyNotFoundError, check_trivy_available, scan_project
from maintenance_man.models.config import ProjectConfig


@pytest.fixture()
def scan_results_dir(mm_home: Path) -> Path:
    """Ensure scan-results directory exists under temp MM_HOME."""
    d = mm_home / "scan-results"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _make_project(path: str, pm: str = "uv") -> ProjectConfig:
    return ProjectConfig(path=Path(path), package_manager=pm)


class TestCheckTrivyAvailable:
    def test_trivy_is_available(self):
        # Should not raise — trivy is installed on this machine
        check_trivy_available()

    def test_trivy_not_available(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("PATH", "/nonexistent")
        with pytest.raises(TrivyNotFoundError):
            check_trivy_available()


class TestScanProject:
    def test_scan_project_with_vulns(self, scan_results_dir: Path):
        """Scan lifts — known to have vulnerabilities."""
        project = _make_project("/home/glykon/dev/lifts")
        result = scan_project("lifts", project)

        assert isinstance(result, ScanResult)
        assert result.project == "lifts"
        assert result.trivy_target == "/home/glykon/dev/lifts"
        assert result.scanned_at is not None
        assert len(result.vulnerabilities) > 0
        assert result.has_actionable_vulns is True

        # Structural checks on findings
        for v in result.vulnerabilities:
            assert v.vuln_id.startswith("CVE-") or v.vuln_id.startswith("GHSA-")
            assert v.pkg_name
            assert v.installed_version
            assert v.severity in Severity
            assert v.title
            assert v.status

    def test_scan_project_clean(self, scan_results_dir: Path):
        """Scan feetfax — expected to be clean."""
        project = _make_project("/home/glykon/dev/feetfax", "bun")
        result = scan_project("feetfax", project)

        assert isinstance(result, ScanResult)
        assert result.project == "feetfax"
        assert len(result.vulnerabilities) == 0
        assert result.has_actionable_vulns is False

    def test_scan_writes_results_file(self, scan_results_dir: Path):
        """Scan should write JSON results to scan-results dir."""
        project = _make_project("/home/glykon/dev/lifts")
        scan_project("lifts", project)

        results_file = scan_results_dir / "lifts.json"
        assert results_file.exists()

        data = json.loads(results_file.read_text())
        assert data["project"] == "lifts"
        assert "vulnerabilities" in data
        assert "secrets" in data

        # Round-trip: the JSON should deserialise back into a ScanResult
        reloaded = ScanResult.model_validate(data)
        assert reloaded.project == "lifts"

    def test_scan_nonexistent_path(self, scan_results_dir: Path):
        """Scan a path that doesn't exist — should raise."""
        project = _make_project("/nonexistent/path")
        with pytest.raises(FileNotFoundError):
            scan_project("ghost", project)
```

**Step 2:** Run tests to verify they fail.

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_scanner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'maintenance_man.scanner'`

### Subtask 2.2: Implement scanner module

**Step 1:** Create `src/maintenance_man/scanner.py`:

```python
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from maintenance_man.config import MM_HOME
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import ScanResult, SecretFinding, Severity, VulnFinding


class TrivyNotFoundError(Exception):
    pass


class TrivyScanError(Exception):
    pass


def check_trivy_available() -> None:
    """Raise TrivyNotFoundError if trivy is not on PATH."""
    if shutil.which("trivy") is None:
        raise TrivyNotFoundError(
            "Trivy is not installed or not on PATH. "
            "Install it from https://trivy.dev/"
        )


def _parse_vulns(results: list[dict]) -> list[VulnFinding]:
    """Extract vulnerability findings from Trivy results."""
    findings: list[VulnFinding] = []
    for result in results:
        if result.get("Class") != "lang-pkgs":
            continue
        for v in result.get("Vulnerabilities") or []:
            severity_raw = v.get("Severity", "UNKNOWN").upper()
            try:
                severity = Severity(severity_raw)
            except ValueError:
                severity = Severity.UNKNOWN

            published = None
            if v.get("PublishedDate"):
                try:
                    published = datetime.fromisoformat(v["PublishedDate"])
                except ValueError:
                    pass

            findings.append(
                VulnFinding(
                    vuln_id=v["VulnerabilityID"],
                    pkg_name=v["PkgName"],
                    installed_version=v["InstalledVersion"],
                    fixed_version=v.get("FixedVersion"),
                    severity=severity,
                    title=v.get("Title", ""),
                    description=v.get("Description", ""),
                    status=v.get("Status", "unknown"),
                    primary_url=v.get("PrimaryURL"),
                    published_date=published,
                )
            )
    return findings


def _parse_secrets(results: list[dict]) -> list[SecretFinding]:
    """Extract secret findings from Trivy results."""
    findings: list[SecretFinding] = []
    for result in results:
        if result.get("Class") != "secret":
            continue
        target = result.get("Target", "")
        for s in result.get("Secrets") or []:
            findings.append(
                SecretFinding(
                    file=target,
                    rule_id=s.get("RuleID", ""),
                    title=s.get("Title", ""),
                    severity=s.get("Severity", "UNKNOWN"),
                )
            )
    return findings


def scan_project(name: str, project: ProjectConfig) -> ScanResult:
    """Run Trivy against a project and return parsed results.

    Also writes the results JSON to ~/.mm/scan-results/<name>.json.

    Raises:
        TrivyNotFoundError: If trivy is not on PATH.
        TrivyScanError: If trivy exits with non-zero status.
        FileNotFoundError: If the project path does not exist.
    """
    check_trivy_available()

    project_path = Path(project.path)
    if not project_path.exists():
        raise FileNotFoundError(f"Project path does not exist: {project_path}")

    completed = subprocess.run(
        ["trivy", "fs", "--format", "json", "--scanners", "vuln,secret", str(project_path)],
        capture_output=True,
        text=True,
    )

    if completed.returncode != 0:
        raise TrivyScanError(
            f"Trivy exited with code {completed.returncode}: {completed.stderr.strip()}"
        )

    trivy_output = json.loads(completed.stdout)
    results = trivy_output.get("Results", [])

    vulns = _parse_vulns(results)
    secrets = _parse_secrets(results)

    scan_result = ScanResult(
        project=name,
        scanned_at=datetime.now(timezone.utc),
        trivy_target=str(project_path),
        vulnerabilities=vulns,
        secrets=secrets,
    )

    # Write results to disk
    results_dir = MM_HOME / "scan-results"
    results_dir.mkdir(parents=True, exist_ok=True)
    results_file = results_dir / f"{name}.json"
    results_file.write_text(scan_result.model_dump_json(indent=2))

    return scan_result
```

**Step 2:** Run scanner tests.

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_scanner.py -v`
Expected: All tests PASS. Note: these tests invoke real Trivy and take a few seconds each.

**Step 3:** Run full test suite.

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All tests PASS.

---

## Task 3: CLI Integration

Wire the scanner into the existing `scan` CLI command with Rich output.

**Files:**
- Modify: `src/maintenance_man/cli.py`
- Modify: `tests/test_cli.py` (remove old scan stubs, add new tests)
- Create: `tests/test_scan_cli.py`

**Note:** The CLI uses cyclopts (not Typer). Commands use `sys.exit()` for exit codes. Tests use `pytest.raises(SystemExit)` and `capsys` for output capture — there is no `CliRunner`.

### Subtask 3.1: Write failing integration tests for the scan command

**Step 1:** Create `tests/test_scan_cli.py`. These test the full CLI flow end-to-end.

```python
import json
from pathlib import Path

import pytest

from maintenance_man.cli import app
from maintenance_man.models.scan import ScanResult


class TestScanSingleProject:
    def test_scan_project_with_vulns_exits_2(self, mm_home: Path):
        """mm scan lifts — has vulns, should exit 2."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "lifts"])
        assert exc_info.value.code == 2

    def test_scan_project_with_vulns_shows_findings(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        """Output should contain vulnerability information."""
        with pytest.raises(SystemExit):
            app(["scan", "lifts"])
        assert "CVE-" in capsys.readouterr().out or "vuln" in capsys.readouterr().out.lower()

    def test_scan_clean_project_exits_0(self, mm_home: Path):
        """mm scan feetfax — clean, should exit 0."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "feetfax"])
        assert exc_info.value.code == 0

    def test_scan_writes_results_file(self, mm_home: Path):
        """mm scan lifts should write results JSON."""
        with pytest.raises(SystemExit):
            app(["scan", "lifts"])
        results_file = mm_home / "scan-results" / "lifts.json"
        assert results_file.exists()
        data = json.loads(results_file.read_text())
        ScanResult.model_validate(data)

    def test_scan_unknown_project_exits_1(self, mm_home: Path):
        """mm scan nonexistent — should exit 1."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan", "nonexistent"])
        assert exc_info.value.code == 1


class TestScanAllProjects:
    def test_scan_all_exits_worst_case(self, mm_home: Path):
        """mm scan (no args) — should exit 2 if any project has vulns."""
        with pytest.raises(SystemExit) as exc_info:
            app(["scan"])
        # lifts has vulns, so worst case is 2
        assert exc_info.value.code == 2

    def test_scan_all_writes_results_for_each(self, mm_home: Path):
        """mm scan should write a results file per project."""
        with pytest.raises(SystemExit):
            app(["scan"])
        results_dir = mm_home / "scan-results"
        # Should have at least one results file
        json_files = list(results_dir.glob("*.json"))
        assert len(json_files) > 0
```

Note: These tests rely on the `mm_home` fixture from `conftest.py` which redirects `MM_HOME` to a temp dir. The test fixture needs to create a config file with real project paths. Update `conftest.py` accordingly (see Subtask 3.2).

**Step 2:** Run tests to verify they fail.

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_scan_cli.py -v`
Expected: FAIL — scan command still prints "Not implemented."

### Subtask 3.2: Update conftest and implement the scan command

**Step 1:** Update `tests/conftest.py` to provide a config with real projects:

```python
from pathlib import Path

import pytest


@pytest.fixture()
def mm_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect MM_HOME to a temp directory with real project config."""
    home = tmp_path / ".mm"
    home.mkdir()
    (home / "scan-results").mkdir()
    (home / "worktrees").mkdir()

    config_text = """\
[defaults]
min_version_age_days = 7

[projects.feetfax]
path = "/home/glykon/dev/feetfax"
package_manager = "bun"

[projects.lifts]
path = "/home/glykon/dev/lifts"
package_manager = "uv"
"""
    (home / "config.toml").write_text(config_text)

    monkeypatch.setattr("maintenance_man.config.MM_HOME", home)
    return home
```

**Step 2:** Update `tests/test_cli.py` — remove the scan stub tests since scan is now implemented. Remove `test_scan_stub_no_args` and `test_scan_stub_with_project`. Keep all other tests. Use `pytest.raises(SystemExit)` and `capsys` (no `CliRunner`).

```python
import pytest

from maintenance_man.cli import app


class TestHelp:
    def test_help_exits_zero(self):
        with pytest.raises(SystemExit) as exc_info:
            app(["--help"])
        assert exc_info.value.code == 0

    def test_help_contains_description(self, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit):
            app(["--help"])
        assert "maintenance" in capsys.readouterr().out.lower()


class TestVersion:
    def test_version_exits_zero(self):
        with pytest.raises(SystemExit) as exc_info:
            app(["--version"])
        assert exc_info.value.code == 0

    def test_version_prints_version(self, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit):
            app(["--version"])
        assert "0.1.0" in capsys.readouterr().out


class TestUpdateStub:
    def test_update_requires_project(self):
        with pytest.raises(SystemExit) as exc_info:
            app(["update"])
        assert exc_info.value.code != 0

    def test_update_stub_with_project(self, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit) as exc_info:
            app(["update", "feetfax"])
        assert exc_info.value.code == 1
        assert "not implemented" in capsys.readouterr().out.lower()


class TestDeployStub:
    def test_deploy_requires_project(self):
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"])
        assert exc_info.value.code != 0

    def test_deploy_stub_with_project(self, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "feetfax"])
        assert exc_info.value.code == 1
        assert "not implemented" in capsys.readouterr().out.lower()
```

**Step 3:** Implement the `scan` command in `src/maintenance_man/cli.py`. The CLI uses cyclopts. Key patterns:
- `@app.command` (no parentheses) for commands
- `sys.exit(code)` for exit codes
- Numpydoc-style docstrings for parameter help
- `print()` for output (Rich `rprint` for styled output)

The full updated `cli.py`:

```python
import sys

import cyclopts
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from maintenance_man import __version__
from maintenance_man.config import load_config, resolve_project
from maintenance_man.models.scan import ScanResult
from maintenance_man.scanner import TrivyNotFoundError, TrivyScanError, scan_project

app = cyclopts.App(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    version=__version__,
    version_flags=["--version", "-v"],
)


def _print_scan_result(result: ScanResult) -> None:
    """Print a Rich-formatted summary of scan results for one project."""
    console = Console()

    actionable = [v for v in result.vulnerabilities if v.actionable]
    advisories = [v for v in result.vulnerabilities if not v.actionable]
    secrets = result.secrets

    total = len(actionable) + len(advisories) + len(secrets)

    if total == 0:
        rprint(f"[bold green]{result.project}[/] — clean")
        return

    parts = []
    if actionable:
        parts.append(f"{len(actionable)} vulnerabilit{'y' if len(actionable) == 1 else 'ies'}")
    if advisories:
        parts.append(f"{len(advisories)} advisor{'y' if len(advisories) == 1 else 'ies'}")
    if secrets:
        parts.append(f"{len(secrets)} secret{'s' if len(secrets) != 1 else ''}")

    rprint(f"\n[bold]{result.project}[/] — {', '.join(parts)}")

    if actionable:
        table = Table(show_header=True, show_edge=False, pad_edge=False, box=None)
        table.add_column("", style="bold red", width=4)
        table.add_column("Package")
        table.add_column("Installed")
        table.add_column("Fix")
        table.add_column("Severity")
        table.add_column("CVE")
        for v in actionable:
            table.add_row(
                "VULN",
                v.pkg_name,
                v.installed_version,
                v.fixed_version or "",
                v.severity.value,
                v.vuln_id,
            )
        console.print(table)

    if advisories:
        table = Table(show_header=False, show_edge=False, pad_edge=False, box=None)
        table.add_column("", style="bold yellow", width=4)
        table.add_column("Package")
        table.add_column("Installed")
        table.add_column("Status")
        table.add_column("Severity")
        table.add_column("CVE")
        for v in advisories:
            table.add_row(
                "ADV",
                v.pkg_name,
                v.installed_version,
                v.status,
                v.severity.value,
                v.vuln_id,
            )
        console.print(table)

    if secrets:
        for s in secrets:
            rprint(f"  [bold magenta]SECRET[/]  {s.file} — {s.title}")


@app.command
def scan(
    project: str | None = None,
) -> None:
    """Scan projects for vulnerabilities and available updates.

    Parameters
    ----------
    project: str | None
        Project name to scan. Scans all if omitted.
    """
    config = load_config()

    try:
        check_trivy_available()
    except TrivyNotFoundError as e:
        rprint(f"[bold red]Error:[/] {e}")
        sys.exit(1)

    if project:
        # Single project scan
        proj_config = resolve_project(config, project)
        try:
            result = scan_project(project, proj_config)
        except TrivyScanError as e:
            rprint(f"[bold red]Error:[/] {e}")
            sys.exit(1)

        _print_scan_result(result)
        sys.exit(2 if result.has_actionable_vulns else 0)

    # Scan all projects
    has_vulns = False
    for name, proj_config in config.projects.items():
        if not proj_config.path.exists():
            rprint(f"[bold yellow]Warning:[/] {name} — path does not exist: {proj_config.path}")
            continue
        try:
            result = scan_project(name, proj_config)
        except TrivyScanError as e:
            rprint(f"[bold red]Error:[/] {name} — {e}")
            continue

        _print_scan_result(result)
        if result.has_actionable_vulns:
            has_vulns = True

    sys.exit(2 if has_vulns else 0)


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
    print("Not implemented.")
    sys.exit(1)


@app.command
def deploy(
    project: str,
) -> None:
    """Deploy a project.

    Parameters
    ----------
    project: str
        Project name to deploy.
    """
    print("Not implemented.")
    sys.exit(1)


@app.command(name="list")
def list_projects() -> None:
    """List all configured projects."""
    config = load_config()

    if not config.projects:
        print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    console = Console()
    table = Table(title="Configured Projects")
    table.add_column("Name", style="bold")
    table.add_column("Path")
    table.add_column("Package Manager")

    for name, project in sorted(config.projects.items()):
        table.add_row(name, str(project.path), project.package_manager)

    console.print(table)


def main() -> None:
    app()
```

**Step 4:** Run the new scan CLI tests.

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_scan_cli.py -v`
Expected: All tests PASS.

**Step 5:** Run the full test suite.

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All tests PASS.

**Step 6:** Manual smoke test.

Run: `cd /home/glykon/dev/maintenance-man && uv run mm scan lifts`
Expected: Rich-formatted output showing vulnerability findings, exits with code 2.

Run: `cd /home/glykon/dev/maintenance-man && uv run mm scan feetfax`
Expected: "feetfax — clean", exits with code 0.

Run: `cd /home/glykon/dev/maintenance-man && uv run mm scan`
Expected: Scans all configured projects, shows summary for each.

**Step 7:** Run linter.

Run: `cd /home/glykon/dev/maintenance-man && uv run ruff check src/ tests/`
Expected: No errors.