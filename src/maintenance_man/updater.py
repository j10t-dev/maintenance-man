from __future__ import annotations

import json
import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from packaging.version import InvalidVersion, Version
from rich import print as rprint

from maintenance_man import sanitise_project_name
from maintenance_man.env import project_env
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    MaintenanceFlow,
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
)
from maintenance_man.uv_dependencies import (
    UvDependencyError,
    UvDependencyLocation,
    get_uv_dependency_locations,
)
from maintenance_man.vcs import (
    branch_slug,
    discard_changes,
    git_checkout,
    git_commit_all,
    git_create_branch,
    push_and_create_pr,
    reset_to_main,
)


class NoScanResultsError(Exception):
    pass


class NoTestConfigError(Exception):
    pass


def _has_test_config(project_config: ProjectConfig) -> bool:
    """Return True if any test phase is configured."""
    return any(
        [
            project_config.test_unit,
            project_config.test_integration,
            project_config.test_component,
        ]
    )


type UpdateKind = Literal["vuln", "update"]


class Finding(Protocol):
    """Common interface for VulnFinding and UpdateFinding during stack processing."""

    pkg_name: str
    installed_version: str
    update_status: UpdateStatus | None
    failed_phase: str | None
    flow: MaintenanceFlow | None

    @property
    def target_version(self) -> str: ...

    @property
    def detail(self) -> str: ...


@dataclass(slots=True)
class UpdateResult:
    """Tracks the outcome of a single update attempt."""

    pkg_name: str
    kind: UpdateKind
    passed: bool
    failed_phase: str | None = None


@dataclass(frozen=True, slots=True)
class _StackConfig:
    """Varying parameters for a stack processing run."""

    branch_prefix: str
    kind: UpdateKind
    label: str
    submit_label: str
    commit_fmt: str


_VULN_STACK = _StackConfig(
    branch_prefix="fix/",
    kind="vuln",
    label="[bold red]VULN[/]",
    submit_label="Fix PRs",
    commit_fmt="fix: upgrade {pkg} {old} -> {new} for {detail}",
)

_UPDATE_STACK = _StackConfig(
    branch_prefix="bump/",
    kind="update",
    label="[bold cyan]UPDATE[/]",
    submit_label="Update PRs",
    commit_fmt="update: {pkg} {old} -> {new} ({detail})",
)

_RISK_ORDER = {
    SemverTier.PATCH: 0,
    SemverTier.MINOR: 1,
    SemverTier.MAJOR: 2,
    SemverTier.UNKNOWN: 3,
}


def _highest_fix_version(vulns: list[VulnFinding]) -> str:
    """Return the highest ``fixed_version`` from *vulns*.

    Uses :class:`packaging.version.Version` for comparison.  Unparsable
    version strings are ignored; if *none* can be parsed the last item
    in the list is returned as a fallback.
    """

    def _sort_key(v: VulnFinding) -> Version:
        try:
            return Version(v.fixed_version or "0")
        except InvalidVersion:
            return Version("0")

    best = max(vulns, key=_sort_key)
    return best.fixed_version or vulns[-1].fixed_version or ""


@dataclass
class _ConsolidatedVuln:
    """Proxy that groups several vulns for the same package into one finding.

    Satisfies the :class:`Finding` protocol so it can be passed straight into
    :func:`_process_stack`.  Writes to :attr:`update_status`, :attr:`failed_phase`
    and :attr:`flow` are fanned out to every original :class:`VulnFinding` so
    that serialisation (which works on the originals) stays consistent.
    """

    pkg_name: str
    installed_version: str
    _target_version: str
    _detail: str
    _originals: list[VulnFinding] = field(repr=False)
    _update_status: UpdateStatus | None = None
    _failed_phase: str | None = None
    _flow: MaintenanceFlow | None = None

    @property
    def target_version(self) -> str:
        return self._target_version

    @property
    def detail(self) -> str:
        return self._detail

    @property
    def update_status(self) -> UpdateStatus | None:
        return self._update_status

    @update_status.setter
    def update_status(self, value: UpdateStatus | None) -> None:
        self._update_status = value
        for orig in self._originals:
            orig.update_status = value

    @property
    def failed_phase(self) -> str | None:
        return self._failed_phase

    @failed_phase.setter
    def failed_phase(self, value: str | None) -> None:
        self._failed_phase = value
        for orig in self._originals:
            orig.failed_phase = value

    @property
    def flow(self) -> MaintenanceFlow | None:
        return self._flow

    @flow.setter
    def flow(self, value: MaintenanceFlow | None) -> None:
        self._flow = value
        for orig in self._originals:
            orig.flow = value


def _consolidate_vulns(
    vulns: list[VulnFinding],
) -> list[_ConsolidatedVuln]:
    """Group actionable vulns by package and pick the highest fix version."""
    by_pkg: dict[str, list[VulnFinding]] = {}
    for v in vulns:
        by_pkg.setdefault(v.pkg_name, []).append(v)

    consolidated: list[_ConsolidatedVuln] = []
    for pkg, group in by_pkg.items():
        best_version = _highest_fix_version(group)
        detail = ", ".join(v.vuln_id for v in group)
        consolidated.append(
            _ConsolidatedVuln(
                pkg_name=pkg,
                installed_version=group[0].installed_version,
                _target_version=best_version,
                _detail=detail,
                _originals=group,
            )
        )
    return consolidated


def process_vulns(
    vulns: list[VulnFinding],
    project_config: ProjectConfig,
    *,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process vuln fixes as branches off main.

    Vulns for the same package are consolidated so only one branch is
    created per package (using the highest fix version). If all processed
    findings pass, the tip branch is pushed and a PR is created before
    returning to main. A test failure keeps the failing branch for
    ``--continue`` and defers submission.
    """
    actionable = [v for v in vulns if v.actionable]
    consolidated = _consolidate_vulns(actionable)
    return _process_stack(
        consolidated,
        project_config,
        _VULN_STACK,
        scan_result=scan_result,
        project_name=project_name,
        results_dir=results_dir,
    )


def process_updates(
    updates: list[UpdateFinding],
    project_config: ProjectConfig,
    *,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process updates as branches, risk-ascending.

    On the first test failure the loop stops, the failing branch is kept
    so the user can inspect and ``--continue``, and PR submission is
    deferred until the branch is green.
    """
    sorted_updates = sort_updates_by_risk(updates)
    return _process_stack(
        sorted_updates,
        project_config,
        _UPDATE_STACK,
        scan_result=scan_result,
        project_name=project_name,
        results_dir=results_dir,
    )


def load_scan_results(project_name: str, results_dir: Path) -> ScanResult:
    """Load scan results JSON for a project. Raises NoScanResultsError if missing."""
    results_file = _results_path(project_name, results_dir)
    try:
        data = json.loads(results_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise NoScanResultsError(
            f"No scan results found for '{project_name}'. "
            f"Run 'mm scan {project_name}' first."
        ) from None
    return ScanResult.model_validate(data)


def save_scan_results(
    project_name: str, results_dir: Path, scan_result: ScanResult
) -> None:
    """Write scan results (with update statuses) back to disk."""
    results_file = _results_path(project_name, results_dir)
    results_file.write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")


def sort_updates_by_risk(updates: list[UpdateFinding]) -> list[UpdateFinding]:
    """Sort updates risk-ascending: PATCH < MINOR < MAJOR < UNKNOWN."""
    return sorted(updates, key=lambda u: _RISK_ORDER[u.semver_tier])


def get_update_commands(
    package_manager: str,
    pkg_name: str,
    version: str,
    project_path: Path,
) -> list[list[str]]:
    """Return the shell command or commands to update a package."""
    match package_manager:
        case "bun":
            return [["bun", "add", f"{pkg_name}@{version}"]]
        case "uv":
            locations = get_uv_dependency_locations(project_path, pkg_name)
            return [
                _get_uv_update_command(pkg_name, version, location)
                for location in locations
            ]
        case "mvn":
            return [[
                "mvn",
                "versions:use-dep-version",
                f"-Dincludes={pkg_name}",
                f"-DdepVersion={version}",
            ]]
        case _:
            raise ValueError(f"Unsupported package manager: {package_manager}")


def _get_uv_update_command(
    pkg_name: str, version: str, location: UvDependencyLocation
) -> list[str]:
    command = ["uv", "add"]
    if location.kind == "group":
        if location.group is None:
            raise UvDependencyError("UV group dependency location missing group name")
        command.extend(["--group", location.group])
    command.append(f"{pkg_name}=={version}")
    return command


# TODO: extract as part of test command feature
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


def _process_stack(
    findings: Sequence[Finding],
    project_config: ProjectConfig,
    cfg: _StackConfig,
    *,
    scan_result: ScanResult | None = None,
    project_name: str = "",
    results_dir: Path | None = None,
) -> list[UpdateResult]:
    """Process a list of findings as individual branches.

    Each finding gets its own branch. On the first retryable test failure
    the loop stops, the failing branch is kept so the user can inspect and
    ``--continue``, and submission is deferred. If processing completes
    without a retryable test failure, the tip branch is pushed and a PR is
    created.
    """
    if not _has_test_config(project_config):
        raise NoTestConfigError(
            f"No test configuration for project at {project_config.path}"
        )

    results: list[UpdateResult] = []
    project_path = Path(project_config.path)

    for f in findings:
        rprint(
            f"\n  {cfg.label} {f.pkg_name} {f.installed_version} "
            f"-> {f.target_version} ({f.detail})"
        )

        f.update_status = UpdateStatus.STARTED
        _persist_status(scan_result, project_name, results_dir)

        msg = cfg.commit_fmt.format(
            pkg=f.pkg_name,
            old=f.installed_version,
            new=f.target_version,
            detail=f.detail,
        )
        branch = f"{cfg.branch_prefix}{branch_slug(f.pkg_name)}"

        if not _apply_update(
            project_config.package_manager,
            f.pkg_name,
            f.target_version,
            project_path,
        ):
            results.append(
                _record_failure(
                    f,
                    cfg.kind,
                    "apply",
                    project_path,
                    scan_result,
                    project_name,
                    results_dir,
                )
            )
            continue

        if not git_create_branch(branch, project_path):
            results.append(
                _record_failure(
                    f,
                    cfg.kind,
                    "branch",
                    project_path,
                    scan_result,
                    project_name,
                    results_dir,
                )
            )
            continue

        if not git_commit_all(msg, project_path):
            results.append(
                _record_failure(
                    f,
                    cfg.kind,
                    "commit",
                    project_path,
                    scan_result,
                    project_name,
                    results_dir,
                )
            )
            continue

        passed, failed_phase = run_test_phases(project_config, project_path)
        if passed:
            rprint(f"  [bold green]PASS[/] {f.pkg_name}")
            f.update_status = UpdateStatus.COMPLETED
        else:
            rprint(f"  [bold red]FAIL[/] {f.pkg_name} — {failed_phase} failed")
            f.update_status = UpdateStatus.FAILED

        _persist_status(scan_result, project_name, results_dir)
        results.append(
            UpdateResult(
                pkg_name=f.pkg_name,
                kind=cfg.kind,
                passed=passed,
                failed_phase=failed_phase,
            )
        )

        if not passed:
            break

    last_failed_phase = results[-1].failed_phase if results else None

    passing = [r for r in results if r.passed]
    if passing and not _should_defer_submit_for_continue(last_failed_phase):
        tip = f"{cfg.branch_prefix}{branch_slug(passing[-1].pkg_name)}"
        if not git_checkout(tip, project_path):
            rprint(
                f"  [bold red]{cfg.submit_label} checkout failed — skipping submit.[/]"
            )
            _mark_stack_failed(
                results, findings, "submit", scan_result, project_name, results_dir
            )
        else:
            ok, output = push_and_create_pr(project_path)
            if ok:
                rprint(f"  [bold green]{cfg.submit_label} submitted.[/]")
            else:
                rprint(f"  [bold red]{cfg.submit_label} submit failed.[/]")
                _mark_stack_failed(
                    results,
                    findings,
                    "submit",
                    scan_result,
                    project_name,
                    results_dir,
                )
            if output:
                rprint(f"  [dim]{output}[/]")

    if results and not results[-1].passed and _should_keep_failed_branch(
        results[-1].failed_phase
    ):
        # Check out the failing branch so the user can inspect and --continue.
        failed_branch = f"{cfg.branch_prefix}{branch_slug(results[-1].pkg_name)}"
        if git_checkout(failed_branch, project_path):
            pending = len(findings) - len(results)
            suffix = f" ({pending} more pending)" if pending else ""
            continue_cmd = (
                f"mm update {project_name} --continue"
                if project_name
                else "mm update --continue"
            )
            rprint(
                f"\n  Branch [bold cyan]{failed_branch}[/] kept —"
                f" fix the issue, then run [bold]{continue_cmd}[/].{suffix}"
            )
        else:
            rprint(
                f"  [bold red]Could not check out {failed_branch}[/]"
                " — returning to main."
            )
            if not git_checkout("main", project_path):
                reset_to_main(project_path)
    else:
        if not git_checkout("main", project_path):
            reset_to_main(project_path)
    return results


def _should_defer_submit_for_continue(failed_phase: str | None) -> bool:
    """Return True when a failed phase supports manual fix + --continue.

    Only test-phase failures are retryable in-place. Apply/branch/commit/
    submit failures are automation failures, so they should not defer
    submission or keep a branch checked out for continuation.
    """
    return failed_phase in {"unit", "integration", "component"}



def _should_keep_failed_branch(failed_phase: str | None) -> bool:
    """Return True when the failed branch should be left checked out."""
    return _should_defer_submit_for_continue(failed_phase)



def _mark_stack_failed(
    results: list[UpdateResult],
    findings: Sequence[Finding],
    phase: str,
    scan_result: ScanResult | None,
    project_name: str,
    results_dir: Path | None,
) -> None:
    """Mark all passing results and completed findings as failed."""
    for r in results:
        if r.passed:
            r.passed = False
            r.failed_phase = phase
    for f in findings:
        if f.update_status == UpdateStatus.COMPLETED:
            f.update_status = UpdateStatus.FAILED
    _persist_status(scan_result, project_name, results_dir)


def _record_failure(
    finding: Finding,
    kind: UpdateKind,
    phase: str,
    project_path: Path,
    scan_result: ScanResult | None,
    project_name: str,
    results_dir: Path | None,
) -> UpdateResult:
    """Discard changes, mark the finding as failed, persist and return a result."""
    discard_changes(project_path)
    finding.update_status = UpdateStatus.FAILED
    _persist_status(scan_result, project_name, results_dir)
    return UpdateResult(
        pkg_name=finding.pkg_name,
        kind=kind,
        passed=False,
        failed_phase=phase,
    )


def _results_path(project_name: str, results_dir: Path) -> Path:
    """Return the path to a project's scan results file."""
    return results_dir / f"{sanitise_project_name(project_name)}.json"


def _project_env() -> dict[str, str]:
    """Return a copy of os.environ with venv isolation.

    Delegates to :func:`maintenance_man.env.project_env`.
    """
    return project_env()


def _persist_status(
    scan_result: ScanResult | None,
    project_name: str,
    results_dir: Path | None,
) -> None:
    """Save scan results if tracking args are provided."""
    if scan_result is not None and results_dir is not None:
        save_scan_results(project_name, results_dir, scan_result)


def _apply_update(
    package_manager: str, pkg_name: str, version: str, project_path: Path
) -> bool:
    """Apply a single package update. Returns True on success."""
    env = _project_env()
    try:
        commands = get_update_commands(package_manager, pkg_name, version, project_path)
    except UvDependencyError as e:
        rprint(f"  [bold red]FAIL[/] {e}")
        return False

    for cmd in commands:
        completed = subprocess.run(
            cmd,
            cwd=project_path,
            timeout=300,
            capture_output=True,
            text=True,
            env=env,
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
            env=env,
        )
        if commit.returncode != 0:
            rprint(
                f"  [bold red]FAIL[/] mvn versions:commit failed: "
                f"{commit.stderr.strip()}"
            )
            return False
    return True
