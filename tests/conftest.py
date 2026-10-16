import dataclasses
import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from maintenance_man import cli, vcs
from maintenance_man.cli import app
from maintenance_man.config import load_config
from maintenance_man.gradle import (
    GRADLE_INVENTORY_BOM_RELPATH,
    GRADLE_INVENTORY_MARKER_RELPATH,
    GRADLE_INVENTORY_RELPATH,
)
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.config import MmConfig, ProjectConfig
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    Workflow,
)
from maintenance_man.package_managers import PackageManagerOps, package_manager_ops
from maintenance_man.process import ToolNotFoundError
from maintenance_man.storage import save_scan_results
from maintenance_man.vcs import Repository
from tests.fake_vcs import FakeCall, FakeJjState
from tests.fakes import FakeFindingProcessor


@dataclasses.dataclass
class FakeClock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


def completed(
    argv: str | list[str] | tuple[str, ...] = (),
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def make_project(path: Path, **overrides: Any) -> ProjectConfig:
    return ProjectConfig.model_validate(
        {"path": path, "package_manager": "uv"} | overrides
    )


def make_config(**overrides: Any) -> MmConfig:
    return MmConfig.model_validate({"projects": {}} | overrides)


def write_config(home: Path, text: str, *, filename: str = "config.toml") -> Path:
    home.mkdir(parents=True, exist_ok=True)
    path = home / filename
    path.write_text(text, encoding="utf-8")
    return path


def run_mm(*argv: str) -> int:
    try:
        result = app(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    assert result is None
    return 0


def configure_fake_vcs(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[FakeJjState, dict[str, Path]]:
    config_path = home / "config.toml"
    configured = load_config(config_path)
    replacements: dict[Path, Path] = {}
    state = FakeJjState()
    for project in configured.projects.values():
        if project.path in replacements:
            continue
        target = tmp_path / "repositories" / f"repo-{len(replacements)}"
        replacements[project.path] = target
        state.seed_repository(target, files={"dep.txt": "version=1\n"})
    text = config_path.read_text(encoding="utf-8")
    for source, target in replacements.items():
        text = text.replace(str(source), str(target))
    write_config(home, text)
    paths_by_name = {
        name: replacements[project.path]
        for name, project in configured.projects.items()
    }
    monkeypatch.setattr("maintenance_man.cli.make_vcs_services", state.services)
    return state, paths_by_name


_TERMINAL_OVERRIDES = ("FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE")


@pytest.fixture(autouse=True)
def _plain_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render CLI output as plain 80-column text whatever terminal runs the suite.

    The CLI console is built at import, during collection, so it has already
    read the invoking environment. Replace it with one that is never treated
    as a terminal, and clear the overrides so child processes are plain too.
    """
    for name in _TERMINAL_OVERRIDES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "console", Console(force_terminal=False, width=80))


@pytest.fixture(autouse=True)
def _tools_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve CLI and scanner tool requirements without the host PATH."""

    def found(name: str, hint: str) -> Path:
        return Path("/usr/bin") / name

    monkeypatch.setattr("maintenance_man.vcs_workflow.require_tool", found)
    monkeypatch.setattr("maintenance_man.scanner.require_tool", found)


FIXTURES_DIR = Path(__file__).parent / "fixtures"
GRADLE_FIXTURES = FIXTURES_DIR / "gradle"

_GRADLEW_STUB = "#!/bin/sh\nexit 0\n"

FIXTURE = GRADLE_FIXTURES / "resolution" / "empty.json"


def report_payload():
    return json.loads(FIXTURE.read_text())


def fixture_runner(root, args, *, label):
    assert args[0] == "mmGradleReport"
    assert "--rerun-tasks" in args and "--no-build-cache" in args
    owned = root / GRADLE_INVENTORY_RELPATH
    assert (root / GRADLE_INVENTORY_MARKER_RELPATH).is_file()
    assert (owned / "gradle-report.gradle").read_text().startswith("import ")
    (root / GRADLE_INVENTORY_BOM_RELPATH).write_text(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"group":"g","name":"a","version":"1.0","purl":"pkg:maven/g/a@1.0"}]}'
    )
    value = report_payload()
    value["scopes"][0]["components"].append(
        {
            "id": "a",
            "kind": "module",
            "module": {"group": "g", "artifact": "a", "version": "1.0"},
            "variants": ["runtime"],
        }
    )
    value["scopes"][0]["edges"].append(
        {"source": "root", "target": "a", "requested": "g:a:1.0", "constraint": False}
    )
    value["catalogue_digest"] = hashlib.sha256(
        (root / "gradle/libs.versions.toml").read_bytes()
    ).hexdigest()
    (owned / "report.json").write_text(json.dumps(value))
    return completed(tuple(args))


def make_vuln(**overrides: Any) -> VulnFinding:
    defaults = {
        "vuln_id": "CVE-2024-0001",
        "pkg_name": "some-pkg",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
        "severity": Severity.HIGH,
        "title": "Test vuln",
        "description": "desc",
        "status": "fixed",
    }
    return VulnFinding(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_update(tier: SemverTier = SemverTier.PATCH, **overrides: Any) -> UpdateFinding:
    name, installed, latest = {
        SemverTier.PATCH: ("pkg-a", "1.0.0", "1.0.1"),
        SemverTier.MINOR: ("pkg-b", "1.0.0", "1.1.0"),
        SemverTier.MAJOR: ("pkg-c", "1.0.0", "2.0.0"),
    }.get(tier, ("pkg-x", "1.0.0", "2.0.0"))
    defaults = {
        "pkg_name": name,
        "installed_version": installed,
        "latest_version": latest,
        "semver_tier": tier,
    }
    return UpdateFinding(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_scan_result(
    vulns: list[VulnFinding] | None = None,
    updates: list[UpdateFinding] | None = None,
) -> ScanResult:
    return ScanResult(
        project="vulnerable",
        scanned_at=datetime.now(tz=UTC),
        trivy_target="tests/fixtures/vulnerable-project",
        vulnerabilities=vulns if vulns is not None else [make_vuln()],
        updates=updates if updates is not None else [make_update()],
    )


def make_activity(
    *, success: bool, commit_id: str | None
) -> dict[str, ProjectActivity]:
    return {
        "app": ProjectActivity(
            last_deploy=ActivityEvent(
                timestamp=datetime(2026, 3, 20, tzinfo=UTC),
                success=success,
                branch="main",
                commit_id=commit_id,
            )
        )
    }


def missing_tool(tool: str) -> Callable[[str, str], Path]:
    def require(name: str, hint: str) -> Path:
        if name == tool:
            msg = f"{name} is not installed or not on PATH. {hint}"
            raise ToolNotFoundError(msg)
        return Path("/usr/bin") / name

    return require


def seed_project(
    tmp_path: Path,
    name: str,
    scan: ScanResult,
    *,
    test_unit: str | None = "pytest",
) -> tuple[FakeJjState, ProjectConfig]:
    project = make_project(tmp_path / name, test_unit=test_unit)
    state = FakeJjState()
    state.seed_repository(project.path, files={"dep.txt": "version=1\n"})
    state.register_files(
        project.path,
        "mm-fixture-some-pkg.txt",
        "mm-fixture-pkg-a.txt",
        "mm-fixture-pkg-b.txt",
    )
    scan.project = name
    save_scan_results(name, scan)
    return state, project


@pytest.fixture(autouse=True)
def _isolated_mm_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every test gets its own mm home; nothing reaches the real ~/.mm."""
    home = tmp_path / ".mm"
    monkeypatch.setattr("maintenance_man.paths.MM_HOME", home)
    return home


@pytest.fixture()
def mm_home(_isolated_mm_home: Path) -> Path:
    """Return the per-test MM_HOME without creating it."""
    return _isolated_mm_home


@pytest.fixture()
def mm_home_with_projects(mm_home: Path) -> Path:
    """MM_HOME populated with directory structure and real project config."""
    mm_home.mkdir(parents=True, exist_ok=True)
    (mm_home / "scan-results").mkdir(exist_ok=True)
    (mm_home / "workspaces").mkdir(exist_ok=True)

    vuln_path = FIXTURES_DIR / "vulnerable-project"
    clean_path = FIXTURES_DIR / "clean-project"

    config_text = f"""\
[defaults]
min_version_age_days = 7

[projects.vulnerable]
path = "{vuln_path}"
package_manager = "uv"
test_unit = "uv run pytest"

[projects.clean]
path = "{clean_path}"
package_manager = "uv"
test_unit = "uv run pytest"

[projects.outdated]
path = "{clean_path}"
package_manager = "bun"
test_unit = "bun test"

[projects.no-tests]
path = "{clean_path}"
package_manager = "uv"

[projects.deployable]
path = "{clean_path}"
package_manager = "bun"
build_command = "scripts/build.sh"
deploy_command = "scripts/deploy.sh"
test_unit = "bun test"

[projects.deploy-only]
path = "{clean_path}"
package_manager = "uv"
deploy_command = "scripts/deploy.sh"
test_unit = "uv run pytest"

[projects.no-deploy]
path = "{clean_path}"
package_manager = "uv"
test_unit = "uv run pytest"
"""
    write_config(mm_home, config_text)
    return mm_home


@pytest.fixture()
def scan_results_dir(mm_home: Path) -> Path:
    """MM_HOME with scan-results directory (no config file needed)."""
    mm_home.mkdir(parents=True, exist_ok=True)
    d = mm_home / "scan-results"
    d.mkdir(exist_ok=True)
    return d


@dataclasses.dataclass(frozen=True, slots=True)
class CliDeps:
    vcs_state: FakeJjState
    scan_result: ScanResult
    project_paths: dict[str, Path]
    save_scan: Callable[[], None]


def cli_deps(
    flow: Workflow,
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> CliDeps:
    if flow is Workflow.UPDATE:
        scan_result = make_scan_result()
        fixture_files = (
            "mm-fixture-some-pkg.txt",
            "mm-fixture-pkg-a.txt",
            "mm-fixture-pkg-b.txt",
            "mm-fixture-pkg-c.txt",
        )
        outcomes = {
            "some-pkg": (True, None),
            "pkg-a": (True, None),
            "pkg-b": (True, None),
            "pkg-c": (True, None),
        }
        processor_path = "maintenance_man.services.update.process_findings"
    else:
        scan_result = make_scan_result(
            vulns=[
                make_vuln(
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                    failed_phase="unit",
                ),
            ],
            updates=[
                make_update(
                    update_status=UpdateStatus.FAILED,
                    flow=Workflow.RESOLVE,
                    failed_phase="unit",
                ),
            ],
        )
        fixture_files = ("mm-fixture-some-pkg.txt", "mm-fixture-pkg-a.txt")
        outcomes = {"some-pkg": (True, None), "pkg-a": (True, None)}
        processor_path = "maintenance_man.services.resolve.process_findings"

    vcs_state, project_paths = configure_fake_vcs(mm_home, tmp_path, monkeypatch)
    for project_path in set(project_paths.values()):
        vcs_state.register_files(project_path, *fixture_files)

    if flow is Workflow.RESOLVE:
        vcs_state.repository(project_paths["vulnerable"]).set_bookmark(
            bookmark="mm/resolve-dependencies", revision="@-"
        )

    def save_scan() -> None:
        save_scan_results("vulnerable", scan_result)

    save_scan()
    for project_name in project_paths:
        if project_name == "vulnerable":
            continue
        project_scan = deepcopy(scan_result)
        project_scan.project = project_name
        save_scan_results(project_name, project_scan)
    monkeypatch.setattr(processor_path, FakeFindingProcessor(outcomes))
    return CliDeps(vcs_state, scan_result, project_paths, save_scan)


@pytest.fixture()
def mock_update_cli_deps(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> CliDeps:
    return cli_deps(Workflow.UPDATE, mm_home_with_projects, tmp_path, monkeypatch)


@pytest.fixture()
def mock_resolve_cli_deps(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> CliDeps:
    return cli_deps(Workflow.RESOLVE, mm_home_with_projects, tmp_path, monkeypatch)


def make_gradle_member(**overrides: Any) -> GradleMember:
    defaults = {
        "kind": "library",
        "alias": "room-runtime",
        "coordinate": "androidx.room:room-runtime",
        "installed_version": "2.8.4",
    }
    return GradleMember(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


def make_gradle_target(**overrides: Any) -> GradleUpdateTarget:
    defaults = {
        "version_ref": "room",
        "members": [
            make_gradle_member(
                alias="room-runtime", coordinate="androidx.room:room-runtime"
            ),
            make_gradle_member(
                alias="room-compiler", coordinate="androidx.room:room-compiler"
            ),
            make_gradle_member(
                alias="room-testing", coordinate="androidx.room:room-testing"
            ),
        ],
        "target_version": "2.8.5",
    }
    return GradleUpdateTarget(**(defaults | overrides))  # ty:ignore[invalid-argument-type]


@pytest.fixture()
def gradle_project(tmp_path: Path) -> ProjectConfig:
    """A real on-disk Gradle project with an executable wrapper substitute."""
    root = tmp_path / "gradle-project"
    (root / "gradle").mkdir(parents=True)
    (root / "gradle" / "libs.versions.toml").write_text(
        (GRADLE_FIXTURES / "libs.versions.toml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    wrapper = root / "gradlew"
    wrapper.write_text(_GRADLEW_STUB, encoding="utf-8")
    wrapper.chmod(0o755)
    return ProjectConfig(
        path=root, package_manager="gradle", test_unit="./gradlew test"
    )


@pytest.fixture()
def mm_home_with_gradle(
    mm_home_with_projects: Path, gradle_project: ProjectConfig
) -> Path:
    config_path = mm_home_with_projects / "config.toml"
    write_config(
        mm_home_with_projects,
        config_path.read_text()
        + f'\n[projects.android]\npath = "{gradle_project.path}"\n'
        f'package_manager = "gradle"\ntest_unit = "./gradlew testDebugUnitTest"\n',
    )
    return mm_home_with_projects


def ops_with_outdated(
    outdated: Callable[[ProjectConfig], list[UpdateFinding]],
) -> Callable[[str], PackageManagerOps]:
    """Return a scanner table lookup whose entries use *outdated* instead."""

    def lookup(name: str) -> PackageManagerOps:
        return dataclasses.replace(package_manager_ops(name), outdated=outdated)

    return lookup


MANAGED = "mm/update-dependencies"


@dataclass
class OriginPeer:
    repo: Repository
    commit_file: Callable[[str, str, str], str]
    push_main: Callable[[], None]
    remote_bookmark_targets: Callable[[str], tuple[str, ...]]


@dataclass
class RepositoryCase:
    repo: Repository
    bind: Callable[[Path], Repository]
    register_file: Callable[[str], None]
    write_file: Callable[[str, str | None], None]
    commit_file: Callable[[str, str, str], str]
    describe: Callable[[str], None]
    force_bookmark: Callable[[str, str], None]
    conflict_bookmark: Callable[[str, str, str], None]
    origin_peer: OriginPeer
    track_main: Callable[[bool], None]
    after_push: Callable[[Callable[[], None]], None]
    after_operation: Callable[[str, Callable[[], None]], None]
    attempts: list[FakeCall] | None
    commands: list[tuple[str, ...]] | None


def _run_jj(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(JJ_USER="MM Tests", JJ_EMAIL="mm@example.invalid")
    return subprocess.run(
        ["jj", *arguments],
        cwd=path,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def _write_repository_file(
    repository: Repository, filename: str, content: str | None
) -> None:
    target = repository.path / filename
    if content is None:
        target.unlink(missing_ok=True)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _commit_repository_file(
    repository: Repository,
    register_file: Callable[[str], None],
    filename: str,
    content: str,
    message: str,
) -> str:
    register_file(filename)
    _write_repository_file(repository, filename, content)
    repository.commit(message=message)
    return repository.resolve_revision(revision="@-")


def _skip_file_registration(_filename: str) -> None:
    return None


def _initialize_real_repository(tmp_path: Path) -> tuple[vcs.JjRepository, Path]:
    path = tmp_path / "real-repository"
    path.mkdir()
    assert _run_jj(path, "git", "init", "--colocate").returncode == 0
    origin = tmp_path / "origin"
    initialized = _run_jj(tmp_path, "git", "init", "--no-colocate", str(origin))
    assert initialized.returncode == 0, initialized.stderr
    origin_git = origin / ".jj" / "repo" / "store" / "git"
    added = _run_jj(path, "git", "remote", "add", "origin", str(origin_git))
    assert added.returncode == 0, added.stderr
    (path / "dep.txt").write_text("version=1\n", encoding="utf-8")
    assert _run_jj(path, "commit", "-m", "baseline").returncode == 0
    assert _run_jj(path, "bookmark", "create", "main", "-r", "@-").returncode == 0
    return vcs.JjRepository(path), origin_git


def _initialize_real_peer(tmp_path: Path, origin_git: Path) -> OriginPeer:
    peer_path = tmp_path / "origin-peer"
    peer_path.mkdir()
    assert _run_jj(peer_path, "git", "init", "--colocate").returncode == 0
    added = _run_jj(peer_path, "git", "remote", "add", "origin", str(origin_git))
    assert added.returncode == 0, added.stderr
    fetched = _run_jj(peer_path, "git", "fetch", "--remote", "origin")
    assert fetched.returncode == 0, fetched.stderr
    created = _run_jj(peer_path, "bookmark", "create", "main", "-r", "main@origin")
    assert created.returncode == 0, created.stderr
    tracked = _run_jj(peer_path, "bookmark", "track", "main@origin")
    assert tracked.returncode == 0, tracked.stderr
    assert _run_jj(peer_path, "new", "main").returncode == 0
    peer_repo = vcs.JjRepository(peer_path)

    def remote_bookmark_targets(bookmark: str) -> tuple[str, ...]:
        fetched = _run_jj(peer_path, "git", "fetch", "--remote", "origin")
        assert fetched.returncode == 0, fetched.stderr
        result = _run_jj(
            peer_path,
            "log",
            "-r",
            f"{bookmark}@origin",
            "--no-graph",
            "-T",
            'commit_id ++ "\\n"',
        )
        return () if result.returncode != 0 else (result.stdout.strip(),)

    return OriginPeer(
        peer_repo,
        partial(_commit_repository_file, peer_repo, _skip_file_registration),
        partial(_push_real_peer_main, peer_repo),
        remote_bookmark_targets,
    )


def _push_real_peer_main(repository: Repository) -> None:
    repository.set_bookmark(bookmark="main", revision="@-")
    repository.push_bookmark(bookmark="main")


def _install_real_postcheck_interceptor(
    path: Path,
    monkeypatch: pytest.MonkeyPatch | None,
    pending_after_operation: list[tuple[str, Callable[[], None]]],
    commands: list[tuple[str, ...]],
) -> None:
    if monkeypatch is None:
        return
    captured_run = vcs.run_captured

    def intercept_push(command, cwd, **kwargs):
        commands.append(tuple(command))
        completed = captured_run(command, cwd, **kwargs)
        arguments = list(command)
        operation = None
        if arguments[1:4] == ["bookmark", "set", "main"]:
            operation = "promote"
        elif arguments[1:4] == ["bookmark", "set", MANAGED]:
            operation = "reset"
        elif arguments[1:3] == ["git", "push"]:
            operation = "push"
        if pending_after_operation and Path(cwd).resolve() == path.resolve():
            expected, action = pending_after_operation[0]
            if operation == expected:
                pending_after_operation.pop(0)
                action()
        return completed

    monkeypatch.setattr(vcs, "run_captured", intercept_push)


def _bind_real_repository(path: Path) -> Repository:
    inspected = _run_jj(path, "workspace", "root")
    assert inspected.returncode == 0, f"unknown repository view: {path}"
    return vcs.JjRepository(path)


def _describe_real_repository(repository: Repository, message: str) -> None:
    result = _run_jj(repository.path, "describe", "-m", message)
    assert result.returncode == 0, result.stderr


def _force_real_bookmark(repository: Repository, bookmark: str, revision: str) -> None:
    result = _run_jj(
        repository.path,
        "bookmark",
        "set",
        bookmark,
        "-r",
        revision,
        "--allow-backwards",
    )
    assert result.returncode == 0, result.stderr


def _conflict_real_bookmark(
    repository: Repository, bookmark: str, left: str, right: str
) -> None:
    if bookmark == "main":
        untracked = _run_jj(repository.path, "bookmark", "untrack", "main@origin")
        assert untracked.returncode == 0, untracked.stderr
    if repository.bookmark_exists(bookmark=bookmark):
        deleted = _run_jj(repository.path, "bookmark", "delete", bookmark)
        assert deleted.returncode == 0, deleted.stderr
    operation = _run_jj(
        repository.path, "op", "log", "--limit", "1", "--no-graph", "-T", "id"
    ).stdout.strip()
    created = _run_jj(repository.path, "bookmark", "create", bookmark, "-r", left)
    assert created.returncode == 0, created.stderr
    conflicted = _run_jj(
        repository.path,
        "--at-op",
        operation,
        "bookmark",
        "create",
        bookmark,
        "-r",
        right,
    )
    assert conflicted.returncode == 0, conflicted.stderr
    assert _run_jj(repository.path, "bookmark", "list", bookmark).returncode == 0


def _real_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch | None = None
) -> RepositoryCase:
    repo, origin_git = _initialize_real_repository(tmp_path)
    pending_after_operation: list[tuple[str, Callable[[], None]]] = []
    commands: list[tuple[str, ...]] = []
    _install_real_postcheck_interceptor(
        repo.path, monkeypatch, pending_after_operation, commands
    )
    repo.push_bookmark(bookmark="main")
    origin_peer = _initialize_real_peer(tmp_path, origin_git)

    def register_file(_filename: str) -> None:
        return None

    def track_main(enabled: bool) -> None:
        action = "track" if enabled else "untrack"
        result = _run_jj(repo.path, "bookmark", action, "main@origin")
        assert result.returncode == 0, result.stderr

    def after_push(action: Callable[[], None]) -> None:
        after_operation("push", action)

    def after_operation(operation: str, action: Callable[[], None]) -> None:
        assert not pending_after_operation, "only one pending operation is supported"
        pending_after_operation.append((operation, action))

    return RepositoryCase(
        repo=repo,
        bind=_bind_real_repository,
        register_file=register_file,
        write_file=partial(_write_repository_file, repo),
        commit_file=partial(_commit_repository_file, repo, register_file),
        describe=partial(_describe_real_repository, repo),
        force_bookmark=partial(_force_real_bookmark, repo),
        conflict_bookmark=partial(_conflict_real_bookmark, repo),
        origin_peer=origin_peer,
        track_main=track_main,
        after_push=after_push,
        after_operation=after_operation,
        attempts=None,
        commands=commands,
    )


def _register_fake_file(state: FakeJjState, path: Path, filename: str) -> None:
    state.register_files(path, filename)


def _seed_fake_bookmark(
    state: FakeJjState,
    path: Path,
    bookmark: str,
    *targets: str,
) -> None:
    state.seed_bookmark(path, bookmark=bookmark, targets=targets)


def _track_fake_main(state: FakeJjState, path: Path, enabled: bool) -> None:
    state.track_main(path, enabled=enabled)


def _install_fake_after_push(
    state: FakeJjState, path: Path, action: Callable[[], None]
) -> None:
    state.hook(
        "push_bookmark",
        phase="postcheck",
        action=action,
        path=path,
    )


def _install_fake_after_operation(
    state: FakeJjState, path: Path, operation: str, action: Callable[[], None]
) -> None:
    methods = {
        "promote": "promote_bookmark_to_main",
        "reset": "reset_verified_bookmark",
        "push": "push_bookmark",
    }
    state.hook(methods[operation], phase="postcheck", action=action, path=path)


def _fake_case(tmp_path: Path) -> RepositoryCase:
    state = FakeJjState()
    path = tmp_path / "fake-repository"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    repo.push_bookmark(bookmark="main")
    peer_path = tmp_path / "origin-peer"
    peer_repo = state.seed_peer(peer_path, source=path, track_main=True)

    register_file = partial(_register_fake_file, state, path)

    def describe(message: str) -> None:
        repo.describe(message=message)

    def peer_push_main() -> None:
        peer_repo.set_bookmark(bookmark="main", revision="@-")
        peer_repo.push_bookmark(bookmark="main")

    state.clear_calls()

    return RepositoryCase(
        repo=repo,
        bind=state.repository,
        register_file=register_file,
        write_file=partial(_write_repository_file, repo),
        commit_file=partial(_commit_repository_file, repo, register_file),
        describe=describe,
        force_bookmark=partial(_seed_fake_bookmark, state, path),
        conflict_bookmark=partial(_seed_fake_bookmark, state, path),
        origin_peer=OriginPeer(
            peer_repo,
            partial(
                _commit_repository_file,
                peer_repo,
                partial(_register_fake_file, state, peer_path),
            ),
            peer_push_main,
            lambda bookmark: state.remote_bookmark_targets(
                peer_path, bookmark=bookmark
            ),
        ),
        track_main=partial(_track_fake_main, state, path),
        after_push=partial(_install_fake_after_push, state, path),
        after_operation=partial(_install_fake_after_operation, state, path),
        attempts=state.attempts,
        commands=None,
    )


@pytest.fixture(params=["fake", pytest.param("real", marks=pytest.mark.integration)])
def repository_case(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> RepositoryCase:
    assert hasattr(vcs, "JjRepository"), "repository adapter is not implemented"
    return (
        _fake_case(tmp_path)
        if request.param == "fake"
        else _real_case(tmp_path, monkeypatch)
    )


def _bookmark_targets(
    repo: Repository, *, bookmark: str, candidates: set[str]
) -> frozenset[str]:
    observed = {
        revision: repo.revision_bookmarks(revision=revision) for revision in candidates
    }
    return frozenset(
        revision for revision, names in observed.items() if bookmark in names
    )


def _bookmark_state(
    repo: Repository, *, bookmark: str, candidates: set[str]
) -> tuple[bool, frozenset[str], str | None]:
    conflicted = repo.bookmark_conflicted(bookmark=bookmark)
    return (
        conflicted,
        _bookmark_targets(repo, bookmark=bookmark, candidates=candidates),
        None if conflicted else repo.resolve_revision(revision=bookmark),
    )


def _assert_origin_baseline_only(c: RepositoryCase, *, base: str) -> None:
    c.origin_peer.repo.fetch(main_only=False)
    assert c.origin_peer.repo.resolve_revision(revision="main") == base
    if isinstance(c.repo, vcs.JjRepository):
        missing = _run_jj(
            c.origin_peer.repo.path,
            "log",
            "-r",
            f"{MANAGED}@origin",
            "--no-graph",
            "-T",
            'commit_id ++ "\\n"',
        )
        assert missing.returncode != 0
