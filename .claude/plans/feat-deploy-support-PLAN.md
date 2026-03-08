# Deploy Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Add `mm build` and `mm deploy` commands that invoke per-project build/deploy scripts.

**Architecture:** Two new optional config fields (`build_command`, `deploy_command`) on `ProjectConfig`. A new `deployer.py` module with a shared `_run_script` helper that both `run_build` and `run_deploy` delegate to — runs commands via `subprocess.run(shell=True, executable="/bin/bash")` with live output streaming, 600s timeout, and venv-scrubbed environment. CLI wires it together with distinct exit codes for build vs deploy failure. `--build` flag on deploy optionally runs build first; `--check` flag is a P2 stub for healthchecker integration.

**Tech Stack:** Python 3.14+, cyclopts, Rich, Pydantic v2, subprocess

**Skills to Use:**
- test-driven-development
- verification-before-completion

**Required Files:** (executor will auto-read these)
- @src/maintenance_man/models/config.py
- @src/maintenance_man/cli.py
- @src/maintenance_man/updater.py (for subprocess patterns — `run_test_phases` at line 286, `_project_env` at line 487)
- @tests/conftest.py
- @tests/test_test_cli.py (for CLI test patterns)
- @tests/test_models_config.py (for model test patterns)

---

## Task 1: Config model + deployer module + updater fix

This task adds the config fields, creates the deployer module, and fixes venv PATH leakage in `updater.py`. These have no dependency on the CLI layer and can be built and tested in isolation.

**Files:**
- Modify: `src/maintenance_man/models/config.py`
- Create: `src/maintenance_man/deployer.py`
- Modify: `src/maintenance_man/updater.py`
- Modify: `tests/test_models_config.py`
- Create: `tests/test_deployer.py`

### Subtask 1.1: Add config fields and write model tests

**Step 1:** Add failing tests to `tests/test_models_config.py`

```python
class TestProjectConfigDeployFields:
    def test_no_deploy_fields(self):
        pc = ProjectConfig(path=Path("/tmp/x"), package_manager="bun")
        assert pc.build_command is None
        assert pc.deploy_command is None

    def test_deploy_only(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="uv",
            deploy_command="scripts/deploy.sh",
        )
        assert pc.deploy_command == "scripts/deploy.sh"
        assert pc.build_command is None

    def test_build_and_deploy(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="bun",
            build_command="scripts/build.sh",
            deploy_command="scripts/deploy.sh",
        )
        assert pc.build_command == "scripts/build.sh"
        assert pc.deploy_command == "scripts/deploy.sh"
```

**Step 2:** Run tests to verify they fail

Run: `uv run pytest tests/test_models_config.py::TestProjectConfigDeployFields -v`
Expected: FAIL — `ProjectConfig` rejects unknown fields `build_command` and `deploy_command` due to `extra="forbid"`.

**Step 3:** Add fields to `ProjectConfig` in `src/maintenance_man/models/config.py`

Add two lines after `test_component`:

```python
    build_command: str | None = None
    deploy_command: str | None = None
```

**Step 4:** Run tests to verify they pass

Run: `uv run pytest tests/test_models_config.py::TestProjectConfigDeployFields -v`
Expected: PASS

### Subtask 1.2: Create deployer module with tests

**Step 1:** Create `tests/test_deployer.py` with tests

```python
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.deployer import BuildError, DeployError, run_build, run_deploy


class TestRunBuild:
    @patch("maintenance_man.deployer.subprocess.run")
    def test_successful_build(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        run_build("myproject", "scripts/build.sh", tmp_path)
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["cwd"] == tmp_path
        assert call_kwargs["shell"] is True
        assert call_kwargs["executable"] == "/bin/bash"
        assert call_kwargs["timeout"] == 600

    @patch("maintenance_man.deployer.subprocess.run")
    def test_failed_build_raises(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
        with pytest.raises(BuildError, match="myproject"):
            run_build("myproject", "scripts/build.sh", tmp_path)

    @patch("maintenance_man.deployer.subprocess.run")
    def test_build_strips_virtual_env(self, mock_run: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VIRTUAL_ENV", "/some/venv")
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        run_build("myproject", "scripts/build.sh", tmp_path)
        env = mock_run.call_args.kwargs["env"]
        assert "VIRTUAL_ENV" not in env

    @patch("maintenance_man.deployer.subprocess.run")
    def test_build_scrubs_venv_from_path(self, mock_run: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        venv_dir = "/some/venv"
        monkeypatch.setenv("VIRTUAL_ENV", venv_dir)
        monkeypatch.setenv("PATH", f"{venv_dir}/bin:/usr/bin:/bin")
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        run_build("myproject", "scripts/build.sh", tmp_path)
        env = mock_run.call_args.kwargs["env"]
        assert f"{venv_dir}/bin" not in env["PATH"].split(":")
        assert "/usr/bin" in env["PATH"].split(":")


class TestRunDeploy:
    @patch("maintenance_man.deployer.subprocess.run")
    def test_successful_deploy(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        run_deploy("myproject", "scripts/deploy.sh", tmp_path)
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["shell"] is True
        assert call_kwargs["executable"] == "/bin/bash"

    @patch("maintenance_man.deployer.subprocess.run")
    def test_failed_deploy_raises(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
        with pytest.raises(DeployError, match="myproject"):
            run_deploy("myproject", "scripts/deploy.sh", tmp_path)
```

**Step 2:** Run tests to verify they fail

Run: `uv run pytest tests/test_deployer.py -v`
Expected: FAIL — `maintenance_man.deployer` does not exist.

**Step 3:** Create `src/maintenance_man/deployer.py`

```python
from __future__ import annotations

import os
import subprocess
from pathlib import Path


class BuildError(Exception):
    pass


class DeployError(Exception):
    pass


def _project_env() -> dict[str, str]:
    """Return a copy of os.environ with venv isolation.

    Strips VIRTUAL_ENV and removes the venv bin/ directory from PATH
    so that build/deploy scripts don't accidentally use mm's Python.
    """
    env = os.environ.copy()
    venv = env.pop("VIRTUAL_ENV", None)
    if venv:
        venv_bin = str(Path(venv) / "bin")
        path_dirs = env.get("PATH", "").split(os.pathsep)
        env["PATH"] = os.pathsep.join(d for d in path_dirs if d != venv_bin)
    return env


def _run_script(
    command: str,
    project_name: str,
    project_path: Path,
    error_cls: type[Exception],
    label: str,
) -> None:
    """Run a shell command with live output. Raises error_cls on failure."""
    result = subprocess.run(
        command,
        cwd=project_path,
        shell=True,
        executable="/bin/bash",
        env=_project_env(),
        timeout=600,
    )
    if result.returncode != 0:
        msg = f"{label} failed for {project_name} (exit code {result.returncode})"
        raise error_cls(msg)


def run_build(project_name: str, build_command: str, project_path: Path) -> None:
    """Run a project's build command. Raises BuildError on failure."""
    _run_script(build_command, project_name, project_path, BuildError, "Build")


def run_deploy(project_name: str, deploy_command: str, project_path: Path) -> None:
    """Run a project's deploy command. Raises DeployError on failure."""
    _run_script(deploy_command, project_name, project_path, DeployError, "Deploy")
```

stdout/stderr are inherited from the parent process (not captured), which gives live streaming for free. `shell=True` is intentional — the command is a user-configured script path from their own TOML config, not untrusted input. `executable="/bin/bash"` ensures bashisms work even for inline commands.

**Step 4:** Run tests to verify they pass

Run: `uv run pytest tests/test_deployer.py -v`
Expected: PASS

### Subtask 1.3: Fix `_project_env` in updater.py

The existing `_project_env()` in `updater.py` only strips `VIRTUAL_ENV` but leaves the venv `bin/` in `PATH`. Apply the same fix.

**Step 1:** Replace `_project_env` in `src/maintenance_man/updater.py` (around line 487)

Replace:

```python
def _project_env() -> dict[str, str]:
    """Return a copy of os.environ without VIRTUAL_ENV.

    Prevents the host venv leaking into subprocess calls that run inside
    a target project directory (e.g. ``uv run``, ``uv add``).
    """
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)
    return env
```

With:

```python
def _project_env() -> dict[str, str]:
    """Return a copy of os.environ with venv isolation.

    Strips VIRTUAL_ENV and removes the venv bin/ directory from PATH.
    Prevents the host venv leaking into subprocess calls that run inside
    a target project directory (e.g. ``uv run``, ``uv add``).
    """
    env = os.environ.copy()
    venv = env.pop("VIRTUAL_ENV", None)
    if venv:
        venv_bin = str(Path(venv) / "bin")
        path_dirs = env.get("PATH", "").split(os.pathsep)
        env["PATH"] = os.pathsep.join(d for d in path_dirs if d != venv_bin)
    return env
```

Note: `Path` is already imported in `updater.py`.

**Step 2:** Run full test suite to check nothing is broken

Run: `uv run pytest -m 'not integration and not component' -v`
Expected: All existing tests still pass.

---

## Task 2: CLI commands + exit codes

This task wires the deployer module into the CLI. Depends on Task 1.

**Files:**
- Modify: `src/maintenance_man/cli.py`
- Create: `tests/test_build_cli.py`
- Create: `tests/test_deploy_cli.py`
- Modify: `tests/conftest.py`

### Subtask 2.1: Update conftest with deploy-capable fixtures

**Step 1:** Add projects with deploy config to the `mm_home_with_projects` fixture in `tests/conftest.py`

Add these project entries to the `config_text` string, after the existing `no-tests` project:

```toml
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
```

Use the same `clean_path` variable already defined in the fixture. Note: `deploy-only` and `no-deploy` both have `test_unit` to avoid confusing update-related tests that iterate all projects.

### Subtask 2.2: Add exit codes and build command

**Step 1:** Write failing tests in `tests/test_build_cli.py`

```python
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.cli import ExitCode, app
from maintenance_man.deployer import BuildError


class TestBuildCommand:
    def test_no_build_config(self, mm_home_with_projects: Path) -> None:
        """Error when project has no build_command configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "no-deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    def test_no_build_config_deploy_only_project(self, mm_home_with_projects: Path) -> None:
        """Error when project has deploy_command but no build_command."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "deploy-only"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    @patch("maintenance_man.cli.run_build")
    def test_successful_build(self, mock_build: MagicMock, mm_home_with_projects: Path) -> None:
        """Exit 0 on successful build."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_build.assert_called_once()

    @patch("maintenance_man.cli.run_build", side_effect=BuildError("build failed"))
    def test_failed_build(self, mock_build: MagicMock, mm_home_with_projects: Path) -> None:
        """Exit BUILD_FAILED on build failure."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.BUILD_FAILED

    def test_unknown_project(self, mm_home_with_projects: Path) -> None:
        """Error when project doesn't exist."""
        with pytest.raises(SystemExit) as exc_info:
            app(["build", "nonexistent"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR
```

**Step 2:** Run tests to verify they fail

Run: `uv run pytest tests/test_build_cli.py -v`
Expected: FAIL — `ExitCode.BUILD_FAILED` does not exist, `build` command not implemented.

**Step 3:** Add exit codes to `ExitCode` in `src/maintenance_man/cli.py`

Add after `TEST_FAILED = 5`:

```python
    BUILD_FAILED = 6
    DEPLOY_FAILED = 7
```

**Step 4:** Add the `build` command to `src/maintenance_man/cli.py`

Add an import at the top with the other imports:

```python
from maintenance_man.deployer import BuildError, DeployError, run_build, run_deploy
```

Add the command (place it after the `test` command, before the `list_projects` command):

```python
@app.command
def build(
    project: str,
    *,
    config: Path | None = None,
) -> None:
    """Build a project's artefacts.

    Parameters
    ----------
    project: str
        Project name to build.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)

    if not proj_config.build_command:
        _fatal(
            f"No build_command configured for [bold]{project}[/]. "
            f"Add build_command to [projects.{project}] in ~/.mm/config.toml."
        )

    console.print(f"[bold]Building {project}[/]\n")

    try:
        run_build(project, proj_config.build_command, proj_config.path)
    except BuildError as e:
        _fatal(str(e), code=ExitCode.BUILD_FAILED)

    console.print("\n[bold green]Build succeeded.[/]")
    sys.exit(ExitCode.OK)
```

**Step 5:** Run tests to verify they pass

Run: `uv run pytest tests/test_build_cli.py -v`
Expected: PASS

### Subtask 2.3: Implement deploy command

**Step 1:** Write failing tests in `tests/test_deploy_cli.py`

```python
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.cli import ExitCode, app
from maintenance_man.deployer import BuildError, DeployError


class TestDeployCommand:
    def test_no_deploy_config(self, mm_home_with_projects: Path) -> None:
        """Error when project has no deploy_command configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "no-deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR

    @patch("maintenance_man.cli.run_deploy")
    def test_successful_deploy(self, mock_deploy: MagicMock, mm_home_with_projects: Path) -> None:
        """Exit 0 on successful deploy."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_deploy.assert_called_once()

    @patch("maintenance_man.cli.run_deploy", side_effect=DeployError("deploy failed"))
    def test_failed_deploy(self, mock_deploy: MagicMock, mm_home_with_projects: Path) -> None:
        """Exit DEPLOY_FAILED on deploy failure."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.DEPLOY_FAILED

    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_build_flag_runs_build_then_deploy(
        self, mock_build: MagicMock, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """--build runs build before deploy."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable", "--build"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_build.assert_called_once()
        mock_deploy.assert_called_once()

    @patch("maintenance_man.cli.run_deploy")
    def test_build_flag_skips_when_no_build_command(
        self, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """--build silently skips if no build_command configured."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deploy-only", "--build"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        mock_deploy.assert_called_once()

    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build", side_effect=BuildError("build failed"))
    def test_build_failure_aborts_deploy(
        self, mock_build: MagicMock, mock_deploy: MagicMock, mm_home_with_projects: Path
    ) -> None:
        """Deploy is not attempted if build fails."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "deployable", "--build"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.BUILD_FAILED
        mock_deploy.assert_not_called()

    def test_unknown_project(self, mm_home_with_projects: Path) -> None:
        """Error when project doesn't exist."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "nonexistent"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.ERROR
```

**Step 2:** Run tests to verify they fail

Run: `uv run pytest tests/test_deploy_cli.py -v`
Expected: FAIL — current `deploy` command doesn't accept `--build` flag and always exits with ERROR.

**Step 3:** Replace the existing `deploy` stub in `src/maintenance_man/cli.py`

Replace the entire `deploy` function with:

```python
@app.command
def deploy(
    project: str,
    *,
    build: bool = False,
    check: bool = False,
    config: Path | None = None,
) -> None:
    """Deploy a project.

    Parameters
    ----------
    project: str
        Project name to deploy.
    build: bool
        Run build_command before deploying. Silently skips if no build_command
        is configured.
    check: bool
        Verify deployment health via healthchecker after deploy (not yet implemented).
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)
    proj_config = _resolve_proj(cfg, project)

    if not proj_config.deploy_command:
        _fatal(
            f"No deploy_command configured for [bold]{project}[/]. "
            f"Add deploy_command to [projects.{project}] in ~/.mm/config.toml."
        )

    if build and proj_config.build_command:
        console.print(f"[bold]Building {project}[/]\n")
        try:
            run_build(project, proj_config.build_command, proj_config.path)
        except BuildError as e:
            _fatal(str(e), code=ExitCode.BUILD_FAILED)
        console.print("\n[bold green]Build succeeded.[/]\n")

    console.print(f"[bold]Deploying {project}[/]\n")

    try:
        run_deploy(project, proj_config.deploy_command, proj_config.path)
    except DeployError as e:
        _fatal(str(e), code=ExitCode.DEPLOY_FAILED)

    console.print("\n[bold green]Deploy succeeded.[/]")

    if check:
        console.print("[dim]--check: healthchecker verification not yet implemented[/]")

    sys.exit(ExitCode.OK)
```

**Step 4:** Run deploy tests

Run: `uv run pytest tests/test_deploy_cli.py -v`
Expected: PASS

**Step 5:** Run build tests again to confirm nothing broke

Run: `uv run pytest tests/test_build_cli.py -v`
Expected: PASS

**Step 6:** Run full test suite

Run: `uv run pytest -m 'not integration and not component' -v`
Expected: All tests pass.

**Step 7:** Fix imports — run ruff

Run: `uv run ruff check --fix src/maintenance_man/cli.py`
Expected: Import sorting fixed if needed.

---
