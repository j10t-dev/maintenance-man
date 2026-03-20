# Mass Deploy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Allow `mm deploy` with no project argument to build and deploy all configured projects.

**Architecture:** Make the `project` parameter optional on the `deploy` command. When omitted, iterate all projects with `deploy_command`, build (if configured) then deploy each one, continuing on failure. Print a summary table at the end. Mirrors the `_update_all` pattern.

**Tech Stack:** Python, cyclopts CLI, Rich tables, Pydantic

**Skills to Use:**
- test-driven-development
- verification-before-completion

**Required Files:** (executor will auto-read these)
- @src/maintenance_man/cli.py (deploy command at line 512-585, _update_all pattern at line 450-484, _print_mass_update_summary at line 487-509)
- @src/maintenance_man/deployer.py (run_build, run_deploy, BuildError, DeployError, check_health)
- @src/maintenance_man/models/config.py (ProjectConfig with deploy_command, build_command)
- @tests/test_deploy_cli.py (existing deploy tests)
- @tests/conftest.py (mm_home_with_projects fixture — has "deployable", "deploy-only", "no-deploy" projects)

---

## Task 1: Mass deploy implementation and tests

This is a single task because all changes are tightly coupled — the CLI command, the batch helper, the summary printer, and all tests modify the same two files (`cli.py` and `test_deploy_cli.py`).

**Files:**
- Modify: `src/maintenance_man/cli.py`
- Modify: `tests/test_deploy_cli.py`

### Subtask 1.1: Write tests for mass deploy

**Step 1:** Add a new test class `TestMassDeployCommand` to `tests/test_deploy_cli.py`:

```python
class TestMassDeployCommand:
    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_deploys_all_projects_with_deploy_command(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Mass deploy runs build+deploy for all projects with deploy_command."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        # "deployable" has both build+deploy, "deploy-only" has deploy only
        assert mock_deploy.call_count == 2
        # Only "deployable" has build_command
        assert mock_build.call_count == 1

    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_skips_projects_without_deploy_command(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Projects without deploy_command are silently skipped."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        output = capsys.readouterr().out
        # "no-deploy", "vulnerable", "clean", "outdated", "no-tests" have no deploy_command
        # They should NOT appear in the output as being deployed
        deployed_projects = [
            call.args[0] for call in mock_deploy.call_args_list
        ]
        assert "no-deploy" not in deployed_projects
        assert "vulnerable" not in deployed_projects

    @patch(
        "maintenance_man.cli.run_deploy",
        side_effect=DeployError("deploy failed"),
    )
    @patch("maintenance_man.cli.run_build")
    def test_continues_after_deploy_failure(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Deploy failure on one project doesn't stop others."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.DEPLOY_FAILED
        # Should attempt both deployable projects despite failures
        assert mock_deploy.call_count == 2

    @patch("maintenance_man.cli.run_deploy")
    @patch(
        "maintenance_man.cli.run_build",
        side_effect=BuildError("build failed"),
    )
    def test_build_failure_skips_deploy_for_that_project(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """Build failure skips deploy for that project but continues to next."""
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.DEPLOY_FAILED
        # "deployable" build fails so deploy skipped, "deploy-only" has no build so deploy runs
        assert mock_deploy.call_count == 1

    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_prints_summary_table(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mm_home_with_projects: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Mass deploy prints a summary table."""
        with pytest.raises(SystemExit):
            app(["deploy"], exit_on_error=False)
        output = capsys.readouterr().out
        assert "Deploy Summary" in output

    @patch(
        "maintenance_man.cli.check_health",
        return_value=HealthCheckResult(is_up=True),
    )
    @patch("maintenance_man.cli.run_deploy")
    @patch("maintenance_man.cli.run_build")
    def test_check_flag_works_in_mass_mode(
        self,
        mock_build: MagicMock,
        mock_deploy: MagicMock,
        mock_check: MagicMock,
        mm_home_with_projects: Path,
    ) -> None:
        """--check runs health check for each deployed project."""
        config_path = mm_home_with_projects / "config.toml"
        text = config_path.read_text().replace(
            "min_version_age_days = 7",
            'min_version_age_days = 7\nhealthcheck_url = "http://pihost:8080"',
        )
        config_path.write_text(text)

        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "--check"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        # Health check called for each successfully deployed project
        assert mock_check.call_count == 2

    def test_no_projects_configured(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Mass deploy with no projects prints message and exits OK."""
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "worktrees").mkdir()
        (mm_home / "config.toml").write_text("[defaults]\nmin_version_age_days = 7\n")
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"], exit_on_error=False)
        assert exc_info.value.code == ExitCode.OK
        assert "no projects" in capsys.readouterr().out.lower()
```

Note: The `mm_home` fixture is imported from conftest — it redirects `MM_HOME` to a temp dir but doesn't create it on disk. The `mm_home_with_projects` fixture creates the directory structure with test projects.

**Step 2:** Run to verify tests fail:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_deploy_cli.py::TestMassDeployCommand -v`
Expected: FAIL (deploy requires project argument currently)

### Subtask 1.2: Implement mass deploy

**Step 1:** Create a dataclass for deploy results. Add near the top of `cli.py`, after the `ExitCode` enum (around line 80):

```python
@dataclass
class DeployResult:
    project: str
    build_status: str  # "pass", "fail", "skip"
    deploy_status: str  # "pass", "fail", "skip"
```

Add the `dataclass` import — it's not currently imported in cli.py:
```python
from dataclasses import dataclass
```

**Step 2:** Create a `_deploy_one` helper that handles a single project in mass mode. Place it before the `deploy` command function:

```python
def _deploy_one(
    name: str,
    proj_config: ProjectConfig,
    cfg: MmConfig,
    *,
    check: bool = False,
) -> DeployResult:
    """Build and deploy a single project. Returns result, never raises."""
    activity_path = _config.MM_HOME / "activity.json"
    branch = _safe_branch(proj_config.path)
    build_status = "skip"
    deploy_status = "skip"

    # Build (always attempted in mass mode if configured)
    if proj_config.build_command:
        console.print(f"  [bold]Building...[/]")
        try:
            run_build(name, proj_config.build_command, proj_config.path)
        except BuildError as e:
            record_activity(activity_path, name, "build", success=False, branch=branch)
            console.print(f"  [bold red]Build failed:[/] {e}")
            build_status = "fail"
            return DeployResult(project=name, build_status=build_status, deploy_status=deploy_status)
        record_activity(activity_path, name, "build", success=True, branch=branch)
        build_status = "pass"

    # Deploy
    console.print(f"  [bold]Deploying...[/]")
    try:
        run_deploy(name, proj_config.deploy_command, proj_config.path)
    except DeployError as e:
        record_activity(activity_path, name, "deploy", success=False, branch=branch)
        console.print(f"  [bold red]Deploy failed:[/] {e}")
        deploy_status = "fail"
        return DeployResult(project=name, build_status=build_status, deploy_status=deploy_status)
    record_activity(activity_path, name, "deploy", success=True, branch=branch)
    deploy_status = "pass"

    # Health check
    if check and cfg.defaults.healthcheck_url:
        result = check_health(cfg.defaults.healthcheck_url, name)
        if result.is_up:
            console.print(f"  [bold green]Healthy[/]")
        elif result.error:
            console.print(f"  [bold yellow]Warning:[/] {result.error}")
        else:
            console.print(f"  [bold yellow]Warning:[/] {name} is not healthy")

    return DeployResult(project=name, build_status=build_status, deploy_status=deploy_status)
```

**Step 3:** Create a `_deploy_all` function. Place it after `_deploy_one`:

```python
def _deploy_all(cfg: MmConfig, *, check: bool = False) -> NoReturn:
    """Deploy all configured projects that have a deploy_command."""
    if not cfg.projects:
        console.print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        sys.exit(ExitCode.OK)

    results: list[DeployResult] = []

    for name, proj_config in sorted(cfg.projects.items()):
        if not proj_config.deploy_command:
            continue

        if not proj_config.path.exists():
            console.print(
                f"[bold yellow]Warning:[/] {name} — "
                f"path does not exist: {proj_config.path}"
            )
            results.append(DeployResult(project=name, build_status="skip", deploy_status="fail"))
            continue

        console.print(f"\n{'═' * 40}")
        console.print(f"[bold]{name}[/]")
        console.print("═" * 40)

        results.append(_deploy_one(name, proj_config, cfg, check=check))

    _print_deploy_summary(results)

    any_failed = any(r.deploy_status == "fail" or r.build_status == "fail" for r in results)
    sys.exit(ExitCode.DEPLOY_FAILED if any_failed else ExitCode.OK)
```

**Step 4:** Create `_print_deploy_summary`. Place it after `_deploy_all`:

```python
def _print_deploy_summary(results: list[DeployResult]) -> None:
    """Print a cross-project deploy summary table."""
    if not results:
        console.print("\n[dim]No projects have deploy_command configured.[/]")
        return

    _STATUS_DISPLAY = {
        "pass": "[green]PASS[/]",
        "fail": "[red]FAIL[/]",
        "skip": "[dim]SKIP[/]",
    }

    table = Table(title="Deploy Summary")
    table.add_column("Project", style="bold")
    table.add_column("Build")
    table.add_column("Deploy")

    for r in results:
        table.add_row(
            r.project,
            _STATUS_DISPLAY[r.build_status],
            _STATUS_DISPLAY[r.deploy_status],
        )

    console.print()
    console.print(table)
```

**Step 5:** Modify the `deploy` command signature and body. Change `project: str` to `project: str | None = None` and add routing logic:

```python
@app.command
def deploy(
    project: str | None = None,
    *,
    build: bool = False,
    check: bool = False,
    config: Path | None = None,
) -> None:
    """Deploy a project.

    Parameters
    ----------
    project: str | None
        Project name to deploy. Deploys all if omitted.
    build: bool
        Run build_command before deploying. Silently skips if no build_command
        is configured. Always enabled in mass mode.
    check: bool
        Verify deployment health via healthchecker after deploy.
    config: Path | None
        Path to config file. Uses ~/.mm/config.toml if omitted.
    """
    cfg = _load_cfg(config)

    if not project:
        _deploy_all(cfg, check=check)

    proj_config = _resolve_proj(cfg, project)
    # ... rest of existing single-project deploy code unchanged ...
```

IMPORTANT: The existing single-project deploy code (lines 537-585) stays exactly as-is. Only the function signature changes and the `if not project: _deploy_all(...)` routing is added at the top. `_deploy_all` calls `sys.exit()` so it never falls through.

**Step 6:** Run tests:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest tests/test_deploy_cli.py -v`
Expected: All PASSED (existing + new)

**Step 7:** Run full test suite:

Run: `cd /home/glykon/dev/maintenance-man && uv run pytest -v`
Expected: All PASSED (except the pre-existing test_vcs failure)

**Step 8:** Run ruff:

Run: `cd /home/glykon/dev/maintenance-man && uv run ruff check --fix src/maintenance_man/cli.py tests/test_deploy_cli.py`
