# Test Project Fixtures — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task.

**Goal:** Add `--config` flag to CLI commands, create test fixture projects with known vulnerabilities/outdated deps, and add `mm-test-scan` helper command.

**Architecture:** Extend `load_config()` with optional config path + relative path resolution. Create minimal fixture projects (one per package manager) with deliberately old dependencies. Wire up via `tests/fixtures/test-config.toml` using relative paths.

**Tech Stack:** Python 3.14, cyclopts, Pydantic, uv, bun, Maven

**Skills to Use:**
- test-driven-development
- verification-before-completion

**Required Files:** (executor will auto-read these)
- @src/maintenance_man/config.py
- @src/maintenance_man/cli.py
- @src/maintenance_man/models/config.py
- @tests/test_config.py
- @tests/conftest.py
- @pyproject.toml
- @.gitignore

---

## Task 1: `--config` flag + relative path resolution

**Files:**
- Modify: `src/maintenance_man/config.py` (lines 18-37, `load_config`)
- Modify: `src/maintenance_man/cli.py` (lines 79-141, 144-290, 308-330 — `scan`, `update`, `list_projects`)
- Modify: `tests/test_config.py`

### Subtask 1.1: Write failing tests for `load_config(config_path=...)`

**Step 1:** Add tests to `tests/test_config.py` in `TestLoadConfig`:

```python
def test_loads_from_custom_path(self, tmp_path: Path):
    """load_config(config_path=...) reads from the given file."""
    config_file = tmp_path / "custom-config.toml"
    config_file.write_text("[defaults]\nmin_version_age_days = 42\n")
    config = load_config(config_path=config_file)
    assert config.defaults.min_version_age_days == 42

def test_custom_path_does_not_create_mm_home(self, mm_home: Path):
    """Using a custom config path should not create ~/.mm/."""
    config_file = mm_home.parent / "custom-config.toml"
    config_file.write_text("[defaults]\n")
    load_config(config_path=config_file)
    assert not mm_home.exists()

def test_custom_path_file_not_found(self, tmp_path: Path):
    """Missing custom config file raises ConfigError."""
    with pytest.raises(ConfigError):
        load_config(config_path=tmp_path / "nonexistent.toml")
```

**Step 2:** Run tests to confirm they fail:

Run: `uv run pytest tests/test_config.py::TestLoadConfig -v`
Expected: FAIL — `load_config()` doesn't accept `config_path`

### Subtask 1.2: Write failing tests for relative path resolution

**Step 1:** Add test to `tests/test_config.py` in `TestLoadConfig`:

```python
def test_resolves_relative_project_paths(self, tmp_path: Path):
    """Relative project paths resolve against config file's parent dir."""
    project_dir = tmp_path / "projects" / "myapp"
    project_dir.mkdir(parents=True)
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        '[projects.myapp]\npath = "projects/myapp"\npackage_manager = "bun"\n'
    )
    config = load_config(config_path=config_file)
    assert config.projects["myapp"].path == project_dir

def test_absolute_paths_unchanged(self, tmp_path: Path):
    """Absolute project paths are not modified during resolution."""
    project_dir = tmp_path / "myapp"
    project_dir.mkdir()
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        f'[projects.myapp]\npath = "{project_dir}"\npackage_manager = "bun"\n'
    )
    config = load_config(config_path=config_file)
    assert config.projects["myapp"].path == project_dir
```

**Step 2:** Run tests to confirm they fail:

Run: `uv run pytest tests/test_config.py::TestLoadConfig -v`
Expected: FAIL

### Subtask 1.3: Implement `load_config(config_path=...)`

**Step 1:** Modify `load_config` in `src/maintenance_man/config.py`:

```python
def load_config(config_path: Path | None = None) -> MmConfig:
    """Load and validate config from a TOML file.

    If config_path is None, reads from ~/.mm/config.toml (creating it if needed).
    Relative project paths are resolved against the config file's parent directory.
    """
    if config_path is None:
        ensure_mm_home()
        config_path = MM_HOME / "config.toml"

    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    try:
        with config_path.open("rb") as f:
            raw = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(
            f"Failed to parse {config_path}\n{e}"
        ) from e

    try:
        config = MmConfig(**raw)
    except ValidationError as e:
        raise ConfigError(
            f"Invalid config in {config_path}\n{e}"
        ) from e

    # Resolve relative project paths against config file's parent directory
    config_dir = config_path.parent.resolve()
    for project in config.projects.values():
        if not project.path.is_absolute():
            project.path = (config_dir / project.path).resolve()

    return config
```

**Step 2:** Run all config tests:

Run: `uv run pytest tests/test_config.py -v`
Expected: ALL PASS

Note: the existing `test_loads_skeleton_config_on_first_run` test passes because when `config_path=None`, `ensure_mm_home()` still creates the skeleton config. The existing `test_invalid_config_raises_config_error` still works because it writes to `mm_home / "config.toml"` and calls `load_config()` without arguments.

### Subtask 1.4: Add `--config` flag to CLI commands

**Step 1:** Add `--config` parameter to the `scan` command in `src/maintenance_man/cli.py`:

Change the signature from:
```python
@app.command
def scan(
    project: str | None = None,
) -> None:
```
to:
```python
@app.command
def scan(
    project: str | None = None,
    *,
    config: Path | None = None,
) -> None:
```

And change `load_config()` call to `load_config(config_path=config)`.

**Step 2:** Add `--config` parameter to the `update` command. Same pattern — add `*, config: Path | None = None` and pass to `load_config(config_path=config)`.

**Step 3:** Add `--config` parameter to the `list_projects` command. Same pattern.

**Step 4:** Verify the CLI works:

Run: `uv run mm scan --help`
Expected: `--config` option visible in help output

Run: `uv run mm update --help`
Expected: `--config` option visible in help output

Run: `uv run mm list --help`
Expected: `--config` option visible in help output

### Subtask 1.5: Run full test suite

Run: `uv run pytest -v`
Expected: ALL PASS

---

## Task 2: Test fixture projects

This task is **independent of Task 1** and can run in parallel.

**Files:**
- Create: `tests/fixtures/projects/dirty-bun/package.json`
- Create: `tests/fixtures/projects/dirty-uv/pyproject.toml`
- Create: `tests/fixtures/projects/dirty-mvn/pom.xml`
- Create: `tests/fixtures/test-config.toml`
- Modify: `.gitignore`

### Subtask 2.1: Create dirty-bun fixture

**Step 1:** Create `tests/fixtures/projects/dirty-bun/package.json` with deliberately old, vulnerable packages:

```json
{
  "name": "dirty-bun-fixture",
  "version": "0.0.0",
  "private": true,
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.15"
  }
}
```

Package rationale:
- `express@4.17.1` — multiple CVEs including CVE-2024-29041 (open redirect), significantly outdated
- `lodash@4.17.15` — CVE-2021-23337 (command injection), CVE-2020-28500 (ReDoS)

**Step 2:** Generate the lockfile:

Run: `cd tests/fixtures/projects/dirty-bun && bun install`

This creates `bun.lock` (committed) and `node_modules/` (gitignored).

### Subtask 2.2: Create dirty-uv fixture

**Step 1:** Create `tests/fixtures/projects/dirty-uv/pyproject.toml`:

```toml
[project]
name = "dirty-uv-fixture"
version = "0.0.0"
requires-python = ">=3.12"
dependencies = [
    "requests==2.25.0",
    "jinja2==3.0.0",
]
```

Package rationale:
- `requests==2.25.0` — CVE-2023-32681 (info leak via Proxy-Authorization header), very outdated
- `jinja2==3.0.0` — CVE-2024-22195 (XSS), outdated

**Step 2:** Generate lockfile and venv:

Run: `cd tests/fixtures/projects/dirty-uv && uv sync`

This creates `uv.lock` (committed) and `.venv/` (gitignored).

### Subtask 2.3: Create dirty-mvn fixture

**Step 1:** Create `tests/fixtures/projects/dirty-mvn/pom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>dirty-mvn-fixture</artifactId>
    <version>0.0.0</version>
    <packaging>jar</packaging>

    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.0</version>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-text</artifactId>
            <version>1.9</version>
        </dependency>
    </dependencies>
</project>
```

Package rationale:
- `log4j-core:2.14.0` — CVE-2021-44228 (Log4Shell), critical RCE
- `commons-text:1.9` — CVE-2022-42889 (Text4Shell), RCE

No install step needed — Trivy scans `pom.xml` directly.

### Subtask 2.4: Create test config

**Step 1:** Create `tests/fixtures/test-config.toml`:

```toml
[defaults]
min_version_age_days = 0

[projects.dirty-bun]
path = "projects/dirty-bun"
package_manager = "bun"

[projects.dirty-uv]
path = "projects/dirty-uv"
package_manager = "uv"

[projects.dirty-mvn]
path = "projects/dirty-mvn"
package_manager = "mvn"
scan_secrets = false
```

Paths are relative — resolved against `tests/fixtures/` (config file's parent) by the relative path support from Task 1.

`scan_secrets = false` on dirty-mvn because there's no source tree to scan.

### Subtask 2.5: Update `.gitignore`

**Step 1:** Add entries to `.gitignore`:

```
# Test fixture installed deps
tests/fixtures/projects/dirty-bun/node_modules/
tests/fixtures/projects/dirty-uv/.venv/
```

### Subtask 2.6: Verify fixtures produce findings

This step requires Task 1 to be complete (for `--config` flag).

Run: `uv run mm scan --config tests/fixtures/test-config.toml`

Expected: scan output showing vulnerabilities and outdated packages for all three projects. Non-zero exit code.

If any fixture produces no findings, investigate and adjust pinned versions.

---

## Task 3: `mm-test-scan` helper command

**Depends on:** Task 1 (needs `--config` flag to exist)

**Files:**
- Modify: `src/maintenance_man/cli.py`
- Modify: `pyproject.toml`

### Subtask 3.1: Add `test_scan` function

**Step 1:** Add to `src/maintenance_man/cli.py`, after the existing `main` function:

```python
def test_scan() -> None:
    """Run scan against test fixture projects."""
    project_root = Path(__file__).resolve().parents[2]
    test_config = project_root / "tests" / "fixtures" / "test-config.toml"
    if not test_config.exists():
        console.print(
            f"[bold red]Error:[/] Test config not found: {test_config}\n"
            "Are you running from the project root?"
        )
        sys.exit(1)
    app(["scan", "--config", str(test_config)])
```

### Subtask 3.2: Add script entry to `pyproject.toml`

**Step 1:** Add to `[project.scripts]`:

```toml
[project.scripts]
mm = "maintenance_man.cli:main"
mm-test-scan = "maintenance_man.cli:test_scan"
```

**Step 2:** Reinstall the package to register the new script:

Run: `uv sync`

### Subtask 3.3: Verify helper works

Run: `uv run mm-test-scan`

Expected: same output as `uv run mm scan --config tests/fixtures/test-config.toml`
