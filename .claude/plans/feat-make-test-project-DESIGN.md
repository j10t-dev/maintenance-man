# Test Project Fixtures — Design

## Goal

Create test project fixtures with known vulnerabilities and outdated dependencies for manual testing of `mm scan`. These must **not** interfere with normal scan workflows.

## Approach

### 1. `--config` flag on CLI commands

Add a `--config` / `-c` option to `mm scan` (and other commands that call `load_config()`) so an alternative config file can be specified:

```
mm scan --config tests/fixtures/test-config.toml
```

Implementation: `load_config()` already reads from `MM_HOME / "config.toml"`. Add an optional `path` parameter that overrides this. Thread it through from the CLI.

### 2. Test project directories

Plain directories under `tests/fixtures/projects/`, one per package manager:

```
tests/fixtures/projects/
  dirty-bun/        # package.json + bun.lock
  dirty-uv/         # pyproject.toml + uv.lock + .venv/
  dirty-mvn/        # pom.xml
```

Each project pins a few packages at deliberately old versions chosen to produce:
- **Outdated findings** — packages with newer versions available
- **Vulnerability findings** — packages with known CVEs at the pinned version (Trivy will detect these)

These are committed to the repo as fixtures. No git init, no remotes, no submodules.

### 3. Test config file

`tests/fixtures/test-config.toml`:

```toml
[defaults]
min_version_age_days = 0  # no age filtering for test fixtures

[projects.dirty-bun]
path = "tests/fixtures/projects/dirty-bun"  # relative to repo root, resolved at runtime
package_manager = "bun"

[projects.dirty-uv]
path = "tests/fixtures/projects/dirty-uv"
package_manager = "uv"

[projects.dirty-mvn]
path = "tests/fixtures/projects/dirty-mvn"
package_manager = "mvn"
```

Note: `ProjectConfig.path` is currently an absolute `Path`. We'll support both:
- **Absolute paths** (preferred, existing behaviour)
- **Relative paths** resolved against the config file's parent directory (for portability, e.g. test fixtures)

### 4. Helper command

Add a `[project.scripts]` entry to `pyproject.toml`:

```toml
[project.scripts]
mm = "maintenance_man.cli:main"
mm-test-scan = "maintenance_man.cli:test_scan"
```

`test_scan` is a thin wrapper that calls the main scan entry point with `--config tests/fixtures/test-config.toml` resolved relative to the project root (using `importlib.resources` or `__file__` traversal).

### 5. Reset mechanism

`git checkout -- tests/fixtures/projects/` restores all fixture manifests to their committed (dirty) state. Lock files are committed. Installed deps (node_modules, .venv) are gitignored and can be blown away and reinstalled.

## Out of scope

- Testing the update workflow (`mm update`) — scan only
- Testing `--continue` / failure recovery paths
- Breaking change simulation (can be unit-tested with mocked data separately)
- Submodules / separate GitHub repos

## Package selection criteria

For each package manager, pick 2-3 packages where:
1. An old version has a known CVE (for vuln findings)
2. The current version is several majors/minors behind latest (for outdated findings)
3. The package is small / has few transitive deps (to keep fixtures lightweight)

Specific packages to be determined during implementation.
