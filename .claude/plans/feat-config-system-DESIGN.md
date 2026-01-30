# Config System — Design Document

Reference: [Main Design](main-DESIGN.md) | [Backlog Item #2](BACKLOG.md)

## Overview

TOML config loading, validation, and the `~/.mm/` directory structure. The foundation everything else reads from.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Config modelling | Pydantic (strict) | Built-in validation, clear errors, reject unknown keys |
| File layout | Separate models + loading | `models/config.py` for Pydantic models, `config.py` for loading logic |
| Directory bootstrap | Auto-create on first run | No `mm init` needed, tool just works |
| Project registration | Hand-edit TOML | Power-user tool, 5 lines per project |
| `mm list` command | Yes | Sanity check after editing config |
| `mm add` command | No (for now) | YAGNI |
| Project fields | `path` + `package_manager` only | Language is implied by package manager |
| Path validation | At command time, not load time | Allows `mm list` to work even if a path is temporarily unavailable |
| Error reporting | Rich-formatted, fail on first error | Pydantic gives all field errors for a model; no need for multi-section aggregation |
| `update_policy` field | Omitted | YAGNI — add when we implement update policies |

## Directory Structure

When any `mm` command runs, the config module checks for `~/.mm/` and bootstraps if missing:

```
~/.mm/
  config.toml              # project registry and defaults
  scan-results/            # populated later by scan command
  worktrees/               # populated later by update command
```

## Skeleton Config

Auto-created on first run:

```toml
[defaults]
min_version_age_days = 7

# [projects.my-project]
# path = "/home/user/dev/my-project"
# package_manager = "bun"        # bun | uv | mvn
```

## Pydantic Models

Location: `src/maintenance_man/models/config.py`

### `DefaultsConfig`

- `min_version_age_days: int = 7`
- `ConfigDict(extra="forbid")`

### `ProjectConfig`

- `path: Path` (required)
- `package_manager: Literal["bun", "uv", "mvn"]` (required)
- `ConfigDict(extra="forbid")`

### `MmConfig`

- `defaults: DefaultsConfig = DefaultsConfig()` — optional in TOML, all fields have defaults
- `projects: dict[str, ProjectConfig] = {}` — empty is valid; commands that need projects check at runtime

## Config Loading

Location: `src/maintenance_man/config.py`

### Exports

- **`MM_HOME: Path`** — `Path.home() / ".mm"`
- **`ensure_mm_home() -> None`** — creates `~/.mm/`, subdirectories, and skeleton `config.toml` if missing. Idempotent.
- **`load_config() -> MmConfig`** — calls `ensure_mm_home()`, reads TOML with `tomllib` (stdlib), validates through Pydantic, returns typed config. On validation failure, prints Rich error and raises `typer.Exit(1)`.
- **`resolve_project(config: MmConfig, name: str) -> ProjectConfig`** — looks up project by name, validates path exists on disk. Fails with clear error if project not found or path missing.

### Dependency flow

```
cli.py → config.py → models/config.py
```

One-way. Config module does not import from CLI.

## CLI Integration

Commands call `load_config()` at the top:

```python
@app.command()
def scan(project: str | None = ...):
    config = load_config()
    if project:
        proj = resolve_project(config, project)
        # scan one
    else:
        if not config.projects:
            # "No projects configured" error
        # scan all
```

### `mm list` command

New command added by this work. Loads config and prints a table of registered projects (name, path, package manager).

## Testing Strategy

All tests use `tmp_path` and monkeypatch `MM_HOME` — no touching real `~/.mm/`.

### Unit tests (`tests/test_config.py`)

- Valid TOML parses into correct `MmConfig`
- Missing required fields raise validation errors
- Unknown keys rejected (strict mode)
- Invalid `package_manager` value rejected
- `defaults` section is optional (falls back to defaults)
- Empty `projects` is valid
- `resolve_project()` fails for unknown project name

### Filesystem tests

- `ensure_mm_home()` creates directory structure when missing
- `ensure_mm_home()` is idempotent
- Skeleton `config.toml` is written and is valid TOML
- `resolve_project()` fails when project path doesn't exist on disk

## Dependencies

- **pydantic** — new dependency in `pyproject.toml`
- **tomllib** — stdlib (Python 3.11+), no install needed
