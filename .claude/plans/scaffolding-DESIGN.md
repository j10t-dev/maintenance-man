# Backlog #1: Project Scaffolding — Design

## Decisions

- **Layout:** `src/` layout (`src/maintenance_man/`)
- **Package name:** `maintenance_man`, CLI command `mm`
- **Entry point:** `pyproject.toml` `[project.scripts]` only, no `__main__.py`
- **Linting:** Ruff from day one (lint + format)
- **Trivy:** Not installed by mm. Runtime check with helpful error message when scan is invoked.

## Structure

```
maintenance-man/
  src/maintenance_man/
    __init__.py           # version string
    cli.py                # Typer app, top-level commands
  tests/
    __init__.py
    test_cli.py           # smoke tests
  pyproject.toml          # project metadata, deps, scripts, ruff, pytest
  .gitignore
```

## CLI Contract

```
mm --help             → app description + available commands
mm --version          → prints version
mm scan [project]     → stub, prints "Not implemented", exits 1
mm update <project>   → stub, prints "Not implemented", exits 1 (project required)
mm deploy <project>   → stub, prints "Not implemented", exits 1 (project required)
```

Rich markup enabled on the Typer app.

## pyproject.toml

- Python >=3.12
- Dependencies: `typer[all]` (includes Rich)
- Dev dependencies: `pytest`, `ruff`
- Scripts: `mm = "maintenance_man.cli:app"`
- Ruff: line length 88, standard rule set
- Pytest: `testpaths = ["tests"]`

## Tests

Smoke tests covering:
- `mm --help` exits 0 and contains app description
- `mm --version` exits 0 and prints version
- Each stub command exits 1 with "Not implemented" message
- `mm update` without project arg errors
- `mm deploy` without project arg errors
