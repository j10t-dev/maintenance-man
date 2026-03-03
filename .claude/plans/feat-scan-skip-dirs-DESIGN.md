# Scan Skip Dirs — Design

## Problem

When `mm` scans its own repo (or any repo with test fixtures containing intentionally vulnerable projects), trivy reports false-positive vulnerabilities from those fixture directories.

## Solution

Add a `scan_skip_dirs` field to `ProjectConfig` — a list of relative directory paths/globs forwarded to trivy's `--skip-dirs` flag.

## Config Shape

```toml
[projects.maintenance-man]
path = "/home/glykon/dev/maintenance-man"
package_manager = "uv"
scan_skip_dirs = ["tests/fixtures"]
```

- **Field:** `scan_skip_dirs: list[str] = []` on `ProjectConfig`
- Per-project only (no `[defaults]` level) — trivy already skips common dirs like `.venv`, `node_modules`

## Implementation

1. Add `scan_skip_dirs` field to `ProjectConfig` in `models/config.py`
2. Thread the list through `scan_project()` → `_run_trivy_scan()` in `scanner.py`
3. For each entry, append `--skip-dirs <entry>` to the trivy command
4. Tests: verify the constructed trivy command includes the flags
