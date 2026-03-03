# Mass Update — Design

## Goal

Run `mm update` with no arguments to update all configured projects in turn,
auto-selecting all actionable findings for each.

## Decisions

- **project arg becomes optional** — mirrors the `scan` command pattern
- **`--continue` requires a project** — it's inherently single-project (matches a branch)
- **Auto-select all findings** in batch mode — no interactive prompt per project
- **Cross-project summary table** at the end — project / passed / failed / details
- **No return-type changes to updater.py** — PR URL capture deferred

## Scope

Changes to `cli.py` only (+ tests). No changes to `updater.py`.
