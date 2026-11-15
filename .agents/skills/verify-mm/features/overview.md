# Initialise and inspect projects

Initialise a separate mm state directory and inspect the saved maintenance work for configured projects.

## Sub-features

- `overview-init` creates a skeleton configuration in the selected MM_HOME.
- `overview-detail` shows the saved dependency update for `fixture`.
- `overview-summary` shows project counts and maintenance timestamps.
- `overview-todo` reads a configured project's TODO file.

## How to get to it (user POV)

- Run `mm init` or `mm --version`.
- Run `mm list`, `mm status` or `mm st`, optionally with `--detail` or `-d`.
- Run `mm todo fixture` or `mm todo`.

## Driving it with verify-mm

Preconditions: use the repository root and a new run path as specified in Launch.

- Initialise: `uv run python .agents/skills/verify-mm/scripts/verify.py launch "$MM_VERIFY_RUN"`. `actions.jsonl` records real `mm init` exit `0` and the isolated directory; launch then replaces only that run's skeleton with synthetic fixture config.
- Inspect: `uv run python .agents/skills/verify-mm/scripts/verify.py doctor "$MM_VERIFY_RUN"`. `doctor-version` records the CLI version; `doctor-list` stdout contains a TSV update row for `fixture`, `mm-proof-dep`, `1.0.0`, `1.0.1`. `baseline.json` provides the independent saved-scan view.

## Gotchas

- Doctor exercises piped `mm list --detail`. Terminal layout, summary, aliases and TODO entry points remain unproved.
- `--config` selects a config file but does not isolate scan storage or update workspaces. The helper's explicit MM_HOME is required.
- Launch seeds a scan; it does not run a scanner. After the update completes, `mm list --detail` correctly reports no saved findings.
