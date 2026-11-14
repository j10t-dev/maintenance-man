# Interactive dependency updates

Choose saved dependency findings, apply them in an isolated workspace, run the project's tests and promote passing changes to local main.

## Sub-features

- `update-picker` rejects invalid input and accepts a numbered selection.
- `update-cancel` accepts `none` without changing dependencies or running tests.
- `update-apply` installs the requested version and runs configured tests.
- `update-promote` advances local main and removes completed scan rows without publishing.
- `update-batch` applies all or a named subset, with optional exclusions.

## How to get to it (user POV)

- Run `mm update fixture` for the interactive picker.
- Run `mm update` for all configured projects, or `mm update api worker` for a named batch.
- Run `mm update -n api worker` to exclude named projects.
- At the picker enter `all`, `updates`, `vulns` when available, comma-separated numbers, `none`, or Enter for the default.

## Driving it with verify-mm

Preconditions: a fresh launched run with the saved `mm-proof-dep` update, local main at `1.0.0` and passing compatibility tests for `1.0.1`.

- Choose and cancel: `uv run python .agents/skills/verify-mm/scripts/verify.py drive "$MM_VERIFY_RUN"`. The first PTY sends `invalid`, requires `Invalid selection: invalid`, then sends `none`. `before.json` and `cancelled.json` must agree on scan, dependencies, lock and main/origin IDs; no test log exists yet.
- Apply: the same command starts a second `mm update fixture`, sends `1` at `Select updates` and requires exit `0`. `update.terminal.txt` records the selected package and promotion. `test-runs.jsonl` records `1.0.1` from the throwaway workspace. `updated.json` has the committed new manifest, changed main, empty update rows and no registered fixture workspace; the peer still sees the old origin main.
- Confirm installation: the helper runs the real configured test from the promoted project before syncing. Its action record must exit `0` with installed version `1.0.1`.
- A package-command apply that changes no files fails in `apply`: on a fresh launch, `uv run python .agents/skills/verify-mm/scripts/verify.py drive "$MM_VERIFY_RUN" --journey noop`. The helper commits `mm-proof-dep==1.0.1` to local main first, then selects `1`. `update-noop.terminal.txt` must hold `changed no files` and the run must exit `4`. `update-noop.json` has the saved state `failed/update/apply` and the main recorded before the update.

## Gotchas

- Cancelling can leave `mm/update-dependencies` at the original main. Cancellation does create and clean a workspace. It is not a VCS-operation-free preview.
- This recipe has one update and no vulnerability rows. Comma-separated multi-selection, keywords/default, batch/exclusion modes and bun/mvn/Gradle updates are unproved.
- The saved scan and local wheels intentionally avoid live registries. This proves real uv application, not vulnerability scanning or registry metadata.
- The drive also syncs after recording the unpublished state. Judge non-publication from `updated.json`, and publication from `synced.json`.
