# Recover a failed update

Keep failed maintenance work visible, take it over in the project directory, commit a manual repair and resume tests before promotion.

## Sub-features

- `recovery-update-failure` records a failed test phase and withholds promotion.
- `recovery-resolve` reapplies failed work and leaves its edits available for repair.
- `recovery-continue` tests a committed repair without reapplying the update.
- `recovery-promote` clears completed findings and advances local main.

## How to get to it (user POV)

- Run `mm update fixture` and select the finding which fails project tests.
- Run `mm resolve fixture` to take over the failed work.
- Commit a repair with jj in the disposable project, then run `mm resolve fixture --continue`.

## Driving it with verify-mm

Preconditions: a separate fresh launch. The helper creates a tracked synthetic compatibility requirement that the test can satisfy only after `repair.txt` exists.

- Fail and pause: `uv run python .agents/skills/verify-mm/scripts/verify.py drive "$MM_VERIFY_RUN" --journey recovery`. `update-fails.terminal.txt` and `update-failed.json` must show exit `4`, failed update/unit state and unchanged main. `resolve-pauses.terminal.txt` also exits `4`; `resolve-paused.json` captures resolve ownership and pending dependency edits.
- Repair and continue: the same command writes and commits `repair.txt` in the disposable project, then invokes `mm resolve fixture --continue`. Its transcript must exit `0`. `updated.json` shows promotion and empty update rows, while the real test log and installed-version check prove `1.0.1` works with the repair. The final sync independently proves origin publication.

## Gotchas

- A failed test here is deliberate fixture behaviour. The recipe fails if mm returns success before the repair.
- `--continue` requires the saved paused resolve state and a committed repair. Do not replace this entry point with a fresh `mm update`.
- Application failures, commit failures, missing bookmarks, VCS conflicts, several pending findings and non-uv adapters are unproved by this single-unit-failure recipe.
