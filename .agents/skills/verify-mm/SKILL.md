---
name: verify-mm
description: Drive and prove Maintenance Man's real interactive CLI update, local sync and failed-update recovery using an isolated MM_HOME, disposable jj repositories and a PTY.
---

# Verify mm

Run from the maintenance-man repository root. Read [the feature map](features/README.md) before choosing coverage. This is regular end-to-end verification of the installed editable CLI. Use `uv`, Python 3.14 and jj 0.45.1. jj also needs its Git transport executable on PATH; issue VCS commands through jj exclusively.

The helper uses `tests/support/repository.py` and the scan builders already used by CLI tests. It drives a separate real `mm` process under a controlling PTY, applies real uv wheel updates and runs actual project tests. It replaces external package distribution with two synthetic local wheels at uv's existing package-source boundary. The saved scan is fixture input. Scanner collection, live registries, real projects, deployment and production remotes are outside this proof.

## Launch

Install this checkout's dependencies locally, then choose an absent task-specific path. Keep the printed path for subsequent commands. In each new shell call, set `MM_VERIFY_RUN` to that path again. Launch refuses an existing directory.

```sh
uv sync --locked
MM_VERIFY_RUN="/tmp/verify-mm-$(date -u +%Y%m%dT%H%M%S)-$$"
printf '%s\n' "$MM_VERIFY_RUN"
uv run python .agents/skills/verify-mm/scripts/verify.py launch "$MM_VERIFY_RUN"
```

Ready means `Doctor passed: isolated fixture at .../state/mm` followed by `Ready: ...`. Launch first runs `mm init` against an empty `MM_HOME`, then creates one `fixture` project with `mm-proof-dep==1.0.0`, a saved `1.0.1` update, an executable test, a local bare origin and an independent peer checkout. Both wheels, the uv cache, environments, jj configuration and every project live under `state/`. The origin is the bare backing store of a jj repository created with `jj git init --no-colocate`.

Each command starts its own short-lived process. There is no server or port. The helper sets explicit `MM_HOME`, offline uv settings, local wheel sources, synthetic jj identity and isolated jj/Git configuration for its children. `HOME` retains its normal value. Use the helper for fixture mutations so these settings apply. Never point it at a normal project or `~/.mm`.

## Doctor

```sh
uv run python .agents/skills/verify-mm/scripts/verify.py doctor "$MM_VERIFY_RUN"
```

Require exit `0`, `Doctor passed` and `evidence/doctor.json` with `healthy: true`. This checks the fixture config and paths, local origin, bare store, imported checkout, effective child `MM_HOME`, CLI version and saved findings through `mm list --detail`. It reads app and repository state without snapshotting, fetching or repairing it. Diagnostic evidence is written separately. Run it before driving and whenever an instance looks wrong. A cleaned instance must be launched at a new path.

## Drive

For the normal update journey:

```sh
uv run python .agents/skills/verify-mm/scripts/verify.py drive "$MM_VERIFY_RUN"
```

The helper waits for the real `Select updates ... (all): ` prompt, types `invalid`, observes the rejection, then types `none`. It proves cancellation leaves the scan, manifest, lock and local/remote main unchanged, runs no tests and removes the temporary update workspace. Cancellation can leave the managed update bookmark; it is recorded in `cancelled.json`.

It next runs `mm update fixture`, selects `1`, waits for exit `0` and checks the installed dependency with `uv run --locked`, the manifest committed on `main`, saved scan removal, changed local `main` and removed update workspace. It fetches the origin through the independent peer to prove the update has not published anything. It then runs `mm sync fixture` in a PTY and fetches again to prove the origin now contains the promoted commit.

For failure recovery, use a separate fresh launch and substitute:

```sh
uv run python .agents/skills/verify-mm/scripts/verify.py drive "$MM_VERIFY_RUN" --journey recovery
```

This journey makes the synthetic project's compatibility test require `repair.txt`, selects the real update and requires exit `4` with a saved failed `unit` phase and unchanged main. `mm resolve fixture` must also exit `4` with the saved state `failed/resolve/unit` and the failed changes present. The helper writes and commits the synthetic repair through jj, then runs `mm resolve fixture --continue`. It requires promotion, an empty pending scan, successful installed-version tests and local sync. These fixture commits and pushes affect only the disposable repositories.

For an apply that changes no files, use a separate fresh launch and substitute:

```sh
uv run python .agents/skills/verify-mm/scripts/verify.py drive "$MM_VERIFY_RUN" --journey noop
```

This journey runs `uv add mm-proof-dep==1.0.1` in the synthetic project, commits it through jj and moves local `main` onto it, so the saved `1.0.0` to `1.0.1` update is already applied. It selects the update and requires exit `4`, `changed no files` in the transcript, the saved state `failed/update/apply` and local `main` unchanged. It records no updated state and runs no sync.

Each launch supports one drive. Reusing a completed scan is not a second proof. All three journeys require `PROVED ...` and `evidence/verdict.json`. A failed launch or drive removes its owned scratch state automatically and retains diagnostic evidence. Inspect the failed command and terminal transcript, fix the cause, then launch a new path.

## Evidence

Evidence lives at `"$MM_VERIFY_RUN/evidence"`, beside `state/`, which cleanup removes. Capture these files when reporting a proof:

- `actions.jsonl`: exact commands, working directories, stdout/stderr and exit codes for captured commands; PTY PIDs, prompt replies, expected/actual exit and reaped PIDs for interactive commands.
- `picker-cancel.terminal.txt`, `update.terminal.txt` and `sync.terminal.txt`: real merged PTY streams, including input echo. Recovery uses `update-fails`, `resolve-pauses` and `resolve-continue` transcripts instead of `update`. No-op uses `update-noop` instead of `update` and `sync`.
- `baseline.json`, `before.json`, `cancelled.json`, `updated.json`, `synced.json`: saved scan, manifest, lock, manifest committed on main, local/remote commit IDs, bookmarks and registered workspaces. Recovery also captures `update-failed.json` and `resolve-paused.json`. No-op captures `update-noop.json` instead of `updated.json` and `synced.json`.
- `test-runs.jsonl`: actual installed package versions and test working directories, including the throwaway mm update workspace.
- `doctor.json`, `verdict.json`, `cleanup.json`: instance health, journey verdict and retained artefacts after teardown.

Read the action and resulting state together. A final success line alone proves nothing. A peer fetch supplies a second view of origin, and running the actual fixture test after promotion verifies installation rather than only a changed manifest. Report each mapped entry point as proved, unproved or blocked. The two wheels are synthetic; this evidence does not establish registry access, vulnerability detection or non-uv adapter behaviour.

## Cleanup

Always run cleanup after a successful drive, and after an interrupted or failed attempt if the helper did not finish its automatic cleanup:

```sh
uv run python .agents/skills/verify-mm/scripts/verify.py cleanup "$MM_VERIFY_RUN"
test ! -e "$MM_VERIFY_RUN/state"
test -s "$MM_VERIFY_RUN/evidence/actions.jsonl"
test -s "$MM_VERIFY_RUN/evidence/verdict.json"
test -s "$MM_VERIFY_RUN/evidence/cleanup.json"
```

For a failed attempt, omit the `verdict.json` check and retain its error/transcript. Cleanup is idempotent, validates the repository/UID ownership marker and removes only this run's `state/`. It preserves `owner.json` and all evidence. Interactive commands reap their exact child PID; timeout/interruption terminates only that child's owned process group. No services or ports remain. After an uncatchable helper termination, inspect recorded PIDs and their command lines before stopping an orphan; PID records alone do not establish current ownership. The reused test support also creates a `/tmp/mm-tests-jj-*` template outside `state/`, removed on normal process exit; inspect its ownership before removing an orphan after an uncatchable termination.

The executable helper is `.agents/skills/verify-mm/scripts/verify.py`; all supported invocations are above. Its implementation lives in `tests/support/verification.py` so the normal type and lint checks cover it. Keep this map current with `/maintain-verification-skill`.
