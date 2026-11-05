# Sync main with origin

Publish local main to the configured origin and incorporate compatible incoming main history.

## Sub-features

- `sync-push` publishes a promoted local main.
- `sync-fetch` fetches remote main before deciding how to sync.
- `sync-batch` syncs all or a named subset of configured projects.

## How to get to it (user POV)

- Run `mm sync fixture` for one project.
- Run `mm sync api worker` for several projects or `mm sync` for all projects.

## Driving it with verify-mm

Preconditions: a fresh launch. Either drive recipe first creates a promoted local change and verifies origin still has the baseline.

- Publish: `uv run python .agents/skills/verify-mm/scripts/verify.py drive "$MM_VERIFY_RUN"` runs the update and then actual `mm sync fixture` in a PTY. `sync.terminal.txt` must show a passed sync, and the corresponding action exits `0`.
- Verify independently: the helper fetches through the peer repository after sync. `synced.json` must have identical `main` and `remote_main` IDs, matching `updated.json` main. The earlier `updated.json` has the original remote ID, proving sync caused publication.

## Gotchas

- Only the synthetic bare local origin is authorised. The helper checks its exact remote path in Doctor.
- This proof covers the outgoing fast-forward case. It does not establish incoming/divergent history, all-project/multi-project selection, auth failures or remote outages.
- jj's transport uses Git internally. Every invoked VCS command in the harness is `jj`; there are no direct Git commands.
