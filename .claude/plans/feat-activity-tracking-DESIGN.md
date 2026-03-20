# Activity Tracking — Design

## Problem

User works across multiple projects simultaneously and forgets what was last built/deployed where. `mm list` already shows last scan time but has no visibility into build/deploy activity.

## Storage

Single JSON file at `~/.mm/activity.json`. One entry per project, recording last build and last deploy.

```json
{
  "feetfax": {
    "last_build": {
      "timestamp": "2026-03-20T14:32",
      "success": true,
      "branch": "main"
    },
    "last_deploy": {
      "timestamp": "2026-03-20T15:01",
      "success": false,
      "branch": "feat/new-thing"
    }
  }
}
```

- Timestamps: ISO 8601 truncated to minutes (no seconds/sub-seconds).
- File created on first build/deploy event, updated in-place thereafter.
- Pydantic model for the record structure, consistent with existing patterns.

## Recording Events

After `run_build` / `run_deploy` completes (whether success or failure), record the event in `activity.json`.

Recording is **fire-and-forget**: wrapped in a try/except that catches all exceptions. If the file is corrupt, missing directory, permission error, etc., the CLI continues normally — activity tracking must never crash the build/deploy command.

Branch captured via existing `get_current_branch()` (also wrapped — falls back to `"unknown"` on failure).

### Where recording happens

- `mm build` command — after `run_build` returns or raises `BuildError`
- `mm deploy` command — after `run_deploy` returns or raises `DeployError`
- `mm deploy --build` — records build event (from the build step) AND deploy event (from the deploy step)

## `mm list` Table Changes

### Columns removed
- **Path** — truncated to uselessness on smaller screens, adds no value

### Columns renamed
- **Pkg Mgr** → **Type**

### Columns added
- **Built** — relative time string (e.g. "3h ago"), or "—" if never built
- **Deployed** — relative time string, or "—" if never deployed

### Failure indicator

Failed events display as e.g. `3h ago [F]` so user can see at a glance that the last build/deploy didn't succeed.

## What's NOT in scope

- No event history — latest only, overwritten each time
- No changes to `--detail` behaviour
- No SQLite
- No changes to scan, update, or test commands
