# Design: `mm todo` command

## Purpose

Give the user a quick way to browse TODO items across all projects from a single command, so they can decide what to work on without opening each repo.

## CLI interface

```
mm todo [project] [--config PATH]
```

- `mm todo` — iterate all configured projects, print each project's TODO.md status under a bold header.
- `mm todo <project>` — print only that project's TODO.md. If missing, log "No TODO.md found for <project>" and exit 0.

### Exit codes

Missing TODO.md exits 0 — it's not an error. Unknown project name exits 1 (config error, same as other commands).

## Three states per project

1. **No TODO.md** — file doesn't exist. Print `[dim]no TODO.md[/]`.
2. **Empty TODO.md** — file exists but blank/whitespace-only. Print `[dim]empty[/]`.
3. **TODO.md with content** — print file contents as-is (raw text).

## Behaviour

1. Load config (reuse `_load_cfg`).
2. If `project` specified, resolve it (reuse `_resolve_proj`), then read `project.path / "TODO.md"`.
3. If no `project`, iterate `cfg.projects` (sorted by name, consistent with `list`).
4. For each project, print `[bold]{name}[/]` header, then the appropriate state output.

## Output format (MVP)

Raw file contents under bold project headers. No Rich Markdown rendering for now — easy to upgrade later by swapping the print call for `console.print(Markdown(content))`.

## Implementation

All changes in `cli.py`:

- New `@app.command` function `todo(project: str | None = None, *, config: Path | None = None)`.
- Reads `TODO.md` via `Path.read_text()`. No new module needed.
- No model changes. No config changes. Uses existing `ProjectConfig.path`.

## Testing

- Test with a project that has a TODO.md with content — verify output contains content under header.
- Test with a project that has no TODO.md — verify dim "no TODO.md" message.
- Test with a project that has an empty TODO.md — verify dim "empty" message.
- Test all-projects mode with a mix of all three states.
- Test single-project mode for each state.
- Use `tmp_path` fixtures and mock config, consistent with existing test patterns.

## Future

- Rich Markdown rendering for nicer display.
- Possibly filter/search within TODOs.
