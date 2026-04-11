# `mm todo` Plan Review

Good plan overall — small scope, well-structured. A few issues I'd flag:

**1. Test fixture duplicates `mm_home` setup unnecessarily**

The `todo_home` fixture calls `mm_home.mkdir(parents=True)` and creates subdirs manually, but `mm_home` from conftest.py already gives you a monkeypatched path. The existing tests (e.g. `TestDeployCommand`) show the pattern — just use `mm_home` directly and do the mkdir/config setup inline. The plan does this, but `todo_home` is a misleading name since it's really just `mm_home` with config written. Consider renaming to something like `mm_home_with_todos` or just inlining the setup, consistent with how `TestDeployCommand` does it.

**2. Missing `mm_home` in fixture dependency chain**

The `todo_home` fixture takes `mm_home: Path` — good, that gets the monkeypatch. But every test method only lists `todo_home` as a fixture, not `mm_home`. This should work since `todo_home` depends on `mm_home`, which triggers the monkeypatch. Fine technically, just worth confirming.

**3. `_resolve_proj` calls `sys.exit(1)` on unknown project — test relies on this but the design says "always exit 0"**

The design doc says "Always `ExitCode.OK` (0). Missing TODO.md is not an error." but `test_todo_unknown_project_exits_error` expects exit code 1 for an unknown project name. This is actually correct behaviour (unknown project != missing TODO.md), but the design doc's blanket "always 0" statement is misleading. Worth clarifying.

**4. No test for "no projects configured" branch**

The implementation has a `if not cfg.projects` early return printing "No projects configured." — there's no test covering this path.

**5. Raw `console.print(content)` will interpret Rich markup in TODO.md**

If a TODO.md contains text like `[red]` or `[bold]something[/]`, Rich will interpret it as markup rather than printing it literally. Should use `console.print(content, highlight=False)` or wrap in `Text(content)` to avoid this. This is a real-world concern — TODO files often contain brackets like `[WIP]`, `[blocked]`, etc.

**6. No `[defaults]` section in the test config TOML**

The test config only has `[projects.*]` entries. Check whether `_load_cfg` / `load_config` requires a `[defaults]` section — existing test fixtures like `mm_home_with_projects` include one. If validation is strict, the tests would fail for the wrong reason.

**7. Minor: plan says "7 tests" but there are only 6**

Subtask 1.2 Step 3 says "All 7 tests PASS" but only 6 test methods are defined.

---

**Summary of recommended changes before executing:**
- Use `Text(content)` or `console.print(content, highlight=False)` to avoid Rich markup injection
- Add a `[defaults]` section to the test TOML (or verify it's optional)
- Add a test for the "no projects configured" branch
- Fix the "7 tests" typo to "6 tests"
- Clarify the design doc's "always exit 0" — it means "missing file is not an error", not "unknown project is not an error"
