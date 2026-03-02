# Flatten Test Config into ProjectConfig

## Summary

Remove `PhaseTestConfig` and promote its fields (`test_unit`, `test_integration`, `test_component`) directly onto `ProjectConfig`. All three are independently optional.

## Config shape

```toml
[projects.dirty-uv]
path = "projects/dirty-uv"
package_manager = "uv"
test_unit = "uv run pytest"
test_integration = "uv run pytest -m integration"
```

## Model change

Delete `PhaseTestConfig`. `ProjectConfig` becomes:

```python
class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Path
    package_manager: Literal["bun", "uv", "mvn"]
    scan_secrets: bool = True
    test_unit: str | None = None
    test_integration: str | None = None
    test_component: str | None = None
```

## Code changes

| File | What changes |
|---|---|
| `models/config.py` | Delete `PhaseTestConfig`, add 3 fields to `ProjectConfig` |
| `updater.py` | `run_test_phases` takes `ProjectConfig` directly; references become `config.test_unit` etc. The "has test config" check becomes `config.test_unit is not None or ...` |
| `cli.py` | `proj_config.test is None` checks become checking whether any `test_*` field is set; error message drops `[projects.X.test]` wording |
| `tests/test_models_config.py` | Replace `PhaseTestConfig` tests with flat-field equivalents |
| `tests/test_updater.py` | Update fixtures and assertions to use flat fields |
| `tests/fixtures/test-config.toml` | No change needed (no test sections currently) |
