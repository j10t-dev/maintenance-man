from pathlib import Path

import pytest
from pydantic import ValidationError

from maintenance_man.models.config import PhaseTestConfig, ProjectConfig


class TestPhaseTestConfig:
    def test_unit_only(self):
        tc = PhaseTestConfig(unit="uv run pytest")
        assert tc.unit == "uv run pytest"
        assert tc.integration is None
        assert tc.component is None

    def test_all_phases(self):
        tc = PhaseTestConfig(
            unit="bun test",
            integration="bun run test:integration",
            component="bun run test:component",
        )
        assert tc.unit == "bun test"
        assert tc.integration == "bun run test:integration"
        assert tc.component == "bun run test:component"

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError, match="unknown"):
            PhaseTestConfig(unit="bun test", unknown="bad")


class TestProjectConfigWithTest:
    def test_project_without_test_config(self):
        pc = ProjectConfig(path=Path("/tmp/x"), package_manager="bun")
        assert pc.test is None

    def test_project_with_test_config(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="bun",
            test=PhaseTestConfig(unit="bun test"),
        )
        assert pc.test is not None
        assert pc.test.unit == "bun test"
