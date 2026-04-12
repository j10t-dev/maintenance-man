from pathlib import Path

import pytest
from pydantic import ValidationError

from maintenance_man.models.config import DefaultsConfig, ProjectConfig


class TestProjectConfigTestFields:
    def test_no_test_fields(self):
        pc = ProjectConfig(path=Path("/tmp/x"), package_manager="bun")
        assert pc.test_unit is None
        assert pc.test_integration is None
        assert pc.test_component is None

    def test_unit_only(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"), package_manager="uv", test_unit="uv run pytest"
        )
        assert pc.test_unit == "uv run pytest"
        assert pc.test_integration is None

    def test_all_phases(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="bun",
            test_unit="bun test",
            test_integration="bun run test:integration",
            test_component="bun run test:component",
        )
        assert pc.test_unit == "bun test"
        assert pc.test_integration == "bun run test:integration"
        assert pc.test_component == "bun run test:component"

    def test_rejects_extra_fields(self):
        with pytest.raises(ValidationError, match="unknown"):
            ProjectConfig(path=Path("/tmp/x"), package_manager="bun", unknown="bad")


class TestProjectConfigScanSkipDirs:
    def test_defaults_to_empty_list(self):
        pc = ProjectConfig(path=Path("/tmp/x"), package_manager="uv")
        assert pc.scan_skip_dirs == []

    def test_accepts_skip_dirs(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="uv",
            scan_skip_dirs=["tests/fixtures", "vendor"],
        )
        assert pc.scan_skip_dirs == ["tests/fixtures", "vendor"]


class TestProjectConfigDeployFields:
    def test_no_deploy_fields(self):
        pc = ProjectConfig(path=Path("/tmp/x"), package_manager="bun")
        assert pc.build_command is None
        assert pc.deploy_command is None

    def test_deploy_only(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="uv",
            deploy_command="scripts/deploy.sh",
        )
        assert pc.deploy_command == "scripts/deploy.sh"
        assert pc.build_command is None

    def test_build_and_deploy(self):
        pc = ProjectConfig(
            path=Path("/tmp/x"),
            package_manager="bun",
            build_command="scripts/build.sh",
            deploy_command="scripts/deploy.sh",
        )
        assert pc.build_command == "scripts/build.sh"
        assert pc.deploy_command == "scripts/deploy.sh"


class TestDefaultsConfigHealthcheck:
    def test_no_healthcheck_url(self):
        dc = DefaultsConfig()
        assert dc.healthcheck_url is None

    def test_healthcheck_url(self):
        dc = DefaultsConfig(healthcheck_url="http://pihost:8080")
        assert dc.healthcheck_url == "http://pihost:8080"
