from pathlib import Path

import pytest
from pydantic import ValidationError

from maintenance_man.config import ConfigError, load_config
from maintenance_man.models.config import ProjectConfig
from tests.support.projects import write_config


@pytest.mark.parametrize(
    "fields, expected",
    [
        ({}, ()),
        ({"test_unit": "make unit"}, (("unit", "make unit"),)),
        (
            {"test_unit": "u", "test_integration": "i", "test_component": "c"},
            (("unit", "u"), ("integration", "i"), ("component", "c")),
        ),
        ({"test_unit": "", "test_integration": "i"}, (("integration", "i"),)),
        ({"test_unit": "  ", "test_component": "c"}, (("component", "c"),)),
    ],
)
def test_test_phases(tmp_path, fields, expected):
    project = ProjectConfig(path=tmp_path, package_manager="uv", **fields)
    assert project.test_phases == expected


_PATH = Path("/project")


@pytest.mark.parametrize(
    ("settings", "field"),
    [
        ({"package_manager": "bun"}, "path"),
        ({"path": _PATH}, "package_manager"),
        ({"path": _PATH, "package_manager": "npm"}, "package_manager"),
        (
            {"path": _PATH, "package_manager": "bun", "language": "typescript"},
            "language",
        ),
        *(
            (
                {
                    "path": _PATH,
                    "package_manager": "gradle",
                    "gradle_repository_routing": value,
                },
                "gradle_repository_routing",
            )
            for value in ("", "custom", "STANDARD-PUBLIC", True, 1, [])
        ),
    ],
)
def test_given_invalid_project_settings_when_validated_then_error_names_the_field(
    settings, field
):
    with pytest.raises(ValidationError, match=field):
        ProjectConfig.model_validate(settings)


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        ({}, None),
        ({"gradle_repository_routing": None}, None),
        ({"gradle_repository_routing": "standard-public"}, "standard-public"),
    ],
    ids=["omitted", "none", "standard-public"],
)
def test_given_routing_declaration_when_validated_then_it_is_kept(
    tmp_path, settings, expected
):
    project = ProjectConfig.model_validate(
        {"path": tmp_path, "package_manager": "gradle"} | settings
    )

    assert project.gradle_repository_routing == expected


def test_given_negative_minimum_age_when_config_loaded_then_config_error(
    tmp_path: Path,
) -> None:
    config_path = write_config(tmp_path, "[defaults]\nmin_version_age_days = -1\n")

    with pytest.raises(ConfigError, match="min_version_age_days"):
        load_config(config_path)
