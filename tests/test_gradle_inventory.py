import json

import pytest

from maintenance_man.gradle import GradleError
from maintenance_man.gradle_inventory import (
    bind_inventory,
    load_inventory,
    parse_inventory_text,
)
from maintenance_man.models.gradle import (
    LocalProjectIdentity,
    ModuleId,
    ResolutionReport,
    ResolvedComponent,
    ScopeId,
    ScopeResolution,
)
from tests.conftest import GRADLE_FIXTURES

SCOPE = ScopeId(project_path=":", domain="project", configuration="runtimeClasspath")
OTHER_SCOPE = ScopeId(project_path=":app", domain="project", configuration="compile")


def _module(artifact: str, version: str = "1", group: str = "g") -> ModuleId:
    return ModuleId(group=group, artifact=artifact, version=version)


def _report(
    scopes: dict[ScopeId, list[ModuleId]],
    local_projects: tuple[LocalProjectIdentity, ...] = (),
) -> ResolutionReport:
    return ResolutionReport(
        schema_version=1,
        root_project=":",
        producer_versions={"gradle": "8", "cyclonedx": "3.4.1", "report": "1"},
        catalogue_digest="digest",
        repositories=(),
        selected_scopes=tuple(scopes),
        scopes=tuple(
            ScopeResolution(
                scope=scope,
                components=(
                    ResolvedComponent(id="root", kind="root", module=None, variants=()),
                    *(
                        ResolvedComponent(
                            id=str(index), kind="module", module=module, variants=()
                        )
                        for index, module in enumerate(modules)
                    ),
                ),
                edges=(),
                unresolved=(),
            )
            for scope, modules in scopes.items()
        ),
        local_projects=local_projects,
    )


def _inventory(*purls: str):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{"type": "library", "purl": purl} for purl in purls],
    }
    return parse_inventory_text(json.dumps(document), source="memory-bom")


class TestLoadInventory:
    @pytest.mark.parametrize(
        "fixture, expected",
        [
            (None, "produced no inventory"),
            ("bom-empty.json", "no components"),
            ("bom-non-maven.json", "no Maven components"),
        ],
    )
    def test_unusable_inventory_is_an_error_not_a_clean_scan(
        self, tmp_path, fixture, expected
    ):
        bom = tmp_path / "bom.json"
        if fixture is not None:
            bom.write_text(
                (GRADLE_FIXTURES / fixture).read_text(encoding="utf-8"),
                encoding="utf-8",
            )

        with pytest.raises(GradleError, match=expected):
            load_inventory(bom)

    @pytest.mark.parametrize(
        "spec, accepted",
        [("1.5", True), ("1.6", True), ("1.7", True), ("1.4", False), ("junk", False)],
    )
    def test_spec_floor_is_not_an_equality(self, tmp_path, spec, accepted):
        """A CycloneDX patch bump must not brick every Gradle scan."""
        document = json.loads((GRADLE_FIXTURES / "bom.json").read_text())
        document["specVersion"] = spec
        bom = tmp_path / "bom.json"
        bom.write_text(json.dumps(document), encoding="utf-8")

        if accepted:
            load_inventory(bom)
        else:
            with pytest.raises(GradleError, match=r"1.5 or later"):
                load_inventory(bom)

    def test_malformed_inventory_json_is_an_error(self, tmp_path):
        bom = tmp_path / "bom.json"
        bom.write_text("{not json", encoding="utf-8")

        with pytest.raises(GradleError, match="malformed CycloneDX inventory"):
            load_inventory(bom)

    @pytest.mark.parametrize(
        "document",
        [
            [],
            None,
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [None]},
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": {"purl": "pkg:maven/g/a@1"},
            },
        ],
    )
    def test_malformed_inventory_structure_is_a_gradle_error(self, tmp_path, document):
        bom = tmp_path / "bom.json"
        bom.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(GradleError, match="malformed CycloneDX inventory"):
            load_inventory(bom)


def test_load_inventory_returns_the_original_bytes(tmp_path):
    bom = tmp_path / "bom.json"
    payload = (GRADLE_FIXTURES / "bom.json").read_bytes()
    bom.write_bytes(payload)

    loaded, inventory = load_inventory(bom)

    assert loaded == payload
    assert inventory.components


def test_load_inventory_rejects_undecodable_bytes(tmp_path):
    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xff\xfe")
    with pytest.raises(GradleError, match="malformed CycloneDX inventory"):
        load_inventory(bom)


def test_parse_inventory_text_labels_errors_with_its_source():
    with pytest.raises(GradleError, match="memory-bom is not a CycloneDX document"):
        parse_inventory_text('{"bomFormat": "other"}', source="memory-bom")


def test_construction_defers_nested_identity_validation():
    inventory = parse_inventory_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "library",
                        "purl": "pkg:maven/g/lib@1",
                        "components": [{"purl": 42}],
                    }
                ],
            }
        ),
        source="memory-bom",
    )
    with pytest.raises(GradleError, match="Malformed CycloneDX inventory"):
        bind_inventory(inventory, _report({SCOPE: [_module("lib")]}))


def test_bind_reports_missing_and_extra_modules_in_order():
    coverage = bind_inventory(
        _inventory("pkg:maven/g/extra@1"), _report({SCOPE: [_module("lib")]})
    )

    assert coverage.errors == (
        f"Inventory module has no selected resolution identity: {_module('extra')}",
        f"resolved module missing from inventory: {_module('lib')}",
    )


def test_bind_matches_modules_and_collects_their_scopes():
    report = _report({SCOPE: [_module("lib")], OTHER_SCOPE: [_module("lib")]})

    coverage = bind_inventory(_inventory("pkg:maven/g/lib@1"), report)

    assert coverage.errors == ()
    assert coverage.modules == (_module("lib"),)
    assert coverage.scopes == {_module("lib"): frozenset({SCOPE, OTHER_SCOPE})}


def test_bind_dedupes_sorts_and_decodes_modules():
    report = _report(
        {SCOPE: [_module("b"), _module("a b", "2"), _module("a b", "1", group="a")]}
    )

    coverage = bind_inventory(
        _inventory(
            "pkg:maven/g/b@1",
            "pkg:maven/g/a%20b@2",
            "pkg:maven/g/b@1?type=jar",
            "pkg:maven/a/a%20b@1#sub",
        ),
        report,
    )

    assert coverage.modules == (
        _module("a b", "1", group="a"),
        _module("a b", "2"),
        _module("b"),
    )
    assert coverage.errors == ()


def test_bind_excludes_verified_local_projects():
    local = LocalProjectIdentity(project_path=":app", module=_module("app"))
    report = _report({SCOPE: [_module("lib")], OTHER_SCOPE: []}, (local,))

    coverage = bind_inventory(
        _inventory("pkg:maven/g/lib@1", "pkg:maven/g/app@1?project_path=%3Aapp"),
        report,
    )

    assert coverage.modules == (_module("lib"),)
    assert coverage.errors == ()


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:maven/g/app@1?project_path=%3Aother",
        "pkg:maven/other/app@1?project_path=%3Aapp",
        "pkg:maven/g/app@1?project_path=%3Aapp&project_path=%3Aapp",
    ],
)
def test_bind_refuses_unverified_local_identity(purl):
    local = LocalProjectIdentity(project_path=":app", module=_module("app"))
    report = _report({SCOPE: [_module("lib")], OTHER_SCOPE: []}, (local,))

    with pytest.raises(GradleError, match="unverified local project identity"):
        bind_inventory(_inventory("pkg:maven/g/lib@1", purl), report)


@pytest.mark.parametrize(
    "component, message",
    [
        ({"type": "library", "purl": 42}, "purl must be a string"),
        ({"type": "library", "purl": "pkg:maven/g/lib"}, "malformed Maven purl"),
        ({"type": "library"}, "no package identity"),
        (
            {"purl": "pkg:maven/g/lib@1", "components": {}},
            "components must be an array",
        ),
        ({"purl": "pkg:maven/g/lib@1", "components": [3]}, "must be an object"),
    ],
)
def test_bind_rejects_malformed_nested_identity(component, message):
    inventory = parse_inventory_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"type": "library", "purl": "pkg:maven/g/lib@1"},
                    component,
                ],
            }
        ),
        source="memory-bom",
    )
    with pytest.raises(GradleError, match=f"Malformed CycloneDX inventory.*{message}"):
        bind_inventory(inventory, _report({SCOPE: [_module("lib")]}))
