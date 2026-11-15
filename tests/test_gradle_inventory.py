import json

import pytest

from maintenance_man.gradle import GradleError
from maintenance_man.gradle_inventory import inventory_scopes, load_inventory
from maintenance_man.models.gradle import LocalProjectIdentity, ModuleId, ScopeId
from tests.support.gradle import GRADLE_FIXTURES, make_resolution_report

SCOPE = ScopeId(project_path=":", domain="project", configuration="runtimeClasspath")
APP_SCOPE = ScopeId(
    project_path=":app", domain="project", configuration="runtimeClasspath"
)
LIB = "group='g' artifact='lib' version='1'"


def _module(artifact: str, version: str = "1", group: str = "g") -> ModuleId:
    return ModuleId(group=group, artifact=artifact, version=version)


def _components(*purls: str) -> list[dict[str, object]]:
    return [{"type": "library", "purl": purl} for purl in purls]


class TestLoadInventory:
    @pytest.mark.parametrize(
        "payload, message",
        [
            pytest.param(
                None, "cyclonedxBom produced no inventory at {bom};", id="absent"
            ),
            pytest.param(
                (GRADLE_FIXTURES / "bom-empty.json").read_bytes(),
                "CycloneDX inventory {bom} has no components;",
                id="empty",
            ),
            pytest.param(
                (GRADLE_FIXTURES / "bom-non-maven.json").read_bytes(),
                "CycloneDX inventory {bom} has no Maven components;",
                id="non-maven",
            ),
            pytest.param(
                b'{"bomFormat": "other"}',
                "{bom} is not a CycloneDX document",
                id="other-format",
            ),
            pytest.param(
                b"{not json", "malformed CycloneDX inventory {bom}:", id="invalid-json"
            ),
            pytest.param(
                b"\xff\xfe", "malformed CycloneDX inventory {bom}:", id="undecodable"
            ),
            pytest.param(b"[]", "malformed CycloneDX inventory {bom}:", id="array"),
            pytest.param(b"null", "malformed CycloneDX inventory {bom}:", id="null"),
            pytest.param(
                b'{"bomFormat": "CycloneDX", "specVersion": "1.6", '
                b'"components": [null]}',
                "malformed CycloneDX inventory {bom}:",
                id="null-component",
            ),
            pytest.param(
                b'{"bomFormat": "CycloneDX", "specVersion": "1.6", '
                b'"components": {"purl": "pkg:maven/g/a@1"}}',
                "malformed CycloneDX inventory {bom}:",
                id="components-not-an-array",
            ),
        ],
    )
    def test_unusable_inventory_is_an_error_not_a_clean_scan(
        self, tmp_path, payload, message
    ):
        bom = tmp_path / "bom.json"
        if payload is not None:
            bom.write_bytes(payload)

        with pytest.raises(GradleError) as caught:
            load_inventory(bom)

        assert str(caught.value).startswith(message.format(bom=bom))

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


def test_inventory_scopes_report_extra_modules_sorted_then_missing_modules():
    report = make_resolution_report(scopes={":": ["g:lib:1"]})

    with pytest.raises(GradleError) as caught:
        inventory_scopes(
            _components(
                "pkg:maven/g/zeta@1", "pkg:maven/g/alpha@2", "pkg:maven/a/beta@1"
            ),
            report,
        )

    assert str(caught.value) == (
        "Incomplete Gradle inventory: "
        "Inventory module has no selected resolution identity: "
        "group='a' artifact='beta' version='1'; "
        "Inventory module has no selected resolution identity: "
        "group='g' artifact='alpha' version='2'; "
        "Inventory module has no selected resolution identity: "
        "group='g' artifact='zeta' version='1'; "
        f"resolved module missing from inventory: {LIB}"
    )


def test_inventory_scopes_collect_the_scopes_of_each_module():
    report = make_resolution_report(scopes={":": ["g:lib:1"], ":app": ["g:lib:1"]})

    scopes = inventory_scopes(_components("pkg:maven/g/lib@1"), report)

    assert scopes == {_module("lib"): frozenset({SCOPE, APP_SCOPE})}


def test_inventory_scopes_dedupe_and_decode_inventory_modules():
    report = make_resolution_report(scopes={":": ["g:b:1", "g:a+b:2", "a:a+b:1"]})

    scopes = inventory_scopes(
        _components(
            "pkg:maven/g/b@1",
            "pkg:maven/g/a%2Bb@2",
            "pkg:maven/g/b@1?type=jar",
            "pkg:maven/a/a%2Bb@1#sub",
        ),
        report,
    )

    assert scopes == {
        _module("b"): frozenset({SCOPE}),
        _module("a+b", "2"): frozenset({SCOPE}),
        _module("a+b", "1", group="a"): frozenset({SCOPE}),
    }


def _report_with_local_project():
    return make_resolution_report(
        scopes={":": ["g:lib:1"], ":app": []},
        local_projects=[
            LocalProjectIdentity(project_path=":app", module=_module("app"))
        ],
    )


def test_inventory_scopes_exclude_verified_local_projects():
    scopes = inventory_scopes(
        _components("pkg:maven/g/lib@1", "pkg:maven/g/app@1?project_path=%3Aapp"),
        _report_with_local_project(),
    )

    assert scopes == {_module("lib"): frozenset({SCOPE})}


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:maven/g/app@1?project_path=%3Aother",
        "pkg:maven/other/app@1?project_path=%3Aapp",
        "pkg:maven/g/app@1?project_path=%3Aapp&project_path=%3Aapp",
    ],
)
def test_inventory_scopes_refuse_unverified_local_identity(purl):
    with pytest.raises(GradleError) as caught:
        inventory_scopes(
            _components("pkg:maven/g/lib@1", purl), _report_with_local_project()
        )

    assert str(caught.value) == (
        "Malformed CycloneDX inventory: unverified local project identity"
    )


@pytest.mark.parametrize(
    "component, message",
    [
        pytest.param(
            {"type": "library", "purl": 42},
            "purl\n  Input should be a valid string",
            id="purl-not-a-string",
        ),
        pytest.param(
            {"type": "library", "purl": "pkg:maven/g/lib"},
            "malformed Maven purl",
            id="purl-without-version",
        ),
        pytest.param(
            {"type": "library"},
            "library component has no package identity",
            id="no-purl",
        ),
        pytest.param(
            {"purl": "pkg:maven/g/lib@1", "components": {}},
            "components\n  Input should be a valid tuple",
            id="components-not-an-array",
        ),
        pytest.param(
            {"purl": "pkg:maven/g/lib@1", "components": [3]},
            "Input should be a valid dictionary or instance of _Component",
            id="nested-component-not-an-object",
        ),
        pytest.param(
            {
                "type": "library",
                "purl": "pkg:maven/g/lib@1",
                "components": [{"purl": 42}],
            },
            "Input should be a valid string",
            id="nested-purl-not-a-string",
        ),
    ],
)
def test_inventory_scopes_reject_malformed_nested_identity(component, message):
    components: list[dict[str, object]] = [
        {"type": "library", "purl": "pkg:maven/g/lib@1"},
        component,
    ]

    with pytest.raises(GradleError) as caught:
        inventory_scopes(components, make_resolution_report(scopes={":": ["g:lib:1"]}))

    assert str(caught.value).startswith("Malformed CycloneDX inventory: ")
    assert message in str(caught.value)
