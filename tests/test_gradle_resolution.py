import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from maintenance_man import gradle_resolution as candidates
from maintenance_man import paths
from maintenance_man.dependency_age import PublicationLookupContext
from maintenance_man.gradle import (
    GradleError,
    ReportProposal,
    build_update_findings,
    parse_catalogue,
)
from maintenance_man.gradle_resolution import (
    NON_DIRECT_OWNER,
    ROUTING_UNDECLARED,
    _validation_requests,
    attach_gradle_publications,
    exact_fix_candidate,
    generate_gradle_report,
    parse_resolution_report,
    prepare_gradle_candidates,
    resolve_gradle_owners,
    select_gradle_candidates,
    validate_gradle_candidates,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    CandidateValidation,
    CandidateWithheld,
    GradleCandidate,
    ModuleId,
    PublicationFact,
    PublicationRequest,
    RepositoryDeclaration,
    ScopeId,
)
from maintenance_man.models.scan import GradleBlock, Severity, VulnFinding
from tests.support.clock import FakeClock
from tests.support.findings import (
    make_gradle_member,
    make_gradle_target,
    make_update,
    make_vuln,
)
from tests.support.gradle import (
    fixture_runner,
    make_gradle_candidate,
    make_resolution_report,
    report_directory,
    report_payload,
)
from tests.support.process import completed
from tests.support.projects import make_project

EMPTY_REPORT = make_resolution_report(scopes={":": []})
_SCOPE = "project_path=':' domain='project' configuration='runtimeClasspath'"


@pytest.mark.parametrize(
    "change,expected",
    [
        ("empty", None),
        (
            "unresolved",
            f"Incomplete Gradle resolution: {_SCOPE}: g:a:1.0 could not resolve",
        ),
        ("missing", f"Incomplete Gradle resolution: Missing selected scope: {_SCOPE}"),
        ("selection", "Incomplete Gradle resolution: root direct task missing"),
    ],
)
def test_selected_scope_completeness(change, expected):
    value = report_payload()
    if change == "unresolved":
        value["scopes"][0]["unresolved"] = ["g:a:1.0 could not resolve"]
    elif change == "missing":
        value["scopes"] = []
    elif change == "selection":
        value["selection_errors"] = ["root direct task missing"]

    if expected is None:
        assert len(parse_resolution_report(json.dumps(value)).selected_scopes) == 1
    else:
        with pytest.raises(GradleError) as caught:
            parse_resolution_report(json.dumps(value))
        assert str(caught.value) == expected


def test_malformed_scope_precedes_incomplete_resolution():
    raw = report_payload()
    raw["selected_scopes"][0]["project_path"] = "app"
    raw["selection_errors"] = ["scope unavailable"]
    with pytest.raises(
        GradleError, match=r"^Malformed Gradle resolution report: "
    ) as caught:
        parse_resolution_report(json.dumps(raw))
    assert type(caught.value.__cause__) is ValidationError


@pytest.mark.parametrize("change", ["reference", "duplicate", "url", "schema"])
def test_malformed_report_is_boundary_error(change):
    value = report_payload()
    if change == "schema":
        value["schema_version"] = 2
    elif change == "reference":
        value["scopes"][0]["edges"] = [
            {
                "source": "root",
                "target": "missing",
                "requested": "g:a:1",
                "constraint": False,
            }
        ]
    elif change == "duplicate":
        value["selected_scopes"] *= 2
    else:
        value["repositories"][0]["url"] = "https://user:secret@example.org/maven"
    with pytest.raises(GradleError):
        parse_resolution_report(json.dumps(value))


def _write_gradle_project_files(tmp_path: Path) -> None:
    (tmp_path / "gradle").mkdir()
    (tmp_path / "gradle/libs.versions.toml").write_text('[versions]\nx = "1.0"\n')


def test_capture_reads_before_cleanup_and_returns_durable_models(tmp_path):
    _write_gradle_project_files(tmp_path)
    project = make_project(tmp_path, package_manager="gradle")
    calls = []

    def runner(root, args, *, label):
        calls.append(args)
        return fixture_runner(root, args, label=label)

    with patch("maintenance_man.gradle_resolution.run_gradle", side_effect=runner):
        with generate_gradle_report(project) as generated:
            assert generated.bom_path.is_file()
            assert len(generated.report.selected_scopes) == 1
            assert generated.scopes == {
                ModuleId(group="g", artifact="a", version="1.0"): frozenset(
                    generated.report.selected_scopes
                )
            }
        assert not generated.bom_path.exists()

    directory = report_directory(calls[0])
    assert calls == [
        [
            "mmGradleReport",
            "--init-script",
            str(directory / "gradle-report.gradle"),
            f"-Pmm.reportDirectory={directory}",
            "--no-daemon",
            "--console=plain",
            "--rerun-tasks",
            "--no-build-cache",
            "--no-configuration-cache",
        ]
    ]


@pytest.mark.parametrize(
    "arrange",
    [
        "mm-home-not-yet-created",
        "mm-home-holds-workspaces",
        "stale-directory-from-a-killed-run",
        "caller-path-in-the-project",
    ],
)
def test_given_mm_home_state_when_reported_then_outputs_live_under_it_and_go_afterwards(
    gradle_project: ProjectConfig,
    mm_home: Path,
    monkeypatch: pytest.MonkeyPatch,
    arrange: str,
) -> None:
    keep = {
        "mm-home-not-yet-created": None,
        "mm-home-holds-workspaces": mm_home / "workspaces" / "api" / "keep.txt",
        "stale-directory-from-a-killed-run": mm_home
        / "gradle-report-stale"
        / "keep.txt",
        "caller-path-in-the-project": gradle_project.path
        / ".mm-gradle-inventory"
        / "keep.txt",
    }[arrange]
    if keep is not None:
        keep.parent.mkdir(parents=True)
        keep.write_text("keep\n", encoding="utf-8")
    directories: list[Path] = []

    def runner(root, args, *, label):
        directories.append(report_directory(args))
        return fixture_runner(root, args, label=label)

    monkeypatch.setattr("maintenance_man.gradle_resolution.run_gradle", runner)

    with generate_gradle_report(gradle_project) as generated:
        assert generated.bom_path == directories[0] / "bom.json"
        assert generated.bom_path.is_file()

    assert directories[0].parent == mm_home
    assert not directories[0].exists()
    if keep is not None:
        assert keep.read_text(encoding="utf-8") == "keep\n"


def test_given_mm_home_file_when_report_generated_then_error_before_gradle_runs(
    gradle_project: ProjectConfig, mm_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mm_home.write_text("not a directory\n", encoding="utf-8")
    monkeypatch.setattr(
        "maintenance_man.gradle_resolution.run_gradle",
        lambda *args, **kwargs: pytest.fail("Gradle must not run"),
    )

    with (
        pytest.raises(GradleError, match="Could not create a Gradle report directory"),
        generate_gradle_report(gradle_project),
    ):
        pass


def test_inventory_envelope_is_refused_before_the_report_is_parsed(tmp_path):
    _write_gradle_project_files(tmp_path)
    project = make_project(tmp_path, package_manager="gradle")

    def runner(root, args, *, label):
        completed = fixture_runner(root, args, label=label)
        (report_directory(args) / "bom.json").write_text("[]")
        (report_directory(args) / "report.json").write_text("{not json")
        return completed

    with (
        patch("maintenance_man.gradle_resolution.run_gradle", side_effect=runner),
        pytest.raises(GradleError, match="malformed CycloneDX inventory"),
        generate_gradle_report(project),
    ):
        pytest.fail("malformed inventory must not yield")


@pytest.mark.parametrize(
    "installed,fixes,expected",
    [
        ("4.1.0.Final", "4.1.9.Final, 4.2.1.Final", "4.1.9.Final"),
        ("4.1.0", "4.1.9, 4.1.10", None),
        ("4.1.0", "5.0.0", "5.0.0"),
        ("release", "1.0.1, 2.0.1", None),
        ("1.0.0", "[1.0,2.0)", None),
        ("1.0.0", "1.0.1,", None),
        ("1.0.0", "1.0.1, 1.0.1", "1.0.1"),
    ],
)
def test_fix_tokens_have_one_exact_branch_candidate(installed, fixes, expected):
    assert exact_fix_candidate(installed, fixes) == expected


BASE_EDGES = [("root", "parent"), ("parent", "child")]
_LIBRARY_CATALOGUE = """
[versions]
a = "1.0.0"
b = "1.0.0"
[libraries]
a = { module = "g:parent", version.ref = "a" }
b = { module = "g:other", version.ref = "b" }
"""
_PLUGIN_CATALOGUE = """
[versions]
plugin = "1.0.0"
[plugins]
plugin = { id = "com.example.plugin", version.ref = "plugin" }
"""


def _module_version(name):
    return "2.0.0" if name == "child" else "1.0.0"


def resolution_graph(
    tmp_path, edges, *, domain="project", catalogue=_LIBRARY_CATALOGUE, modules=None
):
    """Parse *catalogue* and build one scope holding every edge endpoint. An edge
    is (source, target) or (source, target, option), where option is "constraint"
    or the requested notation. A module named "child" resolves at 2.0.0 and every
    other at 1.0.0 as g:<name>, unless *modules* maps its name to
    group:artifact:version."""
    (tmp_path / "libs.toml").write_text(catalogue)
    parsed = parse_catalogue(tmp_path / "libs.toml")
    coordinates = {
        name: f"g:{name}:{_module_version(name)}"
        for source, target, *_ in edges
        for name in (source, target)
    } | (modules or {})

    raw = report_payload()
    raw["selected_scopes"][0]["domain"] = domain
    scope = raw["scopes"][0]
    scope["scope"]["domain"] = domain
    scope["components"] += [
        {
            "id": name,
            "kind": "module",
            "module": dict(
                zip(
                    ("group", "artifact", "version"), coordinate.split(":"), strict=True
                )
            ),
        }
        for name, coordinate in coordinates.items()
        if name != "root"
    ]

    def edge(source, target, option=None):
        return {
            "source": source,
            "target": target,
            "requested": coordinates[target]
            if option in (None, "constraint")
            else option,
            "constraint": option == "constraint",
        }

    scope["edges"] = [edge(*row) for row in edges]
    return parsed, parse_resolution_report(json.dumps(raw))


def _two_scope_graph(tmp_path, first_edges, second_edges, **options):
    """A report whose second scope resolves *second_edges* in the same project.
    A module already in the first scope keeps its coordinates; *options* go to
    resolution_graph."""
    catalogue, base = resolution_graph(tmp_path, first_edges, **options)
    raw = base.model_dump(mode="json")
    first = raw["scopes"][0]
    second_id = {
        "project_path": ":",
        "domain": "project",
        "configuration": "testRuntimeClasspath",
    }
    first_modules = {c["id"]: c["module"] for c in first["components"] if c["module"]}
    names = dict.fromkeys(n for edge in second_edges for n in edge if n != "root")
    modules = {
        name: first_modules.get(name)
        or {"group": "g", "artifact": name, "version": _module_version(name)}
        for name in names
    }
    second = {
        "scope": second_id,
        "unresolved": [],
        "components": [
            *(c for c in first["components"] if c["id"] == "root"),
            *(
                {"id": name, "kind": "module", "module": module}
                for name, module in modules.items()
            ),
        ],
        "edges": [
            {
                "source": s,
                "target": t,
                "requested": f"g:{t}:{modules[t]['version']}",
                "constraint": False,
            }
            for s, t in second_edges
        ],
    }
    raw["selected_scopes"].append(second_id)
    raw["scopes"].append(second)
    return catalogue, parse_resolution_report(json.dumps(raw))


_SHARED_REF_CATALOGUE = """
[versions]
a = "2.0.0"
[libraries]
parent = { module = "g:parent", version.ref = "a" }
child = { module = "g:child", version.ref = "a" }
"""
_NON_DIRECT = GradleBlock(kind="mapping", reason=NON_DIRECT_OWNER)
_CONFLICT = GradleBlock(
    kind="conflict", reason="conflicting or non-exact catalogue proposals"
)
_PARENT_TARGET = make_gradle_target(
    version_ref="a",
    members=[
        make_gradle_member(alias="a", coordinate="g:parent", installed_version="1.0.0")
    ],
    target_version="1.0.0",
)


@pytest.mark.parametrize(
    ("graph", "affected", "discovered", "expected_candidates", "expected_withheld"),
    [
        pytest.param(
            lambda tmp_path: _two_scope_graph(
                tmp_path, [("root", "parent")], [("root", "other"), ("other", "parent")]
            ),
            "parent",
            [],
            [("ref:a", (0,))],
            [
                CandidateWithheld(
                    group_key="ref:b", block=_NON_DIRECT, vulnerability_indices=(0,)
                )
            ],
            id="direct-under-a-indirect-under-b",
        ),
        pytest.param(
            lambda tmp_path: resolution_graph(
                tmp_path, [("root", "parent"), ("parent", "child", "constraint")]
            ),
            "child",
            [],
            [],
            [
                CandidateWithheld(
                    group_key="ref:a", block=_NON_DIRECT, vulnerability_indices=(0,)
                )
            ],
            id="constraint-owner-only",
        ),
        pytest.param(
            lambda tmp_path: _two_scope_graph(
                tmp_path,
                [("root", "child"), ("root", "parent")],
                [("root", "parent"), ("parent", "child")],
                catalogue=_SHARED_REF_CATALOGUE,
                modules={"parent": "g:parent:2.0.0"},
            ),
            "child",
            [],
            [],
            [
                CandidateWithheld(
                    group_key="ref:a", block=_NON_DIRECT, vulnerability_indices=(0,)
                )
            ],
            id="direct-in-one-scope-indirect-in-another",
        ),
        pytest.param(
            lambda tmp_path: resolution_graph(tmp_path, [("root", "parent")]),
            "parent",
            [
                make_update(
                    pkg_name="g:parent",
                    installed_version="1.0.0",
                    latest_version="1.0.0",
                    gradle_target=_PARENT_TARGET,
                    state=_CONFLICT,
                )
            ],
            [],
            [
                CandidateWithheld(
                    group_key="ref:a", block=_CONFLICT, vulnerability_indices=(0,)
                )
            ],
            id="discovery-blocked-group",
        ),
    ],
)
def test_given_owner_shape_when_candidates_selected_then_only_direct_owners_link(
    tmp_path, graph, affected, discovered, expected_candidates, expected_withheld
):
    catalogue, report = graph(tmp_path)
    installed = "1.0.0" if affected == "parent" else "2.0.0"
    advisory = make_vuln(
        pkg_name=f"g:{affected}",
        installed_version=installed,
        fixed_version="1.0.1" if affected == "parent" else "2.0.1",
    )

    plan = select_gradle_candidates(catalogue, report, [advisory], discovered)

    assert [
        (c.target.group_key, c.vulnerability_indices) for c in plan.candidates
    ] == expected_candidates
    assert list(plan.withheld) == expected_withheld


@pytest.mark.parametrize(
    "edges, affected, modules, expected",
    [
        (BASE_EDGES, "child", {}, ("ref:a", False)),
        (
            [("root", "parent"), ("parent", "child", "constraint")],
            "child",
            {},
            ("ref:a", False),
        ),
        ([*BASE_EDGES, ("child", "parent")], "child", {}, ("ref:a", False)),
        (
            [
                ("root", "parent"),
                ("parent", "constrained-bridge", "constraint"),
                ("constrained-bridge", "child"),
                ("parent", "unconstrained-bridge"),
                ("unconstrained-bridge", "child"),
            ],
            "child",
            {},
            ("ref:a", False),
        ),
        (BASE_EDGES, "parent", {}, ("ref:a", True)),
        ([*BASE_EDGES, ("root", "other"), ("other", "child")], "child", {}, None),
        (
            [
                *BASE_EDGES,
                ("root", "other"),
                ("other", "intermediate"),
                ("intermediate", "child"),
            ],
            "child",
            {},
            None,
        ),
        ([*BASE_EDGES, ("root", "other"), ("other", "parent")], "child", {}, None),
        ([*BASE_EDGES, ("root", "other"), ("other", "parent")], "parent", {}, None),
        (BASE_EDGES, "child", {"parent": "g:parent:1.1.0"}, None),
    ],
    ids=[
        "chain",
        "constraint",
        "cycle",
        "converging",
        "direct",
        "second-owner",
        "second-owner-longer-path",
        "overlapping-child",
        "overlapping-parent",
        "catalogue-version-differs",
    ],
)
def test_given_resolved_edges_when_owners_resolved_then_one_owner_or_unknown(
    tmp_path, edges, affected, modules, expected
):
    catalogue, report = resolution_graph(tmp_path, edges, modules=modules)
    module = ModuleId(
        group="g",
        artifact=affected,
        version="1.0.0" if affected == "parent" else "2.0.0",
    )

    assert resolve_gradle_owners(catalogue, report, module) == (expected,)


def plugin_marker_graph(tmp_path, *, domain="buildscript", failure=None):
    requested = {
        "range": "com.example:implementation:[1,3)",
        "mismatch": "com.example:implementation:2.1.0",
    }.get(failure, "com.example:implementation:2.0.0")
    edges = [
        ("root", "marker", "com.example.plugin:com.example.plugin.gradle.plugin:1.0.0"),
        ("marker", "implementation", requested),
    ]
    if failure == "two_edges":
        edges.append(("marker", "other"))
    return resolution_graph(
        tmp_path,
        edges,
        domain=domain,
        catalogue=_PLUGIN_CATALOGUE,
        modules={
            "marker": "com.example.plugin:com.example.plugin.gradle.plugin:1.0.0",
            "implementation": "com.example:implementation:2.0.0",
        },
    )


@pytest.mark.parametrize(
    "domain,expected",
    [("buildscript", ("ref:plugin", False)), ("project", None)],
)
def test_plugin_marker_owner_is_limited_to_buildscript(tmp_path, domain, expected):
    catalogue, report = plugin_marker_graph(tmp_path, domain=domain)
    owners = resolve_gradle_owners(
        catalogue,
        report,
        ModuleId(group="com.example", artifact="implementation", version="2.0.0"),
    )
    assert owners == (expected,)


@pytest.mark.parametrize("failure", ["two_edges", "range", "mismatch"])
def test_plugin_marker_requires_one_exact_implementation_edge(tmp_path, failure):
    catalogue, report = plugin_marker_graph(tmp_path, failure=failure)
    owners = resolve_gradle_owners(
        catalogue,
        report,
        ModuleId(group="com.example", artifact="implementation", version="2.0.0"),
    )
    assert owners == (None,)


def candidate():
    member = make_gradle_member(
        alias="a", coordinate="g:parent", installed_version="1.0.0"
    )
    return make_gradle_candidate(
        make_gradle_target(version_ref="a", members=[member], target_version="1.0.1")
    )


def test_parent_never_invents_version_from_child_fix(tmp_path):
    catalogue, resolution = resolution_graph(tmp_path, BASE_EDGES)
    finding = VulnFinding(
        vuln_id="CVE-2030-1",
        pkg_name="g:child",
        installed_version="2.0.0",
        fixed_version="2.0.1",
        severity=Severity.HIGH,
        title="example",
        description="example",
        status="affected",
    )
    result = select_gradle_candidates(catalogue, resolution, [finding], [])
    assert result.candidates == ()
    assert result.withheld[0].group_key == "ref:a"
    assert result.withheld[0].block == _NON_DIRECT


def test_given_underscored_version_ref_when_selected_then_rows_share_one_candidate(
    tmp_path,
):
    (tmp_path / "libs.toml").write_text(
        '[versions]\nroom_version = "2.8.4"\n'
        "[libraries]\n"
        'room-runtime = { module = "androidx.room:room-runtime", '
        'version.ref = "room_version" }\n'
    )
    catalogue = parse_catalogue(tmp_path / "libs.toml")
    raw = report_payload()
    scope = raw["scopes"][0]
    scope["components"].append(
        {
            "id": "room",
            "kind": "module",
            "module": {
                "group": "androidx.room",
                "artifact": "room-runtime",
                "version": "2.8.4",
            },
        }
    )
    scope["edges"].append(
        {
            "source": "root",
            "target": "room",
            "requested": "androidx.room:room-runtime:2.8.4",
            "constraint": False,
        }
    )
    resolution = parse_resolution_report(json.dumps(raw))
    discovered = build_update_findings(
        catalogue,
        [
            ReportProposal(
                kind="library",
                alias="room-runtime",
                coordinate="androidx.room:room-runtime",
                version="2.8.5",
            )
        ],
    )
    advisory = make_vuln(
        vuln_id="CVE-2030-9",
        pkg_name="androidx.room:room-runtime",
        installed_version="2.8.4",
        fixed_version="2.8.5",
    )

    plan = select_gradle_candidates(catalogue, resolution, [advisory], discovered)

    assert [(c.target.group_key, c.vulnerability_indices) for c in plan.candidates] == [
        ("ref:room-version", (0,))
    ]
    assert plan.withheld == ()


def test_given_indirect_owners_in_two_scopes_when_selected_then_each_withholds_it(
    tmp_path,
):
    catalogue, resolution = _two_scope_graph(
        tmp_path, BASE_EDGES, [("root", "other"), ("other", "child")]
    )
    discovered = [
        build_update_findings(
            catalogue,
            [
                ReportProposal(
                    kind="library", alias=alias, coordinate=coordinate, version=version
                )
            ],
        )[0]
        for alias, coordinate, version in (
            ("a", "g:parent", "1.0.1"),
            ("b", "g:other", "1.0.2"),
        )
    ]
    advisory = make_vuln(
        pkg_name="g:child", installed_version="2.0.0", fixed_version="2.0.1"
    )

    plan = select_gradle_candidates(catalogue, resolution, [advisory], discovered)

    assert [(c.target.group_key, c.vulnerability_indices) for c in plan.candidates] == [
        ("ref:a", ()),
        ("ref:b", ()),
    ]
    assert list(plan.withheld) == [
        CandidateWithheld(group_key=key, block=_NON_DIRECT, vulnerability_indices=(0,))
        for key in ("ref:a", "ref:b")
    ]


def test_direct_security_fix_is_retained_pending_native_proof(tmp_path):
    catalogue, resolution = resolution_graph(tmp_path, BASE_EDGES)
    finding = VulnFinding(
        vuln_id="CVE-2030-1",
        pkg_name="g:parent",
        installed_version="1.0.0",
        fixed_version="1.0.1",
        severity=Severity.HIGH,
        title="example",
        description="example",
        status="affected",
    )

    result = select_gradle_candidates(catalogue, resolution, [finding], [])

    assert result.withheld == ()
    assert result.candidates == (
        make_gradle_candidate(candidate().target, vulnerability_indices=(0,)),
    )


@pytest.mark.parametrize(
    ("proposed", "fixed_in", "linked"),
    [
        pytest.param("1.0.5", "2.0.0", False, id="below-fix"),
        pytest.param("2.0.0", "2.0.0", True, id="at-fix"),
        pytest.param("2.1.0", "1.0.3, 2.0.0", True, id="above-every-listed"),
        pytest.param("1.5.0", "1.0.3, 2.0.0", False, id="between-two-listed"),
        pytest.param("2.0.0", "2.0.0-jre", False, id="qualifier-differs"),
    ],
)
def test_given_ordinary_proposal_when_selected_then_advisory_links_only_if_known_fixed(
    tmp_path, proposed, fixed_in, linked
):
    catalogue, resolution = resolution_graph(tmp_path, BASE_EDGES)
    finding = VulnFinding(
        vuln_id="CVE-2030-1",
        pkg_name="g:parent",
        installed_version="1.0.0",
        fixed_version=fixed_in,
        severity=Severity.HIGH,
        title="example",
        description="example",
        status="affected",
    )
    discovered = build_update_findings(
        catalogue,
        [
            ReportProposal(
                kind="library", alias="a", coordinate="g:parent", version=proposed
            )
        ],
    )

    result = select_gradle_candidates(catalogue, resolution, [finding], discovered)

    assert [
        (c.target.group_key, c.target.target_version, c.vulnerability_indices)
        for c in result.candidates
    ] == [("ref:a", proposed, (0,) if linked else ())]
    reason = (
        f"proposed {proposed} is not known to fix this advisory (fixed in {fixed_in})"
    )
    assert list(result.withheld) == (
        []
        if linked
        else [
            CandidateWithheld(
                group_key=None,
                block=GradleBlock(kind="mapping", reason=reason),
                vulnerability_indices=(0,),
            )
        ]
    )


def test_given_no_fix_advisory_on_same_owner_when_selected_then_fixed_one_qualifies(
    tmp_path,
):
    catalogue, resolution = resolution_graph(tmp_path, BASE_EDGES)
    advisories = [
        VulnFinding(
            vuln_id=vuln_id,
            pkg_name="g:parent",
            installed_version="1.0.0",
            fixed_version=fixed_version,
            severity=Severity.HIGH,
            title="example",
            description="example",
            status="affected",
        )
        for vuln_id, fixed_version in (("CVE-2030-1", "1.0.1"), ("CVE-2030-2", None))
    ]

    result = select_gradle_candidates(catalogue, resolution, advisories, [])

    assert result.withheld == ()
    assert [
        (c.target.group_key, c.vulnerability_indices) for c in result.candidates
    ] == [("ref:a", (0,))]


def test_conflicting_ordinary_proposals_for_one_group_are_withheld(tmp_path):
    catalogue, resolution = resolution_graph(tmp_path, BASE_EDGES)
    discovered = [
        build_update_findings(
            catalogue,
            [
                ReportProposal(
                    kind="library",
                    alias="a",
                    coordinate="g:parent",
                    version=version,
                )
            ],
        )[0]
        for version in ("1.0.1", "1.0.2")
    ]

    result = select_gradle_candidates(catalogue, resolution, [], discovered)

    assert result.candidates == ()
    assert len(result.withheld) == 1
    assert result.withheld[0].group_key == "ref:a"
    assert result.withheld[0].block == GradleBlock(
        kind="conflict", reason="conflicting or non-exact catalogue proposals"
    )


@pytest.mark.parametrize(
    "versions",
    [("2.1.0", "1.5.0"), ("1.5.0", "2.1.0")],
    ids=["fixing-first", "fixing-last"],
)
def test_given_conflicting_proposals_when_advisory_is_direct_then_conflict_reason(
    tmp_path, versions
):
    catalogue, resolution = resolution_graph(tmp_path, BASE_EDGES)
    finding = VulnFinding(
        vuln_id="CVE-2030-1",
        pkg_name="g:parent",
        installed_version="1.0.0",
        fixed_version="2.0.0",
        severity=Severity.HIGH,
        title="example",
        description="example",
        status="affected",
    )
    discovered = [
        build_update_findings(
            catalogue,
            [
                ReportProposal(
                    kind="library", alias="a", coordinate="g:parent", version=version
                )
            ],
        )[0]
        for version in versions
    ]

    result = select_gradle_candidates(catalogue, resolution, [finding], discovered)

    assert result.candidates == ()
    assert list(result.withheld) == [
        CandidateWithheld(
            group_key="ref:a", block=_CONFLICT, vulnerability_indices=(0,)
        )
    ]


def test_native_batch_deduplicates_consuming_projects_and_validates_plugins_at_root(
    tmp_path,
):
    _write_gradle_project_files(tmp_path)
    project = make_project(tmp_path, package_manager="gradle")
    base = make_resolution_report(scopes={":app": ["g:a:1.0.0"], ":lib": ["g:a:1.0.0"]})
    compile_scope = base.scopes[0].model_copy(
        update={
            "scope": ScopeId(
                project_path=":app", domain="project", configuration="compileClasspath"
            )
        }
    )
    report = base.model_copy(
        update={
            "selected_scopes": (*base.selected_scopes, compile_scope.scope),
            "scopes": (*base.scopes, compile_scope),
        }
    )
    calls = []
    arguments = []
    before = (tmp_path / "gradle/libs.versions.toml").read_bytes()

    def respond(root, directory, requests):
        calls.append(requests)
        rows = [
            _success_row(
                request,
                implementation=(
                    {"group": "g", "artifact": "impl", "version": "3.0.0"}
                    if request["kind"] == "plugin"
                    else None
                ),
            )
            for request in requests
        ]
        (directory / "candidate-validation.json").write_text(
            json.dumps({"schema_version": 1, "results": rows})
        )

    def runner(root, args, *, label):
        arguments.append(args)
        return _validation_runner(respond)(root, args, label=label)

    with patch("maintenance_man.gradle_resolution.run_gradle", side_effect=runner):
        result = validate_gradle_candidates(project, [two_member_candidate()], report)

    directory = report_directory(arguments[0])
    assert arguments == [
        [
            "mmGradleValidateCandidates",
            "--init-script",
            str(directory / "gradle-report.gradle"),
            f"-Pmm.reportDirectory={directory}",
            "--no-daemon",
            "--console=plain",
            "--rerun-tasks",
            "--no-build-cache",
            "--no-configuration-cache",
        ]
    ]
    assert [
        (row["request_id"], row["alias"], row["project_path"], row["coordinate"])
        for row in calls[0]
    ] == [
        ("0", "a", ":app", "g:a"),
        ("1", "a", ":lib", "g:a"),
        ("2", "p", ":", "com.example.plugin"),
    ]
    assert len(result) == 3
    assert (tmp_path / "gradle/libs.versions.toml").read_bytes() == before
    assert list(paths.mm_home().glob("gradle-report-*")) == []


def _group_member(alias, kind="library"):
    coordinate = f"g:{alias}" if kind == "library" else "com.example.plugin"
    return make_gradle_member(
        kind=kind, alias=alias, coordinate=coordinate, installed_version="1.0.0"
    )


def _group_candidate(*members):
    return make_gradle_candidate(
        make_gradle_target(
            version_ref="grp", members=list(members), target_version="2.0.0"
        )
    )


def _two_library_candidate():
    return _group_candidate(_group_member("a"), _group_member("b"))


def _plugin_candidate():
    return _group_candidate(_group_member("p", "plugin"))


def two_member_candidate():
    return _group_candidate(_group_member("a"), _group_member("p", "plugin"))


def test_attach_gradle_publications_binds_scoped_repositories_and_modules():
    """Each member's requests are scoped to its own project path; a repository
    wrong domain or wrong project path is never leaked into the request."""
    candidate = _two_library_candidate()
    repositories = (
        RepositoryDeclaration(
            project_path=":app",
            domain="library",
            url="https://dl.google.com/dl/android/maven2",
        ),
        RepositoryDeclaration(
            project_path=":lib",
            domain="library",
            url="https://repo.maven.apache.org/maven2",
        ),
        RepositoryDeclaration(
            project_path=":app", domain="plugin", url="https://plugins.gradle.org/m2"
        ),
        RepositoryDeclaration(
            project_path=":other",
            domain="library",
            url="https://repo1.maven.org/maven2",
        ),
    )
    report = make_resolution_report(scopes={":": []}, repositories=repositories)
    requests = _validation_requests((candidate,), report)
    validations = [
        _validated({**requests[0], "project_path": ":app"}),
        _validated({**requests[1], "project_path": ":lib"}),
    ]

    result = attach_gradle_publications(candidate, report, validations)

    assert isinstance(result, GradleCandidate)
    assert [(r.module, r.repositories) for r in result.publication_requests] == [
        (ModuleId(group="g", artifact="a", version="2.0.0"), ("google",)),
        (ModuleId(group="g", artifact="b", version="2.0.0"), ("central",)),
    ]


def test_attach_gradle_publications_withholds_when_a_row_is_missing():
    result = attach_gradle_publications(
        _group_candidate(_group_member("a")), EMPTY_REPORT, []
    )

    assert result == GradleBlock(
        kind="mapping", reason="missing native candidate validation"
    )


def test_attach_gradle_publications_withholds_conflicting_marker_implementations():
    candidate = _plugin_candidate()
    (request,) = _validation_requests((candidate,), EMPTY_REPORT)
    validations = [
        _validated(
            request,
            implementation={
                "group": "com.example",
                "artifact": "impl",
                "version": "2.0.0",
            },
        ),
        _validated(
            {**request, "request_id": "1"},
            implementation={
                "group": "com.example",
                "artifact": "impl",
                "version": "3.0.0",
            },
        ),
    ]

    result = attach_gradle_publications(candidate, EMPTY_REPORT, validations)

    assert result == GradleBlock(
        kind="mapping", reason="conflicting marker implementations"
    )


def test_attach_gradle_publications_builds_plugin_marker_module():
    candidate = _plugin_candidate()
    implementation = ModuleId(group="com.example", artifact="impl", version="2.0.0")
    repositories = (
        RepositoryDeclaration(
            project_path=":", domain="plugin", url="https://plugins.gradle.org/m2"
        ),
        RepositoryDeclaration(
            project_path=":",
            domain="library",
            url="https://dl.google.com/dl/android/maven2",
        ),
    )
    report = make_resolution_report(scopes={":": []}, repositories=repositories)
    (request,) = _validation_requests((candidate,), report)

    result = attach_gradle_publications(
        candidate,
        report,
        [_validated(request, implementation=implementation.model_dump())],
    )

    assert isinstance(result, GradleCandidate)
    assert result.publication_requests == (
        PublicationRequest(
            module=ModuleId(
                group="com.example.plugin",
                artifact="com.example.plugin.gradle.plugin",
                version="2.0.0",
            ),
            repositories=("portal",),
            routing_supported=True,
            marker_implementation=implementation,
        ),
    )


def _success_row(request, **overrides):
    row = {
        "request_id": request["request_id"],
        "selected_version": request["candidate_version"],
        "implementation": None,
        "reason": None,
    }
    row.update(overrides)
    return row


def _validated(request, **overrides):
    """*request* paired with the result Gradle reported for it."""
    return request, CandidateValidation.model_validate(
        _success_row(request, **overrides)
    )


def _validation_runner(build_response):
    def runner(root, args, *, label):
        assert args[0] == "mmGradleValidateCandidates"
        directory = report_directory(args)
        requests = json.loads((directory / "candidate-requests.json").read_text())[
            "requests"
        ]
        build_response(root, directory, requests)
        return completed(args, returncode=0, stdout="", stderr="")

    return runner


def _write_candidate_validation_response(directory, rows):
    (directory / "candidate-validation.json").write_text(
        json.dumps({"schema_version": 1, "results": rows})
    )


@pytest.mark.parametrize("security_only", [False, True])
def test_shared_members_validate_only_in_projects_that_resolve_them(
    tmp_path, security_only
):
    _write_gradle_project_files(tmp_path)
    project = make_project(tmp_path, package_manager="gradle")
    catalogue_path = tmp_path / "gradle/libs.versions.toml"
    catalogue_path.write_text(
        '[versions]\ngrp = "1.0.0"\n[libraries]\n'
        'a = { module = "g:a", version.ref = "grp" }\n'
        'b = { module = "g:b", version.ref = "grp" }\n'
    )
    catalogue = parse_catalogue(catalogue_path)
    report = make_resolution_report(
        scopes={":app": ["g:a:1.0.0"], ":lib": ["g:b:1.0.0"]},
        repositories=[
            RepositoryDeclaration(
                project_path=":app",
                domain="library",
                url="https://dl.google.com/dl/android/maven2",
            ),
            RepositoryDeclaration(
                project_path=":lib",
                domain="library",
                url="https://repo.maven.apache.org/maven2",
            ),
        ],
    )
    discovered = build_update_findings(
        catalogue,
        [
            ReportProposal(
                kind="library", alias=alias, coordinate=f"g:{alias}", version="2.0.0"
            )
            for alias in ("a", "b")
        ],
    )
    vulnerability = VulnFinding(
        vuln_id="CVE-2030-1",
        pkg_name="g:a",
        installed_version="1.0.0",
        fixed_version="2.0.0",
        severity=Severity.HIGH,
        title="",
        description="",
        status="affected",
    )
    plan = select_gradle_candidates(
        catalogue,
        report,
        [vulnerability] if security_only else [],
        [] if security_only else discovered,
    )
    assert len(plan.candidates) == 1

    def respond(root, directory, requests):
        rows = []
        for request in requests:
            row = _success_row(request)
            if (request["alias"], request["project_path"]) not in {
                ("a", ":app"),
                ("b", ":lib"),
            }:
                row.update(selected_version=None, reason="unavailable in this project")
            rows.append(row)
        (directory / "candidate-validation.json").write_text(
            json.dumps({"schema_version": 1, "results": rows})
        )

    with patch(
        "maintenance_man.gradle_resolution.run_gradle",
        side_effect=_validation_runner(respond),
    ):
        validations = validate_gradle_candidates(project, plan.candidates, report)
    bound = attach_gradle_publications(plan.candidates[0], report, validations)
    assert isinstance(bound, GradleCandidate), bound
    assert [
        (request["alias"], request["project_path"]) for request, _ in validations
    ] == [("a", ":app"), ("b", ":lib")]
    assert [
        (r.module.coordinate, r.repositories) for r in bound.publication_requests
    ] == [
        ("g:a", ("google",)),
        ("g:b", ("central",)),
    ]


def test_given_unavailable_native_result_when_attached_then_withheld_with_reason(
    tmp_path,
):
    _write_gradle_project_files(tmp_path)
    project = make_project(tmp_path, package_manager="gradle")
    reason = "unavailable in this project"

    def build_response(root, directory, requests):
        _write_candidate_validation_response(
            directory, [_success_row(requests[0], selected_version=None, reason=reason)]
        )

    with patch(
        "maintenance_man.gradle_resolution.run_gradle",
        side_effect=_validation_runner(build_response),
    ):
        validations = validate_gradle_candidates(project, [candidate()], EMPTY_REPORT)

    assert attach_gradle_publications(
        candidate(), EMPTY_REPORT, validations
    ) == GradleBlock(kind="mapping", reason=reason)


def _mutate_catalogue(root, rows):
    (root / "gradle/libs.versions.toml").write_text("mutated = true\n")
    return rows


@pytest.mark.parametrize(
    ("candidate_factory", "rows_for", "reason"),
    [
        pytest.param(
            two_member_candidate,
            lambda root, requests: [
                _success_row(requests[0]),
                _success_row(
                    requests[1],
                    implementation={
                        "group": "g",
                        "artifact": "impl",
                        "version": "2.0",
                    },
                ),
                _success_row(requests[0]),
            ],
            "coverage",
            id="duplicate-request-id",
        ),
        pytest.param(
            candidate,
            lambda root, requests: [
                _success_row(requests[0]),
                _success_row({**requests[0], "request_id": "99"}),
            ],
            "coverage",
            id="extra-row",
        ),
        pytest.param(
            candidate, lambda root, requests: [], "coverage", id="missing-row"
        ),
        pytest.param(
            candidate,
            lambda root, requests: [
                _success_row(requests[0], selected_version="9.9.9")
            ],
            "selected a different version",
            id="wrong-selected-version",
        ),
        pytest.param(
            two_member_candidate,
            lambda root, requests: [
                _success_row(requests[0]),
                _success_row(requests[1], implementation=None),
            ],
            "marker success lacks implementation",
            id="missing-plugin-implementation",
        ),
        pytest.param(
            candidate,
            lambda root, requests: _mutate_catalogue(root, [_success_row(requests[0])]),
            "modified the catalogue",
            id="catalogue-mutated",
        ),
    ],
)
def test_validate_gradle_candidates_refuses_invalid_native_response(
    tmp_path, candidate_factory, rows_for, reason
):
    _write_gradle_project_files(tmp_path)
    project = make_project(tmp_path, package_manager="gradle")

    def build_response(root, directory, requests):
        _write_candidate_validation_response(directory, rows_for(root, requests))

    with (
        patch(
            "maintenance_man.gradle_resolution.run_gradle",
            side_effect=_validation_runner(build_response),
        ),
        pytest.raises(GradleError, match=reason),
    ):
        validate_gradle_candidates(project, [candidate_factory()], EMPTY_REPORT)
    assert list(paths.mm_home().glob("gradle-report-*")) == []


def test_given_unremovable_report_directory_when_report_completes_then_gradle_error(
    gradle_project: ProjectConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    removal = shutil.rmtree

    def rmtree(path, ignore_errors=False, **kwargs):
        if not ignore_errors:
            message = "busy"
            raise OSError(message)
        removal(path, ignore_errors=True)

    monkeypatch.setattr("maintenance_man.gradle_resolution.run_gradle", fixture_runner)
    monkeypatch.setattr("maintenance_man.gradle_resolution.shutil.rmtree", rmtree)

    with (
        pytest.raises(
            GradleError, match="Could not remove the Gradle report directory"
        ),
        generate_gradle_report(gradle_project),
    ):
        pass


def test_mixed_library_plugin_alias_keeps_member_validation_separate():
    candidate = make_gradle_candidate(
        make_gradle_target(
            version_ref="kotlin",
            members=[
                make_gradle_member(
                    alias="kotlin",
                    coordinate="org.jetbrains.kotlin:kotlin-stdlib",
                    installed_version="2.0.0",
                ),
                make_gradle_member(
                    kind="plugin",
                    alias="kotlin",
                    coordinate="org.jetbrains.kotlin.jvm",
                    installed_version="2.0.0",
                ),
            ],
            target_version="2.1.0",
        )
    )
    implementation = ModuleId(
        group="org.jetbrains.kotlin", artifact="kotlin-gradle-plugin", version="2.1.0"
    )
    validations = [
        _validated(
            request,
            implementation=implementation.model_dump()
            if request["kind"] == "plugin"
            else None,
        )
        for request in _validation_requests((candidate,), EMPTY_REPORT)
    ]
    result = attach_gradle_publications(candidate, EMPTY_REPORT, validations)
    assert isinstance(result, GradleCandidate)
    assert [r.module.coordinate for r in result.publication_requests] == [
        "org.jetbrains.kotlin:kotlin-stdlib",
        "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin",
    ]
    assert result.publication_requests[1].marker_implementation == implementation


_NOW = datetime(2030, 6, 15, 12, tzinfo=UTC)
_MODULE = ModuleId(group="g", artifact="lib", version="2")


def _age_candidate():
    member = make_gradle_member(alias="lib", coordinate="g:lib", installed_version="1")
    return make_gradle_candidate(
        make_gradle_target(version_ref="lib", members=[member], target_version="2"),
        publication_requests=(
            PublicationRequest(
                module=_MODULE, repositories=("central",), routing_supported=True
            ),
        ),
    )


def _prepare_with_publication(published, minimum_age_days, clock, *, prefetch=None):
    candidate = _age_candidate()
    fact = PublicationFact(
        repository="central",
        module=_MODULE,
        artifact_digest="0" * 64,
        timestamp=published,
        checked_at=_NOW,
    )
    publication = SimpleNamespace(
        prefetch=lambda requests: prefetch(list(requests)) if prefetch else None,
        submit=lambda repository, module: SimpleNamespace(result=lambda: fact),
    )
    project = ProjectConfig(path=Path("/unused"), package_manager="gradle")
    with (
        patch.object(candidates, "validate_gradle_candidates", lambda *args: []),
        patch.object(candidates, "attach_gradle_publications", lambda c, *args: c),
    ):
        (prepared,) = prepare_gradle_candidates(
            project.model_copy(update={"gradle_repository_routing": "standard-public"}),
            (candidate,),
            report_stub(),
            cast(PublicationLookupContext, publication),
            minimum_age_days,
            clock=clock,
        )
    return prepared


def report_stub():
    return parse_resolution_report(json.dumps(report_payload()))


def test_given_undeclared_routing_when_prepared_then_candidate_is_withheld():
    validate = MagicMock()
    project = ProjectConfig(
        path=Path("/unused"), package_manager="gradle", gradle_repository_routing=None
    )
    with patch.object(candidates, "validate_gradle_candidates", validate):
        (prepared,) = prepare_gradle_candidates(
            project,
            (_age_candidate(),),
            report_stub(),
            cast(PublicationLookupContext, SimpleNamespace()),
            7,
            clock=FakeClock(_NOW),
        )

    assert prepared.block == GradleBlock(kind="mapping", reason=ROUTING_UNDECLARED)
    validate.assert_not_called()


def test_candidate_age_reads_the_clock_after_prefetch():
    clock = FakeClock(_NOW)
    published = _NOW - timedelta(days=7) + timedelta(microseconds=1)
    assert _prepare_with_publication(published, 7, clock).block == GradleBlock(
        kind="age", reason="publication younger than required 7 days"
    )
    advanced = _prepare_with_publication(
        published,
        7,
        clock,
        prefetch=lambda requests: clock.advance(timedelta(microseconds=1)),
    )
    assert advanced.block is None
    assert advanced.published_date == published
