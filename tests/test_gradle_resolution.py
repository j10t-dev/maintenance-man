import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from maintenance_man.gradle import GradleError, parse_catalogue
from maintenance_man.gradle_resolution import (
    attach_gradle_publications,
    collect_gradle_resolution,
    exact_fix_candidate,
    generate_gradle_report,
    parse_resolution_report,
    resolve_gradle_owners,
    select_gradle_candidates,
    validate_gradle_candidates,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    CandidateValidation,
    CandidateValidationBatch,
    CandidateWithheld,
    CompleteResolution,
    GradleCandidate,
    IncompleteResolution,
    KnownOwner,
    ModuleId,
    RepositoryDeclaration,
    ResolutionReport,
    ResolvedComponent,
    ScopeId,
    ScopeResolution,
)
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    Severity,
    VulnFinding,
)

FIXTURE = Path(__file__).parent / "fixtures/gradle/resolution/empty.json"


def report_payload():
    return json.loads(FIXTURE.read_text())


@pytest.mark.parametrize(
    "change,expected",
    [
        ("empty", CompleteResolution),
        ("unresolved", IncompleteResolution),
        ("missing", IncompleteResolution),
        ("selection", IncompleteResolution),
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
    result = parse_resolution_report(json.dumps(value))
    assert isinstance(result, expected)
    assert len(result.report.selected_scopes) == 1


@pytest.mark.parametrize(
    "change", ["schema", "reference", "duplicate", "url", "version"]
)
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
    elif change == "url":
        value["repositories"][0]["url"] = "https://user:secret@example.org/maven"
    else:
        value["producer_versions"] = {}
    with pytest.raises(GradleError):
        parse_resolution_report(json.dumps(value))


def make_project(tmp_path):
    (tmp_path / "gradle").mkdir()
    (tmp_path / "gradle/libs.versions.toml").write_text('[versions]\nx = "1.0"\n')
    return ProjectConfig(path=tmp_path, package_manager="gradle")


def fixture_runner(root, args, *, label):
    assert args[0] == "mmGradleReport"
    assert "--rerun-tasks" in args and "--no-build-cache" in args
    owned = root / ".mm-gradle-inventory"
    assert (owned / ".mm-owned").is_file()
    assert (owned / "gradle-report.gradle").read_text().startswith("import ")
    (owned / "bom.json").write_text(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"group":"g","name":"a","version":"1.0","purl":"pkg:maven/g/a@1.0"}]}'
    )
    value = report_payload()
    value["scopes"][0]["components"].append(
        {
            "id": "a",
            "kind": "module",
            "module": {"group": "g", "artifact": "a", "version": "1.0"},
            "variants": ["runtime"],
        }
    )
    value["scopes"][0]["edges"].append(
        {"source": "root", "target": "a", "requested": "g:a:1.0", "constraint": False}
    )
    value["catalogue_digest"] = hashlib.sha256(
        (root / "gradle/libs.versions.toml").read_bytes()
    ).hexdigest()
    (owned / "report.json").write_text(json.dumps(value))
    return subprocess.CompletedProcess(args, 0, "", "")


def test_capture_reads_before_cleanup_and_returns_durable_models(tmp_path):
    project = make_project(tmp_path)
    with patch(
        "maintenance_man.gradle_resolution.run_gradle", side_effect=fixture_runner
    ):
        with generate_gradle_report(project) as (bom, resolution):
            assert bom.is_file()
            assert isinstance(resolution, CompleteResolution)
        assert not (tmp_path / ".mm-gradle-inventory").exists()
        result = collect_gradle_resolution(
            project, parse_catalogue(tmp_path / "gradle/libs.versions.toml")
        )
    assert isinstance(result, CompleteResolution)
    assert result.report.scopes[0].components[0].kind == "root"


def test_unmarked_output_is_never_reclaimed(tmp_path):
    project = make_project(tmp_path)
    owned = tmp_path / ".mm-gradle-inventory"
    owned.mkdir()
    (owned / "caller.txt").write_text("keep")
    with patch("maintenance_man.gradle_resolution.run_gradle") as runner:
        with pytest.raises(GradleError):
            with generate_gradle_report(project):
                pass
    runner.assert_not_called()
    assert (owned / "caller.txt").read_text() == "keep"


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


def ownership_graph(
    tmp_path,
    *,
    ambiguous=False,
    constraint=False,
    domain="project",
    longer_path=False,
    overlapping=False,
):
    (tmp_path / "libs.toml").write_text(
        """
[versions]
a = "1.0.0"
b = "1.0.0"
[libraries]
a = { module = "g:parent", version.ref = "a" }
b = { module = "g:other", version.ref = "b" }
"""
    )
    catalogue = parse_catalogue(tmp_path / "libs.toml")
    raw = report_payload()
    raw["selected_scopes"][0]["domain"] = domain
    scope = raw["scopes"][0]
    scope["scope"]["domain"] = domain
    scope["components"] += [
        {
            "id": "parent",
            "kind": "module",
            "module": {"group": "g", "artifact": "parent", "version": "1.0.0"},
            "variants": ["runtime"],
        },
        {
            "id": "child",
            "kind": "module",
            "module": {"group": "g", "artifact": "child", "version": "2.0.0"},
            "variants": ["runtime"],
        },
    ]
    scope["edges"] = [
        {
            "source": "root",
            "target": "parent",
            "requested": "g:parent:1.0.0",
            "constraint": False,
        },
        {
            "source": "parent",
            "target": "child",
            "requested": "g:child:2.0.0",
            "constraint": constraint,
        },
    ]
    if ambiguous:
        scope["components"].append(
            {
                "id": "other",
                "kind": "module",
                "module": {"group": "g", "artifact": "other", "version": "1.0.0"},
                "variants": [],
            }
        )
        scope["edges"] += [
            {
                "source": "root",
                "target": "other",
                "requested": "g:other:1.0.0",
                "constraint": False,
            },
            {
                "source": "other",
                "target": "child",
                "requested": "g:child:2.0.0",
                "constraint": False,
            },
        ]
        if overlapping:
            scope["edges"][-1] = {
                "source": "other",
                "target": "parent",
                "requested": "g:parent:1.0.0",
                "constraint": False,
            }
        elif longer_path:
            scope["components"].append(
                {
                    "id": "intermediate",
                    "kind": "module",
                    "module": {
                        "group": "g",
                        "artifact": "intermediate",
                        "version": "1.0.0",
                    },
                    "variants": [],
                }
            )
            scope["edges"][-1] = {
                "source": "other",
                "target": "intermediate",
                "requested": "g:intermediate:1.0.0",
                "constraint": False,
            }
            scope["edges"].append(
                {
                    "source": "intermediate",
                    "target": "child",
                    "requested": "g:child:2.0.0",
                    "constraint": False,
                }
            )
    result = parse_resolution_report(json.dumps(raw))
    assert isinstance(result, CompleteResolution)
    return catalogue, result


@pytest.mark.parametrize(
    "ambiguous,constraint,longer_path,overlapping,affected,expected",
    [
        (False, False, False, False, "child", "parent"),
        (False, True, False, False, "child", "platform"),
        (True, False, False, False, "child", "unknown"),
        (True, False, True, False, "child", "unknown"),
        (True, False, False, True, "child", "unknown"),
        (True, False, False, True, "parent", "unknown"),
    ],
)
def test_actual_edges_establish_unique_owner(
    tmp_path, ambiguous, constraint, longer_path, overlapping, affected, expected
):
    catalogue, result = ownership_graph(
        tmp_path,
        ambiguous=ambiguous,
        constraint=constraint,
        longer_path=longer_path,
        overlapping=overlapping,
    )
    module = ModuleId(
        group="g",
        artifact=affected,
        version="1.0.0" if affected == "parent" else "2.0.0",
    )
    owners = resolve_gradle_owners(catalogue, result, module)
    assert len(owners) == 1
    assert owners[0].kind == expected
    if isinstance(owners[0], KnownOwner):
        assert owners[0].group_key == "ref:a"


def candidate():
    return GradleCandidate(
        target=GradleUpdateTarget(
            version_ref="a",
            members=[
                GradleMember(
                    kind="library",
                    alias="a",
                    coordinate="g:parent",
                    installed_version="1.0.0",
                )
            ],
            target_version="1.0.1",
        ),
        origins=frozenset({"ordinary"}),
    )


@pytest.mark.parametrize("response_kind", ["success", "unresolved", "missing"])
def test_metadata_batch_is_complete_and_does_not_mutate(tmp_path, response_kind):
    project = make_project(tmp_path)
    before = (tmp_path / "gradle/libs.versions.toml").read_bytes()
    calls = []

    def runner(root, args, *, label):
        calls.append(args)
        assert args[0] == "mmGradleValidateCandidates"
        assert "cyclonedxBom" not in args
        directory = root / ".mm-gradle-inventory"
        request = json.loads((directory / "candidate-requests.json").read_text())[
            "requests"
        ][0]
        row = {
            key: request[key]
            for key in ("request_id", "group_key", "alias", "project_path", "kind")
        }
        row.update(
            selected_version="1.0.1" if response_kind == "success" else None,
            implementation=None,
            reason=None if response_kind == "success" else "unresolved",
        )
        (directory / "candidate-validation.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "results": [] if response_kind == "missing" else [row],
                }
            )
        )
        return subprocess.CompletedProcess(args, 0, "", "")

    with patch("maintenance_man.gradle_resolution.run_gradle", side_effect=runner):
        if response_kind == "missing":
            with pytest.raises(GradleError, match="coverage"):
                validate_gradle_candidates(project, [candidate()])
        else:
            result = validate_gradle_candidates(project, [candidate()])
            assert (result.results[0].reason is None) == (response_kind == "success")
    assert len(calls) == 1
    assert (tmp_path / "gradle/libs.versions.toml").read_bytes() == before
    assert not (tmp_path / ".mm-gradle-inventory").exists()


def test_parent_never_invents_version_from_child_fix(tmp_path):
    catalogue, resolution = ownership_graph(tmp_path)
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
    assert "independent" in result.withheld[0].reason


def test_direct_security_fix_is_retained_pending_native_proof(tmp_path):
    catalogue, resolution = ownership_graph(tmp_path)
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
    assert len(result.candidates) == 1
    selected = result.candidates[0]
    assert selected.target == candidate().target
    assert selected.origins == frozenset({"security"})
    assert selected.requested_advisories == frozenset({"CVE-2030-1"})
    assert selected.requested_coordinates == frozenset({"g:parent"})
    assert selected.owner_keys == ("ref:a",)
    assert selected.scopes == (
        ScopeId(project_path=":", domain="project", configuration="runtimeClasspath"),
    )
    assert selected.publication_requests == ()


def test_native_batch_requests_each_member_in_each_distinct_project(tmp_path):
    project = make_project(tmp_path)
    selected = two_member_candidate().model_copy(
        update={
            "scopes": (
                ScopeId(
                    project_path=":app",
                    domain="project",
                    configuration="runtimeClasspath",
                ),
                ScopeId(
                    project_path=":app",
                    domain="project",
                    configuration="compileClasspath",
                ),
                ScopeId(
                    project_path=":lib",
                    domain="project",
                    configuration="runtimeClasspath",
                ),
            )
        }
    )
    calls = []
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

    with patch(
        "maintenance_man.gradle_resolution.run_gradle",
        side_effect=_validation_runner(respond),
    ):
        result = validate_gradle_candidates(project, [selected])

    assert len(calls) == 1
    assert [
        (row["request_id"], row["alias"], row["project_path"], row["coordinate"])
        for row in calls[0]
    ] == [
        ("0", "a", ":app", "g:a"),
        ("1", "a", ":lib", "g:a"),
        ("2", "p", ":", "com.example.plugin"),
    ]
    assert len(result.results) == 3
    assert (tmp_path / "gradle/libs.versions.toml").read_bytes() == before
    assert not (tmp_path / ".mm-gradle-inventory").exists()


@pytest.mark.parametrize("declaration", [None, "standard-public"])
def test_gradle_publication_requires_operator_declaration(tmp_path, declaration):
    from maintenance_man.gradle_resolution import gradle_routing_prerequisite

    project = ProjectConfig(
        path=tmp_path, package_manager="gradle", gradle_repository_routing=declaration
    )
    block = gradle_routing_prerequisite(project)
    if declaration is None:
        assert block is not None
        assert block.kind == "age"
        assert block.reason == (
            "Public repository routing has not been declared; automatic "
            "publication eligibility requires "
            "gradle_repository_routing = 'standard-public'"
        )
    else:
        assert block is None


def _resolution_with_repositories(repositories):
    scope = ScopeId(
        project_path=":", domain="project", configuration="runtimeClasspath"
    )
    root = ResolvedComponent(id="root", kind="root", module=None, variants=())
    return CompleteResolution(
        report=ResolutionReport(
            schema_version=1,
            root_project=":",
            producer_versions={"gradle": "9.0", "cyclonedx": "3.0.0", "report": "1"},
            catalogue_digest="0" * 64,
            repositories=repositories,
            selected_scopes=(scope,),
            scopes=(
                ScopeResolution(
                    scope=scope, components=(root,), edges=(), unresolved=()
                ),
            ),
        )
    )


def _two_library_candidate():
    return GradleCandidate(
        target=GradleUpdateTarget(
            version_ref="grp",
            members=[
                GradleMember(
                    kind="library",
                    alias="a",
                    coordinate="g:a",
                    installed_version="1.0.0",
                ),
                GradleMember(
                    kind="library",
                    alias="b",
                    coordinate="g:b",
                    installed_version="1.0.0",
                ),
            ],
            target_version="2.0.0",
        ),
        origins=frozenset({"ordinary"}),
    )


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
        # Wrong domain for a library member: must never be included for "a".
        RepositoryDeclaration(
            project_path=":app", domain="plugin", url="https://plugins.gradle.org/m2"
        ),
        # Wrong project path for either member: must never be included.
        RepositoryDeclaration(
            project_path=":other",
            domain="library",
            url="https://repo1.maven.org/maven2",
        ),
    )
    resolution = _resolution_with_repositories(repositories)
    batch = CandidateValidationBatch(
        schema_version=1,
        results=(
            CandidateValidation(
                kind="library",
                request_id="0",
                project_path=":app",
                group_key="ref:grp",
                alias="a",
                selected_version="2.0.0",
                implementation=None,
                reason=None,
            ),
            CandidateValidation(
                kind="library",
                request_id="1",
                project_path=":lib",
                group_key="ref:grp",
                alias="b",
                selected_version="2.0.0",
                implementation=None,
                reason=None,
            ),
        ),
    )

    result = attach_gradle_publications(candidate, resolution, batch)

    assert isinstance(result, GradleCandidate)
    assert len(result.publication_requests) == 2
    request_a = next(r for r in result.publication_requests if r.module.artifact == "a")
    request_b = next(r for r in result.publication_requests if r.module.artifact == "b")
    assert request_a.module == ModuleId(group="g", artifact="a", version="2.0.0")
    assert request_a.repositories == ("google",)
    assert request_b.module == ModuleId(group="g", artifact="b", version="2.0.0")
    assert request_b.repositories == ("central",)


def test_attach_gradle_publications_withholds_when_a_row_is_missing():
    candidate = GradleCandidate(
        target=GradleUpdateTarget(
            version_ref="grp",
            members=[
                GradleMember(
                    kind="library",
                    alias="a",
                    coordinate="g:a",
                    installed_version="1.0.0",
                )
            ],
            target_version="2.0.0",
        ),
        origins=frozenset({"ordinary"}),
    )
    resolution = _resolution_with_repositories(())
    batch = CandidateValidationBatch(schema_version=1, results=())

    result = attach_gradle_publications(candidate, resolution, batch)

    assert isinstance(result, CandidateWithheld)
    assert result.reason == "missing native candidate validation"


def _plugin_candidate():
    return GradleCandidate(
        target=GradleUpdateTarget(
            version_ref="grp",
            members=[
                GradleMember(
                    kind="plugin",
                    alias="p",
                    coordinate="com.example.plugin",
                    installed_version="1.0.0",
                )
            ],
            target_version="2.0.0",
        ),
        origins=frozenset({"ordinary"}),
    )


def test_attach_gradle_publications_withholds_conflicting_marker_implementations():
    candidate = _plugin_candidate()
    resolution = _resolution_with_repositories(())
    batch = CandidateValidationBatch(
        schema_version=1,
        results=(
            CandidateValidation(
                kind="plugin",
                request_id="0",
                project_path=":",
                group_key="ref:grp",
                alias="p",
                selected_version="2.0.0",
                implementation=ModuleId(
                    group="com.example", artifact="impl", version="2.0.0"
                ),
                reason=None,
            ),
            CandidateValidation(
                kind="plugin",
                request_id="1",
                project_path=":",
                group_key="ref:grp",
                alias="p",
                selected_version="2.0.0",
                implementation=ModuleId(
                    group="com.example", artifact="impl", version="3.0.0"
                ),
                reason=None,
            ),
        ),
    )

    result = attach_gradle_publications(candidate, resolution, batch)

    assert isinstance(result, CandidateWithheld)
    assert result.reason == "conflicting marker implementations"


def test_attach_gradle_publications_builds_plugin_marker_module():
    candidate = _plugin_candidate()
    implementation = ModuleId(group="com.example", artifact="impl", version="2.0.0")
    repositories = (
        RepositoryDeclaration(
            project_path=":", domain="plugin", url="https://plugins.gradle.org/m2"
        ),
        # Wrong domain for a plugin member: must never be included.
        RepositoryDeclaration(
            project_path=":",
            domain="library",
            url="https://dl.google.com/dl/android/maven2",
        ),
    )
    resolution = _resolution_with_repositories(repositories)
    batch = CandidateValidationBatch(
        schema_version=1,
        results=(
            CandidateValidation(
                kind="plugin",
                request_id="0",
                project_path=":",
                group_key="ref:grp",
                alias="p",
                selected_version="2.0.0",
                implementation=implementation,
                reason=None,
            ),
        ),
    )

    result = attach_gradle_publications(candidate, resolution, batch)

    assert isinstance(result, GradleCandidate)
    assert len(result.publication_requests) == 1
    request = result.publication_requests[0]
    assert request.module == ModuleId(
        group="com.example.plugin",
        artifact="com.example.plugin.gradle.plugin",
        version="2.0.0",
    )
    assert request.marker_implementation == implementation
    assert request.repositories == ("portal",)


def two_member_candidate():
    return GradleCandidate(
        target=GradleUpdateTarget(
            version_ref="grp",
            members=[
                GradleMember(
                    kind="library",
                    alias="a",
                    coordinate="g:a",
                    installed_version="1.0.0",
                ),
                GradleMember(
                    kind="plugin",
                    alias="p",
                    coordinate="com.example.plugin",
                    installed_version="1.0.0",
                ),
            ],
            target_version="2.0.0",
        ),
        origins=frozenset({"ordinary"}),
    )


def _success_row(request, **overrides):
    row = {
        "request_id": request["request_id"],
        "kind": request["kind"],
        "group_key": request["group_key"],
        "alias": request["alias"],
        "project_path": request["project_path"],
        "selected_version": request["candidate_version"],
        "implementation": None,
        "reason": None,
    }
    row.update(overrides)
    return row


def _validation_runner(build_response):
    def runner(root, args, *, label):
        assert args[0] == "mmGradleValidateCandidates"
        directory = root / ".mm-gradle-inventory"
        requests = json.loads((directory / "candidate-requests.json").read_text())[
            "requests"
        ]
        build_response(root, directory, requests)
        return subprocess.CompletedProcess(args, 0, "", "")

    return runner


def test_validate_gradle_candidates_refuses_duplicate_request_id(tmp_path):
    """Both requests are covered by id, but a request_id repeats: the
    duplicate collapses in the response dict, so its row count no longer
    matches what Gradle actually returned."""
    project = make_project(tmp_path)

    def build_response(root, directory, requests):
        rows = [
            _success_row(requests[0]),
            _success_row(
                requests[1],
                implementation={"group": "g", "artifact": "impl", "version": "2.0"},
            ),
            _success_row(requests[0]),
        ]
        (directory / "candidate-validation.json").write_text(
            json.dumps({"schema_version": 1, "results": rows})
        )

    with patch(
        "maintenance_man.gradle_resolution.run_gradle",
        side_effect=_validation_runner(build_response),
    ):
        with pytest.raises(GradleError, match="coverage"):
            validate_gradle_candidates(project, [two_member_candidate()])


def test_validate_gradle_candidates_refuses_extra_row(tmp_path):
    project = make_project(tmp_path)

    def build_response(root, directory, requests):
        rows = [
            _success_row(requests[0]),
            _success_row({**requests[0], "request_id": "99"}),
        ]
        (directory / "candidate-validation.json").write_text(
            json.dumps({"schema_version": 1, "results": rows})
        )

    with patch(
        "maintenance_man.gradle_resolution.run_gradle",
        side_effect=_validation_runner(build_response),
    ):
        with pytest.raises(GradleError, match="coverage"):
            validate_gradle_candidates(project, [candidate()])


@pytest.mark.parametrize("identity", [{"alias": "wrong-alias"}, {"kind": "plugin"}])
def test_validate_gradle_candidates_refuses_identity_mismatch(tmp_path, identity):
    project = make_project(tmp_path)

    def build_response(root, directory, requests):
        rows = [_success_row(requests[0], **identity)]
        (directory / "candidate-validation.json").write_text(
            json.dumps({"schema_version": 1, "results": rows})
        )

    with patch(
        "maintenance_man.gradle_resolution.run_gradle",
        side_effect=_validation_runner(build_response),
    ):
        with pytest.raises(GradleError, match="identity mismatch"):
            validate_gradle_candidates(project, [candidate()])


def test_validate_gradle_candidates_refuses_success_with_different_version(tmp_path):
    project = make_project(tmp_path)

    def build_response(root, directory, requests):
        rows = [_success_row(requests[0], selected_version="9.9.9")]
        (directory / "candidate-validation.json").write_text(
            json.dumps({"schema_version": 1, "results": rows})
        )

    with patch(
        "maintenance_man.gradle_resolution.run_gradle",
        side_effect=_validation_runner(build_response),
    ):
        with pytest.raises(GradleError, match="selected a different version"):
            validate_gradle_candidates(project, [candidate()])


def test_validate_gradle_candidates_refuses_plugin_success_without_implementation(
    tmp_path,
):
    project = make_project(tmp_path)

    def build_response(root, directory, requests):
        rows = [
            _success_row(requests[0]),
            _success_row(requests[1], implementation=None),
        ]
        (directory / "candidate-validation.json").write_text(
            json.dumps({"schema_version": 1, "results": rows})
        )

    with patch(
        "maintenance_man.gradle_resolution.run_gradle",
        side_effect=_validation_runner(build_response),
    ):
        with pytest.raises(GradleError, match="marker success lacks implementation"):
            validate_gradle_candidates(project, [two_member_candidate()])


def test_validate_gradle_candidates_refuses_symlinked_response(tmp_path):
    project = make_project(tmp_path)

    def runner(root, args, *, label):
        directory = root / ".mm-gradle-inventory"
        request = json.loads((directory / "candidate-requests.json").read_text())[
            "requests"
        ][0]
        external = root / "caller-validation.json"
        external.write_text(
            json.dumps({"schema_version": 1, "results": [_success_row(request)]})
        )
        (directory / "candidate-validation.json").symlink_to(external)
        return subprocess.CompletedProcess(args, 0, "", "")

    with patch("maintenance_man.gradle_resolution.run_gradle", side_effect=runner):
        with pytest.raises(GradleError, match="symlink"):
            validate_gradle_candidates(project, [candidate()])


def test_validate_gradle_candidates_refuses_catalogue_mutation(tmp_path):
    project = make_project(tmp_path)

    def build_response(root, directory, requests):
        rows = [_success_row(requests[0])]
        (directory / "candidate-validation.json").write_text(
            json.dumps({"schema_version": 1, "results": rows})
        )
        (root / "gradle/libs.versions.toml").write_text("mutated = true\n")

    with patch(
        "maintenance_man.gradle_resolution.run_gradle",
        side_effect=_validation_runner(build_response),
    ):
        with pytest.raises(GradleError, match="modified the catalogue"):
            validate_gradle_candidates(project, [candidate()])


def test_mixed_library_plugin_alias_keeps_member_validation_separate():
    from maintenance_man.gradle_resolution import _validation_requests

    candidate = GradleCandidate(
        target=GradleUpdateTarget(
            version_ref="kotlin",
            members=[
                GradleMember(
                    kind="library",
                    alias="kotlin",
                    coordinate="org.jetbrains.kotlin:kotlin-stdlib",
                    installed_version="2.0.0",
                ),
                GradleMember(
                    kind="plugin",
                    alias="kotlin",
                    coordinate="org.jetbrains.kotlin.jvm",
                    installed_version="2.0.0",
                ),
            ],
            target_version="2.1.0",
        ),
        origins=frozenset({"ordinary"}),
    )
    implementation = ModuleId(
        group="org.jetbrains.kotlin", artifact="kotlin-gradle-plugin", version="2.1.0"
    )
    batch = CandidateValidationBatch(
        schema_version=1,
        results=tuple(
            CandidateValidation(
                kind=request["kind"],
                request_id=request["request_id"],
                project_path=request["project_path"],
                group_key=request["group_key"],
                alias=request["alias"],
                selected_version="2.1.0",
                implementation=implementation if request["kind"] == "plugin" else None,
                reason=None,
            )
            for request in _validation_requests((candidate,))
        ),
    )
    result = attach_gradle_publications(
        candidate, _resolution_with_repositories(()), batch
    )
    assert isinstance(result, GradleCandidate)
    assert [r.module.coordinate for r in result.publication_requests] == [
        "org.jetbrains.kotlin:kotlin-stdlib",
        "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin",
    ]
    assert result.publication_requests[1].marker_implementation == implementation
