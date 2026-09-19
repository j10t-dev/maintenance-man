import hashlib
import json
import shutil
import subprocess
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from maintenance_man import gradle_verification as verification
from maintenance_man import scanner, updater
from maintenance_man.cli import _gradle_workspace_revision as _SDK_WORKSPACE_CHECK
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    CheckEvidence,
    CompleteResolution,
    FindingEvidence,
    FindingKey,
    GradleCandidate,
    GradleSnapshot,
    IncompleteResolution,
    ModuleId,
    PublicationEvidence,
    PublicationFact,
    ReadyAttempt,
    ResolutionReport,
    ResolvedComponent,
    ScopeId,
    ScopeResolution,
    VerifiedComparison,
    WithheldAttempt,
)
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    SemverTier,
    Severity,
    VulnFinding,
    Workflow,
)
from maintenance_man.updater import run_gradle_checks as _RUN_GRADLE_CHECKS


@pytest.fixture
def scope():
    return ScopeId(
        project_path=":app", domain="project", configuration="runtimeClasspath"
    )


@pytest.fixture
def resolution(scope):
    root = ResolvedComponent(id="root", kind="root", module=None, variants=())
    component = ResolvedComponent(
        id="lib",
        kind="module",
        module=ModuleId(group="g", artifact="lib", version="1"),
        variants=("runtime",),
    )
    return CompleteResolution(
        report=ResolutionReport(
            schema_version=1,
            root_project=":",
            producer_versions={"gradle": "8.14", "cyclonedx": "3.4.1", "report": "1"},
            catalogue_digest="catalogue",
            repositories=(),
            selected_scopes=(scope,),
            scopes=(
                ScopeResolution(
                    scope=scope, components=(root, component), edges=(), unresolved=()
                ),
            ),
        )
    )


@pytest.fixture
def candidate():
    return GradleCandidate(
        target=GradleUpdateTarget(
            version_ref="lib",
            members=[
                GradleMember(
                    kind="library",
                    alias="lib",
                    coordinate="g:lib",
                    installed_version="1",
                )
            ],
            target_version="2",
        ),
        origins=frozenset({"ordinary"}),
    )


def evidence(scope, advisory="CVE-1", version="1", severity=Severity.HIGH):
    row = VulnFinding(
        vuln_id=advisory,
        pkg_name="g:lib",
        installed_version=version,
        severity=severity,
        title="",
        description="",
        status="affected",
    )
    return FindingEvidence(
        key=FindingKey(advisory_id=advisory, coordinate="g:lib", scope=scope),
        affected_versions=frozenset({version}),
        severity=severity,
        has_unknown=severity == Severity.UNKNOWN,
        rows=(row,),
    )


def snapshot(resolution, findings, context="ctx", tree="tree"):
    return GradleSnapshot(
        tree_id=tree,
        resolution=resolution,
        context_identity=context,
        findings=tuple(findings),
        inventory_digest="bom",
        inventory_modules=(),
    )


@pytest.mark.parametrize(
    "case,expected",
    [
        ("same", "verified"),
        ("changed-version", "verified"),
        ("removed", "verified"),
        ("new", "rejected"),
        ("higher-severity", "rejected"),
        ("more-versions", "rejected"),
        ("unknown-to-known", "incomparable"),
        ("known-to-unknown", "incomparable"),
        ("unknown-same", "verified"),
        ("unknown-removed", "verified"),
        ("context-changed", "incomparable"),
        ("dropped-scope", "incomparable"),
        ("additional-scope", "rejected"),
    ],
)
def test_comparison_policy(scope, resolution, candidate, case, expected):
    old = evidence(scope)
    current = old
    before_resolution = resolution
    after_resolution = resolution
    if case.startswith("unknown"):
        old = evidence(scope, severity=Severity.UNKNOWN)
        current = old
    if case == "changed-version":
        current = evidence(scope, version="2")
    if case == "higher-severity":
        current = evidence(scope, severity=Severity.CRITICAL)
    if case == "unknown-to-known":
        current = evidence(scope, severity=Severity.HIGH)
    if case == "known-to-unknown":
        current = evidence(scope, severity=Severity.UNKNOWN)
    if case == "more-versions":
        second = evidence(scope, version="2")
        current = old.model_copy(
            update={
                "affected_versions": frozenset({"1", "2"}),
                "rows": (*old.rows, *second.rows),
            }
        )
    after_rows = [] if case in {"removed", "unknown-removed"} else [current]
    if case == "new":
        after_rows.append(evidence(scope, advisory="CVE-2"))
    if case == "dropped-scope":
        after_resolution = CompleteResolution(
            report=resolution.report.model_copy(
                update={"selected_scopes": (), "scopes": ()}
            )
        )
    if case == "additional-scope":
        extra = scope.model_copy(update={"configuration": "testRuntimeClasspath"})
        report = resolution.report.model_copy(
            update={
                "selected_scopes": (scope, extra),
                "scopes": (
                    *resolution.report.scopes,
                    resolution.report.scopes[0].model_copy(update={"scope": extra}),
                ),
            }
        )
        before_resolution = after_resolution = CompleteResolution(report=report)
        after_rows.append(evidence(extra))
    before = snapshot(before_resolution, [old])
    after = snapshot(
        after_resolution, after_rows, "other" if case == "context-changed" else "ctx"
    )
    result = verification.compare_gradle_snapshots(before, after, candidate)
    assert result.kind == expected
    if expected == "verified":
        assert isinstance(result, VerifiedComparison)
        assert result.removed == (
            frozenset({old.key}) if not after_rows else frozenset()
        )
        assert result.residual == frozenset(row.key for row in after_rows)


@pytest.mark.parametrize(
    "origins,removed,expected",
    [
        ({"security"}, 1, "rejected"),
        ({"security"}, 2, "verified"),
        ({"ordinary", "security"}, 1, "verified"),
        ({"ordinary", "security"}, 0, "verified"),
        ({"ordinary"}, 0, "verified"),
    ],
)
def test_origin_fix_requirements(
    scope, resolution, candidate, origins, removed, expected
):
    rows = [evidence(scope, "CVE-1"), evidence(scope, "CVE-2")]
    candidate = candidate.model_copy(
        update={
            "origins": frozenset(origins),
            "requested_advisories": frozenset({"CVE-1", "CVE-2"}),
            "requested_coordinates": frozenset({"g:lib"}),
        }
    )
    result = verification.compare_gradle_snapshots(
        snapshot(resolution, rows), snapshot(resolution, rows[removed:]), candidate
    )
    assert result.kind == expected


def test_reintroduced_fix_is_rejected(scope, resolution, candidate):
    row = evidence(scope)
    first = verification.compare_gradle_snapshots(
        snapshot(resolution, [row]), snapshot(resolution, []), candidate
    )
    assert isinstance(first, VerifiedComparison)
    assert first.removed == frozenset({row.key})
    second = verification.compare_gradle_snapshots(
        snapshot(resolution, []), snapshot(resolution, [row]), candidate
    )
    assert second.kind == "rejected"


def test_snapshot_round_trip_identity(scope, resolution):
    before = snapshot(resolution, [evidence(scope)])
    loaded = GradleSnapshot.model_validate_json(before.model_dump_json())
    assert loaded == before
    assert loaded.snapshot_id == before.snapshot_id


@pytest.fixture
def frozen_context(tmp_path, monkeypatch, resolution):
    for name in tuple(verification.os.environ):
        if name.startswith("TRIVY_"):
            monkeypatch.delenv(name)
    project_path = tmp_path / "project"
    project_path.mkdir()
    binary = tmp_path / "trivy"
    binary.write_text("binary")
    monkeypatch.setattr(verification.shutil, "which", lambda name: str(binary))
    calls = []

    def command(argv, cwd):
        calls.append(argv)
        if "--version" in argv:
            return "Version: 0.65.0"
        folder, filename = (
            ("java-db", "trivy-java.db")
            if "--download-java-db-only" in argv
            else ("db", "trivy.db")
        )
        (cwd / folder).mkdir()
        (cwd / folder / filename).write_bytes(b"database")
        (cwd / folder / "metadata.json").write_text("{}")
        return ""

    monkeypatch.setattr(verification, "_run", command)
    project = ProjectConfig(path=project_path, package_manager="gradle")
    context = verification.initialize_comparison_context(
        project, resolution, tmp_path / "caches"
    )
    return project, context, calls


@pytest.mark.parametrize(
    "hours,expected", [(0, True), (23.99, True), (24, False), (-1, False)]
)
def test_context_lifetime(frozen_context, hours, expected):
    project, context, calls = frozen_context
    assert (
        verification.context_inputs_valid(
            context, project, context.created_at + timedelta(hours=hours)
        )
        is expected
    )
    assert sum("--download-db-only" in call for call in calls) == 1
    assert sum("--download-java-db-only" in call for call in calls) == 1


@pytest.mark.parametrize("mutation", ["db", "ignore", "binary", "owner", "config"])
def test_context_rejects_modified_inputs(frozen_context, mutation):
    project, context, _ = frozen_context
    if mutation == "ignore":
        (project.path / ".trivyignore").write_text("CVE-1\n")
    elif mutation == "binary":
        binary = next(
            key.removeprefix("binary:")
            for key in context.loaded_input_digests
            if key.startswith("binary:")
        )
        Path(binary).write_text("new binary")
    else:
        name = {
            "db": "db/trivy.db",
            "owner": ".mm-comparison-owner",
            "config": "config.json",
        }[mutation]
        (context.private_cache_path / name).write_text("changed")
    assert not verification.context_inputs_valid(context, project, context.created_at)


def test_cleanup_refuses_changed_owner(frozen_context):
    project, context, _ = frozen_context
    (context.private_cache_path / ".mm-comparison-owner").write_text("caller")
    with pytest.raises(verification.GradleError, match="ownership"):
        verification.release_comparison_context(context)
    assert context.private_cache_path.exists()


@pytest.mark.parametrize("match,expected", [(True, "snapshot"), (False, "incomplete")])
def test_capture_reads_before_cleanup_and_never_discovers(
    frozen_context, resolution, monkeypatch, match, expected
):
    project, context, _ = frozen_context
    bom = project.path / "temporary-bom.json"

    @contextmanager
    def report(_project):
        bom.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "components": [
                        {
                            "type": "library",
                            "purl": "pkg:maven/g/lib@1"
                            if match
                            else "pkg:maven/g/other@1",
                        }
                    ],
                }
            )
        )
        try:
            yield bom, resolution
        finally:
            bom.unlink()

    monkeypatch.setattr(scanner, "generate_gradle_report", report)
    monkeypatch.setattr(
        scanner,
        "_check_outdated",
        lambda *args: pytest.fail("discovery during verification"),
    )

    def tree(path):
        assert not bom.exists()
        return "checked-tree"

    monkeypatch.setattr(scanner, "revision_tree_id", tree)
    scan_calls = []

    def trivy(command, **kwargs):
        scan_calls.append(command)
        assert bom.exists()
        assert "--skip-db-update" in command
        assert "--skip-java-db-update" in command
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {
                    "Results": [
                        {
                            "Class": "lang-pkgs",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-1",
                                    "PkgName": "g:lib",
                                    "InstalledVersion": "1",
                                    "Severity": "HIGH",
                                }
                            ],
                        }
                    ]
                }
            ),
            "",
        )

    monkeypatch.setattr(scanner.subprocess, "run", trivy)
    result = scanner.capture_gradle_snapshot(project, context)
    if expected == "incomplete":
        assert isinstance(result, IncompleteResolution)
        assert result.kind == "incomplete"
        assert not scan_calls
    else:
        assert isinstance(result, GradleSnapshot)
        assert result.tree_id == "checked-tree"
        assert len(result.findings) == 1
        assert result.findings[0].key.scope == resolution.report.selected_scopes[0]
        assert result.findings[0].rows[0].update_status is None
    assert not bom.exists()


@pytest.fixture
def workflow(frozen_context, resolution, candidate, scope, monkeypatch, tmp_path):
    project, context, _ = frozen_context
    project = project.model_copy(
        update={
            "build_command": "./gradlew assembleDebug",
            "test_unit": "./gradlew testDebugUnitTest",
            "gradle_repository_routing": "standard-public",
        }
    )
    initial = snapshot(resolution, [evidence(scope)], context.identity, "base-tree")
    after = snapshot(
        resolution, [evidence(scope, version="2")], context.identity, "after-tree"
    )
    monkeypatch.setattr(updater._config, "MM_HOME", tmp_path / "mm")
    commands = (project.build_command, project.test_unit)
    checks = CheckEvidence(
        commands=commands,
        command_digests=tuple(
            hashlib.sha256(command.encode()).hexdigest() for command in commands
        ),
        success=True,
        checked_at=context.created_at,
    )
    fact = PublicationFact(
        repository="central",
        module=ModuleId(group="g", artifact="lib", version="2"),
        source_url="https://repo.maven.apache.org/maven2/g/lib/2/lib-2.pom",
        method="last_modified",
        artifact_digest="0" * 64,
        timestamp=context.created_at - timedelta(days=30),
        checked_at=context.created_at,
    )
    publication = SimpleNamespace(
        evidence_for=lambda candidate: (PublicationEvidence(facts=(fact,)),)
    )
    effects = []
    catalogue = project.path / "gradle/libs.versions.toml"
    catalogue.parent.mkdir()
    catalogue.write_text(
        '[versions]\nlib = "1"\n[libraries]\n'
        'lib = { module = "g:lib", version.ref = "lib" }\n'
    )
    state = {"snapshot": initial, "tree": "base-tree"}
    monkeypatch.setattr(updater, "run_gradle_checks", lambda *args: checks)
    monkeypatch.setattr(
        updater, "capture_gradle_snapshot", lambda *args: state["snapshot"]
    )
    monkeypatch.setattr(
        updater,
        "revision_tree_id",
        lambda path, revision="@": "base-tree" if revision == "base" else state["tree"],
    )
    monkeypatch.setattr(updater, "validate_gradle_target", lambda *args: None)
    monkeypatch.setattr(updater, "evaluate_gradle_candidate_age", lambda *args: None)

    def apply(*args):
        stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
        assert stored is not None
        assert stored.attempts[0].state == "applying"
        effects.append("apply")
        catalogue.write_text(catalogue.read_text().replace('lib = "1"', 'lib = "2"'))
        state.update(snapshot=after, tree="after-tree")
        return None

    monkeypatch.setattr(updater, "apply_gradle_update", apply)
    monkeypatch.setattr(updater, "current_change_has_changes", lambda *args: True)
    monkeypatch.setattr(
        updater, "commit_current_change", lambda *args: effects.append("commit") or True
    )
    monkeypatch.setattr(updater, "exact_commit_id", lambda *args: "accepted")
    monkeypatch.setattr(
        updater,
        "create_or_reset_bookmark",
        lambda *args: effects.append("bookmark") or True,
    )

    def discard(*args):
        effects.append("discard")
        state.update(snapshot=initial, tree="base-tree")
        return True

    monkeypatch.setattr(updater, "discard_current_change", discard)
    return SimpleNamespace(
        project=project,
        context=context,
        initial=initial,
        after=after,
        candidate=candidate,
        publication=publication,
        state=state,
        effects=effects,
    )


def begin_workflow(workflow, flow=Workflow.UPDATE, candidate=None):
    return updater.start_gradle_run(
        "sample",
        workflow.project,
        flow,
        "base",
        workflow.context,
        (candidate or workflow.candidate,),
    )


def test_ordinary_residual_is_ready_without_cve_lifecycle(workflow):
    run = begin_workflow(workflow)
    result = updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    assert isinstance(result.attempts[0], ReadyAttempt)
    assert result.attempts[0].state == "ready"
    assert result.accepted_snapshot.findings[0].affected_versions == frozenset({"2"})
    assert result.accepted_snapshot.findings[0].rows[0].update_status is None
    assert result.attempts[0].receipt.verified_fixes == frozenset()
    assert len(result.attempts[0].receipt.residual_keys) == 1
    assert workflow.effects == ["apply", "commit", "bookmark"]
    loaded = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert loaded is not None
    assert loaded == result
    updater.gradle_run_finalization_check(
        loaded, workflow.project, workflow.publication, 7
    )


@pytest.mark.parametrize(
    "flow,expected_effects",
    [
        (Workflow.UPDATE, ["apply", "discard"]),
        (Workflow.RESOLVE, ["apply"]),
    ],
)
def test_security_residual_fails_and_obeys_workspace_policy(
    workflow, flow, expected_effects
):
    security = workflow.candidate.model_copy(
        update={
            "origins": frozenset({"security"}),
            "requested_advisories": frozenset({"CVE-1"}),
            "requested_coordinates": frozenset({"g:lib"}),
        }
    )
    run = begin_workflow(workflow, flow, security)
    result = updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    assert result.attempts[0].state == "failed"
    assert result.accepted_snapshot == workflow.initial
    assert workflow.effects == expected_effects
    assert workflow.state["tree"] == (
        "base-tree" if flow == Workflow.UPDATE else "after-tree"
    )
    with pytest.raises(updater.GradleError, match="failed"):
        updater.gradle_run_finalization_check(
            result, workflow.project, workflow.publication, 7
        )
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) == result


def test_start_persists_baseline_before_any_apply(workflow):
    run = begin_workflow(workflow)
    assert workflow.effects == []
    assert run.initial_snapshot == workflow.initial
    assert run.accepted_snapshot == workflow.initial
    assert run.attempts[0].state == "planned"
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) == run


def test_failed_checks_prevent_capture_and_ready(workflow, monkeypatch):
    run = begin_workflow(workflow)

    def failed(*args):
        raise updater.GradleError("unit failed")

    monkeypatch.setattr(updater, "run_gradle_checks", failed)
    monkeypatch.setattr(
        updater,
        "capture_gradle_snapshot",
        lambda *args: pytest.fail("capture after failed checks"),
    )
    result = updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    assert result.attempts[0].state == "failed"
    assert workflow.effects == ["apply", "discard"]


def test_finalization_rejects_credited_fix_reintroduced(workflow, scope):
    run = begin_workflow(workflow)
    result = updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    ready = result.attempts[0]
    assert isinstance(ready, ReadyAttempt)
    key = evidence(scope).key
    # Simulate a corrupt historical credit with consistent tree/snapshot bindings;
    # finalization must independently reject it against final findings.
    receipt = ready.receipt.model_copy(
        update={"verified_fixes": frozenset({key}), "residual_keys": frozenset()}
    )
    ready = ready.model_copy(update={"receipt": receipt})
    result = result.model_copy(update={"attempts": (ready,)})
    with pytest.raises(updater.GradleError, match="reintroduced"):
        updater.gradle_run_finalization_check(
            result, workflow.project, workflow.publication, 7
        )


@pytest.mark.parametrize("minimum_age_days", [0, 7])
def test_missing_routing_declaration_withholds_before_apply(
    workflow, monkeypatch, minimum_age_days
):
    run = begin_workflow(workflow)
    project = workflow.project.model_copy(update={"gradle_repository_routing": None})
    monkeypatch.setattr(
        updater,
        "evaluate_gradle_candidate_age",
        lambda *args: pytest.fail("publication lookup without routing declaration"),
    )
    result = updater.process_gradle_run(
        run, project, workflow.publication, minimum_age_days
    )
    assert isinstance(result.attempts[0], WithheldAttempt)
    assert result.attempts[0].state == "withheld"
    assert "gradle_repository_routing" in result.attempts[0].reason
    assert result.accepted_snapshot == run.accepted_snapshot
    assert workflow.effects == []


def test_removed_routing_declaration_blocks_finalization(workflow):
    run = begin_workflow(workflow)
    ready = updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    project = workflow.project.model_copy(update={"gradle_repository_routing": None})
    with pytest.raises(updater.GradleError, match="gradle_repository_routing"):
        updater.gradle_run_finalization_check(ready, project, workflow.publication, 7)


def test_gradle_no_updates_does_not_require_build_hooks(
    workflow, monkeypatch, tmp_path
):
    from maintenance_man import cli
    from maintenance_man.models.scan import ScanResult

    project = workflow.project.model_copy(
        update={
            "build_command": None,
            "test_unit": None,
            "test_component": None,
            "test_integration": None,
        }
    )
    empty = ScanResult(
        project="sample",
        scanned_at=workflow.context.created_at,
        trivy_target=str(project.path),
    )
    monkeypatch.setattr(cli, "load_scan_results", lambda *args: empty)
    monkeypatch.setattr(cli, "prune_stale_bookmarks", lambda *args: True)
    monkeypatch.setattr(cli, "ensure_main_bookmark", lambda *args: True)
    monkeypatch.setattr(cli, "exact_commit_id", lambda *args: "base")
    monkeypatch.setattr(cli, "_gradle_workspace_revision", lambda *args: "base")
    monkeypatch.setattr(cli, "workspace_path_for_project", lambda *args: project.path)
    monkeypatch.setattr(cli, "remove_workspace", lambda *args: None)
    monkeypatch.setattr(cli, "create_workspace", lambda *args: True)
    monkeypatch.setattr(cli, "edit_new_change", lambda *args: True)
    monkeypatch.setattr(cli, "create_or_reset_bookmark", lambda *args: True)
    monkeypatch.setattr(cli, "discover_gradle_updates", lambda *args: [])
    monkeypatch.setattr(
        updater,
        "gradle_check_commands",
        lambda *args: pytest.fail("No update needs acceptance hooks"),
    )
    assert (
        cli._run_gradle_flow(
            "sample",
            project,
            tmp_path,
            Workflow.UPDATE,
            interactive=False,
            minimum_age_days=7,
        )
        == cli.ExitCode.OK
    )
    assert workflow.effects == []
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) is None


@pytest.fixture
def driver(workflow, resolution, monkeypatch, tmp_path):
    from maintenance_man import cli
    from maintenance_man.models.gradle import (
        CandidateValidation,
        CandidateValidationBatch,
    )
    from maintenance_man.models.scan import ScanResult, UpdateFinding

    project = workflow.project.model_copy(update={"scan_secrets": False})
    (project.path / "gradle").mkdir(exist_ok=True)
    (project.path / "gradle/libs.versions.toml").write_text(
        '[versions]\nlib = "1"\nother = "1"\n[libraries]\n'
        'lib = { module = "g:lib", version.ref = "lib" }\n'
        'other = { module = "g:other", version.ref = "other" }\n'
    )
    proposed = UpdateFinding(
        pkg_name="g:lib",
        installed_version="1",
        latest_version="2",
        semver_tier=SemverTier.MAJOR,
        gradle_target=workflow.candidate.target,
    )
    state = SimpleNamespace(
        project=project,
        proposals=[proposed],
        selection="all",
        refs={"main": "base", "@-": "base", "mm/update-dependencies": "base"},
        effects=workflow.effects,
        results=tmp_path / "results",
        workflow=workflow,
    )
    monkeypatch.setattr(
        cli,
        "load_scan_results",
        lambda *args: ScanResult(
            project="sample",
            scanned_at=workflow.context.created_at,
            trivy_target=str(project.path),
            vulnerabilities=list(workflow.initial.findings[0].rows),
        ),
    )
    monkeypatch.setattr(cli, "collect_gradle_resolution", lambda *args: resolution)
    monkeypatch.setattr(
        cli, "initialize_comparison_context", lambda *args: workflow.context
    )
    monkeypatch.setattr(
        cli,
        "discover_gradle_updates",
        lambda *args: state.proposals if workflow.state["tree"] == "base-tree" else [],
    )

    def native(_project, candidates):
        return CandidateValidationBatch(
            schema_version=1,
            results=tuple(
                CandidateValidation(
                    kind=member.kind,
                    request_id=str(index),
                    project_path=":app",
                    group_key=candidate.target.group_key,
                    alias=member.alias,
                    selected_version=candidate.target.target_version,
                    implementation=None,
                    reason=None,
                )
                for index, (candidate, member) in enumerate(
                    (candidate, member)
                    for candidate in candidates
                    for member in candidate.target.members
                )
            ),
        )

    monkeypatch.setattr(cli, "validate_gradle_candidates", native)
    monkeypatch.setattr(cli, "evaluate_gradle_candidate_age", lambda *args: None)

    @contextmanager
    def publication(*args):
        yield SimpleNamespace(
            prefetch=lambda requests: tuple(requests),
            evidence_for=workflow.publication.evidence_for,
        )

    monkeypatch.setattr(cli, "PublicationLookupContext", publication)

    @contextmanager
    def proof(project, revision):
        assert revision == "accepted"
        yield project

    monkeypatch.setattr(updater, "_gradle_evidence_workspace", proof)
    monkeypatch.setattr(cli, "prune_stale_bookmarks", lambda *args: True)
    monkeypatch.setattr(cli, "ensure_main_bookmark", lambda *args: True)
    monkeypatch.setattr(
        cli, "_gradle_workspace_revision", lambda name, project, revision: revision
    )
    monkeypatch.setattr(cli, "workspace_path_for_project", lambda *args: project.path)
    monkeypatch.setattr(cli, "remove_workspace", lambda *args: None)
    monkeypatch.setattr(cli, "create_workspace", lambda *args: True)
    monkeypatch.setattr(cli, "edit_new_change", lambda *args: True)
    monkeypatch.setattr(cli, "create_or_reset_bookmark", lambda *args: True)
    monkeypatch.setattr(cli, "current_change_has_changes", lambda *args: False)
    monkeypatch.setattr(
        cli, "exact_commit_id", lambda path, revision: state.refs[revision]
    )
    monkeypatch.setattr(cli, "revision_tree_id", lambda *args: workflow.state["tree"])

    def promote(path, bookmark, *, expected_base, expected_tip):
        assert (bookmark, expected_base, expected_tip) == (
            "mm/update-dependencies",
            "base",
            "accepted",
        )
        state.effects.append("promote")
        state.refs["main"] = "accepted"
        return True

    monkeypatch.setattr(cli, "promote_bookmark_to_main", promote)
    monkeypatch.setattr(
        cli,
        "refresh_working_copy_from_main",
        lambda *args: state.effects.append("refresh") or True,
    )
    monkeypatch.setattr(cli.console, "input", lambda *args: state.selection)
    return state


def invoke_driver(driver, *, interactive=False, minimum_age_days=7):
    from maintenance_man import cli

    return cli._run_gradle_flow(
        "sample",
        driver.project,
        driver.results,
        Workflow.UPDATE,
        interactive=interactive,
        minimum_age_days=minimum_age_days,
    )


def test_gradle_driver_promotes_verified_update_with_residual_advisory(driver):
    from maintenance_man.models.scan import ScanResult

    assert invoke_driver(driver) == 0
    run = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert run is not None
    assert run.refreshed and run.promoted_commit_id == "accepted"
    assert run.attempts[0].state == "completed"
    assert driver.effects == ["apply", "commit", "bookmark", "promote", "refresh"]
    fresh = ScanResult.model_validate_json(
        (driver.results / "sample.json").read_bytes()
    )
    assert len(fresh.vulnerabilities) == 1
    assert fresh.vulnerabilities[0].installed_version == "2"
    assert fresh.vulnerabilities[0].update_status is None
    assert fresh.vulnerabilities[0].flow is None


@pytest.mark.parametrize(
    "selection,expected_applies", [("1", 1), ("1,1", 1), ("none", 0)]
)
def test_gradle_driver_selection_applies_whole_group_once(
    driver, selection, expected_applies
):
    driver.selection = selection
    code = invoke_driver(driver, interactive=True)
    # Existing residual findings still remain visible when no candidate is selected.
    assert code == (0 if expected_applies else 4)
    assert driver.effects.count("apply") == expected_applies
    assert driver.effects.count("commit") == expected_applies
    if expected_applies:
        run = updater.load_gradle_run(updater.gradle_run_path("sample"))
        assert run is not None
        assert run.attempts[0].candidate.target == driver.workflow.candidate.target
    else:
        assert driver.effects == []
        assert updater.load_gradle_run(updater.gradle_run_path("sample")) is None


@pytest.mark.parametrize("minimum_age_days", [0, 60])
def test_gradle_driver_uses_current_age_policy_before_apply(
    driver, monkeypatch, minimum_age_days
):
    from maintenance_man import cli
    from maintenance_man.models.gradle import AgeBlock

    def age(candidate, minimum, *args):
        assert minimum == minimum_age_days
        return AgeBlock(reason="exact publication withheld")

    monkeypatch.setattr(cli, "evaluate_gradle_candidate_age", age)
    assert invoke_driver(driver, minimum_age_days=minimum_age_days) == 4
    assert driver.effects == []
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) is None


def test_gradle_driver_withheld_group_does_not_prevent_verified_promotion(
    driver, monkeypatch
):
    from maintenance_man import cli
    from maintenance_man.models.gradle import AgeBlock
    from maintenance_man.models.scan import UpdateFinding

    other = GradleUpdateTarget(
        version_ref="other",
        members=[
            GradleMember(
                kind="library",
                alias="other",
                coordinate="g:other",
                installed_version="1",
            )
        ],
        target_version="2",
    )
    driver.proposals.append(
        UpdateFinding(
            pkg_name="g:other",
            installed_version="1",
            latest_version="2",
            gradle_target=other,
            semver_tier=SemverTier.MAJOR,
        )
    )
    monkeypatch.setattr(
        cli,
        "evaluate_gradle_candidate_age",
        lambda candidate, *args: (
            AgeBlock(reason="exact publication unavailable")
            if candidate.target.group_key == "ref:other"
            else None
        ),
    )
    assert invoke_driver(driver) == 0
    run = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert run is not None
    assert {item.candidate.target.group_key: item.state for item in run.attempts} == {
        "ref:lib": "completed",
        "ref:other": "withheld",
    }
    assert driver.effects == ["apply", "commit", "bookmark", "promote", "refresh"]


def test_gradle_driver_refuses_sdk_before_sync_or_workspace_effects(
    driver, monkeypatch
):
    from maintenance_man import cli
    from maintenance_man.vcs import RevisionFileCheck

    monkeypatch.setattr(cli, "_gradle_workspace_revision", _SDK_WORKSPACE_CHECK)
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (driver.project.path / "local.properties").write_text("sdk.dir=/unavailable\n")
    monkeypatch.setattr(
        cli,
        "revision_file",
        lambda *args: RevisionFileCheck(ok=True, value=False, commit_id="base"),
    )
    monkeypatch.setattr(
        cli,
        "prune_stale_bookmarks",
        lambda *args: driver.effects.append("sync") or True,
    )
    monkeypatch.setattr(
        cli, "remove_workspace", lambda *args: driver.effects.append("remove")
    )
    assert invoke_driver(driver) == 4
    assert driver.effects == []


@pytest.mark.parametrize("post_sync_tracked", [False, True])
def test_gradle_driver_rechecks_sdk_at_pinned_base_before_workspace_effects(
    driver,
    monkeypatch,
    post_sync_tracked,
):
    from maintenance_man import cli
    from maintenance_man.vcs import RevisionFileCheck

    monkeypatch.setattr(cli, "_gradle_workspace_revision", _SDK_WORKSPACE_CHECK)
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (driver.project.path / "local.properties").write_text("sdk.dir=/android\n")
    inspections = []
    synced = False

    def sync(*args):
        nonlocal synced
        synced = True
        return True

    def inspect(path, revision, filename):
        inspections.append((synced, revision, filename))
        return RevisionFileCheck(
            ok=True, value=post_sync_tracked if synced else True, commit_id="base"
        )

    workspace_effects = []
    monkeypatch.setattr(cli, "prune_stale_bookmarks", sync)
    monkeypatch.setattr(cli, "revision_file", inspect)
    monkeypatch.setattr(
        cli, "remove_workspace", lambda *args: workspace_effects.append("remove")
    )
    monkeypatch.setattr(
        cli,
        "create_workspace",
        lambda path, name, revision: (
            workspace_effects.append(("workspace", revision)) or True
        ),
    )
    assert invoke_driver(driver) == (0 if post_sync_tracked else 4)
    assert inspections == [
        (False, "main", "local.properties"),
        (True, "base", "local.properties"),
    ]
    if post_sync_tracked:
        assert ("workspace", "base") in workspace_effects
    else:
        assert workspace_effects == []
        assert driver.effects == []


@pytest.mark.parametrize("sdk_env,properties", [(True, True), (False, False)])
def test_gradle_driver_skips_unneeded_sdk_revision_inspection(
    driver, monkeypatch, sdk_env, properties
):
    from maintenance_man import cli

    monkeypatch.setattr(cli, "_gradle_workspace_revision", _SDK_WORKSPACE_CHECK)
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    if sdk_env:
        monkeypatch.setenv("ANDROID_HOME", "/android")
    if properties:
        (driver.project.path / "local.properties").write_text("sdk.dir=/android\n")
    monkeypatch.setattr(
        cli, "revision_file", lambda *args: pytest.fail("SDK inspection unnecessary")
    )
    assert invoke_driver(driver) == 0


@pytest.mark.parametrize("failure", ["promotion", "refresh"])
def test_gradle_driver_retains_verified_ledger_when_final_effect_fails(
    driver, monkeypatch, failure
):
    from maintenance_man import cli

    if failure == "promotion":
        monkeypatch.setattr(
            cli, "promote_bookmark_to_main", lambda *args, **kwargs: False
        )
    else:
        monkeypatch.setattr(cli, "refresh_working_copy_from_main", lambda *args: False)
    assert invoke_driver(driver) == 4
    run = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert run is not None
    assert run.attempts[0].state == "ready"
    assert run.promoted_commit_id == (None if failure == "promotion" else "accepted")
    assert not run.refreshed
    assert driver.effects.count("apply") == 1
    assert driver.effects.count("commit") == 1
    assert not (driver.results / "sample.json").exists()


def test_gradle_failed_attempt_prevents_finalization_after_another_group_passes(
    workflow, monkeypatch
):
    from maintenance_man.models.gradle import PlannedAttempt

    first = begin_workflow(workflow)
    accepted = updater.process_gradle_run(
        first, workflow.project, workflow.publication, 7
    )
    other = workflow.candidate.model_copy(
        update={
            "target": GradleUpdateTarget(
                version_ref="other",
                members=[
                    GradleMember(
                        kind="library",
                        alias="other",
                        coordinate="g:other",
                        installed_version="1",
                    )
                ],
                target_version="2",
            )
        }
    )
    pending = accepted.model_copy(
        update={"attempts": (*accepted.attempts, PlannedAttempt(candidate=other))}
    )
    updater.save_gradle_run(updater.gradle_run_path("sample"), pending)

    def failing_apply(*args):
        raise updater.GradleError("second group failed")

    monkeypatch.setattr(updater, "apply_gradle_update", failing_apply)
    monkeypatch.setattr(updater, "discard_current_change", lambda *args: True)
    result = updater.process_gradle_run(
        pending, workflow.project, workflow.publication, 7
    )
    assert [item.state for item in result.attempts] == ["ready", "failed"]
    assert result.accepted_snapshot == accepted.accepted_snapshot
    with pytest.raises(updater.GradleError, match="failed"):
        updater.gradle_run_finalization_check(
            result, workflow.project, workflow.publication, 7
        )


@pytest.mark.parametrize("failure", ["build", "tests"])
def test_gradle_baseline_checks_fail_before_capture_or_ledger(
    workflow, monkeypatch, failure
):
    monkeypatch.setattr(updater, "run_gradle_checks", _RUN_GRADLE_CHECKS)
    effects = []

    def build(*args):
        effects.append("build")
        if failure == "build":
            raise updater.BuildError("build failed")

    def tests(*args):
        effects.append("tests")
        return False, "unit"

    monkeypatch.setattr(updater, "run_build", build)
    monkeypatch.setattr(updater, "run_test_phases", tests)
    monkeypatch.setattr(
        updater,
        "capture_gradle_snapshot",
        lambda *args: pytest.fail("capture after failed baseline"),
    )
    with pytest.raises(updater.GradleError, match="failed"):
        begin_workflow(workflow)
    assert effects == (["build"] if failure == "build" else ["build", "tests"])
    assert workflow.effects == []
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) is None
