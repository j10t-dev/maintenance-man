import hashlib
import json
import shutil
import subprocess
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from maintenance_man import cli, scanner, updater
from maintenance_man import gradle_verification as verification
from maintenance_man.cli import _gradle_workspace_revision as _SDK_WORKSPACE_CHECK
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    ApplyingAttempt,
    CheckEvidence,
    CompletedAttempt,
    CompleteResolution,
    FailedAttempt,
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
from maintenance_man.vcs import RevisionCheck


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

    def native(_project, candidates, _resolution):
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


@pytest.mark.parametrize("minimum_age_days", [0, 7])
def test_gradle_finalization_rechecks_routing(
    workflow, monkeypatch, tmp_path, minimum_age_days
):
    run = ready_workflow(workflow)
    undeclared = workflow.project.model_copy(update={"gradle_repository_routing": None})
    before = updater.gradle_run_path(run.project).read_bytes()
    monkeypatch.setattr(
        cli,
        "promote_bookmark_to_main",
        lambda *args, **kwargs: pytest.fail("promotion without routing declaration"),
    )
    monkeypatch.setattr(
        cli,
        "push_bookmark_and_create_pr",
        lambda *args, **kwargs: pytest.fail("submission without routing declaration"),
    )
    with pytest.raises(
        updater.GradleError, match="Public repository routing has not been declared"
    ):
        cli._finish_verified_gradle_run(
            run, undeclared, tmp_path, workflow.publication, minimum_age_days
        )
    assert updater.gradle_run_path(run.project).read_bytes() == before


@pytest.mark.parametrize("stage", ["intent", "mutated", "checked-before-commit"])
@pytest.mark.parametrize("flow", [Workflow.UPDATE, Workflow.RESOLVE])
def test_gradle_uncommitted_interruption_becomes_failed(
    workflow, monkeypatch, stage, flow
):
    run = begin_workflow(workflow, flow)
    checked = stage == "checked-before-commit"
    state = ApplyingAttempt(
        candidate=workflow.candidate,
        baseline=workflow.initial,
        after=workflow.after if checked else None,
        checks=updater.run_gradle_checks(workflow.project, "sample")
        if checked
        else None,
        checked_tree_id="after-tree" if checked else None,
    )
    run = updater._replace_gradle_attempt(run, state)
    updater.save_gradle_run(updater.gradle_run_path("sample"), run)
    dirty = stage != "intent"
    workflow.state["tree"] = "after-tree" if dirty else "base-tree"
    monkeypatch.setattr(updater, "exact_commit_id", lambda *args: "base")
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)
    monkeypatch.setattr(
        updater,
        "current_change_has_changes",
        lambda *args: workflow.state["tree"] != "base-tree",
    )
    from types import SimpleNamespace

    monkeypatch.setattr(
        updater,
        "_run",
        lambda *args: SimpleNamespace(
            returncode=0,
            stdout=str(updater.GRADLE_CATALOGUE_RELPATH) + "\n" if dirty else "",
        ),
    )
    original_discard = updater.discard_current_change

    def discard(path):
        stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
        assert stored is not None
        assert isinstance(stored.attempts[0], FailedAttempt)
        return original_discard(path)

    monkeypatch.setattr(updater, "discard_current_change", discard)
    result = updater.reconcile_gradle_applying(
        run, workflow.project, workflow.publication, 7
    )
    assert isinstance(result.attempts[0], FailedAttempt)
    assert result.attempts[0].after == (workflow.after if checked else None)
    assert result.managed_tip_id == "base"
    assert workflow.effects == (
        ["discard"] if flow == Workflow.UPDATE and dirty else []
    )
    assert workflow.state["tree"] == (
        "after-tree" if flow == Workflow.RESOLVE and dirty else "base-tree"
    )


@pytest.mark.parametrize("unsafe", [None, "parent", "bookmark", "other-file"])
def test_gradle_failed_save_before_rollback_is_recoverable(
    workflow, monkeypatch, unsafe
):
    run = begin_workflow(workflow)
    run = updater._replace_gradle_attempt(
        run,
        FailedAttempt(
            candidate=workflow.candidate,
            baseline=workflow.initial,
            reason="Interrupted before rollback",
        ),
    )
    updater.save_gradle_run(updater.gradle_run_path("sample"), run)
    workflow.state["tree"] = "after-tree"
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)

    def revision(path, rev):
        return (
            "unrelated"
            if (unsafe == "parent" and rev == "@-")
            or (unsafe == "bookmark" and rev == run.managed_bookmark)
            else "base"
        )

    monkeypatch.setattr(updater, "exact_commit_id", revision)
    monkeypatch.setattr(
        updater,
        "current_change_has_changes",
        lambda *args: workflow.state["tree"] != "base-tree",
    )
    from types import SimpleNamespace

    monkeypatch.setattr(
        updater,
        "_run",
        lambda *args: SimpleNamespace(
            returncode=0,
            stdout="build.gradle.kts\n"
            if unsafe == "other-file"
            else str(updater.GRADLE_CATALOGUE_RELPATH) + "\n",
        ),
    )
    before = updater.gradle_run_path("sample").read_bytes()
    if unsafe:
        with pytest.raises(updater.GradleError):
            updater.rollback_failed_gradle_update(run, workflow.project)
        assert workflow.effects == []
        assert workflow.state["tree"] == "after-tree"
    else:
        original_discard = updater.discard_current_change

        def interrupted_discard(path):
            saved = updater.load_gradle_run(updater.gradle_run_path("sample"))
            assert saved is not None
            assert isinstance(saved.attempts[0], FailedAttempt)
            raise updater.GradleError("simulated crash before restore")

        monkeypatch.setattr(updater, "discard_current_change", interrupted_discard)
        with pytest.raises(updater.GradleError, match="crash before restore"):
            updater.rollback_failed_gradle_update(run, workflow.project)
        assert workflow.state["tree"] == "after-tree"
        monkeypatch.setattr(updater, "discard_current_change", original_discard)
        stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
        assert stored is not None
        updater.rollback_failed_gradle_update(stored, workflow.project)
        updater.rollback_failed_gradle_update(stored, workflow.project)
        assert workflow.effects == ["discard"]
        assert workflow.state["tree"] == "base-tree"
    assert updater.gradle_run_path("sample").read_bytes() == before


def test_gradle_resolve_interrupted_before_checks_accepts_only_committed_repair(
    workflow, monkeypatch
):
    run = begin_workflow(workflow, Workflow.RESOLVE)
    run = updater._replace_gradle_attempt(
        run, ApplyingAttempt(candidate=workflow.candidate, baseline=workflow.initial)
    )
    updater.save_gradle_run(updater.gradle_run_path("sample"), run)
    workflow.state.update(snapshot=workflow.after, tree="after-tree")
    monkeypatch.setattr(
        updater,
        "exact_commit_id",
        lambda path, rev: "base" if rev == run.managed_bookmark else "repair",
    )
    monkeypatch.setattr(updater, "current_change_has_changes", lambda *args: False)
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)
    monkeypatch.setattr(
        updater, "is_ancestor", lambda *args: RevisionCheck(ok=True, value=True)
    )
    monkeypatch.setattr(updater, "validate_gradle_recovery", lambda *args: None)
    monkeypatch.setattr(updater, "context_inputs_valid", lambda *args: True)
    failed = updater.reconcile_gradle_applying(
        run, workflow.project, workflow.publication, 7
    )
    assert isinstance(failed.attempts[0], FailedAttempt)
    assert workflow.effects == []
    repaired = updater.continue_gradle_resolve(
        failed, workflow.project, workflow.publication, 7
    )
    assert isinstance(repaired.attempts[0], ReadyAttempt)
    assert repaired.managed_tip_id == "repair"
    assert "apply" not in workflow.effects
    assert "commit" not in workflow.effects
    assert "discard" not in workflow.effects


@contextmanager
def same_proof_workspace(project, revision):
    yield project


def ready_workflow(workflow):
    return updater.process_gradle_run(
        begin_workflow(workflow), workflow.project, workflow.publication, 7
    )


def finalizer_effects(workflow, monkeypatch, run):
    state = {
        "main": run.base_commit_id,
        "promotions": 0,
        "refreshes": 0,
        "published": 0,
    }
    monkeypatch.setattr(updater, "_gradle_evidence_workspace", same_proof_workspace)
    monkeypatch.setattr(cli, "context_inputs_valid", lambda *args: True)
    monkeypatch.setattr(
        cli,
        "exact_commit_id",
        lambda path, rev: state["main"] if rev == "main" else run.managed_tip_id,
    )

    def promote(path, bookmark, *, expected_base, expected_tip):
        assert (bookmark, expected_base, expected_tip) == (
            run.managed_bookmark,
            "base",
            "accepted",
        )
        assert state["main"] == expected_base
        state["main"] = expected_tip
        state["promotions"] += 1
        return True

    def refresh(path):
        saved = updater.load_gradle_run(updater.gradle_run_path(run.project))
        assert saved is not None
        assert saved.promoted_commit_id == "accepted"
        state["refreshes"] += 1
        return state["refreshes"] > 1

    def publish(*args):
        state["published"] += 1

    monkeypatch.setattr(cli, "promote_bookmark_to_main", promote)
    monkeypatch.setattr(cli, "refresh_working_copy_from_main", refresh)
    monkeypatch.setattr(cli, "_publish_verified_gradle_scan", publish)
    return state


def test_gradle_retry_refresh_never_reapplies_or_repromotes(
    workflow, monkeypatch, tmp_path
):
    run = ready_workflow(workflow)
    state = finalizer_effects(workflow, monkeypatch, run)
    with pytest.raises(updater.GradleError, match="refresh failed"):
        cli._finish_verified_gradle_run(
            run, workflow.project, tmp_path, workflow.publication, 7
        )
    saved = updater.load_gradle_run(updater.gradle_run_path(run.project))
    assert saved is not None
    assert saved.promoted_commit_id == "accepted"
    assert not saved.refreshed
    finished = cli._finish_verified_gradle_run(
        saved, workflow.project, tmp_path, workflow.publication, 7
    )
    assert finished.refreshed
    assert isinstance(finished.attempts[0], CompletedAttempt)
    assert state == {
        "main": "accepted",
        "promotions": 1,
        "refreshes": 2,
        "published": 1,
    }
    assert workflow.effects.count("apply") == 1


def test_gradle_crash_after_promotion_before_ledger_is_recognized(
    workflow, monkeypatch, tmp_path
):
    run = ready_workflow(workflow)
    state = finalizer_effects(workflow, monkeypatch, run)
    original_save = updater.save_gradle_run
    crashed = False

    def crash_save(path, value):
        nonlocal crashed
        if value.promoted_commit_id and not crashed:
            crashed = True
            raise updater.GradleError("simulated durable-write crash")
        original_save(path, value)

    monkeypatch.setattr(updater, "save_gradle_run", crash_save)
    with pytest.raises(updater.GradleError, match="durable-write"):
        cli._finish_verified_gradle_run(
            run, workflow.project, tmp_path, workflow.publication, 7
        )
    stored = updater.load_gradle_run(updater.gradle_run_path(run.project))
    assert stored is not None
    assert stored.promoted_commit_id is None
    state["refreshes"] = 1
    finished = cli._finish_verified_gradle_run(
        stored, workflow.project, tmp_path, workflow.publication, 7
    )
    assert finished.refreshed
    assert state["promotions"] == 1
    assert workflow.effects.count("apply") == 1


@pytest.mark.parametrize("stale", [False, True])
def test_gradle_checked_commit_recovery_does_not_apply_twice(
    workflow, monkeypatch, stale
):
    run = begin_workflow(workflow)
    original_save = updater.save_gradle_run
    crashed = False

    def crash_after_commit(path, value):
        nonlocal crashed
        item = value.attempts[0]
        if (
            isinstance(item, ApplyingAttempt)
            and item.accepted_commit_id is not None
            and not crashed
        ):
            crashed = True
            raise updater.GradleError("simulated commit crash")
        original_save(path, value)

    monkeypatch.setattr(updater, "save_gradle_run", crash_after_commit)
    with pytest.raises(updater.GradleError, match="commit crash"):
        updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    interrupted = updater.load_gradle_run(updater.gradle_run_path(run.project))
    assert interrupted is not None
    assert isinstance(interrupted.attempts[0], ApplyingAttempt)
    assert interrupted.attempts[0].checked_tree_id == "after-tree"
    assert interrupted.attempts[0].accepted_commit_id is None
    monkeypatch.setattr(updater, "current_change_has_changes", lambda *args: False)
    monkeypatch.setattr(
        updater,
        "exact_commit_id",
        lambda path, rev: "base" if rev == run.managed_bookmark else "accepted",
    )
    monkeypatch.setattr(
        updater, "is_ancestor", lambda *args: RevisionCheck(ok=True, value=True)
    )
    monkeypatch.setattr(updater, "validate_gradle_recovery", lambda *args: None)
    monkeypatch.setattr(updater, "context_inputs_valid", lambda *args: not stale)
    visited = []

    @contextmanager
    def proof(project, revision):
        visited.append(revision)
        workflow.state.update(
            snapshot=workflow.initial if revision == "base" else workflow.after,
            tree="base-tree" if revision == "base" else "after-tree",
        )
        yield project

    monkeypatch.setattr(updater, "_gradle_evidence_workspace", proof)
    monkeypatch.setattr(updater, "parse_catalogue", lambda *args: object())
    monkeypatch.setattr(
        updater, "collect_gradle_resolution", lambda *args: workflow.initial.resolution
    )
    monkeypatch.setattr(
        updater, "initialize_comparison_context", lambda *args: workflow.context
    )
    recovered = updater.reconcile_gradle_applying(
        interrupted, workflow.project, workflow.publication, 7
    )
    assert recovered.attempts[0].state == "ready"
    assert recovered.managed_tip_id == "accepted"
    assert workflow.effects.count("apply") == 1
    assert workflow.effects.count("commit") == 1
    assert visited == (["base", "accepted"] if stale else [])


def test_gradle_rejected_snapshot_survives_resolve_retry(workflow, monkeypatch):
    security = workflow.candidate.model_copy(
        update={
            "origins": frozenset({"security"}),
            "requested_advisories": frozenset({"CVE-1"}),
            "requested_coordinates": frozenset({"g:lib"}),
        }
    )
    failed = updater.process_gradle_run(
        begin_workflow(workflow, Workflow.RESOLVE, security),
        workflow.project,
        workflow.publication,
        7,
    )
    assert isinstance(failed.attempts[0], FailedAttempt)
    assert failed.attempts[0].after == workflow.after
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)
    monkeypatch.setattr(updater, "current_change_has_changes", lambda *args: False)
    monkeypatch.setattr(
        updater, "is_ancestor", lambda *args: RevisionCheck(ok=True, value=True)
    )
    monkeypatch.setattr(updater, "validate_gradle_recovery", lambda *args: None)
    with pytest.raises(updater.GradleError, match="Security verification"):
        updater.continue_gradle_resolve(
            failed, workflow.project, workflow.publication, 7
        )
    stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert stored is not None
    assert isinstance(stored.attempts[0], FailedAttempt)
    assert stored.attempts[0].state == "failed"
    assert stored.attempts[0].after == workflow.after
    assert workflow.effects == ["apply"]


def test_gradle_cli_uses_ledger_even_without_scan_results(
    workflow, monkeypatch, tmp_path
):
    run = ready_workflow(workflow)
    monkeypatch.setattr(
        cli, "workspace_path_for_project", lambda *args: workflow.project.path
    )
    monkeypatch.setattr(
        cli,
        "exact_commit_id",
        lambda path, revision: "base" if revision == "main" else "accepted",
    )
    monkeypatch.setattr(cli, "context_inputs_valid", lambda *args: True)
    monkeypatch.setattr(
        cli,
        "PublicationLookupContext",
        lambda *args: __import__("contextlib").nullcontext(workflow.publication),
    )
    monkeypatch.setattr(cli, "current_change_has_changes", lambda *args: False)
    monkeypatch.setattr(
        cli, "revision_tree_id", lambda *args: run.accepted_snapshot.tree_id
    )
    finalized = False

    def read_published(*args):
        assert finalized, "scan JSON must not authorize ledger recovery"
        raise cli.NoScanResultsError("no published results")

    def finish(value, *args):
        nonlocal finalized
        finalized = True
        return value.model_copy(update={"refreshed": True})

    monkeypatch.setattr(cli, "load_scan_results", read_published)
    monkeypatch.setattr(cli, "_finish_verified_gradle_run", finish)
    monkeypatch.setattr(cli, "remove_workspace", lambda *args: None)
    assert (
        cli._run_gradle_flow(
            "sample",
            workflow.project,
            tmp_path,
            Workflow.UPDATE,
            interactive=False,
            minimum_age_days=7,
        )
        == cli.ExitCode.OK
    )
    assert workflow.effects.count("apply") == 1


def test_gradle_legacy_ready_without_ledger_refuses_before_workspace(
    workflow, monkeypatch, tmp_path
):
    from maintenance_man.models.scan import ScanResult, UpdateStatus

    row = (
        workflow.initial.findings[0]
        .rows[0]
        .model_copy(update={"update_status": UpdateStatus.READY})
    )
    legacy = ScanResult(
        project="sample",
        scanned_at=workflow.context.created_at,
        trivy_target=str(workflow.project.path),
        vulnerabilities=[row],
    )
    monkeypatch.setattr(cli, "load_scan_results", lambda *args: legacy)
    monkeypatch.setattr(
        cli,
        "create_workspace",
        lambda *args: pytest.fail("workspace effect before legacy guard"),
    )
    assert (
        cli._run_gradle_flow(
            "sample",
            workflow.project,
            tmp_path,
            Workflow.UPDATE,
            interactive=False,
            minimum_age_days=7,
        )
        == cli.ExitCode.UPDATE_FAILED
    )
    assert workflow.effects == []


@pytest.mark.parametrize(
    ("default_dirty", "unsafe", "workspace_exists"),
    [
        (False, False, True),
        (True, False, True),
        (False, True, True),
        (True, True, True),
        (True, False, False),
    ],
)
def test_gradle_failed_update_restart_retains_evidence(
    workflow, monkeypatch, tmp_path, unsafe, default_dirty, workspace_exists
):
    security = workflow.candidate.model_copy(
        update={
            "origins": frozenset({"security"}),
            "requested_advisories": frozenset({"CVE-1"}),
            "requested_coordinates": frozenset({"g:lib"}),
        }
    )
    failed = updater.process_gradle_run(
        begin_workflow(workflow, candidate=security),
        workflow.project,
        workflow.publication,
        7,
    )
    workspace = tmp_path / "managed-workspace"
    if workspace_exists:
        workspace.mkdir()
    user_file = workflow.project.path / "user-notes.txt"
    user_file.write_text("preserve these notes")
    monkeypatch.setattr(cli, "workspace_path_for_project", lambda *args: workspace)
    monkeypatch.setattr(
        cli,
        "current_change_has_changes",
        lambda path: default_dirty if path == workflow.project.path else unsafe,
    )
    monkeypatch.setattr(updater, "rollback_failed_gradle_update", lambda *args: None)
    monkeypatch.setattr(cli, "exact_commit_id", lambda *args: "base")
    monkeypatch.setattr(cli, "revision_tree_id", lambda *args: "base-tree")
    effects = []

    def reset(*args, **kwargs):
        archives = list(
            (updater.gradle_run_path("sample").parent / "history").glob("*.json")
        )
        assert len(archives) == 1
        assert updater.load_gradle_run(archives[0]) == failed
        assert updater.gradle_run_path("sample").exists()
        effects.append("reset")
        return True

    monkeypatch.setattr(cli, "reset_verified_gradle_bookmark", reset)
    if unsafe or not workspace_exists:
        with pytest.raises(updater.GradleError, match="Uncommitted"):
            cli._archive_rolled_back_gradle_run(failed, workflow.project)
        assert updater.load_gradle_run(updater.gradle_run_path("sample")) == failed
        assert effects == []
    else:
        cli._archive_rolled_back_gradle_run(failed, workflow.project)
        assert not updater.gradle_run_path("sample").exists()
        assert effects == ["reset"]
    assert user_file.read_text() == "preserve these notes"


@pytest.mark.parametrize(
    "mutation", ["none", "dirty", "unrelated-parent", "working-tree", "accepted-tree"]
)
def test_gradle_resume_requires_exact_empty_accepted_child(
    workflow, monkeypatch, tmp_path, mutation
):
    run = ready_workflow(workflow)
    before = updater.gradle_run_path("sample").read_bytes()
    monkeypatch.setattr(
        cli, "workspace_path_for_project", lambda *args: workflow.project.path
    )
    monkeypatch.setattr(
        cli,
        "PublicationLookupContext",
        lambda *args: __import__("contextlib").nullcontext(workflow.publication),
    )
    monkeypatch.setattr(cli, "context_inputs_valid", lambda *args: True)
    monkeypatch.setattr(
        cli, "current_change_has_changes", lambda *args: mutation == "dirty"
    )

    def commit(path, revision):
        if revision == "main":
            return "base"
        if revision == "@-" and mutation == "unrelated-parent":
            return "manual-unverified-commit"
        return "accepted"

    def tree(path, revision="@"):
        if (revision == "@" and mutation == "working-tree") or (
            revision == "accepted" and mutation == "accepted-tree"
        ):
            return "unverified-tree"
        return run.accepted_snapshot.tree_id

    monkeypatch.setattr(cli, "exact_commit_id", commit)
    monkeypatch.setattr(cli, "revision_tree_id", tree)
    effects = []
    monkeypatch.setattr(
        updater,
        "process_gradle_run",
        lambda value, *args: effects.append("process") or value,
    )
    monkeypatch.setattr(
        cli,
        "_finish_verified_gradle_run",
        lambda value, *args: (
            effects.append("finalize") or value.model_copy(update={"refreshed": True})
        ),
    )
    monkeypatch.setattr(cli, "remove_workspace", lambda *args: effects.append("remove"))
    result = cli._run_gradle_flow(
        "sample",
        workflow.project,
        tmp_path,
        Workflow.UPDATE,
        interactive=False,
        minimum_age_days=7,
    )
    assert result == (
        cli.ExitCode.OK if mutation == "none" else cli.ExitCode.UPDATE_FAILED
    )
    assert effects == (["process", "finalize", "remove"] if mutation == "none" else [])
    assert updater.gradle_run_path("sample").read_bytes() == before
    assert workflow.effects.count("apply") == 1


def test_gradle_continue_proves_repair_before_automatic_workspace_guard(
    workflow, monkeypatch, tmp_path
):
    updater.process_gradle_run(
        begin_workflow(workflow, Workflow.RESOLVE),
        workflow.project,
        workflow.publication,
        7,
    )
    monkeypatch.setattr(
        cli,
        "PublicationLookupContext",
        lambda *args: __import__("contextlib").nullcontext(workflow.publication),
    )
    monkeypatch.setattr(cli, "context_inputs_valid", lambda *args: True)
    monkeypatch.setattr(
        cli,
        "exact_commit_id",
        lambda path, revision: "base" if revision == "main" else "accepted",
    )
    effects = []

    def repair(value, *args):
        effects.append("verify-committed-repair")
        return value

    def guard(value, project):
        assert effects == ["verify-committed-repair"]
        effects.append("accepted-workspace-guard")

    monkeypatch.setattr(updater, "continue_gradle_resolve", repair)
    monkeypatch.setattr(cli, "_require_gradle_accepted_workspace", guard)
    monkeypatch.setattr(
        updater,
        "process_gradle_run",
        lambda value, *args: effects.append("process") or value,
    )
    monkeypatch.setattr(cli, "_finish_verified_gradle_run", lambda value, *args: value)
    assert (
        cli._run_gradle_flow(
            "sample",
            workflow.project,
            tmp_path,
            Workflow.RESOLVE,
            interactive=False,
            minimum_age_days=7,
            continue_=True,
        )
        == cli.ExitCode.OK
    )
    assert effects == ["verify-committed-repair", "accepted-workspace-guard", "process"]


@pytest.mark.parametrize("repaired", [False, True])
def test_gradle_resolve_checks_actual_catalogue_before_accepting_manual_repair(
    driver, monkeypatch, repaired
):
    from maintenance_man.vcs import RevisionCheck

    workflow = driver.workflow
    run = begin_workflow(workflow, Workflow.RESOLVE)
    failed = updater._replace_gradle_attempt(
        run,
        FailedAttempt(
            candidate=workflow.candidate,
            baseline=workflow.initial,
            reason="manual repair required",
        ),
    )
    ledger = updater.gradle_run_path("sample")
    updater.save_gradle_run(ledger, failed)
    before = ledger.read_bytes()
    catalogue = driver.project.path / "gradle/libs.versions.toml"
    if repaired:
        catalogue.write_text(catalogue.read_text().replace('lib = "1"', 'lib = "2"'))
    workflow.state.update(snapshot=workflow.after, tree="after-tree")
    report = driver.project.path / "gradle/libs.versions.updates.toml"
    marker = driver.project.path / "gradle/.mm-owned-report"
    report.write_bytes(b"interrupted report")
    marker.write_bytes(b"")

    def clean(path):
        assert not report.exists() and not marker.exists()
        return False

    monkeypatch.setattr(updater, "current_change_has_changes", clean)
    monkeypatch.setattr(updater, "exact_commit_id", lambda *args: "repair")
    monkeypatch.setattr(
        updater, "is_ancestor", lambda *args: RevisionCheck(ok=True, value=True)
    )
    checks = updater.run_gradle_checks(driver.project, "sample")
    calls = []
    monkeypatch.setattr(
        updater, "run_gradle_checks", lambda *args: calls.append("checks") or checks
    )
    if repaired:
        result = updater.continue_gradle_resolve(
            failed, driver.project, workflow.publication, 7
        )
        assert isinstance(result.attempts[0], ReadyAttempt)
        assert result.managed_tip_id == "repair"
        assert calls == ["checks"]
        assert workflow.effects == ["bookmark"]
    else:
        with pytest.raises(updater.GradleError, match="expected 2"):
            updater.continue_gradle_resolve(
                failed, driver.project, workflow.publication, 7
            )
        assert calls == []
        assert ledger.read_bytes() == before
        assert workflow.effects == []


def test_gradle_fresh_scan_does_not_clear_unfinished_ledger(driver, monkeypatch):
    from maintenance_man import cli, scanner
    from maintenance_man.models.config import MmConfig
    from maintenance_man.models.scan import ScanResult

    workflow = driver.workflow
    run = begin_workflow(workflow)
    interrupted = updater._replace_gradle_attempt(
        run, ApplyingAttempt(candidate=workflow.candidate, baseline=workflow.initial)
    )
    ledger = updater.gradle_run_path("sample")
    updater.save_gradle_run(ledger, interrupted)
    before = ledger.read_bytes()
    monkeypatch.setattr(
        cli, "_load_cfg", lambda *args: MmConfig(projects={"sample": driver.project})
    )
    monkeypatch.setattr(cli, "check_trivy_available", lambda: None)
    monkeypatch.setattr(
        scanner, "_run_gradle_scan", lambda *args: ([], workflow.initial.resolution)
    )
    monkeypatch.setattr(scanner, "get_outdated", lambda *args: [])
    result_path = updater._config.MM_HOME / "scan-results" / "sample.json"
    result_path.parent.mkdir()
    result_path.write_bytes(b"previous current-main scan")
    with pytest.raises(SystemExit) as exc:
        cli.app(["scan", "sample"])
    assert exc.value.code == 0
    result = ScanResult.model_validate_json(result_path.read_bytes())
    assert result.project == "sample" and result.vulnerabilities == []
    assert ledger.read_bytes() == before
    assert workflow.effects == []


@pytest.mark.parametrize(
    "refreshed,published_exists", [(False, False), (True, False), (True, True)]
)
def test_gradle_result_render_uses_durable_or_published_evidence(
    workflow, monkeypatch, tmp_path, refreshed, published_exists
):
    from maintenance_man.models.scan import ScanResult

    run = ready_workflow(workflow)
    if refreshed:
        run = run.model_copy(
            update={"promoted_commit_id": run.managed_tip_id, "refreshed": True}
        )
    published = ScanResult(
        project="sample",
        scanned_at=workflow.context.created_at,
        trivy_target=str(workflow.project.path),
        vulnerabilities=[],
    )
    reads = []

    def load(*args):
        reads.append("load")
        if published_exists:
            return published
        raise cli.NoScanResultsError("no saved results")

    rendered = []
    monkeypatch.setattr(cli, "load_scan_results", load)
    monkeypatch.setattr(
        cli,
        "_print_scan_result",
        lambda value, **kwargs: rendered.append((value, kwargs)),
    )
    summaries = []
    monkeypatch.setattr(cli, "_print_gradle_run_summary", summaries.append)
    before = run.model_dump_json()
    cli._print_gradle_run_result(run, workflow.project, tmp_path)
    assert len(rendered) == 1
    result, options = rendered[0]
    assert options == {"gradle": True}
    assert summaries == [run]
    assert reads == (["load"] if refreshed else [])
    if refreshed and published_exists:
        assert result is published
    else:
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].installed_version == "2"
        assert result.vulnerabilities[0].update_status is None
        scope = run.accepted_snapshot.findings[0].key.scope
        assert result.vulnerabilities[0].gradle_scopes == (
            f"{scope.project_path}/{scope.domain}/{scope.configuration}",
        )
    assert run.model_dump_json() == before


@pytest.mark.parametrize(
    "variant",
    [
        "local",
        "unknown-path",
        "wrong-coordinate",
        "undeclared",
        "external-mismatch",
        "local-finding",
    ],
)
def test_snapshot_checks_local_project_provenance(
    frozen_context, resolution, monkeypatch, variant
):
    project, context, _ = frozen_context
    payload = resolution.model_dump(mode="json")
    if variant != "undeclared":
        payload["report"]["local_projects"] = [
            {
                "project_path": ":app",
                "module": {
                    "group": "fixture",
                    "artifact": "app",
                    "version": "unspecified",
                },
            }
        ]
    resolution = CompleteResolution.model_validate(payload)
    purl = "pkg:maven/fixture/app@unspecified?project_path=%3Aapp"
    if variant == "unknown-path":
        purl = "pkg:maven/fixture/app@unspecified?project_path=%3Aother"
    elif variant == "wrong-coordinate":
        purl = "pkg:maven/other/app@unspecified?project_path=%3Aapp"
    components = [
        {"type": "library", "purl": purl},
        {"type": "library", "purl": "pkg:maven/g/lib@1"},
    ]
    if variant == "external-mismatch":
        components.append({"type": "library", "purl": "pkg:maven/g/lib@2"})

    @contextmanager
    def generate(_project):
        bom = project.path / "fixture-bom.json"
        bom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": components}))
        try:
            yield bom, resolution
        finally:
            bom.unlink()

    monkeypatch.setattr(scanner, "generate_gradle_report", generate)
    monkeypatch.setattr(scanner, "revision_tree_id", lambda *args: "checked-tree")
    rows = (
        [
            {
                "VulnerabilityID": "CVE-local",
                "PkgName": "fixture:app",
                "InstalledVersion": "unspecified",
                "Severity": "HIGH",
            }
        ]
        if variant == "local-finding"
        else []
    )
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command,
            0,
            json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": rows}]}),
            "",
        ),
    )
    if variant in {"unknown-path", "wrong-coordinate", "undeclared"}:
        with pytest.raises(scanner.GradleError, match="local project"):
            scanner.capture_gradle_snapshot(project, context)
    else:
        result = scanner.capture_gradle_snapshot(project, context)
        if variant == "local":
            assert isinstance(result, GradleSnapshot)
            assert result.inventory_modules == (
                ModuleId(group="g", artifact="lib", version="1"),
            )
        else:
            assert isinstance(result, IncompleteResolution)


def test_batch_output_retains_verified_gradle_progress(driver, capsys):
    from maintenance_man.models.config import MmConfig

    cfg = MmConfig(projects={"sample": driver.project})
    with pytest.raises(SystemExit) as exit_info:
        cli._update_batch_targets(cfg, target_names=["sample"])
    assert exit_info.value.code == 0
    run = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert run is not None and run.refreshed
    assert any(isinstance(attempt, CompletedAttempt) for attempt in run.attempts)
    output = capsys.readouterr().out
    assert "Verified: 1" in output
    assert "No projects had actionable findings" not in output


@pytest.fixture
def rebuild_evidence(workflow, monkeypatch):
    run = ready_workflow(workflow)
    ledger = updater.gradle_run_path("sample")
    before = ledger.read_bytes()
    cache = workflow.context.private_cache_path.with_name("rebuilt-context")
    shutil.copytree(workflow.context.private_cache_path, cache)
    context = workflow.context.model_copy(update={"private_cache_path": cache})
    monkeypatch.setattr(
        updater,
        "capture_gradle_snapshot",
        lambda project, ctx: workflow.state["snapshot"].model_copy(
            update={"context_identity": ctx.identity}
        ),
    )
    observations = SimpleNamespace(mutated=None, visits=[], released=[])

    @contextmanager
    def proof(project, revision):
        observations.visits.append(revision)
        observed = workflow.initial if revision == "base" else workflow.after
        if observations.mutated == revision:
            observed = observed.model_copy(update={"tree_id": "uncommitted-tree"})
        workflow.state.update(snapshot=observed, tree=observed.tree_id)
        yield project

    monkeypatch.setattr(updater, "_gradle_evidence_workspace", proof)
    monkeypatch.setattr(updater, "parse_catalogue", lambda *args: object())
    monkeypatch.setattr(
        updater, "collect_gradle_resolution", lambda *args: workflow.initial.resolution
    )
    monkeypatch.setattr(updater, "initialize_comparison_context", lambda *args: context)
    monkeypatch.setattr(
        updater, "release_comparison_context", observations.released.append
    )
    monkeypatch.setattr(
        updater,
        "revision_tree_id",
        lambda path, revision="@": {"base": "base-tree", "accepted": "after-tree"}.get(
            revision, workflow.state["tree"]
        ),
    )
    return SimpleNamespace(
        run=run,
        context=context,
        ledger=ledger,
        before=before,
        observations=observations,
        workflow=workflow,
    )


@pytest.mark.parametrize("revision", ["base", "accepted"])
def test_rebuilt_evidence_refuses_a_tree_changed_by_checks(rebuild_evidence, revision):
    state = rebuild_evidence
    state.observations.mutated = revision
    with pytest.raises(updater.GradleError, match="tree|baseline"):
        updater.rebuild_gradle_run_evidence(
            state.run, state.workflow.project, state.workflow.publication, 7
        )
    assert state.ledger.read_bytes() == state.before
    assert state.observations.released == [state.context]


def test_rebuilt_evidence_preserves_exact_revision_bindings(rebuild_evidence):
    state = rebuild_evidence
    rebuilt = updater.rebuild_gradle_run_evidence(
        state.run, state.workflow.project, state.workflow.publication, 7
    )
    assert state.observations.visits == ["base", "accepted"]
    assert rebuilt.initial_snapshot.tree_id == "base-tree"
    accepted = rebuilt.attempts[0]
    assert isinstance(accepted, ReadyAttempt)
    assert accepted.after.tree_id == accepted.receipt.checked_tree_id == "after-tree"
    assert accepted.receipt.accepted_commit_id == "accepted"
    assert updater.load_gradle_run(state.ledger) == rebuilt
    assert state.observations.released == [state.run.context]


def test_rebuilt_baseline_check_failure_releases_new_context(
    rebuild_evidence, monkeypatch
):
    state = rebuild_evidence

    def fail_checks(*args):
        raise updater.GradleError("baseline build failed")

    monkeypatch.setattr(updater, "run_gradle_checks", fail_checks)
    with pytest.raises(updater.GradleError, match="baseline build failed"):
        updater.rebuild_gradle_run_evidence(
            state.run, state.workflow.project, state.workflow.publication, 7
        )
    assert state.ledger.read_bytes() == state.before
    assert state.observations.released == [state.context]


@pytest.mark.parametrize("stage", ["checks", "snapshot"])
def test_acceptance_rejects_source_changes_during_verification(
    workflow, monkeypatch, stage
):
    run = begin_workflow(workflow)
    if stage == "checks":
        original = updater.run_gradle_checks

        def mutate(*args):
            workflow.state["tree"] = "unverified-tree"
            workflow.state["snapshot"] = workflow.after.model_copy(
                update={"tree_id": "unverified-tree"}
            )
            return original(*args)

        monkeypatch.setattr(updater, "run_gradle_checks", mutate)
    else:

        def mutate(*args):
            workflow.state["tree"] = "unverified-tree"
            return workflow.after.model_copy(update={"tree_id": "unverified-tree"})

        monkeypatch.setattr(updater, "capture_gradle_snapshot", mutate)
    result = updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    assert isinstance(result.attempts[0], FailedAttempt)
    assert "tree" in result.attempts[0].reason.lower()
    assert workflow.effects == ["apply", "discard"]
    assert result.accepted_snapshot == workflow.initial


def test_acceptance_requires_the_applied_catalogue_version(workflow, monkeypatch):
    run = begin_workflow(workflow)
    catalogue = workflow.project.path / "gradle/libs.versions.toml"
    catalogue.parent.mkdir(exist_ok=True)
    original = updater.apply_gradle_update

    def undo_target(*args):
        original(*args)
        catalogue.write_text(catalogue.read_text().replace('lib = "2"', 'lib = "1"'))

    monkeypatch.setattr(updater, "apply_gradle_update", undo_target)
    # Simulate an apply hook that returns successfully but restores the old version.
    result = updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    assert isinstance(result.attempts[0], FailedAttempt)
    assert workflow.effects == ["apply", "discard"]


def test_snapshot_refuses_inventory_missing_a_resolved_module(
    frozen_context, resolution, monkeypatch
):
    project, context, _ = frozen_context
    benign = ModuleId(group="g", artifact="benign", version="1")
    scope = resolution.report.scopes[0]
    scope = scope.model_copy(
        update={
            "components": (
                *scope.components,
                ResolvedComponent(
                    id="benign", kind="module", module=benign, variants=()
                ),
            )
        }
    )
    resolution = resolution.model_copy(
        update={"report": resolution.report.model_copy(update={"scopes": (scope,)})}
    )

    @contextmanager
    def generate(_project):
        bom = project.path / "fixture-bom.json"
        bom.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [{"type": "library", "purl": "pkg:maven/g/benign@1"}],
                }
            )
        )
        try:
            yield bom, resolution
        finally:
            bom.unlink()

    monkeypatch.setattr(scanner, "generate_gradle_report", generate)
    monkeypatch.setattr(scanner, "revision_tree_id", lambda *args: "tree")
    scans = []

    def scan(command, **kwargs):
        scans.append(command)
        return subprocess.CompletedProcess(command, 0, '{"Results": []}', "")

    monkeypatch.setattr(scanner.subprocess, "run", scan)
    result = scanner.capture_gradle_snapshot(project, context)
    assert isinstance(result, IncompleteResolution)
    assert any("inventory" in reason and "lib" in reason for reason in result.reasons)
    assert scans == []


def test_completed_run_releases_private_databases(driver):
    cache = driver.workflow.context.private_cache_path
    assert cache.is_dir()
    assert invoke_driver(driver) == 0
    saved = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert saved is not None and saved.refreshed
    assert not cache.exists()


@pytest.mark.parametrize("persist", [False, True])
def test_rebuild_retires_only_superseded_durable_context(
    rebuild_evidence, monkeypatch, tmp_path, persist
):
    state = rebuild_evidence
    old = state.run.context
    new_path = tmp_path / "replacement-cache"
    shutil.copytree(old.private_cache_path, new_path)
    new = old.model_copy(update={"private_cache_path": new_path})
    monkeypatch.setattr(updater, "initialize_comparison_context", lambda *args: new)
    monkeypatch.setattr(
        updater, "release_comparison_context", verification.release_comparison_context
    )
    monkeypatch.setattr(
        updater,
        "capture_gradle_snapshot",
        lambda *args: state.workflow.state["snapshot"].model_copy(
            update={"context_identity": new.identity}
        ),
    )
    rebuilt = updater.rebuild_gradle_run_evidence(
        state.run,
        state.workflow.project,
        state.workflow.publication,
        7,
        persist=persist,
    )
    assert rebuilt.context == new
    assert new_path.is_dir()
    assert old.private_cache_path.exists() is (not persist)
    durable = updater.load_gradle_run(state.ledger)
    assert durable is not None
    assert durable.context == (new if persist else old)


def test_failed_rebuild_preserves_durable_context(
    rebuild_evidence, monkeypatch, tmp_path
):
    state = rebuild_evidence
    old = state.run.context
    new_path = tmp_path / "replacement-cache"
    shutil.copytree(old.private_cache_path, new_path)
    new = old.model_copy(update={"private_cache_path": new_path})
    monkeypatch.setattr(updater, "initialize_comparison_context", lambda *args: new)
    monkeypatch.setattr(
        updater, "release_comparison_context", verification.release_comparison_context
    )
    monkeypatch.setattr(
        updater,
        "capture_gradle_snapshot",
        lambda *args: state.workflow.state["snapshot"].model_copy(
            update={"context_identity": new.identity}
        ),
    )

    def fail_save(*args):
        raise updater.GradleError("ledger write failed")

    monkeypatch.setattr(updater, "save_gradle_run", fail_save)
    with pytest.raises(updater.GradleError, match="ledger write failed"):
        updater.rebuild_gradle_run_evidence(
            state.run, state.workflow.project, state.workflow.publication, 7
        )
    assert old.private_cache_path.is_dir()
    assert not new_path.exists()
    assert state.ledger.read_bytes() == state.before


def test_failed_save_after_replace_keeps_new_context(rebuild_evidence, monkeypatch):
    state = rebuild_evidence
    original = updater.save_gradle_run

    def replace_then_fail(path, run):
        original(path, run)
        raise updater.GradleError("directory fsync failed after replace")

    monkeypatch.setattr(updater, "save_gradle_run", replace_then_fail)
    with pytest.raises(updater.GradleError, match="fsync"):
        updater.rebuild_gradle_run_evidence(
            state.run, state.workflow.project, state.workflow.publication, 7
        )
    durable = updater.load_gradle_run(state.ledger)
    assert durable is not None and durable.context == state.context
    assert state.context.private_cache_path.is_dir()
    assert state.observations.released == []


def test_cleanup_retry_is_idempotent_and_keeps_foreign_cache(frozen_context):
    project, context, _ = frozen_context
    cache = context.private_cache_path
    verification.release_comparison_context(context)
    verification.release_comparison_context(context)
    cache.mkdir()
    (cache / ".mm-comparison-owner").write_text("someone-else")
    with pytest.raises(verification.GradleError, match="ownership"):
        verification.release_comparison_context(context)
    assert cache.is_dir()
