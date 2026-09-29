import hashlib
import json
import os
import shutil
import stat
import subprocess
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from maintenance_man import cli, paths, scanner
from maintenance_man import gradle_resolution as candidates
from maintenance_man import gradle_updates as updater
from maintenance_man import gradle_verification as verification
from maintenance_man import gradle_workflow as workflow_service
from maintenance_man.cli import (
    _gradle_workspace_revision as real_gradle_workspace_revision,
)
from maintenance_man.github import CodeHostError
from maintenance_man.gradle_updates import run_gradle_checks as real_run_gradle_checks
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
    GradleRun,
    GradleSnapshot,
    IncompleteResolution,
    ModuleId,
    PlannedAttempt,
    PublicationEvidence,
    PublicationFact,
    ReadyAttempt,
    ResolutionReport,
    ResolvedComponent,
    ScopeId,
    ScopeResolution,
    VerifiedComparison,
)
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    SemverTier,
    Severity,
    VulnFinding,
    Workflow,
)
from maintenance_man.process import ToolNotFoundError
from maintenance_man.vcs import RevisionError
from tests.fake_vcs import FakeJjState


def _workflow_vcs(path: Path, *, files: dict[str, str] | None = None):
    state = FakeJjState()
    state.seed_repository(path, files=files or {})
    return state.services()


def test_saved_ledger_is_private(workflow, tmp_path):
    run = begin_workflow(workflow)
    path = tmp_path / "ledger" / "run.json"
    previous = os.umask(0o022)
    try:
        updater.save_gradle_run(path, run)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


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
    monkeypatch.setattr(verification, "require_tool", lambda name, hint: binary)
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


def test_comparison_setup_requires_trivy_and_leaves_no_cache(
    tmp_path, monkeypatch, resolution
):
    for name in tuple(verification.os.environ):
        if name.startswith("TRIVY_"):
            monkeypatch.delenv(name)
    project = ProjectConfig(path=tmp_path / "project", package_manager="gradle")
    (tmp_path / "project").mkdir()
    parent = tmp_path / "cache"

    def missing(name, hint):
        raise ToolNotFoundError(f"{name} is not installed or not on PATH. {hint}")

    monkeypatch.setattr(verification, "require_tool", missing)
    with pytest.raises(ToolNotFoundError, match="trivy"):
        verification.initialize_comparison_context(project, resolution, parent)
    assert list(parent.iterdir()) == []


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
    _, context, _ = frozen_context
    (context.private_cache_path / ".mm-comparison-owner").write_text("caller")
    with pytest.raises(verification.GradleError, match="ownership"):
        verification.release_comparison_context(context)
    assert context.private_cache_path.exists()


@pytest.mark.parametrize("match,expected", [(True, "snapshot"), (False, "incomplete")])
def test_capture_reads_before_cleanup_and_never_discovers(
    frozen_context, resolution, monkeypatch, match, expected
):
    project, context, _ = frozen_context
    source_path = project.path
    update_path = source_path.parent / "update-workspace"
    shutil.copytree(source_path, update_path)
    state = FakeJjState()
    source_repo = state.seed_repository(source_path, files={"dep.txt": "version=1\n"})
    source_tree = source_repo.tree_id()
    source_repo.add_workspace(name="update", path=update_path, revision="main")
    state.seed_working_copy(
        update_path,
        parent=source_repo.resolve_revision(revision="main"),
        files={"dep.txt": "version=2\n"},
    )
    update_repo = state.repository(update_path)
    expected_tree = update_repo.tree_id()
    assert expected_tree != source_tree
    project = project.model_copy(update={"path": update_path})
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

    def tree() -> None:
        assert not bom.exists()

    state.hook("tree_id", phase="before", action=tree, path=project.path)
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

    monkeypatch.setattr("maintenance_man.process.subprocess.run", trivy)
    result = scanner.capture_gradle_snapshot(project, context, vcs=state.services())
    if expected == "incomplete":
        assert isinstance(result, IncompleteResolution)
        assert result.kind == "incomplete"
        assert not scan_calls
    else:
        assert isinstance(result, GradleSnapshot)
        assert result.tree_id == expected_tree
        assert len(result.findings) == 1
        assert result.findings[0].key.scope == resolution.report.selected_scopes[0]
        assert result.findings[0].rows[0].update_status is None
    assert not bom.exists()


def test_capture_unreadable_bom_is_gradle_error(
    frozen_context, resolution, monkeypatch
):
    project, context, _ = frozen_context

    @contextmanager
    def report(_project):
        yield project.path / "missing-bom.json", resolution

    monkeypatch.setattr(scanner, "generate_gradle_report", report)
    with pytest.raises(
        scanner.GradleError, match="Could not capture Gradle resolution"
    ):
        scanner.capture_gradle_snapshot(project, context)


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
    monkeypatch.setattr(paths, "MM_HOME", tmp_path / "mm")
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
    catalogue_name = "gradle/libs.versions.toml"
    original_catalogue = catalogue.read_text(encoding="utf-8")
    updated_catalogue = original_catalogue.replace('lib = "1"', 'lib = "2"')
    vcs_state = FakeJjState()
    repo = vcs_state.seed_repository(
        project.path, files={catalogue_name: original_catalogue}
    )
    base = repo.resolve_revision(revision="main")
    monkeypatch.setattr(updater, "make_vcs_services", vcs_state.services)
    monkeypatch.setattr(workflow_service, "make_vcs_services", vcs_state.services)
    accepted = vcs_state.seed_commit(
        project.path,
        parent=base,
        files={catalogue_name: updated_catalogue},
        description="accepted fixture",
    )
    initial = snapshot(
        resolution,
        [evidence(scope)],
        context.identity,
        repo.tree_id(revision=base),
    )
    after = snapshot(
        resolution,
        [evidence(scope, version="2")],
        context.identity,
        repo.tree_id(revision=accepted),
    )
    state = {"snapshot": initial, "tree": initial.tree_id}
    monkeypatch.setattr(updater, "run_gradle_checks", lambda *args: checks)
    monkeypatch.setattr(
        updater,
        "capture_gradle_snapshot",
        lambda *args, **kwargs: state["snapshot"],
    )
    monkeypatch.setattr(updater, "validate_gradle_target", lambda *args: None)
    monkeypatch.setattr(updater, "evaluate_gradle_candidate_age", lambda *args: None)

    def apply(applied_project, *_args):
        stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
        assert stored is not None
        assert stored is not None
        assert stored.attempts[0].state == "applying"
        effects.append("apply")
        applied_catalogue = applied_project.path / "gradle/libs.versions.toml"
        applied_catalogue.write_text(
            applied_catalogue.read_text(encoding="utf-8").replace(
                'lib = "1"', 'lib = "2"'
            ),
            encoding="utf-8",
        )
        observed_after = state.get("after", after)
        state.update(snapshot=observed_after, tree=observed_after.tree_id)
        return

    monkeypatch.setattr(updater, "apply_gradle_update", apply)
    vcs_state.hook(
        "commit",
        phase="before",
        action=lambda: effects.append("commit"),
    )
    for method in ("create_bookmark", "set_bookmark"):
        vcs_state.hook(
            method,
            phase="before",
            action=lambda: effects.append("bookmark"),
        )

    def discard():
        effects.append("discard")
        state.update(snapshot=initial, tree=initial.tree_id)

    vcs_state.hook("discard", phase="before", action=discard)
    return SimpleNamespace(
        project=project,
        context=context,
        initial=initial,
        after=after,
        candidate=candidate,
        publication=publication,
        state=state,
        effects=effects,
        vcs_state=vcs_state,
        vcs=vcs_state.services(),
        base=base,
    )


def begin_workflow(workflow, flow=Workflow.UPDATE, candidate=None):
    return updater.start_gradle_run(
        "sample",
        workflow.project,
        flow,
        workflow.base,
        workflow.context,
        (candidate or workflow.candidate,),
        vcs=workflow.vcs,
    )


def _revision_failure(*args, **kwargs):
    raise RevisionError("jj unavailable")


@pytest.mark.parametrize("stage", ["before-checked", "after-checked"])
def test_gradle_revision_failure_is_recorded_or_preserved(workflow, monkeypatch, stage):
    run = begin_workflow(workflow, Workflow.RESOLVE)
    workflow.vcs_state.clear_calls()
    if stage == "before-checked":
        workflow.vcs_state.fail(
            "tree_id",
            error=RevisionError("jj unavailable"),
            path=workflow.project.path,
        )
        result = updater.process_gradle_run(
            run, workflow.project, workflow.publication, 7
        )
        assert isinstance(result.attempts[0], FailedAttempt)
        assert result.attempts[0].reason == "jj unavailable"
        stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
        assert stored == result
    else:
        workflow.vcs_state.fail(
            "commit",
            error=RevisionError("jj unavailable"),
            path=workflow.project.path,
        )
        with pytest.raises(RevisionError, match="jj unavailable"):
            updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
        stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
        assert stored is not None
        assert isinstance(stored.attempts[0], ApplyingAttempt)
        assert stored.attempts[0].checked_tree_id is not None
        assert "discard" not in workflow.effects


def test_gradle_dirty_query_failure_preserves_checked_intent(workflow):
    run = begin_workflow(workflow, Workflow.RESOLVE)
    workflow.vcs_state.clear_calls()
    failure = RevisionError("dirty state unavailable")
    workflow.vcs_state.fail("has_changes", error=failure, path=workflow.project.path)

    with pytest.raises(updater.GradleError, match="inspect tracked changes") as caught:
        updater.process_gradle_run(
            run,
            workflow.project,
            workflow.publication,
            7,
            vcs=workflow.vcs,
        )

    assert caught.value.__cause__ is failure
    stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert stored is not None
    assert isinstance(stored.attempts[0], ApplyingAttempt)
    assert stored.attempts[0].checked_tree_id == workflow.after.tree_id
    assert not {"commit", "discard"} & {
        call.method for call in workflow.vcs_state.effects
    }


def test_gradle_continue_dirty_query_failure_preserves_failed_ledger(
    workflow, monkeypatch
):
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
        vcs=workflow.vcs,
    )
    workflow.vcs_state.seed_bookmark(
        workflow.project.path,
        bookmark=failed.managed_bookmark,
        targets=(failed.managed_tip_id,),
    )
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)
    repo = workflow.vcs.repository(workflow.project.path)
    repo.commit(message="manual repair")
    before = updater.gradle_run_path("sample").read_bytes()
    workflow.vcs_state.clear_calls()
    failure = RevisionError("dirty state unavailable")
    workflow.vcs_state.fail("has_changes", error=failure, path=workflow.project.path)

    with pytest.raises(updater.GradleError, match="inspect manual changes") as caught:
        updater.continue_gradle_resolve(
            failed,
            workflow.project,
            workflow.publication,
            7,
            vcs=workflow.vcs,
        )

    assert caught.value.__cause__ is failure
    assert updater.gradle_run_path("sample").read_bytes() == before
    assert not {"commit", "discard"} & {
        call.method for call in workflow.vcs_state.effects
    }


def test_gradle_continue_revision_failure_is_recorded(workflow, monkeypatch):
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
    workflow.vcs_state.seed_bookmark(
        workflow.project.path,
        bookmark=failed.managed_bookmark,
        targets=(failed.managed_tip_id,),
    )
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)
    repo = workflow.vcs.repository(workflow.project.path)
    repo.commit(message="manual repair")
    workflow.vcs_state.clear_calls()
    workflow.vcs_state.fail(
        "tree_id",
        error=RevisionError("jj unavailable"),
        path=workflow.project.path,
    )
    with pytest.raises(RevisionError, match="jj unavailable"):
        updater.continue_gradle_resolve(
            failed, workflow.project, workflow.publication, 7
        )
    stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert stored is not None
    assert isinstance(stored.attempts[0], FailedAttempt)
    assert stored.attempts[0].reason == "jj unavailable"


def test_gradle_continue_revision_failure_after_checked_intent_is_preserved(
    workflow, monkeypatch
):
    run = begin_workflow(workflow, Workflow.RESOLVE)
    run = updater._replace_gradle_attempt(
        run, ApplyingAttempt(candidate=workflow.candidate, baseline=workflow.initial)
    )
    updater.save_gradle_run(updater.gradle_run_path("sample"), run)
    catalogue = workflow.project.path / "gradle/libs.versions.toml"
    catalogue.write_text(
        catalogue.read_text(encoding="utf-8").replace('lib = "1"', 'lib = "2"'),
        encoding="utf-8",
    )
    repo = workflow.vcs.repository(workflow.project.path)
    repo.commit(message="manual repair")
    workflow.effects.clear()
    workflow.state.update(snapshot=workflow.after, tree=workflow.after.tree_id)
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)
    monkeypatch.setattr(updater, "validate_gradle_recovery", lambda *args: None)
    monkeypatch.setattr(updater, "context_inputs_valid", lambda *args: True)
    failed = updater.reconcile_gradle_applying(
        run, workflow.project, workflow.publication, 7
    )
    workflow.vcs_state.clear_calls()
    workflow.vcs_state.fail(
        "resolve_revision",
        ordinal=10,
        error=RevisionError("jj unavailable"),
        path=workflow.project.path,
    )
    assert isinstance(failed.attempts[0], FailedAttempt)

    saves = []
    original_save = updater.save_gradle_run

    def record(path, value):
        saves.append(value)
        original_save(path, value)

    monkeypatch.setattr(updater, "save_gradle_run", record)
    with pytest.raises(RevisionError, match="jj unavailable"):
        updater.continue_gradle_resolve(
            failed, workflow.project, workflow.publication, 7
        )

    stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert stored is not None
    assert stored == saves[-1]
    attempt = stored.attempts[0]
    assert isinstance(attempt, ApplyingAttempt)
    assert attempt.checked_tree_id == workflow.after.tree_id
    assert attempt.accepted_commit_id is None
    assert not {"apply", "commit", "discard", "bookmark"} & set(workflow.effects)


@pytest.mark.parametrize(
    "error",
    [
        RevisionError("jj unavailable"),
        CodeHostError("host unavailable"),
        ToolNotFoundError("trivy is not installed or not on PATH. hint"),
    ],
)
def test_gradle_flow_reports_revision_failures(workflow, monkeypatch, capsys, error):
    monkeypatch.setattr(
        workflow_service.gradle_updater,
        "load_gradle_run",
        MagicMock(side_effect=error),
    )
    assert (
        cli._run_gradle_flow(
            "sample",
            workflow.project,
            Workflow.UPDATE,
            interactive=False,
            minimum_age_days=7,
            vcs=_workflow_vcs(workflow.project.path),
        )
        == cli.ExitCode.UPDATE_FAILED
    )
    assert f"Cannot complete Gradle update: {error}" in capsys.readouterr().out


def test_gradle_run_has_reports_attempt_kinds(workflow):
    run = begin_workflow(workflow)
    assert run.has(PlannedAttempt)
    assert not run.has(FailedAttempt)
    assert run.has(ApplyingAttempt, PlannedAttempt)


def test_gradle_run_rejects_bookmark_of_other_flow(workflow):
    run = begin_workflow(workflow)
    data = run.model_dump(mode="json")
    data["managed_bookmark"] = {
        "update": "mm/resolve-dependencies",
        "resolve": "mm/update-dependencies",
    }[run.flow]
    with pytest.raises(ValidationError, match="run bookmark and flow disagree"):
        GradleRun.model_validate(data)


def test_blank_only_test_command_is_a_setup_prerequisite(workflow):
    project = workflow.project.model_copy(
        update={"test_unit": "  ", "test_integration": None, "test_component": None}
    )
    with pytest.raises(updater.GradleError, match="Setup prerequisite"):
        updater.gradle_check_commands(project)


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
        workflow.initial.tree_id if flow == Workflow.UPDATE else workflow.after.tree_id
    )
    with pytest.raises(updater.GradleError, match="failed"):
        updater.gradle_run_finalization_check(
            result, workflow.project, workflow.publication, 7
        )
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) == result


def test_start_persists_baseline_before_any_apply(workflow):
    run = begin_workflow(workflow)
    assert not {"apply", "commit"} & set(workflow.effects)
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
        lambda *args, **kwargs: pytest.fail("capture after failed checks"),
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
def test_missing_routing_declaration_allows_checked_update(workflow, minimum_age_days):
    run = begin_workflow(workflow)
    project = workflow.project.model_copy(update={"gradle_repository_routing": None})
    result = updater.process_gradle_run(
        run, project, workflow.publication, minimum_age_days
    )
    assert isinstance(result.attempts[0], ReadyAttempt)
    updater.gradle_run_finalization_check(
        result, project, workflow.publication, minimum_age_days
    )


def test_gradle_no_updates_does_not_require_build_hooks(workflow, monkeypatch):
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
    monkeypatch.setattr(workflow_service, "load_scan_results", lambda *args: empty)
    monkeypatch.setattr(workflow_service, "discover_gradle_updates", lambda *args: [])
    monkeypatch.setattr(
        workflow_service,
        "_run_gradle_scan",
        lambda *args: ([], workflow.initial.resolution),
    )
    monkeypatch.setattr(
        updater,
        "gradle_check_commands",
        lambda *args: pytest.fail("No update needs acceptance hooks"),
    )
    assert (
        cli._run_gradle_flow(
            "sample",
            project,
            Workflow.UPDATE,
            interactive=False,
            minimum_age_days=7,
            vcs=workflow.vcs,
        )
        == cli.ExitCode.OK
    )
    assert not {"apply", "commit"} & set(workflow.effects)
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) is None


@pytest.fixture
def driver(workflow, resolution, monkeypatch):
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
    repo = workflow.vcs.repository(project.path)
    repo.commit(message="driver baseline")
    base = repo.resolve_revision(revision="@-")
    repo.set_bookmark(bookmark="main", revision=base)
    workflow.base = base
    workflow.initial = workflow.initial.model_copy(
        update={"tree_id": repo.tree_id(revision=base)}
    )
    driver_after = workflow.vcs_state.seed_commit(
        project.path,
        parent=base,
        files={
            "gradle/libs.versions.toml": (
                '[versions]\nlib = "2"\nother = "1"\n[libraries]\n'
                'lib = { module = "g:lib", version.ref = "lib" }\n'
                'other = { module = "g:other", version.ref = "other" }\n'
            )
        },
        description="driver accepted fixture",
    )
    workflow.after = workflow.after.model_copy(
        update={"tree_id": repo.tree_id(revision=driver_after)}
    )
    workflow.state.update(
        snapshot=workflow.initial,
        tree=workflow.initial.tree_id,
        after=workflow.after,
    )
    workflow.vcs_state.clear_calls()
    workflow.effects.clear()
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
        refs={"main": base, "@-": base, "mm/update-dependencies": base},
        effects=workflow.effects,
        workflow=workflow,
    )
    monkeypatch.setattr(
        workflow_service,
        "load_scan_results",
        lambda *args: ScanResult(
            project="sample",
            scanned_at=workflow.context.created_at,
            trivy_target=str(project.path),
            vulnerabilities=list(workflow.initial.findings[0].rows),
        ),
    )
    monkeypatch.setattr(
        workflow_service,
        "_run_gradle_scan",
        lambda *args: (list(workflow.initial.findings[0].rows), resolution),
    )
    monkeypatch.setattr(
        workflow_service,
        "initialize_comparison_context",
        lambda *args: workflow.context,
    )
    monkeypatch.setattr(
        workflow_service,
        "discover_gradle_updates",
        lambda *args: (
            state.proposals
            if workflow.state["tree"] == workflow.initial.tree_id
            else []
        ),
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

    monkeypatch.setattr(candidates, "validate_gradle_candidates", native)
    monkeypatch.setattr(candidates, "evaluate_gradle_candidate_age", lambda *args: None)

    @contextmanager
    def publication(*args):
        yield SimpleNamespace(
            prefetch=lambda requests: tuple(requests),
            evidence_for=workflow.publication.evidence_for,
        )

    monkeypatch.setattr(workflow_service, "PublicationLookupContext", publication)

    workflow.vcs_state.hook(
        "promote_bookmark_to_main",
        phase="before",
        path=project.path,
        action=lambda: state.effects.append("promote"),
    )
    workflow.vcs_state.hook(
        "rebase_working_copy",
        phase="before",
        path=project.path,
        action=lambda: state.effects.append("refresh"),
    )
    monkeypatch.setattr(cli.console, "input", lambda *args: state.selection)
    return state


def invoke_driver(driver, *, interactive=False, minimum_age_days=7, vcs=None):
    from maintenance_man import cli

    return cli._run_gradle_flow(
        "sample",
        driver.project,
        Workflow.UPDATE,
        interactive=interactive,
        minimum_age_days=minimum_age_days,
        vcs=vcs or driver.workflow.vcs,
    )


def test_gradle_driver_promotes_verified_update_with_residual_advisory(driver):
    from maintenance_man.models.scan import ScanResult

    assert invoke_driver(driver) == 0
    run = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert run is not None
    assert run.refreshed and run.promoted_commit_id == run.managed_tip_id
    assert run.attempts[0].state == "completed"
    assert driver.effects[-5:] == [
        "apply",
        "commit",
        "bookmark",
        "promote",
        "refresh",
    ]
    fresh = ScanResult.model_validate_json(
        (paths.scan_results_dir() / "sample.json").read_bytes()
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
        assert driver.effects in ([], ["bookmark"])
        assert updater.load_gradle_run(updater.gradle_run_path("sample")) is None


@pytest.mark.parametrize("minimum_age_days", [0, 60])
def test_gradle_driver_uses_current_age_policy_before_apply(
    driver, monkeypatch, minimum_age_days
):
    from maintenance_man.models.gradle import AgeBlock

    def age(candidate, minimum, *args):
        assert minimum == minimum_age_days
        return AgeBlock(reason="exact publication withheld")

    monkeypatch.setattr(candidates, "evaluate_gradle_candidate_age", age)
    assert invoke_driver(driver, minimum_age_days=minimum_age_days) == 4
    assert driver.effects in ([], ["bookmark"])
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) is None


def test_gradle_driver_withheld_group_does_not_prevent_verified_promotion(
    driver, monkeypatch
):
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
        candidates,
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
    assert driver.effects[-5:] == [
        "apply",
        "commit",
        "bookmark",
        "promote",
        "refresh",
    ]


def test_gradle_driver_refuses_sdk_before_sync_or_workspace_effects(
    driver, monkeypatch
):
    from maintenance_man import cli

    monkeypatch.setattr(
        cli, "_gradle_workspace_revision", real_gradle_workspace_revision
    )
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (driver.project.path / "local.properties").write_text("sdk.dir=/unavailable\n")
    monkeypatch.setattr(
        workflow_service,
        "prune_stale_bookmarks",
        lambda *args: driver.effects.append("sync") or True,
    )
    monkeypatch.setattr(
        workflow_service,
        "remove_workspace",
        lambda *args: driver.effects.append("remove"),
    )
    assert invoke_driver(driver) == 4
    assert driver.effects in ([], ["bookmark"])


@pytest.mark.parametrize("post_sync_tracked", [False, True])
def test_gradle_driver_rechecks_sdk_at_pinned_base_before_workspace_effects(
    driver,
    monkeypatch,
    post_sync_tracked,
):
    from maintenance_man import cli

    monkeypatch.setattr(
        cli, "_gradle_workspace_revision", real_gradle_workspace_revision
    )
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    (driver.project.path / "local.properties").write_text("sdk.dir=/android\n")
    catalogue_text = (driver.project.path / "gradle/libs.versions.toml").read_text(
        encoding="utf-8"
    )
    vcs_state = FakeJjState()
    repo = vcs_state.seed_repository(
        driver.project.path,
        files={
            "gradle/libs.versions.toml": catalogue_text,
            "local.properties": "sdk.dir=/android\n",
        },
    )
    original_main = repo.resolve_revision(revision="main")
    post_sync_files = {"gradle/libs.versions.toml": catalogue_text}
    if post_sync_tracked:
        post_sync_files["local.properties"] = "sdk.dir=/android\n"
    post_sync_main = vcs_state.seed_commit(
        driver.project.path,
        parent=original_main,
        files=post_sync_files,
        description="synced main",
    )

    vcs_state.hook(
        "fetch",
        phase="before",
        path=driver.project.path,
        action=lambda: vcs_state.seed_remote(
            driver.project.path, bookmark="main", targets=(post_sync_main,)
        ),
    )
    driver.workflow.initial = driver.workflow.initial.model_copy(
        update={"tree_id": repo.tree_id(revision=post_sync_main)}
    )
    accepted = vcs_state.seed_commit(
        driver.project.path,
        parent=post_sync_main,
        files={
            name: (
                content.replace('lib = "1"', 'lib = "2"')
                if name == "gradle/libs.versions.toml"
                else content
            )
            for name, content in post_sync_files.items()
        },
        description="accepted",
    )
    driver.workflow.after = driver.workflow.after.model_copy(
        update={"tree_id": repo.tree_id(revision=accepted)}
    )
    driver.workflow.state.update(
        snapshot=driver.workflow.initial,
        tree=driver.workflow.initial.tree_id,
        after=driver.workflow.after,
    )
    assert invoke_driver(driver, vcs=vcs_state.services()) == (
        0 if post_sync_tracked else 4
    )
    inspections = [
        dict(call.arguments)
        for call in vcs_state.attempts
        if call.method == "revision_file"
    ]
    assert inspections == [
        {"revision": "main", "filename": "local.properties"},
        {"revision": post_sync_main, "filename": "local.properties"},
    ]
    if post_sync_tracked:
        assert any(
            call.method == "add_workspace"
            and dict(call.arguments)["revision"] == post_sync_main
            for call in vcs_state.effects
        )
    else:
        assert not any(call.method == "add_workspace" for call in vcs_state.effects)
        assert driver.effects == []


@pytest.mark.parametrize("sdk_env,properties", [(True, True), (False, False)])
def test_gradle_driver_skips_unneeded_sdk_revision_inspection(
    driver, monkeypatch, sdk_env, properties
):
    from maintenance_man import cli

    monkeypatch.setattr(
        cli, "_gradle_workspace_revision", real_gradle_workspace_revision
    )
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
    if sdk_env:
        monkeypatch.setenv("ANDROID_HOME", "/android")
    if properties:
        (driver.project.path / "local.properties").write_text("sdk.dir=/android\n")
    else:
        (driver.project.path / "local.properties").unlink(missing_ok=True)
    vcs_state = FakeJjState()
    repo = vcs_state.seed_repository(driver.project.path, files={})
    vcs_state.fail(
        "revision_file",
        error=RevisionError("SDK inspection unnecessary"),
        path=driver.project.path,
    )
    revision = repo.resolve_revision(revision="main")
    assert (
        real_gradle_workspace_revision(
            "sample", driver.project, revision, vcs=vcs_state.services()
        )
        == revision
    )
    assert not any(call.method == "revision_file" for call in vcs_state.attempts)


@pytest.mark.parametrize("failure", ["promotion", "refresh"])
def test_gradle_driver_retains_verified_ledger_when_final_effect_fails(
    driver, monkeypatch, failure
):
    driver.workflow.vcs_state.fail(
        "promote_bookmark_to_main" if failure == "promotion" else "rebase_working_copy",
        error=RevisionError(f"{failure} failed"),
        path=driver.project.path,
    )
    assert invoke_driver(driver) == 4
    run = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert run is not None
    assert run.attempts[0].state == "ready"
    assert run.promoted_commit_id == (
        None if failure == "promotion" else run.managed_tip_id
    )
    assert not run.refreshed
    assert driver.effects.count("apply") == 1
    assert driver.effects.count("commit") == 1
    assert not (paths.scan_results_dir() / "sample.json").exists()


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
    monkeypatch.setattr(updater, "run_gradle_checks", real_run_gradle_checks)
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
        lambda *args, **kwargs: pytest.fail("capture after failed baseline"),
    )
    with pytest.raises(updater.GradleError, match="failed"):
        begin_workflow(workflow)
    assert effects == (["build"] if failure == "build" else ["build", "tests"])
    assert workflow.effects == []
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) is None


def test_gradle_checks_run_configured_tests_through_bash(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "run_build", lambda *args: None)
    project = ProjectConfig(
        path=tmp_path,
        package_manager="gradle",
        build_command="./gradlew assembleDebug",
        test_unit="printf ok > tests-ran && test -f tests-ran",
    )
    evidence = real_run_gradle_checks(project, "sample")
    assert evidence.success is True
    assert (tmp_path / "tests-ran").read_text() == "ok"


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
        checked_tree_id=workflow.after.tree_id if checked else None,
    )
    run = updater._replace_gradle_attempt(run, state)
    updater.save_gradle_run(updater.gradle_run_path("sample"), run)
    dirty = stage != "intent"
    repo = workflow.vcs.repository(workflow.project.path)
    workflow.vcs_state.seed_bookmark(
        workflow.project.path,
        bookmark=run.managed_bookmark,
        targets=(workflow.base,),
    )
    if dirty:
        catalogue = workflow.project.path / "gradle/libs.versions.toml"
        catalogue.write_text(
            catalogue.read_text(encoding="utf-8").replace('lib = "1"', 'lib = "2"'),
            encoding="utf-8",
        )
    workflow.state["tree"] = (
        workflow.after.tree_id if dirty else workflow.initial.tree_id
    )
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)

    def assert_saved_before_discard():
        stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
        assert stored is not None
        assert isinstance(stored.attempts[0], FailedAttempt)

    workflow.vcs_state.hook(
        "discard",
        phase="before",
        path=repo.path,
        action=assert_saved_before_discard,
    )
    result = updater.reconcile_gradle_applying(
        run, workflow.project, workflow.publication, 7
    )
    assert isinstance(result.attempts[0], FailedAttempt)
    assert result.attempts[0].after == (workflow.after if checked else None)
    assert result.managed_tip_id == workflow.base
    assert workflow.effects == (
        ["discard"] if flow == Workflow.UPDATE and dirty else []
    )
    assert workflow.state["tree"] == (
        workflow.after.tree_id
        if flow == Workflow.RESOLVE and dirty
        else workflow.initial.tree_id
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
    repo = workflow.vcs.repository(workflow.project.path)
    catalogue = workflow.project.path / "gradle/libs.versions.toml"
    catalogue.write_text(
        catalogue.read_text(encoding="utf-8").replace('lib = "1"', 'lib = "2"'),
        encoding="utf-8",
    )
    workflow.state["tree"] = workflow.after.tree_id
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)
    other = workflow.vcs_state.seed_commit(
        workflow.project.path,
        parent=workflow.base,
        files={"gradle/libs.versions.toml": catalogue.read_text(encoding="utf-8")},
        description="unrelated",
    )
    workflow.vcs_state.seed_bookmark(
        workflow.project.path,
        bookmark=run.managed_bookmark,
        targets=(other if unsafe == "bookmark" else workflow.base,),
    )
    if unsafe == "parent":
        workflow.vcs_state.seed_working_copy(
            workflow.project.path,
            parent=other,
            files={"gradle/libs.versions.toml": catalogue.read_text(encoding="utf-8")},
        )
    if unsafe == "other-file":
        workflow.vcs_state.register_files(workflow.project.path, "unowned.txt")
        (workflow.project.path / "unowned.txt").write_text("unowned\n")
    before = updater.gradle_run_path("sample").read_bytes()
    if unsafe:
        with pytest.raises(updater.GradleError):
            updater.rollback_failed_gradle_update(run, workflow.project)
        assert workflow.effects == []
        assert workflow.state["tree"] == workflow.after.tree_id
        assert 'lib = "2"' in catalogue.read_text(encoding="utf-8")
    else:

        def assert_saved_before_restore():
            saved = updater.load_gradle_run(updater.gradle_run_path("sample"))
            assert saved is not None
            assert isinstance(saved.attempts[0], FailedAttempt)

        workflow.vcs_state.hook(
            "discard",
            phase="before",
            path=repo.path,
            action=assert_saved_before_restore,
        )
        workflow.vcs_state.fail(
            "discard",
            error=RevisionError("simulated crash before restore"),
            path=repo.path,
        )
        with pytest.raises(updater.GradleError, match="restore"):
            updater.rollback_failed_gradle_update(run, workflow.project)
        assert workflow.state["tree"] == workflow.after.tree_id
        stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
        assert stored is not None
        updater.rollback_failed_gradle_update(stored, workflow.project)
        updater.rollback_failed_gradle_update(stored, workflow.project)
        assert workflow.effects == ["discard"]
        assert workflow.state["tree"] == workflow.initial.tree_id
    assert updater.gradle_run_path("sample").read_bytes() == before


def test_gradle_resolve_interrupted_before_checks_accepts_only_committed_repair(
    workflow, monkeypatch
):
    run = begin_workflow(workflow, Workflow.RESOLVE)
    run = updater._replace_gradle_attempt(
        run, ApplyingAttempt(candidate=workflow.candidate, baseline=workflow.initial)
    )
    updater.save_gradle_run(updater.gradle_run_path("sample"), run)
    catalogue = workflow.project.path / "gradle/libs.versions.toml"
    catalogue.write_text(
        catalogue.read_text(encoding="utf-8").replace('lib = "1"', 'lib = "2"'),
        encoding="utf-8",
    )
    repo = workflow.vcs.repository(workflow.project.path)
    repo.commit(message="manual repair")
    repair = repo.resolve_revision(revision="@-")
    workflow.effects.clear()
    workflow.state.update(snapshot=workflow.after, tree=workflow.after.tree_id)
    monkeypatch.setattr(updater, "reclaim_gradle_outputs", lambda *args: None)
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
    assert repaired.managed_tip_id == repair
    assert "apply" not in workflow.effects
    assert "commit" not in workflow.effects
    assert "discard" not in workflow.effects


def ready_workflow(workflow):
    return updater.process_gradle_run(
        begin_workflow(workflow), workflow.project, workflow.publication, 7
    )


def finalizer_effects(workflow, monkeypatch, run):
    state = {
        "promotions": 0,
        "refreshes": 0,
        "published": 0,
    }
    monkeypatch.setattr(workflow_service, "context_inputs_valid", lambda *args: True)
    repo = workflow.vcs.repository(workflow.project.path)
    repo.new_change(revision=run.base_commit_id)

    def promote():
        state["promotions"] += 1

    def refresh():
        saved = updater.load_gradle_run(updater.gradle_run_path(run.project))
        assert saved is not None
        assert saved.promoted_commit_id == run.managed_tip_id
        state["refreshes"] += 1
        if state["refreshes"] == 1:
            raise RevisionError("refresh failed")

    def publish(*args, **kwargs):
        state["published"] += 1

    workflow.vcs_state.hook(
        "promote_bookmark_to_main",
        phase="before",
        path=workflow.project.path,
        action=promote,
    )
    workflow.vcs_state.hook(
        "rebase_working_copy",
        phase="before",
        path=workflow.project.path,
        action=refresh,
    )
    workflow.vcs_state.hook(
        "rebase_working_copy",
        ordinal=2,
        phase="before",
        path=workflow.project.path,
        action=refresh,
    )
    monkeypatch.setattr(workflow_service, "_publish_verified_gradle_scan", publish)
    return state


def test_gradle_retry_refresh_never_reapplies_or_repromotes(workflow, monkeypatch):
    run = ready_workflow(workflow)
    state = finalizer_effects(workflow, monkeypatch, run)
    with pytest.raises(updater.GradleError, match="refresh failed"):
        workflow_service._finish_verified_gradle_run(
            run,
            workflow.project,
            workflow.publication,
            7,
            vcs=workflow.vcs,
        )
    saved = updater.load_gradle_run(updater.gradle_run_path(run.project))
    assert saved is not None
    assert saved.promoted_commit_id == run.managed_tip_id
    assert not saved.refreshed
    finished = workflow_service._finish_verified_gradle_run(
        saved,
        workflow.project,
        workflow.publication,
        7,
        vcs=workflow.vcs,
    )
    assert finished.refreshed
    assert isinstance(finished.attempts[0], CompletedAttempt)
    assert state == {
        "promotions": 1,
        "refreshes": 2,
        "published": 1,
    }
    assert workflow.effects.count("apply") == 1
    assert workflow.effects.count("commit") == 1
    persisted = updater.load_gradle_run(updater.gradle_run_path(run.project))
    assert persisted is not None
    assert persisted == finished
    assert isinstance(persisted.attempts[0], CompletedAttempt)
    assert 'lib = "2"' in (
        workflow.project.path / "gradle/libs.versions.toml"
    ).read_text(encoding="utf-8")


def test_gradle_crash_after_promotion_before_ledger_is_recognized(
    workflow, monkeypatch
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
        workflow_service._finish_verified_gradle_run(
            run,
            workflow.project,
            workflow.publication,
            7,
            vcs=workflow.vcs,
        )
    stored = updater.load_gradle_run(updater.gradle_run_path(run.project))
    assert stored is not None
    assert stored.promoted_commit_id is None
    state["refreshes"] = 1
    finished = workflow_service._finish_verified_gradle_run(
        stored,
        workflow.project,
        workflow.publication,
        7,
        vcs=workflow.vcs,
    )
    assert finished.refreshed
    assert state["promotions"] == 1


@pytest.mark.parametrize("mutation", ["base", "tip", "base-conflict", "tip-conflict"])
def test_gradle_resolve_submission_guard_failure_keeps_recoverable_ledger(
    workflow, mutation
):
    run = updater.process_gradle_run(
        begin_workflow(workflow, Workflow.RESOLVE),
        workflow.project,
        workflow.publication,
        7,
        vcs=workflow.vcs,
    )
    base, tip = run.base_commit_id, run.managed_tip_id
    sibling = workflow.vcs_state.seed_commit(
        workflow.project.path,
        parent=base,
        files={"gradle/libs.versions.toml": '[versions]\nlib = "sibling"\n'},
        description="concurrent sibling",
    )
    if mutation == "base":
        workflow.vcs_state.seed_bookmark(
            workflow.project.path, bookmark="main", targets=(sibling,)
        )
    elif mutation == "tip":
        workflow.vcs_state.seed_bookmark(
            workflow.project.path,
            bookmark=run.managed_bookmark,
            targets=(base,),
        )
    elif mutation == "base-conflict":
        workflow.vcs_state.seed_bookmark(
            workflow.project.path, bookmark="main", targets=(base, sibling)
        )
    else:
        workflow.vcs_state.seed_bookmark(
            workflow.project.path,
            bookmark=run.managed_bookmark,
            targets=(tip, sibling),
        )
    before = updater.gradle_run_path(run.project).read_bytes()
    workflow.vcs_state.clear_calls()
    host = workflow.vcs.code_host(workflow.project.path)

    with pytest.raises((updater.GradleError, RevisionError)):
        workflow_service._finish_verified_gradle_run(
            run,
            workflow.project,
            workflow.publication,
            7,
            vcs=workflow.vcs,
        )

    assert updater.gradle_run_path(run.project).read_bytes() == before
    assert not any(
        call.method == "push_bookmark" for call in workflow.vcs_state.effects
    )
    assert not any(call.method == "create_pr" for call in host.attempts)


def test_gradle_resolve_host_failure_retries_completed_push_without_reapply(
    workflow,
):
    run = updater.process_gradle_run(
        begin_workflow(workflow, Workflow.RESOLVE),
        workflow.project,
        workflow.publication,
        7,
        vcs=workflow.vcs,
    )
    host = workflow.vcs.code_host(workflow.project.path)
    host.fail("create_pr", error=CodeHostError("host unavailable"))
    apply_count = workflow.effects.count("apply")
    commit_count = workflow.effects.count("commit")

    with pytest.raises(CodeHostError, match="host unavailable"):
        workflow_service._finish_verified_gradle_run(
            run,
            workflow.project,
            workflow.publication,
            7,
            vcs=workflow.vcs,
        )

    stored = updater.load_gradle_run(updater.gradle_run_path(run.project))
    assert stored is not None
    assert stored == run
    assert workflow.vcs_state.remote_bookmark_targets(
        workflow.project.path, bookmark=run.managed_bookmark
    ) == (run.managed_tip_id,)
    finished = workflow_service._finish_verified_gradle_run(
        stored,
        workflow.project,
        workflow.publication,
        7,
        vcs=workflow.vcs,
    )
    assert finished.submitted
    assert isinstance(finished.attempts[0], CompletedAttempt)
    assert workflow.effects.count("apply") == apply_count
    assert workflow.effects.count("commit") == commit_count
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
    assert interrupted.attempts[0].checked_tree_id == workflow.after.tree_id
    assert interrupted.attempts[0].accepted_commit_id is None
    repo = workflow.vcs.repository(workflow.project.path)
    accepted_commit = repo.resolve_revision(revision="@-")
    workflow.vcs_state.seed_bookmark(
        workflow.project.path,
        bookmark=run.managed_bookmark,
        targets=(run.base_commit_id,),
    )
    monkeypatch.setattr(updater, "validate_gradle_recovery", lambda *args: None)
    monkeypatch.setattr(updater, "context_inputs_valid", lambda *args: not stale)

    def capture(project, context, **kwargs):
        tree = workflow.vcs.repository(project.path).tree_id()
        return workflow.initial if tree == workflow.initial.tree_id else workflow.after

    monkeypatch.setattr(updater, "capture_gradle_snapshot", capture)
    monkeypatch.setattr(
        updater, "collect_gradle_resolution", lambda *args: workflow.initial.resolution
    )
    monkeypatch.setattr(
        updater, "initialize_comparison_context", lambda *args: workflow.context
    )
    workflow.vcs_state.clear_calls()
    recovered = updater.reconcile_gradle_applying(
        interrupted,
        workflow.project,
        workflow.publication,
        7,
        vcs=workflow.vcs,
    )
    assert recovered.attempts[0].state == "ready"
    assert recovered.managed_tip_id == accepted_commit
    assert workflow.effects.count("apply") == 1
    assert workflow.effects.count("commit") == 1
    visited = [
        dict(call.arguments)["revision"]
        for call in workflow.vcs_state.effects
        if call.method == "add_workspace"
    ]
    assert visited == ([run.base_commit_id, accepted_commit] if stale else [])


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
    applies_before_retry = workflow.effects.count("apply")
    workflow.vcs.repository(workflow.project.path).commit(message="manual repair")
    with pytest.raises(updater.GradleError, match="Security verification"):
        updater.continue_gradle_resolve(
            failed, workflow.project, workflow.publication, 7
        )
    stored = updater.load_gradle_run(updater.gradle_run_path("sample"))
    assert stored is not None
    assert isinstance(stored.attempts[0], FailedAttempt)
    assert stored.attempts[0].state == "failed"
    assert stored.attempts[0].after == workflow.after
    assert workflow.effects.count("apply") == applies_before_retry == 1


def test_gradle_cli_uses_ledger_even_without_scan_results(workflow, monkeypatch):
    run = ready_workflow(workflow)
    source_repo = workflow.vcs.repository(workflow.project.path)
    workspace = workflow_service.workspace_path_for_project("sample")
    source_repo.add_workspace(
        name="mm-sample", path=workspace, revision=run.managed_tip_id
    )
    workflow.vcs.repository(workspace).new_change(revision=run.managed_tip_id)
    monkeypatch.setattr(workflow_service, "context_inputs_valid", lambda *args: True)
    monkeypatch.setattr(
        workflow_service,
        "PublicationLookupContext",
        lambda *args: __import__("contextlib").nullcontext(workflow.publication),
    )
    finalized = False

    def read_published(*args):
        assert finalized, "scan JSON must not authorize ledger recovery"
        raise cli.NoScanResultsError("no published results")

    def finish(value, *args, **kwargs):
        nonlocal finalized
        finalized = True
        return value.model_copy(update={"refreshed": True})

    monkeypatch.setattr(workflow_service, "load_scan_results", read_published)
    monkeypatch.setattr(workflow_service, "_finish_verified_gradle_run", finish)
    assert (
        cli._run_gradle_flow(
            "sample",
            workflow.project,
            Workflow.UPDATE,
            interactive=False,
            minimum_age_days=7,
            vcs=workflow.vcs,
        )
        == cli.ExitCode.OK
    )
    assert workflow.effects.count("apply") == 1


def test_gradle_legacy_ready_without_ledger_refuses_before_workspace(
    workflow, monkeypatch
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
    monkeypatch.setattr(workflow_service, "load_scan_results", lambda *args: legacy)
    workflow.vcs_state.clear_calls()
    assert (
        cli._run_gradle_flow(
            "sample",
            workflow.project,
            Workflow.UPDATE,
            interactive=False,
            minimum_age_days=7,
            vcs=workflow.vcs,
        )
        == cli.ExitCode.UPDATE_FAILED
    )
    assert not any(
        call.method == "add_workspace" for call in workflow.vcs_state.effects
    )


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
    workflow.vcs_state.seed_bookmark(
        workflow.project.path,
        bookmark=failed.managed_bookmark,
        targets=(failed.managed_tip_id,),
    )
    workspace = workflow_service.workspace_path_for_project("sample")
    if workspace_exists:
        source_repo = workflow.vcs.repository(workflow.project.path)
        source_repo.add_workspace(
            name="mm-sample", path=workspace, revision=failed.managed_tip_id
        )
        workspace_repo = workflow.vcs.repository(workspace)
        workspace_repo.new_change(revision=failed.managed_tip_id)
        if unsafe:
            workflow.vcs_state.register_files(workspace, "unowned.txt")
            (workspace / "unowned.txt").write_text("unsafe\n", encoding="utf-8")
    user_file = workflow.project.path / "user-notes.txt"
    user_file.write_text("preserve these notes")
    if default_dirty:
        user_file.write_text("preserve these dirty notes", encoding="utf-8")
    effects = []

    def reset():
        archives = list(
            (updater.gradle_run_path("sample").parent / "history").glob("*.json")
        )
        assert len(archives) == 1
        assert updater.load_gradle_run(archives[0]) == failed
        assert updater.gradle_run_path("sample").exists()
        effects.append("reset")

    workflow.vcs_state.hook(
        "reset_verified_bookmark",
        phase="before",
        path=workflow.project.path,
        action=reset,
    )
    if unsafe or not workspace_exists:
        with pytest.raises(updater.GradleError):
            workflow_service._archive_rolled_back_gradle_run(
                failed, workflow.project, vcs=workflow.vcs
            )
        assert updater.load_gradle_run(updater.gradle_run_path("sample")) == failed
        assert effects == []
    else:
        workflow_service._archive_rolled_back_gradle_run(
            failed, workflow.project, vcs=workflow.vcs
        )
        assert not updater.gradle_run_path("sample").exists()
        assert effects == ["reset"]
    assert user_file.read_text().startswith("preserve these")


def test_gradle_failed_update_restart_refuses_uncertain_dirty_state(
    workflow, monkeypatch
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
        vcs=workflow.vcs,
    )
    workflow.vcs_state.seed_bookmark(
        workflow.project.path,
        bookmark=failed.managed_bookmark,
        targets=(failed.managed_tip_id,),
    )
    workspace = workflow_service.workspace_path_for_project("sample")
    source_repo = workflow.vcs.repository(workflow.project.path)
    source_repo.add_workspace(
        name="mm-sample", path=workspace, revision=failed.managed_tip_id
    )
    workflow.vcs.repository(workspace).new_change(revision=failed.managed_tip_id)
    workflow.vcs_state.clear_calls()
    workflow.vcs_state.fail(
        "has_changes",
        error=RevisionError("dirty state unavailable"),
        path=workspace,
    )

    with pytest.raises(updater.GradleError, match="inspect") as caught:
        workflow_service._archive_rolled_back_gradle_run(
            failed, workflow.project, vcs=workflow.vcs
        )

    assert isinstance(caught.value.__cause__, RevisionError)
    assert updater.load_gradle_run(updater.gradle_run_path("sample")) == failed
    history = updater.gradle_run_path("sample").parent / "history"
    assert not history.exists()
    assert not {
        "commit",
        "discard",
        "reset_verified_bookmark",
    } & {call.method for call in workflow.vcs_state.effects}


@pytest.mark.parametrize(
    "mutation", ["none", "dirty", "unrelated-parent", "working-tree", "accepted-tree"]
)
def test_gradle_resume_requires_exact_empty_accepted_child(
    workflow, monkeypatch, mutation
):
    run = ready_workflow(workflow)
    source_repo = workflow.vcs.repository(workflow.project.path)
    workspace = workflow_service.workspace_path_for_project("sample")
    source_repo.add_workspace(
        name="mm-sample", path=workspace, revision=run.managed_tip_id
    )
    workspace_repo = workflow.vcs.repository(workspace)
    workspace_repo.new_change(revision=run.managed_tip_id)
    if mutation == "unrelated-parent":
        unrelated = workflow.vcs_state.seed_commit(
            workflow.project.path,
            parent=run.base_commit_id,
            files={
                "gradle/libs.versions.toml": (
                    workflow.project.path / "gradle/libs.versions.toml"
                ).read_text(encoding="utf-8")
            },
            description="unrelated",
        )
        workspace_repo.new_change(revision=unrelated)
    elif mutation in {"dirty", "working-tree"}:
        (workspace / "gradle/libs.versions.toml").write_text(
            '[versions]\nlib = "unverified"\n', encoding="utf-8"
        )
    elif mutation == "accepted-tree":
        run = run.model_copy(
            update={
                "accepted_snapshot": run.accepted_snapshot.model_copy(
                    update={"tree_id": "unverified-tree"}
                )
            }
        )
        updater.save_gradle_run(updater.gradle_run_path("sample"), run)
    before = updater.gradle_run_path("sample").read_bytes()
    monkeypatch.setattr(
        workflow_service,
        "PublicationLookupContext",
        lambda *args: __import__("contextlib").nullcontext(workflow.publication),
    )
    monkeypatch.setattr(workflow_service, "context_inputs_valid", lambda *args: True)
    effects = []
    monkeypatch.setattr(
        updater,
        "process_gradle_run",
        lambda value, *args, **kwargs: effects.append("process") or value,
    )
    monkeypatch.setattr(
        workflow_service,
        "_finish_verified_gradle_run",
        lambda value, *args, **kwargs: (
            effects.append("finalize") or value.model_copy(update={"refreshed": True})
        ),
    )
    workflow.vcs_state.hook(
        "forget_workspace",
        phase="before",
        path=workflow.project.path,
        action=lambda: effects.append("remove"),
    )
    result = cli._run_gradle_flow(
        "sample",
        workflow.project,
        Workflow.UPDATE,
        interactive=False,
        minimum_age_days=7,
        vcs=workflow.vcs,
    )
    assert result == (
        cli.ExitCode.OK if mutation == "none" else cli.ExitCode.UPDATE_FAILED
    )
    assert effects == (["process", "finalize", "remove"] if mutation == "none" else [])
    assert updater.gradle_run_path("sample").read_bytes() == before
    assert workflow.effects.count("apply") == 1


def test_gradle_continue_proves_repair_before_automatic_workspace_guard(
    workflow, monkeypatch
):
    failed = updater.process_gradle_run(
        begin_workflow(workflow, Workflow.RESOLVE),
        workflow.project,
        workflow.publication,
        7,
    )
    workflow.vcs_state.seed_bookmark(
        workflow.project.path,
        bookmark=failed.managed_bookmark,
        targets=(failed.managed_tip_id,),
    )
    monkeypatch.setattr(
        workflow_service,
        "PublicationLookupContext",
        lambda *args: __import__("contextlib").nullcontext(workflow.publication),
    )
    monkeypatch.setattr(workflow_service, "context_inputs_valid", lambda *args: True)
    effects = []

    def repair(value, *args, **kwargs):
        effects.append("verify-committed-repair")
        return value

    def guard(value, project, **kwargs):
        assert effects == ["verify-committed-repair"]
        effects.append("accepted-workspace-guard")

    monkeypatch.setattr(updater, "continue_gradle_resolve", repair)
    monkeypatch.setattr(workflow_service, "_require_gradle_accepted_workspace", guard)
    monkeypatch.setattr(
        updater,
        "process_gradle_run",
        lambda value, *args, **kwargs: effects.append("process") or value,
    )
    monkeypatch.setattr(
        workflow_service,
        "_finish_verified_gradle_run",
        lambda value, *args, **kwargs: value,
    )
    assert (
        cli._run_gradle_flow(
            "sample",
            workflow.project,
            Workflow.RESOLVE,
            interactive=False,
            minimum_age_days=7,
            continue_=True,
            vcs=workflow.vcs,
        )
        == cli.ExitCode.OK
    )
    assert effects == ["verify-committed-repair", "accepted-workspace-guard", "process"]


@pytest.mark.parametrize("repaired", [False, True])
def test_gradle_resolve_checks_actual_catalogue_before_accepting_manual_repair(
    driver, monkeypatch, repaired
):
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
    repo = workflow.vcs.repository(driver.project.path)
    repo.commit(message="Manual repair")
    repair = repo.resolve_revision(revision="@-")
    workflow.effects.clear()
    workflow.state.update(snapshot=workflow.after, tree=workflow.after.tree_id)
    report = driver.project.path / "gradle/libs.versions.updates.toml"
    marker = driver.project.path / "gradle/.mm-owned-report"
    report.write_bytes(b"interrupted report")
    marker.write_bytes(b"")

    checks = updater.run_gradle_checks(driver.project, "sample")
    calls = []
    monkeypatch.setattr(
        updater, "run_gradle_checks", lambda *args: calls.append("checks") or checks
    )
    if repaired:
        result = updater.continue_gradle_resolve(
            failed, driver.project, workflow.publication, 7, vcs=workflow.vcs
        )
        assert isinstance(result.attempts[0], ReadyAttempt)
        assert result.managed_tip_id == repair
        assert calls == ["checks"]
        assert workflow.effects == ["bookmark"]
    else:
        with pytest.raises(updater.GradleError, match="expected 2"):
            updater.continue_gradle_resolve(
                failed, driver.project, workflow.publication, 7, vcs=workflow.vcs
            )
        assert calls == []
        assert ledger.read_bytes() == before
        assert workflow.effects == []
    assert not report.exists() and not marker.exists()


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
    monkeypatch.setattr(
        scanner, "_run_gradle_scan", lambda *args: ([], workflow.initial.resolution)
    )
    monkeypatch.setattr(scanner, "discover_gradle_updates", lambda *args: [])
    result_path = paths.MM_HOME / "scan-results" / "sample.json"
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
    workflow, monkeypatch, refreshed, published_exists
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
    cli._print_gradle_run_result(run, workflow.project)
    assert len(rendered) == 1
    result, options = rendered[0]
    assert options == {}
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
    state = FakeJjState()
    state.seed_repository(project.path, files={})
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
        "maintenance_man.process.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command,
            0,
            json.dumps({"Results": [{"Class": "lang-pkgs", "Vulnerabilities": rows}]}),
            "",
        ),
    )
    if variant in {"unknown-path", "wrong-coordinate", "undeclared"}:
        with pytest.raises(scanner.GradleError, match="local project"):
            scanner.capture_gradle_snapshot(project, context, vcs=state.services())
    else:
        result = scanner.capture_gradle_snapshot(project, context, vcs=state.services())
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
        cli._update_batch_targets(cfg, target_names=["sample"], vcs=driver.workflow.vcs)
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
    accepted = next(
        item
        for item in run.attempts
        if isinstance(item, (ReadyAttempt, CompletedAttempt))
    )
    ledger = updater.gradle_run_path("sample")
    before = ledger.read_bytes()
    cache = workflow.context.private_cache_path.with_name("rebuilt-context")
    shutil.copytree(workflow.context.private_cache_path, cache)
    context = workflow.context.model_copy(update={"private_cache_path": cache})
    observations = SimpleNamespace(mutated=None, visits=[], released=[])

    def checks(project, _project_name):
        catalogue = project.path / "gradle/libs.versions.toml"
        revision = "accepted" if 'lib = "2"' in catalogue.read_text() else "base"
        observations.visits.append(revision)
        if observations.mutated == revision:
            catalogue.write_text(catalogue.read_text() + "# changed by checks\n")
        return accepted.receipt.checks

    def capture(project, ctx, **_kwargs):
        catalogue = project.path / "gradle/libs.versions.toml"
        observed = (
            workflow.after if 'lib = "2"' in catalogue.read_text() else workflow.initial
        )
        repo = workflow.vcs.repository(project.path)
        return observed.model_copy(
            update={"context_identity": ctx.identity, "tree_id": repo.tree_id()}
        )

    monkeypatch.setattr(updater, "run_gradle_checks", checks)
    monkeypatch.setattr(updater, "capture_gradle_snapshot", capture)
    monkeypatch.setattr(updater, "parse_catalogue", lambda *args: object())
    monkeypatch.setattr(
        updater, "collect_gradle_resolution", lambda *args: workflow.initial.resolution
    )
    monkeypatch.setattr(updater, "initialize_comparison_context", lambda *args: context)
    monkeypatch.setattr(
        updater, "release_comparison_context", observations.released.append
    )
    return SimpleNamespace(
        run=run,
        context=context,
        ledger=ledger,
        before=before,
        observations=observations,
        workflow=workflow,
        base_commit_id=run.base_commit_id,
        accepted_commit_id=accepted.receipt.accepted_commit_id,
    )


@pytest.mark.parametrize("revision", ["base", "accepted"])
def test_rebuilt_evidence_refuses_a_tree_changed_by_checks(rebuild_evidence, revision):
    state = rebuild_evidence
    state.observations.mutated = revision
    with pytest.raises(updater.GradleError, match=r"tree|baseline"):
        updater.rebuild_gradle_run_evidence(
            state.run,
            state.workflow.project,
            state.workflow.publication,
            7,
            vcs=state.workflow.vcs,
        )
    assert state.ledger.read_bytes() == state.before
    assert state.observations.released == [state.context]


def test_rebuilt_evidence_preserves_exact_revision_bindings(rebuild_evidence):
    state = rebuild_evidence
    rebuilt = updater.rebuild_gradle_run_evidence(
        state.run,
        state.workflow.project,
        state.workflow.publication,
        7,
        vcs=state.workflow.vcs,
    )
    assert state.observations.visits == ["base", "accepted"]
    assert rebuilt.initial_snapshot.tree_id == state.workflow.initial.tree_id
    accepted = rebuilt.attempts[0]
    assert isinstance(accepted, ReadyAttempt)
    assert (
        accepted.after.tree_id
        == accepted.receipt.checked_tree_id
        == state.workflow.after.tree_id
    )
    assert accepted.receipt.accepted_commit_id == state.accepted_commit_id
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
    catalogue = workflow.project.path / "gradle/libs.versions.toml"
    if stage == "checks":
        original = updater.run_gradle_checks
        capture = MagicMock(side_effect=AssertionError("capture after tree mutation"))

        def mutate(*args):
            catalogue.write_text(
                catalogue.read_text(encoding="utf-8") + "# changed during checks\n",
                encoding="utf-8",
            )
            return original(*args)

        monkeypatch.setattr(updater, "run_gradle_checks", mutate)
        monkeypatch.setattr(updater, "capture_gradle_snapshot", capture)
    else:

        def mutate(*args, **kwargs):
            catalogue.write_text(
                catalogue.read_text(encoding="utf-8") + "# changed during capture\n",
                encoding="utf-8",
            )
            return workflow.after

        monkeypatch.setattr(updater, "capture_gradle_snapshot", mutate)
    result = updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    assert isinstance(result.attempts[0], FailedAttempt)
    assert "tree" in result.attempts[0].reason.lower()
    assert workflow.effects == ["apply", "discard"]
    assert result.accepted_snapshot == workflow.initial
    assert workflow.vcs.repository(workflow.project.path).tree_id() == (
        workflow.initial.tree_id
    )
    if stage == "checks":
        capture.assert_not_called()


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
    scans = []

    def scan(command, **kwargs):
        scans.append(command)
        return subprocess.CompletedProcess(command, 0, '{"Results": []}', "")

    monkeypatch.setattr("maintenance_man.process.subprocess.run", scan)
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
    rebuilt = updater.rebuild_gradle_run_evidence(
        state.run,
        state.workflow.project,
        state.workflow.publication,
        7,
        persist=persist,
        vcs=state.workflow.vcs,
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
    _, context, _ = frozen_context
    cache = context.private_cache_path
    verification.release_comparison_context(context)
    verification.release_comparison_context(context)
    cache.mkdir()
    (cache / ".mm-comparison-owner").write_text("someone-else")
    with pytest.raises(verification.GradleError, match="ownership"):
        verification.release_comparison_context(context)
    assert cache.is_dir()


def test_gradle_retry_replans_after_native_preparation_failure(driver, monkeypatch):
    native = candidates.validate_gradle_candidates
    monkeypatch.setattr(
        workflow_service,
        "initialize_comparison_context",
        verification.initialize_comparison_context,
    )
    monkeypatch.setattr(
        updater,
        "capture_gradle_snapshot",
        lambda project, context, **kwargs: driver.workflow.state["snapshot"].model_copy(
            update={"context_identity": context.identity}
        ),
    )

    def fail(*args):
        raise updater.GradleError("Temporary native metadata failure")

    monkeypatch.setattr(candidates, "validate_gradle_candidates", fail)
    assert invoke_driver(driver) == cli.ExitCode.UPDATE_FAILED
    assert driver.effects == ["bookmark"]
    driver.effects.clear()
    monkeypatch.setattr(candidates, "validate_gradle_candidates", native)
    assert invoke_driver(driver) == cli.ExitCode.OK
    assert driver.effects.count("apply") == 1
    assert driver.effects.count("commit") == 1
    assert driver.effects.count("promote") == 1
    assert driver.effects.count("refresh") == 1


@pytest.mark.parametrize("cached", [False, True])
def test_gradle_empty_discovery_checks_fresh_security_findings(
    driver, monkeypatch, cached
):
    from maintenance_man.models.scan import ScanResult

    driver.proposals = []

    def previous(*args):
        if not cached:
            raise cli.NoScanResultsError("No saved scan")
        return ScanResult(
            project="sample",
            scanned_at=driver.workflow.context.created_at,
            trivy_target=str(driver.project.path),
        )

    monkeypatch.setattr(workflow_service, "load_scan_results", previous)
    # The current graph contains an advisory even though the cached scan does not.
    assert invoke_driver(driver) == cli.ExitCode.UPDATE_FAILED
    assert not {"apply", "commit", "promote", "refresh"} & set(driver.effects)


@pytest.mark.parametrize("inventory_state", ["marked", "unmarked", "cleanup-error"])
def test_gradle_run_applies_shared_target_once_after_owned_output_cleanup(
    workflow, monkeypatch, inventory_state
):
    from maintenance_man import gradle

    root = workflow.project.path
    catalogue = root / gradle.GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        catalogue.read_text()
        + 'second = { module = "g:second", version.ref = "lib" }\n'
    )
    target = workflow.candidate.target.model_copy(
        update={
            "members": [
                *workflow.candidate.target.members,
                GradleMember(
                    kind="library",
                    alias="second",
                    coordinate="g:second",
                    installed_version="1",
                ),
            ]
        }
    )
    candidate = workflow.candidate.model_copy(update={"target": target})
    repo = workflow.vcs.repository(root)
    repo.commit(message="shared target baseline")
    workflow.base = repo.resolve_revision(revision="@-")
    workflow.initial = workflow.initial.model_copy(
        update={"tree_id": repo.tree_id(revision=workflow.base)}
    )
    after_catalogue = catalogue.read_text().replace('lib = "1"', 'lib = "2"')
    accepted = workflow.vcs_state.seed_commit(
        root,
        parent=workflow.base,
        files={str(gradle.GRADLE_CATALOGUE_RELPATH): after_catalogue},
        description="shared target accepted fixture",
    )
    workflow.after = workflow.after.model_copy(
        update={"tree_id": repo.tree_id(revision=accepted)}
    )
    workflow.state.update(
        snapshot=workflow.initial,
        tree=workflow.initial.tree_id,
        after=workflow.after,
    )
    workflow.effects.clear()
    run = begin_workflow(workflow, Workflow.RESOLVE, candidate)
    workflow.vcs_state.clear_calls()
    workflow.effects.clear()
    inventory = root / gradle.GRADLE_INVENTORY_RELPATH
    inventory.mkdir()
    (inventory / "bom.json").write_bytes(b"retained inventory")
    if inventory_state != "unmarked":
        (root / gradle.GRADLE_INVENTORY_MARKER_RELPATH).write_bytes(b"")
    reports = []
    checks = updater.run_gradle_checks

    def apply_command(path, args, *, label):
        assert not inventory.exists()
        reports.append((root / gradle.GRADLE_UPDATE_REPORT_RELPATH).read_text())
        catalogue.write_text(catalogue.read_text().replace('lib = "1"', 'lib = "2"'))
        workflow.state.update(snapshot=workflow.after, tree=workflow.after.tree_id)
        return subprocess.CompletedProcess(args, 0, "", "")

    def check(*args):
        assert not inventory.exists()
        assert not (root / gradle.GRADLE_UPDATE_REPORT_RELPATH).exists()
        assert not (root / gradle.GRADLE_REPORT_MARKER_RELPATH).exists()
        workflow.effects.append("checks")
        return checks(*args)

    monkeypatch.setattr(updater, "apply_gradle_update", gradle.apply_gradle_update)
    monkeypatch.setattr(gradle, "run_gradle", apply_command)
    monkeypatch.setattr(updater, "run_gradle_checks", check)
    if inventory_state == "cleanup-error":

        def fail(*args, **kwargs):
            raise PermissionError("Cannot reclaim inventory")

        monkeypatch.setattr(gradle.shutil, "rmtree", fail)
    result = updater.process_gradle_run(run, workflow.project, workflow.publication, 7)
    if inventory_state == "marked":
        assert isinstance(result.attempts[0], ReadyAttempt)
        assert reports == ['[libraries]\n"lib" = "g:lib:2"\n"second" = "g:second:2"\n']
        assert workflow.effects == ["checks", "commit", "bookmark"]
    else:
        assert isinstance(result.attempts[0], FailedAttempt)
        assert not reports and not workflow.effects
        assert (inventory / "bom.json").read_bytes() == b"retained inventory"
        assert 'lib = "1"' in catalogue.read_text()


@pytest.mark.parametrize("block", ["age", "selection"])
def test_gradle_ineligible_run_does_not_build_or_freeze_scanner_inputs(
    driver, monkeypatch, block
):
    from maintenance_man.models.gradle import AgeBlock

    if block == "age":
        monkeypatch.setattr(
            candidates,
            "evaluate_gradle_candidate_age",
            lambda *args: AgeBlock(reason="Too recent"),
        )
    else:
        driver.selection = "none"

    def unnecessary(*args):
        pytest.fail(
            "Ineligible changes must not build or download a private scanner database"
        )

    monkeypatch.setattr(updater, "run_gradle_checks", unnecessary)
    monkeypatch.setattr(workflow_service, "initialize_comparison_context", unnecessary)
    assert (
        invoke_driver(driver, interactive=block == "selection")
        == cli.ExitCode.UPDATE_FAILED
    )
    assert driver.effects in ([], ["bookmark"])


def test_gradle_retries_an_empty_preparation_ledger_from_older_versions(driver):
    run = updater.start_gradle_run(
        "sample",
        driver.project,
        Workflow.UPDATE,
        driver.workflow.base,
        driver.workflow.context,
        (),
        vcs=driver.workflow.vcs,
    )
    driver.workflow.vcs_state.seed_bookmark(
        driver.project.path,
        bookmark=run.managed_bookmark,
        targets=(driver.workflow.base,),
    )
    assert invoke_driver(driver) == cli.ExitCode.OK
    assert driver.effects == ["apply", "commit", "bookmark", "promote", "refresh"]


def test_gradle_reconsiders_old_withheld_run_on_the_next_invocation(driver):
    from maintenance_man.models.gradle import WithheldAttempt

    run = updater.start_gradle_run(
        "sample",
        driver.project,
        Workflow.UPDATE,
        driver.workflow.base,
        driver.workflow.context,
        (),
        vcs=driver.workflow.vcs,
    )
    driver.workflow.vcs_state.seed_bookmark(
        driver.project.path,
        bookmark=run.managed_bookmark,
        targets=(driver.workflow.base,),
    )
    run = run.model_copy(
        update={
            "attempts": (
                WithheldAttempt(
                    candidate=driver.workflow.candidate,
                    reason="publication lookup timed out",
                ),
            )
        }
    )
    updater.save_gradle_run(updater.gradle_run_path("sample"), run)

    assert invoke_driver(driver) == cli.ExitCode.OK
    assert driver.effects == ["apply", "commit", "bookmark", "promote", "refresh"]


def test_gradle_updates_without_declared_public_routing(driver):
    driver.project = driver.project.model_copy(
        update={"gradle_repository_routing": None}
    )
    assert invoke_driver(driver) == cli.ExitCode.OK
    assert driver.effects[-5:] == [
        "apply",
        "commit",
        "bookmark",
        "promote",
        "refresh",
    ]


def test_checked_gradle_update_can_record_unknown_publication(
    workflow, monkeypatch, tmp_path
):
    from maintenance_man.dependency_age import (
        PublicationLookupContext,
        evaluate_gradle_candidate_age,
    )
    from maintenance_man.models.gradle import PublicationRequest

    request = PublicationRequest(
        module=ModuleId(group="g", artifact="lib", version="2"),
        repositories=("central",),
        routing_supported=True,
    )
    candidate = workflow.candidate.model_copy(
        update={"publication_requests": (request,)}
    )
    run = begin_workflow(workflow, candidate=candidate)
    monkeypatch.setattr(
        updater, "evaluate_gradle_candidate_age", evaluate_gradle_candidate_age
    )
    calls = []

    def timeout(*args):
        calls.append(args[0])
        raise TimeoutError("unavailable")

    with PublicationLookupContext(tmp_path / "publications", timeout) as publication:
        result = updater.process_gradle_run(run, workflow.project, publication, 7)
        assert isinstance(result.attempts[0], ReadyAttempt)
        assert result.attempts[0].receipt.publications == ()
        assert result.attempts[0].receipt.checks.success
        updater.gradle_run_finalization_check(result, workflow.project, publication, 7)
    assert len(calls) == 1
    assert workflow.effects == ["apply", "commit", "bookmark"]
