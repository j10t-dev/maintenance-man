"""Verified Gradle attempts, durable evidence, and recovery."""

from __future__ import annotations

import hashlib
import logging
import shutil
import tempfile
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from maintenance_man import paths
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    evaluate_gradle_candidate_age,
)
from maintenance_man.deployer import BuildError, run_build
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GradleError,
    apply_gradle_update,
    parse_catalogue,
    reclaim_gradle_outputs,
    validate_gradle_recovery,
    validate_gradle_target,
)
from maintenance_man.gradle_resolution import (
    collect_gradle_resolution,
)
from maintenance_man.gradle_verification import (
    compare_gradle_snapshots,
    context_inputs_valid,
    initialize_comparison_context,
    release_comparison_context,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    ApplyingAttempt,
    AttemptState,
    CheckEvidence,
    ComparisonContext,
    CompletedAttempt,
    FailedAttempt,
    GradleCandidate,
    GradleRun,
    GradleSnapshot,
    IncompleteResolution,
    PlannedAttempt,
    ReadyAttempt,
    VerificationReceipt,
    VerifiedComparison,
    WithheldAttempt,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    GradleUpdateTarget,
    Workflow,
)
from maintenance_man.scanner import ScanError, capture_gradle_snapshot
from maintenance_man.storage import atomic_write_text
from maintenance_man.updater import run_test_phases
from maintenance_man.vcs import (
    RevisionError,
    _run,
    commit_current_change,
    create_or_reset_bookmark,
    current_change_has_changes,
    discard_current_change,
    edit_new_change,
    exact_commit_id,
    is_ancestor,
    revision_tree_id,
)


def gradle_run_path(project: str) -> Path:
    try:
        return paths.project_file(paths.gradle_runs_dir(), project, ".json")
    except ValueError as exc:
        raise GradleError("Invalid Gradle run path") from exc


def save_gradle_run(path: Path, run: GradleRun) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise GradleError("Refusing symlinked Gradle run ledger")
    try:
        atomic_write_text(path, run.model_dump_json(indent=2), durable=True, mode=0o600)
    except OSError as exc:
        raise GradleError(f"Cannot persist Gradle run: {exc}") from exc


def load_gradle_run(path: Path) -> GradleRun | None:
    if path.is_symlink():
        raise GradleError("Refusing symlinked Gradle run ledger")
    try:
        return GradleRun.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise GradleError(f"Invalid Gradle run ledger: {exc}") from exc


def retire_gradle_context(context: ComparisonContext) -> None:
    """Clean up retired evidence without invalidating an already saved transition."""
    try:
        release_comparison_context(context)
    except (OSError, GradleError) as exc:
        logging.getLogger(__name__).warning(
            "Could not release retired Gradle cache %s: %s",
            context.private_cache_path,
            exc,
        )


def discard_unpersisted_gradle_context(
    project_name: str, context: ComparisonContext
) -> None:
    # A failed fsync may follow a successful replace. Never delete the database
    # that the durable ledger now references, even when its save raised.
    try:
        durable = load_gradle_run(gradle_run_path(project_name))
    except GradleError:
        return
    if (
        durable is None
        or durable.context.private_cache_path != context.private_cache_path
    ):
        retire_gradle_context(context)


def _replace_gradle_attempt(run: GradleRun, attempt: AttemptState) -> GradleRun:
    attempts = tuple(
        attempt
        if old.candidate.target.group_key == attempt.candidate.target.group_key
        else old
        for old in run.attempts
    )
    if not any(
        old.candidate.target.group_key == attempt.candidate.target.group_key
        for old in run.attempts
    ):
        attempts += (attempt,)
    return GradleRun.model_validate(dict(run) | {"attempts": attempts})


def gradle_check_commands(project: ProjectConfig) -> tuple[str, ...]:
    tests = tuple(command for _, command in project.test_phases)
    if not project.build_command or not tests:
        raise GradleError(
            "Setup prerequisite: configure build_command and at least one test phase"
        )
    return (project.build_command, *tests)


def run_gradle_checks(project: ProjectConfig, project_name: str) -> CheckEvidence:
    commands = gradle_check_commands(project)
    checks_started = time.monotonic()
    try:
        run_build(project_name, commands[0], project.path)
    except BuildError as exc:
        raise GradleError(
            f"Build prerequisite/failure: {exc}; "
            "SDK and wrapper repairs require manual preparation"
        ) from exc
    logging.getLogger(__name__).info(
        "Gradle baseline/update build %.3fs", time.monotonic() - checks_started
    )
    tests_started = time.monotonic()
    passed, phase = run_test_phases(project, project.path)
    logging.getLogger(__name__).info(
        "Gradle configured tests %.3fs", time.monotonic() - tests_started
    )
    if not passed:
        raise GradleError(f"Gradle test phase failed: {phase}")
    return CheckEvidence(
        commands=commands,
        command_digests=tuple(
            hashlib.sha256(command.encode()).hexdigest() for command in commands
        ),
        success=True,
        checked_at=datetime.now(UTC),
    )


def capture_checked_gradle_snapshot(
    project: ProjectConfig,
    project_name: str,
    context: ComparisonContext,
    *,
    expected_tree: str | None = None,
    target: GradleUpdateTarget | None = None,
) -> tuple[CheckEvidence, GradleSnapshot]:
    """Bind build, tests and security evidence to one unchanged source tree."""
    tree = expected_tree or revision_tree_id(project.path)
    if revision_tree_id(project.path) != tree:
        raise GradleError("Working tree differs from the verification revision")
    if target is not None:
        block = validate_gradle_recovery(project, target)
        if block is not None:
            raise GradleError(block.reason)
    checks = run_gradle_checks(project, project_name)
    if revision_tree_id(project.path) != tree:
        raise GradleError("Source tree changed during build or tests")
    snapshot = capture_gradle_snapshot(project, context)
    if isinstance(snapshot, IncompleteResolution):
        raise GradleError("Coverage incomplete: " + "; ".join(snapshot.reasons))
    if snapshot.tree_id != tree or revision_tree_id(project.path) != tree:
        raise GradleError("Source tree changed during security capture")
    return checks, snapshot


def start_gradle_run(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    base_commit_id: str,
    context: ComparisonContext,
    candidates: tuple[GradleCandidate, ...],
    *,
    persist: bool = True,
) -> GradleRun:
    _, baseline = capture_checked_gradle_snapshot(
        project,
        project_name,
        context,
        expected_tree=revision_tree_id(project.path, base_commit_id),
    )
    bookmark = WORKFLOW_BOOKMARKS[flow]
    run = GradleRun(
        project=project_name,
        flow=flow,
        base_commit_id=base_commit_id,
        managed_bookmark=bookmark,
        managed_tip_id=base_commit_id,
        context=context,
        initial_snapshot=baseline,
        accepted_snapshot=baseline,
        attempts=tuple(PlannedAttempt(candidate=candidate) for candidate in candidates),
    )
    if persist:
        save_gradle_run(gradle_run_path(project_name), run)
    return run


def verify_applied_gradle_attempt(
    run: GradleRun,
    candidate: GradleCandidate,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    committed_revision: str | None = None,
) -> GradleRun:
    path = gradle_run_path(run.project)
    checks, after = capture_checked_gradle_snapshot(
        project,
        run.project,
        run.context,
        target=candidate.target,
        expected_tree=(
            revision_tree_id(project.path, committed_revision)
            if committed_revision is not None
            else None
        ),
    )
    # Persist the rejected snapshot too: it is diagnostic evidence, not READY.
    observed = ApplyingAttempt(
        candidate=candidate, baseline=run.accepted_snapshot, checks=checks, after=after
    )
    run = _replace_gradle_attempt(run, observed)
    save_gradle_run(path, run)
    comparison = compare_gradle_snapshots(run.accepted_snapshot, after, candidate)
    if not isinstance(comparison, VerifiedComparison):
        raise GradleError(
            "Security verification failed: " + "; ".join(comparison.reasons)
        )
    block = evaluate_gradle_candidate_age(
        candidate, minimum_age_days, publication, datetime.now(UTC)
    )
    if block is not None:
        raise GradleError(block.reason)
    checked_tree = revision_tree_id(project.path)
    if checked_tree != after.tree_id:
        raise GradleError("Tree changed after security verification")
    prepared = ApplyingAttempt(
        candidate=candidate,
        baseline=run.accepted_snapshot,
        checks=checks,
        after=after,
        checked_tree_id=checked_tree,
    )
    run = _replace_gradle_attempt(run, prepared)
    save_gradle_run(path, run)
    if committed_revision is None:
        if not current_change_has_changes(project.path):
            raise GradleError("Candidate made no tracked source change")
        target = candidate.target
        if not commit_current_change(
            project.path,
            f"chore: bump {target.display_name} to {target.target_version}",
        ):
            raise GradleError("Could not commit verified Gradle update")
        commit_id = exact_commit_id(project.path, "@-")
    else:
        commit_id = exact_commit_id(project.path, committed_revision)
    if revision_tree_id(project.path, commit_id) != checked_tree:
        raise GradleError("Accepted commit tree differs from checked tree")
    prepared = prepared.model_copy(update={"accepted_commit_id": commit_id})
    run = _replace_gradle_attempt(run, prepared)
    save_gradle_run(path, run)
    if not create_or_reset_bookmark(run.managed_bookmark, project.path, commit_id):
        raise GradleError("Could not bind managed bookmark to accepted commit")
    receipt = VerificationReceipt(
        checked_tree_id=checked_tree,
        accepted_commit_id=commit_id,
        baseline_snapshot_id=run.accepted_snapshot.snapshot_id,
        after_snapshot_id=after.snapshot_id,
        context_identity=run.context.identity,
        checks=checks,
        publications=publication.evidence_for(candidate),
        verified_fixes=comparison.removed,
        residual_keys=comparison.residual,
    )
    accepted = ReadyAttempt(
        candidate=candidate,
        baseline=run.accepted_snapshot,
        after=after,
        receipt=receipt,
    )
    run = _replace_gradle_attempt(run, accepted).model_copy(
        update={"managed_tip_id": commit_id, "accepted_snapshot": after}
    )
    run = GradleRun.model_validate(dict(run))
    save_gradle_run(path, run)
    return run


def process_gradle_run(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> GradleRun:
    for planned in tuple(run.attempts):
        if not isinstance(planned, PlannedAttempt):
            continue
        candidate = planned.candidate
        block = validate_gradle_target(project, candidate.target)
        age = evaluate_gradle_candidate_age(
            candidate, minimum_age_days, publication, datetime.now(UTC)
        )
        reason = block.reason if block else age.reason if age else None
        if reason:
            run = _replace_gradle_attempt(
                run, WithheldAttempt(candidate=candidate, reason=reason)
            )
            save_gradle_run(gradle_run_path(run.project), run)
            continue
        if not context_inputs_valid(run.context, project, datetime.now(UTC)):
            raise GradleError(
                "Comparison context expired or changed; "
                "rebuild evidence before continuing"
            )
        run = _replace_gradle_attempt(
            run, ApplyingAttempt(candidate=candidate, baseline=run.accepted_snapshot)
        )
        save_gradle_run(gradle_run_path(run.project), run)
        try:
            block = apply_gradle_update(project, candidate.target)
            if block is not None:
                raise GradleError(block.reason)
            run = verify_applied_gradle_attempt(
                run, candidate, project, publication, minimum_age_days
            )
        except (GradleError, ScanError, RevisionError) as exc:
            # Read latest pre-effect intent to retain commit-crash evidence.
            latest = load_gradle_run(gradle_run_path(run.project))
            if latest is not None:
                run = latest
            state = next(
                item
                for item in run.attempts
                if item.candidate.target.group_key == candidate.target.group_key
            )
            if isinstance(state, ApplyingAttempt) and state.checked_tree_id is not None:
                # A checked commit may already exist. Recovery must reconcile it;
                # never discard or synthesize a failure after that irreversible effect.
                raise
            failed = FailedAttempt(
                candidate=candidate,
                baseline=run.accepted_snapshot,
                reason=str(exc),
                after=state.after if isinstance(state, ApplyingAttempt) else None,
            )
            run = _replace_gradle_attempt(run, failed)
            save_gradle_run(gradle_run_path(run.project), run)
            if run.flow == Workflow.UPDATE:
                if (
                    not discard_current_change(project.path)
                    or revision_tree_id(project.path) != run.accepted_snapshot.tree_id
                ):
                    raise GradleError(
                        "Could not restore the latest accepted Gradle baseline"
                    ) from exc
            else:
                return run
    return run


def gradle_run_finalization_check(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> None:
    if run.has(ApplyingAttempt, FailedAttempt, PlannedAttempt):
        raise GradleError("Unfinished or failed Gradle attempt prevents finalization")
    accepted = [
        attempt
        for attempt in run.attempts
        if isinstance(attempt, (ReadyAttempt, CompletedAttempt))
    ]
    if not accepted:
        raise GradleError("No verified Gradle update to finalize")
    if not context_inputs_valid(run.context, project, datetime.now(UTC)):
        raise GradleError("Final comparison context is stale")
    if (
        exact_commit_id(project.path, run.managed_bookmark) != run.managed_tip_id
        or revision_tree_id(project.path, run.managed_tip_id)
        != run.accepted_snapshot.tree_id
    ):
        raise GradleError("Managed tip differs from the verified snapshot")
    if tuple(gradle_check_commands(project)) != accepted[-1].receipt.checks.commands:
        raise GradleError("Configured verification commands changed")
    probe = accepted[-1].candidate.model_copy(
        update={"origins": frozenset({"ordinary"})}
    )
    comparison = compare_gradle_snapshots(
        run.initial_snapshot, run.accepted_snapshot, probe
    )
    if not isinstance(comparison, VerifiedComparison):
        raise GradleError("Final snapshot regressed against original run baseline")
    credited = frozenset(
        key for attempt in accepted for key in attempt.receipt.verified_fixes
    )
    if credited & frozenset(item.key for item in run.accepted_snapshot.findings):
        raise GradleError("An earlier credited fix was reintroduced")
    for attempt in accepted:
        block = evaluate_gradle_candidate_age(
            attempt.candidate, minimum_age_days, publication, datetime.now(UTC)
        )
        if block is not None:
            raise GradleError(block.reason)


@contextmanager
def _gradle_evidence_workspace(
    project: ProjectConfig, revision: str
) -> Iterator[ProjectConfig]:
    resolved = exact_commit_id(project.path, revision)
    container = Path(tempfile.mkdtemp(prefix="mm-gradle-proof-"))
    token = uuid.uuid4().hex
    marker = container / ".mm-proof-owner"
    marker.write_text(token, encoding="utf-8")
    name = f"mm-proof-{token}"
    root = container / "workspace"
    registered = False
    try:
        result = _run(
            ["jj", "workspace", "add", "--name", name, "-r", resolved, str(root)],
            project.path,
        )
        if result.returncode != 0:
            raise GradleError("Cannot create recorded-baseline proof workspace")
        registered = True
        if not edit_new_change(root, resolved):
            raise GradleError("Cannot create empty proof change")
        yield project.model_copy(update={"path": root})
    finally:
        if registered:
            _run(["jj", "workspace", "forget", name], project.path)
        if (
            not container.is_symlink()
            and marker.is_file()
            and marker.read_text(encoding="utf-8") == token
        ):
            shutil.rmtree(container)


def rebuild_gradle_run_evidence(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    persist: bool = True,
) -> GradleRun:
    if run.has(ApplyingAttempt):
        raise GradleError("Reconcile interrupted attempt before rebuilding context")
    accepted = [
        item
        for item in run.attempts
        if isinstance(item, (ReadyAttempt, CompletedAttempt))
    ]
    with _gradle_evidence_workspace(project, run.base_commit_id) as base_project:
        catalogue = parse_catalogue(base_project.path / GRADLE_CATALOGUE_RELPATH)
        resolution = collect_gradle_resolution(base_project, catalogue)
        if isinstance(resolution, IncompleteResolution):
            raise GradleError("Recorded baseline cannot produce complete coverage")
        context = initialize_comparison_context(
            base_project, resolution, paths.gradle_contexts_dir()
        )
        try:
            _, initial = capture_checked_gradle_snapshot(
                base_project,
                run.project,
                context,
                expected_tree=revision_tree_id(base_project.path, run.base_commit_id),
            )
        except BaseException:
            discard_unpersisted_gradle_context(run.project, context)
            raise
    rebuilt_attempts: dict[str, ReadyAttempt | CompletedAttempt] = {}
    baseline = initial
    try:
        for old in accepted:
            with _gradle_evidence_workspace(
                project, old.receipt.accepted_commit_id
            ) as checked_project:
                checks, after = capture_checked_gradle_snapshot(
                    checked_project,
                    run.project,
                    context,
                    expected_tree=revision_tree_id(
                        checked_project.path, old.receipt.accepted_commit_id
                    ),
                    target=old.candidate.target,
                )
                comparison = compare_gradle_snapshots(baseline, after, old.candidate)
                if not isinstance(comparison, VerifiedComparison):
                    raise GradleError("Recorded accepted change fails fresh comparison")
                block = evaluate_gradle_candidate_age(
                    old.candidate,
                    minimum_age_days,
                    publication,
                    datetime.now(UTC),
                )
                if block is not None:
                    raise GradleError(block.reason)
                if not old.receipt.verified_fixes <= comparison.removed:
                    raise GradleError(
                        "Fresh context cannot prove every credited historical fix"
                    )
                receipt = VerificationReceipt(
                    checked_tree_id=after.tree_id,
                    accepted_commit_id=old.receipt.accepted_commit_id,
                    baseline_snapshot_id=baseline.snapshot_id,
                    after_snapshot_id=after.snapshot_id,
                    context_identity=context.identity,
                    checks=checks,
                    publications=publication.evidence_for(old.candidate),
                    verified_fixes=comparison.removed,
                    residual_keys=comparison.residual,
                )
                updates = {"baseline": baseline, "after": after, "receipt": receipt}
                rebuilt_attempts[old.candidate.target.group_key] = type(
                    old
                ).model_validate(dict(old) | updates)
                baseline = after
        attempts = tuple(
            rebuilt_attempts.get(item.candidate.target.group_key, item)
            for item in run.attempts
        )
        # A failed repair is compared against the newly proven accepted tip.
        attempts = tuple(
            item.model_copy(update={"baseline": baseline})
            if isinstance(item, FailedAttempt)
            else item
            for item in attempts
        )
        rebuilt = GradleRun.model_validate(
            dict(run)
            | {
                "context": context,
                "initial_snapshot": initial,
                "accepted_snapshot": baseline,
                "attempts": attempts,
            }
        )
        if persist:
            save_gradle_run(gradle_run_path(run.project), rebuilt)
            if run.context.private_cache_path != context.private_cache_path:
                retire_gradle_context(run.context)
        return rebuilt
    except BaseException:
        discard_unpersisted_gradle_context(run.project, context)
        raise


def rollback_failed_gradle_update(run: GradleRun, project: ProjectConfig) -> None:
    if run.flow != Workflow.UPDATE or run.has(ApplyingAttempt):
        raise GradleError("Rollback requires a failed update ledger")
    if not run.has(FailedAttempt):
        raise GradleError("Rollback requires a failed update ledger")
    reclaim_gradle_outputs(project.path)
    if (
        exact_commit_id(project.path, run.managed_bookmark) != run.managed_tip_id
        or exact_commit_id(project.path, "@-") != run.managed_tip_id
        or revision_tree_id(project.path, run.managed_tip_id)
        != run.accepted_snapshot.tree_id
    ):
        raise GradleError("Failed update is not a child of its recorded accepted tip")
    changed = _run(["jj", "diff", "--name-only", "-r", "@"], project.path)
    if changed.returncode != 0 or set(changed.stdout.splitlines()) - {
        str(GRADLE_CATALOGUE_RELPATH)
    }:
        raise GradleError("Failed update contains changes outside the owned catalogue")
    if current_change_has_changes(project.path) and not discard_current_change(
        project.path
    ):
        raise GradleError("Could not restore the latest accepted Gradle baseline")
    if (
        current_change_has_changes(project.path)
        or revision_tree_id(project.path) != run.accepted_snapshot.tree_id
    ):
        raise GradleError("Failed update rollback did not restore the accepted tree")


def reconcile_gradle_applying(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> GradleRun:
    pending = [item for item in run.attempts if isinstance(item, ApplyingAttempt)]
    if len(pending) != 1:
        raise GradleError("Expected one interrupted Gradle attempt")
    state = pending[0]
    complete = (
        state.after is not None
        and state.checks is not None
        and state.checked_tree_id is not None
    )
    commit = state.accepted_commit_id
    parent = exact_commit_id(project.path, "@-")
    if not complete or (commit is None and parent == run.managed_tip_id):
        # Includes intent-only, mutation/check interruption and checked intent
        # saved before commit. None is evidence of an accepted commit.
        failed = FailedAttempt(
            candidate=state.candidate,
            baseline=state.baseline,
            reason="Interrupted Gradle attempt requires rollback or committed repair",
            after=state.after,
        )
        run = _replace_gradle_attempt(run, failed)
        save_gradle_run(gradle_run_path(run.project), run)
        if run.flow == Workflow.UPDATE:
            rollback_failed_gradle_update(run, project)
        return run
    if commit is None:
        if current_change_has_changes(project.path):
            raise GradleError(
                "Interrupted working copy is not an empty committed child"
            )
        commit = parent
    ancestry = is_ancestor(project.path, run.managed_tip_id, commit)
    if not ancestry.ok or not ancestry.value or commit == run.managed_tip_id:
        raise GradleError("Interrupted checked commit has no trustworthy run ancestry")
    if (
        revision_tree_id(project.path, commit) != state.checked_tree_id
        or state.after.tree_id != state.checked_tree_id
    ):
        raise GradleError("Interrupted commit differs from checked tree")
    current_tip = exact_commit_id(project.path, run.managed_bookmark)
    if current_tip not in {run.managed_tip_id, commit}:
        raise GradleError("Managed bookmark moved outside interrupted attempt")
    block = validate_gradle_recovery(project, state.candidate.target)
    if block is not None:
        raise GradleError(block.reason)
    after, checks, checked_tree = state.after, state.checks, state.checked_tree_id
    if not context_inputs_valid(run.context, project, datetime.now(UTC)):
        # Keep the on-disk intent until BOTH historical accepted work and the
        # checked interrupted commit have been proven under one fresh context.
        previous_context = run.context
        prefix = run.model_copy(
            update={
                "attempts": tuple(item for item in run.attempts if item is not state)
            }
        )
        prefix = rebuild_gradle_run_evidence(
            prefix, project, publication, minimum_age_days, persist=False
        )
        try:
            with _gradle_evidence_workspace(project, commit) as checked_project:
                checks, after = capture_checked_gradle_snapshot(
                    checked_project,
                    run.project,
                    prefix.context,
                    expected_tree=state.checked_tree_id,
                    target=state.candidate.target,
                )
                state = state.model_copy(
                    update={
                        "baseline": prefix.accepted_snapshot,
                        "after": after,
                        "checks": checks,
                        "accepted_commit_id": commit,
                    }
                )
                run = _replace_gradle_attempt(prefix, state)
                save_gradle_run(gradle_run_path(run.project), run)
                if (
                    previous_context.private_cache_path
                    != prefix.context.private_cache_path
                ):
                    retire_gradle_context(previous_context)
        except BaseException:
            discard_unpersisted_gradle_context(run.project, prefix.context)
            raise
    comparison = compare_gradle_snapshots(state.baseline, after, state.candidate)
    if not isinstance(comparison, VerifiedComparison):
        raise GradleError("Interrupted comparison does not prove acceptance")
    block = evaluate_gradle_candidate_age(
        state.candidate, minimum_age_days, publication, datetime.now(UTC)
    )
    if block is not None:
        raise GradleError(block.reason)
    if not create_or_reset_bookmark(run.managed_bookmark, project.path, commit):
        raise GradleError("Cannot bind interrupted accepted bookmark")
    receipt = VerificationReceipt(
        checked_tree_id=checked_tree,
        accepted_commit_id=commit,
        baseline_snapshot_id=state.baseline.snapshot_id,
        after_snapshot_id=after.snapshot_id,
        context_identity=run.context.identity,
        checks=checks,
        publications=publication.evidence_for(state.candidate),
        verified_fixes=comparison.removed,
        residual_keys=comparison.residual,
    )
    accepted = ReadyAttempt(
        candidate=state.candidate,
        baseline=state.baseline,
        after=after,
        receipt=receipt,
    )
    run = _replace_gradle_attempt(run, accepted).model_copy(
        update={"managed_tip_id": commit, "accepted_snapshot": after}
    )
    run = GradleRun.model_validate(dict(run))
    save_gradle_run(gradle_run_path(run.project), run)
    return run


def continue_gradle_resolve(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
) -> GradleRun:
    if run.flow != Workflow.RESOLVE:
        raise GradleError("Continuation requires a resolve-owned Gradle run")
    reclaim_gradle_outputs(project.path)
    if current_change_has_changes(project.path):
        raise GradleError("Commit or discard manual changes before --continue")
    repaired_commit = exact_commit_id(project.path, "@-")
    ancestry = is_ancestor(project.path, run.managed_tip_id, repaired_commit)
    if not ancestry.ok or not ancestry.value or repaired_commit == run.managed_tip_id:
        raise GradleError("Repair must be a committed descendant of the managed tip")
    failures = [item for item in run.attempts if isinstance(item, FailedAttempt)]
    if len(failures) != 1:
        raise GradleError("Expected exactly one preserved resolve blocker")
    candidate = failures[0].candidate
    block = validate_gradle_recovery(project, candidate.target)
    if block is not None:
        raise GradleError(block.reason)
    if not context_inputs_valid(run.context, project, datetime.now(UTC)):
        run = rebuild_gradle_run_evidence(run, project, publication, minimum_age_days)
    try:
        return verify_applied_gradle_attempt(
            run,
            candidate,
            project,
            publication,
            minimum_age_days,
            committed_revision=repaired_commit,
        )
    except (GradleError, ScanError, RevisionError) as exc:
        latest = load_gradle_run(gradle_run_path(run.project)) or run
        state = next(
            item
            for item in latest.attempts
            if item.candidate.target.group_key == candidate.target.group_key
        )
        if isinstance(state, ApplyingAttempt) and state.checked_tree_id is not None:
            raise
        failed = FailedAttempt(
            candidate=candidate,
            baseline=latest.accepted_snapshot,
            reason=str(exc),
            after=state.after
            if isinstance(state, (ApplyingAttempt, FailedAttempt))
            else None,
        )
        save_gradle_run(
            gradle_run_path(run.project), _replace_gradle_attempt(latest, failed)
        )
        raise
