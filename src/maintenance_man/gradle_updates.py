"""Verified Gradle attempts, durable evidence, and recovery."""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from maintenance_man import paths
from maintenance_man.clock import Clock, utc_now
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
from maintenance_man.models.events import Emit
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
    PublicationEvidence,
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
from maintenance_man.vcs import Repository, RevisionError
from maintenance_man.vcs_workflow import VcsServices, make_vcs_services


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


def persist_gradle_run(run: GradleRun) -> None:
    """Save a run to its canonical project ledger."""
    save_gradle_run(gradle_run_path(run.project), run)


def _verification_receipt(
    *,
    baseline: GradleSnapshot,
    after: GradleSnapshot,
    context: ComparisonContext,
    checks: CheckEvidence,
    commit_id: str,
    comparison: VerifiedComparison,
    publications: tuple[PublicationEvidence, ...],
) -> VerificationReceipt:
    return VerificationReceipt(
        checked_tree_id=after.tree_id,
        accepted_commit_id=commit_id,
        baseline_snapshot_id=baseline.snapshot_id,
        after_snapshot_id=after.snapshot_id,
        context_identity=context.identity,
        checks=checks,
        publications=publications,
        verified_fixes=comparison.removed,
        residual_keys=comparison.residual,
    )


def _accept_attempt(run: GradleRun, attempt: ReadyAttempt) -> GradleRun:
    """Advance the managed tip and accepted snapshot to a verified attempt."""
    advanced = _replace_gradle_attempt(run, attempt).model_copy(
        update={
            "managed_tip_id": attempt.receipt.accepted_commit_id,
            "accepted_snapshot": attempt.after,
        }
    )
    return GradleRun.model_validate(dict(advanced))


def _require_publication_age(
    candidate: GradleCandidate,
    minimum_age_days: int,
    publication: PublicationLookupContext,
    *,
    clock: Clock,
) -> None:
    block = evaluate_gradle_candidate_age(
        candidate, minimum_age_days, publication, clock()
    )
    if block is not None:
        raise GradleError(block.reason)


def _record_failed_attempt(
    run: GradleRun, candidate: GradleCandidate, reason: str
) -> GradleRun | None:
    """Save a FAILED attempt, or return None when checked intent must survive."""
    latest = load_gradle_run(gradle_run_path(run.project)) or run
    state = next(
        item
        for item in latest.attempts
        if item.candidate.target.group_key == candidate.target.group_key
    )
    if isinstance(state, ApplyingAttempt) and state.checked_tree_id is not None:
        # A checked commit may already exist. Recovery must reconcile it;
        # never discard or synthesize a failure after that irreversible effect.
        return None
    failed = FailedAttempt(
        candidate=candidate,
        baseline=latest.accepted_snapshot,
        reason=reason,
        after=state.after
        if isinstance(state, (ApplyingAttempt, FailedAttempt))
        else None,
    )
    latest = _replace_gradle_attempt(latest, failed)
    persist_gradle_run(latest)
    return latest


def _restore_accepted_baseline(
    run: GradleRun, repo: Repository, cause: Exception
) -> None:
    try:
        repo.discard()
    except RevisionError as restore_exc:
        raise GradleError(
            "Could not restore the latest accepted Gradle baseline"
        ) from restore_exc
    if repo.tree_id() != run.accepted_snapshot.tree_id:
        raise GradleError(
            "Could not restore the latest accepted Gradle baseline"
        ) from cause


def gradle_check_commands(project: ProjectConfig) -> tuple[str, ...]:
    tests = tuple(command for _, command in project.test_phases)
    if not project.build_command or not tests:
        raise GradleError(
            "Setup prerequisite: configure build_command and at least one test phase"
        )
    return (project.build_command, *tests)


def run_gradle_checks(
    project: ProjectConfig,
    project_name: str,
    *,
    emit: Emit,
    clock: Clock = utc_now,
) -> CheckEvidence:
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
    passed, phase = run_test_phases(project, project.path, emit=emit)
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
        checked_at=clock(),
    )


def capture_checked_gradle_snapshot(
    project: ProjectConfig,
    project_name: str,
    context: ComparisonContext,
    *,
    expected_tree: str | None = None,
    target: GradleUpdateTarget | None = None,
    vcs: VcsServices | None = None,
    emit: Emit,
    clock: Clock = utc_now,
) -> tuple[CheckEvidence, GradleSnapshot]:
    """Bind build, tests and security evidence to one unchanged source tree."""
    services = vcs or make_vcs_services()
    repo = services.repository(Path(project.path))
    tree = expected_tree or repo.tree_id()
    if repo.tree_id() != tree:
        raise GradleError("Working tree differs from the verification revision")
    if target is not None:
        block = validate_gradle_recovery(project, target)
        if block is not None:
            raise GradleError(block.reason)
    checks = run_gradle_checks(project, project_name, emit=emit, clock=clock)
    if repo.tree_id() != tree:
        raise GradleError("Source tree changed during build or tests")
    snapshot = capture_gradle_snapshot(project, context, vcs=services, clock=clock)
    if isinstance(snapshot, IncompleteResolution):
        raise GradleError("Coverage incomplete: " + "; ".join(snapshot.reasons))
    if snapshot.tree_id != tree or repo.tree_id() != tree:
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
    vcs: VcsServices | None = None,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun:
    services = vcs or make_vcs_services()
    repo = services.repository(Path(project.path))
    _, baseline = capture_checked_gradle_snapshot(
        project,
        project_name,
        context,
        expected_tree=repo.tree_id(revision=base_commit_id),
        vcs=services,
        emit=emit,
        clock=clock,
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
        persist_gradle_run(run)
    return run


def verify_applied_gradle_attempt(
    run: GradleRun,
    candidate: GradleCandidate,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    committed_revision: str | None = None,
    vcs: VcsServices | None = None,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun:
    services = vcs or make_vcs_services()
    repo = services.repository(Path(project.path))
    gradle_run_path(run.project)  # refuse an invalid ledger path before any effect
    checks, after = capture_checked_gradle_snapshot(
        project,
        run.project,
        run.context,
        target=candidate.target,
        expected_tree=(
            repo.tree_id(revision=committed_revision)
            if committed_revision is not None
            else None
        ),
        vcs=services,
        emit=emit,
        clock=clock,
    )
    # Persist the rejected snapshot too: it is diagnostic evidence, not READY.
    observed = ApplyingAttempt(
        candidate=candidate, baseline=run.accepted_snapshot, checks=checks, after=after
    )
    run = _replace_gradle_attempt(run, observed)
    persist_gradle_run(run)
    comparison = compare_gradle_snapshots(run.accepted_snapshot, after, candidate)
    if not isinstance(comparison, VerifiedComparison):
        raise GradleError(
            "Security verification failed: " + "; ".join(comparison.reasons)
        )
    _require_publication_age(candidate, minimum_age_days, publication, clock=clock)
    checked_tree = repo.tree_id()
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
    persist_gradle_run(run)
    if committed_revision is None:
        try:
            dirty = repo.has_changes()
        except RevisionError as exc:
            raise GradleError(
                "Could not inspect tracked changes before Gradle commit"
            ) from exc
        if not dirty:
            raise GradleError("Candidate made no tracked source change")
        target = candidate.target
        repo.commit(
            message=f"chore: bump {target.display_name} to {target.target_version}"
        )
        commit_id = repo.resolve_revision(revision="@-")
    else:
        commit_id = repo.resolve_revision(revision=committed_revision)
    if repo.tree_id(revision=commit_id) != checked_tree:
        raise GradleError("Accepted commit tree differs from checked tree")
    prepared = prepared.model_copy(update={"accepted_commit_id": commit_id})
    run = _replace_gradle_attempt(run, prepared)
    persist_gradle_run(run)
    if repo.bookmark_exists(bookmark=run.managed_bookmark):
        repo.set_bookmark(bookmark=run.managed_bookmark, revision=commit_id)
    else:
        repo.create_bookmark(bookmark=run.managed_bookmark, revision=commit_id)
    receipt = _verification_receipt(
        baseline=run.accepted_snapshot,
        after=after,
        context=run.context,
        checks=checks,
        commit_id=commit_id,
        comparison=comparison,
        publications=publication.evidence_for(candidate),
    )
    accepted = ReadyAttempt(
        candidate=candidate,
        baseline=run.accepted_snapshot,
        after=after,
        receipt=receipt,
    )
    run = _accept_attempt(run, accepted)
    persist_gradle_run(run)
    return run


def process_gradle_run(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices | None = None,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun:
    services = vcs or make_vcs_services()
    repo = services.repository(Path(project.path))
    for planned in tuple(run.attempts):
        if not isinstance(planned, PlannedAttempt):
            continue
        candidate = planned.candidate
        block = validate_gradle_target(project, candidate.target)
        age = evaluate_gradle_candidate_age(
            candidate, minimum_age_days, publication, clock()
        )
        reason = block.reason if block else age.reason if age else None
        if reason:
            run = _replace_gradle_attempt(
                run, WithheldAttempt(candidate=candidate, reason=reason)
            )
            persist_gradle_run(run)
            continue
        if not context_inputs_valid(run.context, project, clock()):
            raise GradleError(
                "Comparison context expired or changed; "
                "rebuild evidence before continuing"
            )
        run = _replace_gradle_attempt(
            run, ApplyingAttempt(candidate=candidate, baseline=run.accepted_snapshot)
        )
        persist_gradle_run(run)
        try:
            block = apply_gradle_update(project, candidate.target)
            if block is not None:
                raise GradleError(block.reason)
            run = verify_applied_gradle_attempt(
                run,
                candidate,
                project,
                publication,
                minimum_age_days,
                vcs=services,
                emit=emit,
                clock=clock,
            )
        except (GradleError, ScanError, RevisionError) as exc:
            # Reads latest pre-effect intent to retain commit-crash evidence.
            failed = _record_failed_attempt(run, candidate, str(exc))
            if failed is None:
                raise
            run = failed
            if run.flow != Workflow.UPDATE:
                return run
            _restore_accepted_baseline(run, repo, exc)
    return run


def gradle_run_finalization_check(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices | None = None,
    clock: Clock = utc_now,
) -> None:
    services = vcs or make_vcs_services()
    repo = services.repository(Path(project.path))
    if run.has(ApplyingAttempt, FailedAttempt, PlannedAttempt):
        raise GradleError("Unfinished or failed Gradle attempt prevents finalization")
    accepted = [
        attempt
        for attempt in run.attempts
        if isinstance(attempt, (ReadyAttempt, CompletedAttempt))
    ]
    if not accepted:
        raise GradleError("No verified Gradle update to finalize")
    if not context_inputs_valid(run.context, project, clock()):
        raise GradleError("Final comparison context is stale")
    if (
        repo.resolve_revision(revision=run.managed_bookmark) != run.managed_tip_id
        or repo.tree_id(revision=run.managed_tip_id) != run.accepted_snapshot.tree_id
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
        _require_publication_age(
            attempt.candidate, minimum_age_days, publication, clock=clock
        )


@contextmanager
def gradle_evidence_workspace(
    project: ProjectConfig, revision: str, *, vcs: VcsServices
) -> Iterator[ProjectConfig]:
    manager = vcs.repository(Path(project.path)).temporary_workspace(revision=revision)
    try:
        workspace = manager.__enter__()
    except RevisionError as exc:
        raise GradleError("Cannot create recorded-baseline proof workspace") from exc
    try:
        yield project.model_copy(update={"path": workspace.path})
    except BaseException as body_error:
        try:
            suppressed = manager.__exit__(
                type(body_error), body_error, body_error.__traceback__
            )
        except BaseException as cleanup_error:
            if cleanup_error is body_error:
                raise
            body_error.add_note(f"proof workspace cleanup failed: {cleanup_error}")
            raise body_error from cleanup_error
        if not suppressed:
            raise
    else:
        try:
            manager.__exit__(None, None, None)
        except RevisionError as exc:
            raise GradleError(
                "Cannot clean up recorded-baseline proof workspace"
            ) from exc


def rebuild_gradle_run_evidence(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    persist: bool = True,
    vcs: VcsServices | None = None,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun:
    services = vcs or make_vcs_services()
    if run.has(ApplyingAttempt):
        raise GradleError("Reconcile interrupted attempt before rebuilding context")
    accepted = [
        item
        for item in run.attempts
        if isinstance(item, (ReadyAttempt, CompletedAttempt))
    ]
    with gradle_evidence_workspace(
        project, run.base_commit_id, vcs=services
    ) as base_project:
        base_repo = services.repository(Path(base_project.path))
        parse_catalogue(base_project.path / GRADLE_CATALOGUE_RELPATH)
        resolution = collect_gradle_resolution(base_project)
        if isinstance(resolution, IncompleteResolution):
            raise GradleError("Recorded baseline cannot produce complete coverage")
        context = initialize_comparison_context(
            base_project, resolution, paths.gradle_contexts_dir(), clock=clock
        )
        try:
            _, initial = capture_checked_gradle_snapshot(
                base_project,
                run.project,
                context,
                expected_tree=base_repo.tree_id(revision=run.base_commit_id),
                vcs=services,
                emit=emit,
                clock=clock,
            )
        except BaseException:
            discard_unpersisted_gradle_context(run.project, context)
            raise
    rebuilt_attempts: dict[str, ReadyAttempt | CompletedAttempt] = {}
    baseline = initial
    try:
        for old in accepted:
            with gradle_evidence_workspace(
                project, old.receipt.accepted_commit_id, vcs=services
            ) as checked_project:
                checked_repo = services.repository(Path(checked_project.path))
                checks, after = capture_checked_gradle_snapshot(
                    checked_project,
                    run.project,
                    context,
                    expected_tree=checked_repo.tree_id(
                        revision=old.receipt.accepted_commit_id
                    ),
                    target=old.candidate.target,
                    vcs=services,
                    emit=emit,
                    clock=clock,
                )
                comparison = compare_gradle_snapshots(baseline, after, old.candidate)
                if not isinstance(comparison, VerifiedComparison):
                    raise GradleError("Recorded accepted change fails fresh comparison")
                _require_publication_age(
                    old.candidate, minimum_age_days, publication, clock=clock
                )
                if not old.receipt.verified_fixes <= comparison.removed:
                    raise GradleError(
                        "Fresh context cannot prove every credited historical fix"
                    )
                receipt = _verification_receipt(
                    baseline=baseline,
                    after=after,
                    context=context,
                    checks=checks,
                    commit_id=old.receipt.accepted_commit_id,
                    comparison=comparison,
                    publications=publication.evidence_for(old.candidate),
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
            persist_gradle_run(rebuilt)
            if run.context.private_cache_path != context.private_cache_path:
                retire_gradle_context(run.context)
        return rebuilt
    except BaseException:
        discard_unpersisted_gradle_context(run.project, context)
        raise


def rollback_failed_gradle_update(
    run: GradleRun,
    project: ProjectConfig,
    *,
    vcs: VcsServices | None = None,
) -> None:
    services = vcs or make_vcs_services()
    repo = services.repository(Path(project.path))
    if run.flow != Workflow.UPDATE or run.has(ApplyingAttempt):
        raise GradleError("Rollback requires a failed update ledger")
    if not run.has(FailedAttempt):
        raise GradleError("Rollback requires a failed update ledger")
    reclaim_gradle_outputs(project.path)
    if (
        repo.resolve_revision(revision=run.managed_bookmark) != run.managed_tip_id
        or repo.resolve_revision(revision="@-") != run.managed_tip_id
        or repo.tree_id(revision=run.managed_tip_id) != run.accepted_snapshot.tree_id
    ):
        raise GradleError("Failed update is not a child of its recorded accepted tip")
    changed = repo.changed_paths()
    if changed - {str(GRADLE_CATALOGUE_RELPATH)}:
        raise GradleError("Failed update contains changes outside the owned catalogue")
    try:
        dirty = repo.has_changes()
    except RevisionError as exc:
        raise GradleError("Could not inspect failed Gradle workspace") from exc
    if dirty:
        try:
            repo.discard()
        except RevisionError as exc:
            raise GradleError(
                "Could not restore the latest accepted Gradle baseline"
            ) from exc
    try:
        dirty = repo.has_changes()
    except RevisionError as exc:
        raise GradleError("Could not inspect failed Gradle workspace") from exc
    if dirty or repo.tree_id() != run.accepted_snapshot.tree_id:
        raise GradleError("Failed update rollback did not restore the accepted tree")


def _record_interrupted_failure(
    run: GradleRun,
    state: ApplyingAttempt,
    project: ProjectConfig,
    *,
    vcs: VcsServices,
) -> GradleRun:
    """Record an uncommitted interruption as FAILED, then roll an update back."""
    failed = FailedAttempt(
        candidate=state.candidate,
        baseline=state.baseline,
        reason="Interrupted Gradle attempt requires rollback or committed repair",
        after=state.after,
    )
    run = _replace_gradle_attempt(run, failed)
    persist_gradle_run(run)
    if run.flow == Workflow.UPDATE:
        rollback_failed_gradle_update(run, project, vcs=vcs)
    return run


def _interrupted_commit(
    run: GradleRun, state: ApplyingAttempt, parent: str, repo: Repository
) -> str:
    commit = state.accepted_commit_id
    if commit is None:
        if repo.has_changes():
            raise GradleError(
                "Interrupted working copy is not an empty committed child"
            )
        commit = parent
    if (
        not repo.is_ancestor(ancestor=run.managed_tip_id, descendant=commit)
        or commit == run.managed_tip_id
    ):
        raise GradleError("Interrupted checked commit has no trustworthy run ancestry")
    if (
        repo.tree_id(revision=commit) != state.checked_tree_id
        or state.after is None
        or state.after.tree_id != state.checked_tree_id
    ):
        raise GradleError("Interrupted commit differs from checked tree")
    current_tip = repo.resolve_revision(revision=run.managed_bookmark)
    if current_tip not in {run.managed_tip_id, commit}:
        raise GradleError("Managed bookmark moved outside interrupted attempt")
    return commit


def _reprove_interrupted_commit(
    run: GradleRun,
    state: ApplyingAttempt,
    commit: str,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices,
    emit: Emit,
    clock: Clock,
) -> tuple[GradleRun, ApplyingAttempt]:
    # Keep the on-disk intent until BOTH historical accepted work and the
    # checked interrupted commit have been proven under one fresh context.
    previous_context = run.context
    prefix = run.model_copy(
        update={"attempts": tuple(item for item in run.attempts if item is not state)}
    )
    prefix = rebuild_gradle_run_evidence(
        prefix,
        project,
        publication,
        minimum_age_days,
        persist=False,
        vcs=vcs,
        emit=emit,
        clock=clock,
    )
    try:
        with gradle_evidence_workspace(project, commit, vcs=vcs) as checked_project:
            checks, after = capture_checked_gradle_snapshot(
                checked_project,
                run.project,
                prefix.context,
                expected_tree=state.checked_tree_id,
                target=state.candidate.target,
                vcs=vcs,
                emit=emit,
                clock=clock,
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
            persist_gradle_run(run)
            if previous_context.private_cache_path != prefix.context.private_cache_path:
                retire_gradle_context(previous_context)
    except BaseException:
        discard_unpersisted_gradle_context(run.project, prefix.context)
        raise
    return run, state


def reconcile_gradle_applying(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices | None = None,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun:
    services = vcs or make_vcs_services()
    repo = services.repository(Path(project.path))
    pending = [item for item in run.attempts if isinstance(item, ApplyingAttempt)]
    if len(pending) != 1:
        raise GradleError("Expected one interrupted Gradle attempt")
    state = pending[0]
    complete = (
        state.after is not None
        and state.checks is not None
        and state.checked_tree_id is not None
    )
    parent = repo.resolve_revision(revision="@-")
    if not complete or (
        state.accepted_commit_id is None and parent == run.managed_tip_id
    ):
        # Includes intent-only, mutation/check interruption and checked intent
        # saved before commit. None is evidence of an accepted commit.
        return _record_interrupted_failure(run, state, project, vcs=services)
    commit = _interrupted_commit(run, state, parent, repo)
    block = validate_gradle_recovery(project, state.candidate.target)
    if block is not None:
        raise GradleError(block.reason)
    if not context_inputs_valid(run.context, project, clock()):
        run, state = _reprove_interrupted_commit(
            run,
            state,
            commit,
            project,
            publication,
            minimum_age_days,
            vcs=services,
            emit=emit,
            clock=clock,
        )
    after, checks = state.after, state.checks
    assert after is not None and checks is not None  # proven complete above
    comparison = compare_gradle_snapshots(state.baseline, after, state.candidate)
    if not isinstance(comparison, VerifiedComparison):
        raise GradleError("Interrupted comparison does not prove acceptance")
    _require_publication_age(
        state.candidate, minimum_age_days, publication, clock=clock
    )
    if repo.bookmark_exists(bookmark=run.managed_bookmark):
        repo.set_bookmark(bookmark=run.managed_bookmark, revision=commit)
    else:
        repo.create_bookmark(bookmark=run.managed_bookmark, revision=commit)
    receipt = _verification_receipt(
        baseline=state.baseline,
        after=after,
        context=run.context,
        checks=checks,
        commit_id=commit,
        comparison=comparison,
        publications=publication.evidence_for(state.candidate),
    )
    accepted = ReadyAttempt(
        candidate=state.candidate,
        baseline=state.baseline,
        after=after,
        receipt=receipt,
    )
    run = _accept_attempt(run, accepted)
    persist_gradle_run(run)
    return run


def continue_gradle_resolve(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices | None = None,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun:
    services = vcs or make_vcs_services()
    repo = services.repository(Path(project.path))
    if run.flow != Workflow.RESOLVE:
        raise GradleError("Continuation requires a resolve-owned Gradle run")
    reclaim_gradle_outputs(project.path)
    try:
        dirty = repo.has_changes()
    except RevisionError as exc:
        raise GradleError("Could not inspect manual changes before --continue") from exc
    if dirty:
        raise GradleError("Commit or discard manual changes before --continue")
    repaired_commit = repo.resolve_revision(revision="@-")
    if (
        not repo.is_ancestor(ancestor=run.managed_tip_id, descendant=repaired_commit)
        or repaired_commit == run.managed_tip_id
    ):
        raise GradleError("Repair must be a committed descendant of the managed tip")
    failures = [item for item in run.attempts if isinstance(item, FailedAttempt)]
    if len(failures) != 1:
        raise GradleError("Expected exactly one preserved resolve blocker")
    candidate = failures[0].candidate
    block = validate_gradle_recovery(project, candidate.target)
    if block is not None:
        raise GradleError(block.reason)
    if not context_inputs_valid(run.context, project, clock()):
        run = rebuild_gradle_run_evidence(
            run,
            project,
            publication,
            minimum_age_days,
            vcs=services,
            emit=emit,
            clock=clock,
        )
    try:
        return verify_applied_gradle_attempt(
            run,
            candidate,
            project,
            publication,
            minimum_age_days,
            committed_revision=repaired_commit,
            vcs=services,
            emit=emit,
            clock=clock,
        )
    except (GradleError, ScanError, RevisionError) as exc:
        _record_failed_attempt(run, candidate, str(exc))
        raise
