"""Gradle workflow preparation, workspace coordination, and finalization."""

import contextlib
import uuid
from collections.abc import Callable
from pathlib import Path

from maintenance_man import gradle_updates as gradle_updater
from maintenance_man import paths
from maintenance_man.clock import Clock, utc_now
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    filter_gradle_updates_by_age,
)
from maintenance_man.github import CodeHostError
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GradleError,
    discover_gradle_updates,
    parse_catalogue,
    workspace_environment_reason,
)
from maintenance_man.gradle_resolution import (
    prepare_gradle_candidates,
    select_gradle_candidates,
)
from maintenance_man.gradle_verification import (
    context_inputs_valid,
    initialize_comparison_context,
    release_comparison_context,
    snapshot_vulnerabilities,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    Emit,
    GradleFlowFailed,
    GradleRunArchived,
    GradleRunReported,
    GradleWithheld,
    NoEligibleGradleChanges,
    Outcome,
    PullRequestOutput,
    ScanReported,
)
from maintenance_man.models.gradle import (
    ApplyingAttempt,
    CompletedAttempt,
    FailedAttempt,
    GradleCandidate,
    GradleRun,
    PlannedAttempt,
    ReadyAttempt,
    WithheldAttempt,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    ScanResult,
    UpdateFinding,
    UpdateStatus,
    Workflow,
)
from maintenance_man.process import ToolNotFoundError
from maintenance_man.scanner import (
    ScanError,
    scan_gradle,
    scan_secrets,
)
from maintenance_man.storage import (
    NoScanResultsError,
    fsync_dir,
    load_scan_results,
    save_scan_results,
)
from maintenance_man.vcs import (
    ExpectedRevisions,
    RevisionError,
    workspace_path_for_project,
)
from maintenance_man.vcs_workflow import (
    VcsServices,
    create_workspace,
    ensure_main_bookmark,
    make_vcs_services,
    prune_stale_bookmarks,
    push_bookmark_and_create_pr,
    refresh_working_copy_from_main,
    remove_workspace,
)

type GradleChooser = Callable[
    [tuple[GradleCandidate, ...]], tuple[GradleCandidate, ...]
]


def _prepare_gradle_run(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    base: str,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    discovered: list[UpdateFinding] | None = None,
    *,
    choose: GradleChooser | None,
    vcs: VcsServices,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun | Outcome:
    # Resolve current security findings even when discovery produces no proposals.
    vulnerabilities, resolution = scan_gradle(project)
    catalogue = parse_catalogue(project.path / GRADLE_CATALOGUE_RELPATH)
    proposals = (
        discovered if discovered is not None else discover_gradle_updates(project)
    )
    plan = select_gradle_candidates(catalogue, resolution, vulnerabilities, proposals)
    candidates = (
        choose(plan.candidates)
        if choose is not None and plan.candidates
        else plan.candidates
    )
    prepared = prepare_gradle_candidates(
        project, candidates, resolution, publication, minimum_age_days, clock=clock
    )
    attempts = tuple(
        WithheldAttempt(candidate=item.candidate, reason=item.block.reason)
        if item.block
        else PlannedAttempt(candidate=item.candidate)
        for item in prepared
    )
    if not any(isinstance(item, PlannedAttempt) for item in attempts):
        emit(
            ScanReported(
                ScanResult(
                    project=project_name,
                    scanned_at=clock(),
                    trivy_target=str(project.path),
                    vulnerabilities=vulnerabilities,
                    gradle_resolution=resolution.report.model_dump(mode="json"),
                )
            )
        )
        for withheld in plan.withheld:
            emit(GradleWithheld(withheld.coordinate, withheld.reason))
        for item in prepared:
            if item.block:
                emit(
                    GradleWithheld(
                        item.candidate.target.display_name, item.block.reason
                    )
                )
        emit(NoEligibleGradleChanges())
        return (
            Outcome.FAILED
            if attempts or plan.withheld or vulnerabilities
            else Outcome.SUCCEEDED
        )
    gradle_updater.gradle_check_commands(project)
    context = initialize_comparison_context(
        project, resolution, paths.gradle_contexts_dir(), clock=clock
    )
    try:
        # The first durable record is a complete plan and checked baseline.
        # Failures before this point have no candidate effects and retry from scratch.
        run = gradle_updater.start_gradle_run(
            project_name,
            project,
            flow,
            base,
            context,
            (),
            persist=False,
            vcs=vcs,
            emit=emit,
            clock=clock,
        )
        run = GradleRun.model_validate(
            dict(run) | {"attempts": attempts, "selection_blocks": plan.withheld}
        )
        gradle_updater.persist_gradle_run(run)
        return run
    except BaseException:
        gradle_updater.discard_unpersisted_gradle_context(project_name, context)
        raise


def _complete_gradle_attempts(run: GradleRun) -> GradleRun:
    attempts = tuple(
        CompletedAttempt(
            candidate=item.candidate,
            baseline=item.baseline,
            after=item.after,
            receipt=item.receipt,
            promoted_commit_id=run.managed_tip_id,
        )
        if isinstance(item, ReadyAttempt)
        else item
        for item in run.attempts
    )
    return GradleRun.model_validate(dict(run) | {"attempts": attempts})


def _publish_verified_gradle_scan(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices,
    clock: Clock = utc_now,
) -> None:
    repo = vcs.repository(Path(project.path))
    if repo.tree_id() != run.accepted_snapshot.tree_id:
        msg = "Refreshed working tree differs from verified tree"
        raise GradleError(msg)
    discovered = filter_gradle_updates_by_age(
        discover_gradle_updates(project),
        project,
        run.accepted_snapshot.resolution,
        minimum_age_days,
        publication,
    )
    rows = snapshot_vulnerabilities(run.accepted_snapshot)
    secrets = (
        scan_secrets(project.path, project.scan_skip_dirs)
        if project.scan_secrets
        else []
    )
    fresh = ScanResult(
        project=run.project,
        scanned_at=clock(),
        trivy_target=str(project.path),
        vulnerabilities=rows,
        secrets=secrets,
        updates=discovered,
        gradle_resolution=run.accepted_snapshot.resolution.report.model_dump(
            mode="json"
        ),
    )
    if repo.tree_id() != run.accepted_snapshot.tree_id:
        msg = "Source changed while publishing verified findings"
        raise GradleError(msg)
    save_scan_results(run.project, fresh)


def _require_gradle_accepted_workspace(
    run: GradleRun, project: ProjectConfig, *, vcs: VcsServices
) -> None:
    repo = vcs.repository(Path(project.path))
    if repo.has_changes():
        msg = "Automatic Gradle processing requires an empty working change"
        raise GradleError(msg)
    if repo.resolve_revision(revision="@-") != run.managed_tip_id:
        msg = "Working change is not an empty child of the recorded accepted tip"
        raise GradleError(msg)
    if (
        repo.resolve_revision(revision=run.managed_bookmark) != run.managed_tip_id
        or repo.tree_id(revision=run.managed_tip_id) != run.accepted_snapshot.tree_id
        or repo.tree_id() != run.accepted_snapshot.tree_id
    ):
        msg = "Working revision differs from the recorded accepted snapshot"
        raise GradleError(msg)


def _finish_verified_gradle_run(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun:
    # Verification reads the accepted revision, not the source workspace's old tree.
    with gradle_updater.gradle_evidence_workspace(
        project, run.managed_tip_id, vcs=vcs
    ) as verified:
        if not context_inputs_valid(run.context, verified, clock()):
            run = gradle_updater.rebuild_gradle_run_evidence(
                run,
                verified,
                publication,
                minimum_age_days,
                vcs=vcs,
                emit=emit,
                clock=clock,
            )
        gradle_updater.gradle_run_finalization_check(
            run, verified, publication, minimum_age_days, vcs=vcs, clock=clock
        )
    if run.flow == Workflow.RESOLVE:
        return _submit_gradle_run(run, project, vcs=vcs, emit=emit)
    run = _promote_gradle_run(run, project, vcs=vcs)
    return _refresh_gradle_run(
        run, project, publication, minimum_age_days, vcs=vcs, clock=clock
    )


def _submit_gradle_run(
    run: GradleRun, project: ProjectConfig, *, vcs: VcsServices, emit: Emit
) -> GradleRun:
    if run.submitted:
        return run
    output = push_bookmark_and_create_pr(
        repo=vcs.repository(Path(project.path)),
        host=vcs.code_host(Path(project.path)),
        bookmark=run.managed_bookmark,
        expected=ExpectedRevisions(base=run.base_commit_id, tip=run.managed_tip_id),
    )
    if output:
        emit(PullRequestOutput(output))
    run = _complete_gradle_attempts(run.model_copy(update={"submitted": True}))
    gradle_updater.persist_gradle_run(run)
    return run


def _promote_gradle_run(
    run: GradleRun, project: ProjectConfig, *, vcs: VcsServices
) -> GradleRun:
    repo = vcs.repository(Path(project.path))
    main = repo.resolve_revision(revision="main")
    if run.promoted_commit_id is None:
        if main != run.managed_tip_id:
            repo.promote_bookmark_to_main(
                bookmark=run.managed_bookmark,
                expected=ExpectedRevisions(
                    base=run.base_commit_id, tip=run.managed_tip_id
                ),
            )
        # main already equals verified tip also covers crash after promotion but
        # before this durable record. Finalization above still checks exact tip.
        run = run.model_copy(update={"promoted_commit_id": run.managed_tip_id})
        gradle_updater.persist_gradle_run(run)
    elif run.promoted_commit_id != run.managed_tip_id or main != run.promoted_commit_id:
        msg = "Main moved after recorded Gradle promotion"
        raise GradleError(msg)
    return run


def _refresh_gradle_run(
    run: GradleRun,
    project: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices,
    clock: Clock = utc_now,
) -> GradleRun:
    if run.refreshed:
        return run
    repo = vcs.repository(Path(project.path))
    try:
        refresh_working_copy_from_main(repo=repo)
    except RevisionError as exc:
        msg = "Promotion recorded; working-copy refresh failed, retry update"
        raise GradleError(msg) from exc
    if repo.resolve_revision(revision="main") != run.managed_tip_id:
        msg = "Main moved during refresh"
        raise GradleError(msg)
    _publish_verified_gradle_scan(
        run, project, publication, minimum_age_days, vcs=vcs, clock=clock
    )
    run = _complete_gradle_attempts(run.model_copy(update={"refreshed": True}))
    gradle_updater.persist_gradle_run(run)
    return run


def _archive_rolled_back_gradle_run(
    run: GradleRun, project: ProjectConfig, *, vcs: VcsServices, emit: Emit
) -> None:
    if (
        run.flow != Workflow.UPDATE
        or run.promoted_commit_id is not None
        or run.has(ApplyingAttempt)
        or not run.has(FailedAttempt)
    ):
        msg = "Only rolled-back failed update runs can restart"
        raise GradleError(msg)
    workspace = workspace_path_for_project(run.project)
    if not workspace.exists():
        msg = "Uncommitted or missing failed workspace requires manual review"
        raise GradleError(msg)
    # Repeat guarded rollback after a crash between saving Failed and restoring.
    gradle_updater.rollback_failed_gradle_update(
        run,
        project.model_copy(update={"path": workspace}),
        vcs=vcs,
    )
    workspace_repo = vcs.repository(workspace)
    source_repo = vcs.repository(Path(project.path))
    if workspace_repo.has_changes():
        msg = "Uncommitted or missing failed workspace requires manual review"
        raise GradleError(msg)
    if (
        source_repo.resolve_revision(revision="main") != run.base_commit_id
        or workspace_repo.resolve_revision(revision=run.managed_bookmark)
        != run.managed_tip_id
        or workspace_repo.resolve_revision(revision="@-") != run.managed_tip_id
        or workspace_repo.tree_id() != run.accepted_snapshot.tree_id
        or workspace_repo.tree_id(revision=run.managed_tip_id)
        != run.accepted_snapshot.tree_id
    ):
        msg = "Failed update rollback cannot be proven; retained for manual review"
        raise GradleError(msg)
    path = gradle_updater.gradle_run_path(run.project)
    archive = path.parent / "history" / f"{path.stem}-{uuid.uuid4().hex}.json"
    gradle_updater.save_gradle_run(archive, run)
    try:
        source_repo.reset_verified_bookmark(
            bookmark=run.managed_bookmark,
            expected=ExpectedRevisions(base=run.base_commit_id, tip=run.managed_tip_id),
        )
    except RevisionError as exc:
        msg = "Revisions changed during restart; original ledger retained"
        raise GradleError(msg) from exc
    path.unlink()
    fsync_dir(path.parent)
    gradle_updater.retire_gradle_context(run.context)
    emit(GradleRunArchived(archive))


def pin_workspace_revision(
    project_name: str,
    project: ProjectConfig,
    revision: str,
    *,
    vcs: VcsServices,
) -> str:
    """Verify SDK file availability and pin the revision inspected."""
    reason = workspace_environment_reason(
        project.path, workspace_path_for_project(project_name)
    )
    if reason is None:
        return revision
    try:
        inspection = vcs.repository(project.path).revision_file(
            revision=revision, filename="local.properties"
        )
    except RevisionError as exc:
        msg = f"Cannot inspect local.properties in {revision}: {exc}"
        raise GradleError(msg) from exc
    if not inspection.is_regular:
        raise GradleError(reason)
    return inspection.commit_id


def _new_gradle_workspace(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    *,
    vcs: VcsServices,
    clock: Clock = utc_now,
) -> tuple[ProjectConfig, str]:
    try:
        scan_result = load_scan_results(project_name)
    except NoScanResultsError:
        scan_result = ScanResult(
            project=project_name,
            scanned_at=clock(),
            trivy_target=str(project.path),
        )
    legacy = [
        item
        for item in scan_result.findings
        if item.update_status in {UpdateStatus.FAILED, UpdateStatus.READY}
    ]
    if legacy:
        msg = (
            "Legacy Gradle progress has no revision-bound ledger; "
            "manual review required"
        )
        raise GradleError(msg)
    if flow == Workflow.UPDATE:
        pin_workspace_revision(project_name, project, "main", vcs=vcs)
    source_repo = vcs.repository(Path(project.path))
    prune_stale_bookmarks(repo=source_repo, host=vcs.code_host(Path(project.path)))
    ensure_main_bookmark(repo=source_repo)
    base = source_repo.resolve_revision(revision="main")
    bookmark = WORKFLOW_BOOKMARKS[flow]
    if flow == Workflow.UPDATE:
        pin_workspace_revision(project_name, project, base, vcs=vcs)
        remove_workspace(repo=source_repo, project=project_name)
        workspace = create_workspace(
            repo=source_repo, project=project_name, revision=base
        )
        work = project.model_copy(update={"path": workspace})
    else:
        if source_repo.has_changes():
            msg = "Commit or discard source edits before resolve"
            raise GradleError(msg)
        work = project
    work_repo = vcs.repository(Path(work.path))
    work_repo.new_change(revision=base)
    if work_repo.bookmark_exists(bookmark=bookmark):
        work_repo.set_bookmark(bookmark=bookmark, revision=base)
    else:
        work_repo.create_bookmark(bookmark=bookmark, revision=base)
    return work, base


def _resume_gradle_workspace(
    run: GradleRun,
    project: ProjectConfig,
    *,
    vcs: VcsServices,
) -> ProjectConfig:
    project_name, flow = run.project, run.flow
    if flow == Workflow.UPDATE:
        workspace = workspace_path_for_project(project_name)
        if not workspace.exists():
            if run.has(ApplyingAttempt):
                msg = "Interrupted workspace missing; manual review required"
                raise GradleError(msg)
            create_workspace(
                repo=vcs.repository(Path(project.path)),
                project=project_name,
                revision=run.managed_tip_id,
            )
            vcs.repository(workspace).new_change(revision=run.managed_tip_id)
        work = project.model_copy(update={"path": workspace})
    else:
        work = project
    expected_main = run.promoted_commit_id or run.base_commit_id
    main = vcs.repository(Path(project.path)).resolve_revision(revision="main")
    if main not in {expected_main, run.managed_tip_id}:
        msg = "Main moved outside the recorded Gradle run"
        raise GradleError(msg)
    if (
        not run.has(ApplyingAttempt)
        and vcs.repository(Path(work.path)).resolve_revision(
            revision=run.managed_bookmark
        )
        != run.managed_tip_id
    ):
        msg = "Managed Gradle bookmark changed"
        raise GradleError(msg)
    return work


def _gradle_run_needs_replanning(run: GradleRun) -> bool:
    """Reconsider plans with no applied changes under the current policy."""
    return (
        all(isinstance(attempt, WithheldAttempt) for attempt in run.attempts)
        and run.managed_tip_id == run.base_commit_id
        and run.accepted_snapshot == run.initial_snapshot
        and run.promoted_commit_id is None
        and not run.submitted
    )


def _gradle_display_result(run: GradleRun, project: ProjectConfig) -> ScanResult:
    result = None
    if run.refreshed:
        # A removed results file must not hide durable residual evidence.
        with contextlib.suppress(NoScanResultsError):
            result = load_scan_results(run.project)
    if result is not None:
        return result
    return ScanResult(
        project=run.project,
        scanned_at=run.context.created_at,
        trivy_target=str(project.path),
        vulnerabilities=snapshot_vulnerabilities(run.accepted_snapshot),
        gradle_resolution=run.accepted_snapshot.resolution.report.model_dump(
            mode="json"
        ),
    )


def _open_gradle_run(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    run: GradleRun | None,
    *,
    continue_: bool,
    vcs: VcsServices,
    emit: Emit,
    clock: Clock = utc_now,
) -> tuple[GradleRun | None, ProjectConfig, str]:
    if (
        run is not None
        and run.flow == Workflow.UPDATE
        and not continue_
        and run.has(FailedAttempt)
    ):
        _archive_rolled_back_gradle_run(run, project, vcs=vcs, emit=emit)
        run = None
    if run is not None and (run.project != project_name or run.flow != flow):
        msg = "Another Gradle workflow owns the unfinished ledger"
        raise GradleError(msg)
    if run is None:
        if continue_:
            msg = "No preserved Gradle resolve attempt to continue"
            raise GradleError(msg)
        work, base = _new_gradle_workspace(
            project_name, project, flow, vcs=vcs, clock=clock
        )
        return None, work, base
    return run, _resume_gradle_workspace(run, project, vcs=vcs), run.base_commit_id


def _prepare_or_replan(
    project_name: str,
    project: ProjectConfig,
    work: ProjectConfig,
    flow: Workflow,
    base: str,
    run: GradleRun | None,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    choose: GradleChooser | None,
    vcs: VcsServices,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun | Outcome:
    unfinished = run is not None and _gradle_run_needs_replanning(run)
    if unfinished:
        _require_gradle_accepted_workspace(run, work, vcs=vcs)
    if run is not None and not unfinished:
        return run
    previous = run
    prepared = _prepare_gradle_run(
        project_name,
        work,
        flow,
        base,
        publication,
        minimum_age_days,
        choose=choose,
        vcs=vcs,
        emit=emit,
        clock=clock,
    )
    if isinstance(prepared, Outcome):
        if previous is not None:
            gradle_updater.gradle_run_path(project_name).unlink()
            gradle_updater.retire_gradle_context(previous.context)
        if flow == Workflow.UPDATE:
            remove_workspace(
                repo=vcs.repository(Path(project.path)), project=project_name
            )
        return prepared
    if (
        previous is not None
        and previous.context.private_cache_path != prepared.context.private_cache_path
    ):
        gradle_updater.retire_gradle_context(previous.context)
    return prepared


def _process_or_continue(
    run: GradleRun,
    work: ProjectConfig,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    continue_: bool,
    vcs: VcsServices,
    emit: Emit,
    clock: Clock = utc_now,
) -> GradleRun:
    if run.has(ApplyingAttempt):
        run = gradle_updater.reconcile_gradle_applying(
            run,
            work,
            publication,
            minimum_age_days,
            vcs=vcs,
            emit=emit,
            clock=clock,
        )
    if continue_:
        run = gradle_updater.continue_gradle_resolve(
            run,
            work,
            publication,
            minimum_age_days,
            vcs=vcs,
            emit=emit,
            clock=clock,
        )
    elif run.has(FailedAttempt):
        msg = "Preserved Gradle failure requires manual review or resolve --continue"
        raise GradleError(msg)
    # Committed resolve repair is separately verified above and becomes
    # the new accepted tip before automatic processing can resume.
    _require_gradle_accepted_workspace(run, work, vcs=vcs)
    if not context_inputs_valid(run.context, work, clock()):
        run = gradle_updater.rebuild_gradle_run_evidence(
            run,
            work,
            publication,
            minimum_age_days,
            vcs=vcs,
            emit=emit,
            clock=clock,
        )
    return gradle_updater.process_gradle_run(
        run,
        work,
        publication,
        minimum_age_days,
        vcs=vcs,
        emit=emit,
        clock=clock,
    )


def _close_ineligible_gradle_run(
    run: GradleRun, project: ProjectConfig, *, vcs: VcsServices, emit: Emit
) -> Outcome:
    emit(GradleRunReported(_gradle_display_result(run, project), run))
    emit(NoEligibleGradleChanges())
    # A clean/withheld-only run has no effects requiring recovery.
    gradle_updater.gradle_run_path(run.project).unlink(missing_ok=True)
    release_comparison_context(run.context)
    if run.flow == Workflow.UPDATE:
        remove_workspace(repo=vcs.repository(Path(project.path)), project=run.project)
    return (
        Outcome.FAILED
        if run.attempts or run.selection_blocks or run.initial_snapshot.findings
        else Outcome.SUCCEEDED
    )


def run_gradle_flow(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    *,
    minimum_age_days: int,
    continue_: bool = False,
    choose: GradleChooser | None,
    emit: Emit,
    vcs: VcsServices | None = None,
    clock: Clock = utc_now,
) -> Outcome:
    services = vcs or make_vcs_services()
    try:
        run = gradle_updater.load_gradle_run(
            gradle_updater.gradle_run_path(project_name)
        )
        if run is not None and (run.refreshed or run.submitted):
            gradle_updater.retire_gradle_context(run.context)
            if continue_:
                return Outcome.SUCCEEDED
            run = None
        run, work, base = _open_gradle_run(
            project_name,
            project,
            flow,
            run,
            continue_=continue_,
            vcs=services,
            emit=emit,
            clock=clock,
        )
        with PublicationLookupContext(
            paths.publications_dir(), clock=clock
        ) as publication:
            prepared = _prepare_or_replan(
                project_name,
                project,
                work,
                flow,
                base,
                run,
                publication,
                minimum_age_days,
                choose=choose,
                vcs=services,
                emit=emit,
                clock=clock,
            )
            if isinstance(prepared, Outcome):
                return prepared
            run = _process_or_continue(
                prepared,
                work,
                publication,
                minimum_age_days,
                continue_=continue_,
                vcs=services,
                emit=emit,
                clock=clock,
            )
            if run.has(ApplyingAttempt, FailedAttempt, PlannedAttempt):
                emit(GradleRunReported(_gradle_display_result(run, project), run))
                return Outcome.FAILED
            if not run.has(ReadyAttempt, CompletedAttempt):
                return _close_ineligible_gradle_run(
                    run, project, vcs=services, emit=emit
                )
            run = _finish_verified_gradle_run(
                run,
                project,
                publication,
                minimum_age_days,
                vcs=services,
                emit=emit,
                clock=clock,
            )
            gradle_updater.retire_gradle_context(run.context)
            emit(GradleRunReported(_gradle_display_result(run, project), run))
        if flow == Workflow.UPDATE and run.refreshed:
            remove_workspace(
                repo=services.repository(Path(project.path)), project=project_name
            )
        return Outcome.SUCCEEDED
    except (
        GradleError,
        ScanError,
        RevisionError,
        CodeHostError,
        ToolNotFoundError,
        OSError,
    ) as exc:
        emit(GradleFlowFailed(flow, str(exc)))
        return Outcome.FAILED
