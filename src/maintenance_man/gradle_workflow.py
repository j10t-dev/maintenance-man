"""Gradle workflow preparation, workspace coordination, and finalization."""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from rich import print as rprint

from maintenance_man import gradle_updates as gradle_updater
from maintenance_man import paths
from maintenance_man.dependency_age import (
    PublicationLookupContext,
    filter_gradle_updates_by_age,
)
from maintenance_man.exit_codes import ExitCode
from maintenance_man.exit_codes import UpdateSetupError as _UpdateSetupError
from maintenance_man.github import CodeHostError
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GradleError,
    discover_gradle_updates,
    parse_catalogue,
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
    _run_gradle_scan,
    _run_trivy_secret_scan,
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


@dataclass(frozen=True)
class GradleInteraction:
    """Presentation and environment checks supplied by the CLI."""

    choose: Callable[[tuple[GradleCandidate, ...]], tuple[GradleCandidate, ...]]
    report: Callable[[GradleRun, ProjectConfig, Path], None]
    report_scan: Callable[[ScanResult], None]
    workspace_revision: Callable[[str, ProjectConfig, str], str]


def _prepare_gradle_run(
    project_name: str,
    project: ProjectConfig,
    flow: Workflow,
    base: str,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    interactive: bool,
    discovered: list[UpdateFinding] | None = None,
    *,
    interaction: GradleInteraction,
    vcs: VcsServices,
) -> GradleRun | ExitCode:
    # Resolve current security findings even when discovery produces no proposals.
    vulnerabilities, resolution = _run_gradle_scan(project)
    catalogue = parse_catalogue(project.path / GRADLE_CATALOGUE_RELPATH)
    proposals = (
        discovered if discovered is not None else discover_gradle_updates(project)
    )
    plan = select_gradle_candidates(catalogue, resolution, vulnerabilities, proposals)
    candidates = (
        interaction.choose(plan.candidates)
        if interactive and plan.candidates
        else plan.candidates
    )
    prepared = prepare_gradle_candidates(
        project, candidates, resolution, publication, minimum_age_days
    )
    attempts = tuple(
        WithheldAttempt(candidate=item.candidate, reason=item.block.reason)
        if item.block
        else PlannedAttempt(candidate=item.candidate)
        for item in prepared
    )
    if not any(isinstance(item, PlannedAttempt) for item in attempts):
        interaction.report_scan(
            ScanResult(
                project=project_name,
                scanned_at=datetime.now(UTC),
                trivy_target=str(project.path),
                vulnerabilities=vulnerabilities,
                gradle_resolution=resolution.report.model_dump(mode="json"),
            )
        )
        for withheld in plan.withheld:
            rprint(f"Withheld {withheld.coordinate}: {withheld.reason}")
        for item in prepared:
            if item.block:
                rprint(
                    f"Withheld {item.candidate.target.display_name}: "
                    f"{item.block.reason}"
                )
        rprint("No eligible Gradle changes")
        return (
            ExitCode.UPDATE_FAILED
            if attempts or plan.withheld or vulnerabilities
            else ExitCode.OK
        )
    gradle_updater.gradle_check_commands(project)
    context = initialize_comparison_context(
        project, resolution, paths.gradle_contexts_dir()
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
        )
        run = GradleRun.model_validate(
            dict(run) | {"attempts": attempts, "selection_blocks": plan.withheld}
        )
        gradle_updater.save_gradle_run(
            gradle_updater.gradle_run_path(project_name), run
        )
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
    results_dir: Path,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices,
) -> None:
    repo = vcs.repository(Path(project.path))
    if repo.tree_id() != run.accepted_snapshot.tree_id:
        raise GradleError("Refreshed working tree differs from verified tree")
    discovered = filter_gradle_updates_by_age(
        discover_gradle_updates(project),
        project,
        run.accepted_snapshot.resolution,
        minimum_age_days,
        publication,
    )
    rows = snapshot_vulnerabilities(run.accepted_snapshot)
    secrets = (
        _run_trivy_secret_scan(project.path, project.scan_skip_dirs)
        if project.scan_secrets
        else []
    )
    fresh = ScanResult(
        project=run.project,
        scanned_at=datetime.now(UTC),
        trivy_target=str(project.path),
        vulnerabilities=rows,
        secrets=secrets,
        updates=discovered,
        gradle_resolution=run.accepted_snapshot.resolution.report.model_dump(
            mode="json"
        ),
    )
    if repo.tree_id() != run.accepted_snapshot.tree_id:
        raise GradleError("Source changed while publishing verified findings")
    results_dir.mkdir(parents=True, exist_ok=True)
    save_scan_results(run.project, results_dir, fresh)


def _require_gradle_accepted_workspace(
    run: GradleRun, project: ProjectConfig, *, vcs: VcsServices
) -> None:
    repo = vcs.repository(Path(project.path))
    if repo.has_changes():
        raise GradleError(
            "Automatic Gradle processing requires an empty working change"
        )
    if repo.resolve_revision(revision="@-") != run.managed_tip_id:
        raise GradleError(
            "Working change is not an empty child of the recorded accepted tip"
        )
    if (
        repo.resolve_revision(revision=run.managed_bookmark) != run.managed_tip_id
        or repo.tree_id(revision=run.managed_tip_id) != run.accepted_snapshot.tree_id
        or repo.tree_id() != run.accepted_snapshot.tree_id
    ):
        raise GradleError(
            "Working revision differs from the recorded accepted snapshot"
        )


def _finish_verified_gradle_run(
    run: GradleRun,
    project: ProjectConfig,
    results_dir: Path,
    publication: PublicationLookupContext,
    minimum_age_days: int,
    *,
    vcs: VcsServices,
) -> GradleRun:
    # Verification reads the accepted revision, not the source workspace's old tree.
    with gradle_updater.gradle_evidence_workspace(
        project, run.managed_tip_id, vcs=vcs
    ) as verified:
        if not context_inputs_valid(run.context, verified, datetime.now(UTC)):
            run = gradle_updater.rebuild_gradle_run_evidence(
                run, verified, publication, minimum_age_days, vcs=vcs
            )
        gradle_updater.gradle_run_finalization_check(
            run, verified, publication, minimum_age_days, vcs=vcs
        )
    path = gradle_updater.gradle_run_path(run.project)
    if run.flow == Workflow.RESOLVE:
        if not run.submitted:
            output = push_bookmark_and_create_pr(
                repo=vcs.repository(Path(project.path)),
                host=vcs.code_host(Path(project.path)),
                bookmark=run.managed_bookmark,
                expected=ExpectedRevisions(
                    base=run.base_commit_id, tip=run.managed_tip_id
                ),
            )
            if output:
                rprint(output)
            run = _complete_gradle_attempts(run.model_copy(update={"submitted": True}))
            gradle_updater.save_gradle_run(path, run)
        return run
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
        gradle_updater.save_gradle_run(path, run)
    elif run.promoted_commit_id != run.managed_tip_id or main != run.promoted_commit_id:
        raise GradleError("Main moved after recorded Gradle promotion")
    if not run.refreshed:
        try:
            refresh_working_copy_from_main(repo=repo)
        except RevisionError as exc:
            raise GradleError(
                "Promotion recorded; working-copy refresh failed, retry update"
            ) from exc
        if repo.resolve_revision(revision="main") != run.managed_tip_id:
            raise GradleError("Main moved during refresh")
        _publish_verified_gradle_scan(
            run,
            project,
            results_dir,
            publication,
            minimum_age_days,
            vcs=vcs,
        )
        run = _complete_gradle_attempts(run.model_copy(update={"refreshed": True}))
        gradle_updater.save_gradle_run(path, run)
    return run


def _archive_rolled_back_gradle_run(
    run: GradleRun, project: ProjectConfig, *, vcs: VcsServices
) -> None:
    if (
        run.flow != Workflow.UPDATE
        or run.promoted_commit_id is not None
        or run.has(ApplyingAttempt)
        or not run.has(FailedAttempt)
    ):
        raise GradleError("Only rolled-back failed update runs can restart")
    workspace = workspace_path_for_project(run.project)
    if not workspace.exists():
        raise GradleError(
            "Uncommitted or missing failed workspace requires manual review"
        )
    # Repeat guarded rollback after a crash between saving Failed and restoring.
    gradle_updater.rollback_failed_gradle_update(
        run,
        project.model_copy(update={"path": workspace}),
        vcs=vcs,
    )
    workspace_repo = vcs.repository(workspace)
    source_repo = vcs.repository(Path(project.path))
    if workspace_repo.has_changes():
        raise GradleError(
            "Uncommitted or missing failed workspace requires manual review"
        )
    if (
        source_repo.resolve_revision(revision="main") != run.base_commit_id
        or workspace_repo.resolve_revision(revision=run.managed_bookmark)
        != run.managed_tip_id
        or workspace_repo.resolve_revision(revision="@-") != run.managed_tip_id
        or workspace_repo.tree_id() != run.accepted_snapshot.tree_id
        or workspace_repo.tree_id(revision=run.managed_tip_id)
        != run.accepted_snapshot.tree_id
    ):
        raise GradleError(
            "Failed update rollback cannot be proven; retained for manual review"
        )
    path = gradle_updater.gradle_run_path(run.project)
    archive = path.parent / "history" / f"{path.stem}-{uuid.uuid4().hex}.json"
    gradle_updater.save_gradle_run(archive, run)
    try:
        source_repo.reset_verified_bookmark(
            bookmark=run.managed_bookmark,
            expected=ExpectedRevisions(base=run.base_commit_id, tip=run.managed_tip_id),
        )
    except RevisionError as exc:
        raise GradleError(
            "Revisions changed during restart; original ledger retained"
        ) from exc
    path.unlink()
    fsync_dir(path.parent)
    gradle_updater.retire_gradle_context(run.context)
    rprint(f"Archived failed Gradle run to {archive}; rebuilding candidates from main")


def _new_gradle_workspace(
    project_name: str,
    project: ProjectConfig,
    results_dir: Path,
    flow: Workflow,
    interaction: GradleInteraction,
    *,
    vcs: VcsServices,
) -> tuple[ProjectConfig, str]:
    try:
        scan_result = load_scan_results(project_name, results_dir)
    except NoScanResultsError:
        scan_result = ScanResult(
            project=project_name,
            scanned_at=datetime.now(UTC),
            trivy_target=str(project.path),
        )
    legacy = [
        item
        for item in scan_result.findings
        if item.update_status in {UpdateStatus.FAILED, UpdateStatus.READY}
    ]
    if legacy:
        raise GradleError(
            "Legacy Gradle progress has no revision-bound ledger; "
            "manual review required"
        )
    if flow == Workflow.UPDATE:
        interaction.workspace_revision(project_name, project, "main")
    source_repo = vcs.repository(Path(project.path))
    prune_stale_bookmarks(repo=source_repo, host=vcs.code_host(Path(project.path)))
    ensure_main_bookmark(repo=source_repo)
    base = source_repo.resolve_revision(revision="main")
    bookmark = WORKFLOW_BOOKMARKS[flow]
    if flow == Workflow.UPDATE:
        interaction.workspace_revision(project_name, project, base)
        remove_workspace(repo=source_repo, project=project_name)
        workspace = create_workspace(
            repo=source_repo, project=project_name, revision=base
        )
        work = project.model_copy(update={"path": workspace})
    else:
        if source_repo.has_changes():
            raise GradleError("Commit or discard source edits before resolve")
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
                raise GradleError(
                    "Interrupted workspace missing; manual review required"
                )
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
        raise GradleError("Main moved outside the recorded Gradle run")
    if (
        not run.has(ApplyingAttempt)
        and vcs.repository(Path(work.path)).resolve_revision(
            revision=run.managed_bookmark
        )
        != run.managed_tip_id
    ):
        raise GradleError("Managed Gradle bookmark changed")
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


def run_gradle_flow(
    project_name: str,
    project: ProjectConfig,
    results_dir: Path,
    flow: Workflow,
    *,
    interactive: bool,
    minimum_age_days: int,
    continue_: bool = False,
    interaction: GradleInteraction,
    vcs: VcsServices | None = None,
) -> int:
    services = vcs or make_vcs_services()
    try:
        path = gradle_updater.gradle_run_path(project_name)
        run = gradle_updater.load_gradle_run(path)
        if run is not None and (run.refreshed or run.submitted):
            gradle_updater.retire_gradle_context(run.context)
            if continue_:
                return ExitCode.OK
            run = None
        if (
            run is not None
            and run.flow == Workflow.UPDATE
            and not continue_
            and run.has(FailedAttempt)
        ):
            _archive_rolled_back_gradle_run(run, project, vcs=services)
            run = None
        if run is not None and (run.project != project_name or run.flow != flow):
            raise GradleError("Another Gradle workflow owns the unfinished ledger")
        if run is None:
            if continue_:
                raise GradleError("No preserved Gradle resolve attempt to continue")
            work, base = _new_gradle_workspace(
                project_name,
                project,
                results_dir,
                flow,
                interaction,
                vcs=services,
            )
        else:
            work = _resume_gradle_workspace(run, project, vcs=services)
            base = run.base_commit_id
        with PublicationLookupContext(paths.gradle_publications_dir()) as publication:
            unfinished = run is not None and _gradle_run_needs_replanning(run)
            if unfinished:
                _require_gradle_accepted_workspace(run, work, vcs=services)
            if run is None or unfinished:
                previous = run
                prepared = _prepare_gradle_run(
                    project_name,
                    work,
                    flow,
                    base,
                    publication,
                    minimum_age_days,
                    interactive,
                    interaction=interaction,
                    vcs=services,
                )
                if isinstance(prepared, ExitCode):
                    if previous is not None:
                        path.unlink()
                        gradle_updater.retire_gradle_context(previous.context)
                    if flow == Workflow.UPDATE:
                        remove_workspace(
                            repo=services.repository(Path(project.path)),
                            project=project_name,
                        )
                    return prepared
                run = prepared
                if (
                    previous is not None
                    and previous.context.private_cache_path
                    != run.context.private_cache_path
                ):
                    gradle_updater.retire_gradle_context(previous.context)
            if run.has(ApplyingAttempt):
                run = gradle_updater.reconcile_gradle_applying(
                    run, work, publication, minimum_age_days, vcs=services
                )
            if continue_:
                run = gradle_updater.continue_gradle_resolve(
                    run, work, publication, minimum_age_days, vcs=services
                )
            elif run.has(FailedAttempt):
                raise GradleError(
                    "Preserved Gradle failure requires manual review "
                    "or resolve --continue"
                )
            # Committed resolve repair is separately verified above and becomes
            # the new accepted tip before automatic processing can resume.
            _require_gradle_accepted_workspace(run, work, vcs=services)
            if not context_inputs_valid(run.context, work, datetime.now(UTC)):
                run = gradle_updater.rebuild_gradle_run_evidence(
                    run, work, publication, minimum_age_days, vcs=services
                )
            run = gradle_updater.process_gradle_run(
                run, work, publication, minimum_age_days, vcs=services
            )
            if run.has(ApplyingAttempt, FailedAttempt, PlannedAttempt):
                interaction.report(run, project, results_dir)
                return ExitCode.UPDATE_FAILED
            if not run.has(ReadyAttempt, CompletedAttempt):
                interaction.report(run, project, results_dir)
                rprint("No eligible Gradle changes")
                # A clean/withheld-only run has no effects requiring recovery.
                path.unlink(missing_ok=True)
                release_comparison_context(run.context)
                if flow == Workflow.UPDATE:
                    remove_workspace(
                        repo=services.repository(Path(project.path)),
                        project=project_name,
                    )
                return (
                    ExitCode.UPDATE_FAILED
                    if run.attempts
                    or run.selection_blocks
                    or run.initial_snapshot.findings
                    else ExitCode.OK
                )
            run = _finish_verified_gradle_run(
                run,
                project,
                results_dir,
                publication,
                minimum_age_days,
                vcs=services,
            )
            gradle_updater.retire_gradle_context(run.context)
            interaction.report(run, project, results_dir)
        if flow == Workflow.UPDATE and run.refreshed:
            remove_workspace(
                repo=services.repository(Path(project.path)), project=project_name
            )
        return ExitCode.OK
    except (
        GradleError,
        ScanError,
        _UpdateSetupError,
        RevisionError,
        CodeHostError,
        ToolNotFoundError,
        OSError,
    ) as exc:
        rprint(f"Cannot complete Gradle {flow}: {exc}")
        return ExitCode.UPDATE_FAILED
