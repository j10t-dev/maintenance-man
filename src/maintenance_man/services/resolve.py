from pathlib import Path

from maintenance_man.gradle import validate_gradle_recovery
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.events import (
    BlockersStillFailing,
    Emit,
    FindingPassed,
    FindingsBlocked,
    FindingStepFailed,
    FindingStepKind,
    Operation,
    OperationFailed,
    Outcome,
    ResolvePaused,
)
from maintenance_man.models.scan import (
    WORKFLOW_BOOKMARKS,
    ScanResult,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    Workflow,
)
from maintenance_man.services import WorkflowError, flows
from maintenance_man.storage import save_scan_results
from maintenance_man.updater import (
    Finding,
    group_findings,
    is_eligible,
    process_findings,
    run_test_phases,
)
from maintenance_man.vcs import Repository, RevisionError
from maintenance_man.vcs_workflow import VcsServices, ensure_main_bookmark


def resolve_project(
    name: str,
    project: ProjectConfig,
    *,
    continue_: bool,
    vcs: VcsServices,
    emit: Emit,
) -> Outcome:
    scan_result = flows.load_validated_scan(name, project, Workflow.RESOLVE, emit=emit)
    if scan_result is None:
        return Outcome.SUCCEEDED
    if flows.report_missing_test_config(name, project, emit=emit):
        return Outcome.FAILED
    if continue_:
        return _handle_continue(name, project, scan_result, vcs=vcs, emit=emit)
    _refuse_mixed_ownership(name, scan_result)
    if any(_is_failed_resolve_finding(finding) for finding in scan_result.findings):
        msg = f"resolve already paused for {name} — rerun with --continue"
        raise WorkflowError(msg)

    repo = vcs.repository(project.path)
    try:
        ensure_main_bookmark(repo=repo)
    except RevisionError as exc:
        raise WorkflowError(str(exc)) from exc
    if _has_update_progress(scan_result):
        _take_over_update_progress(name, repo, scan_result)
        candidates = _select_resolve_candidates(scan_result)
    else:
        candidates = _select_resolve_candidates(scan_result)
        if not _prepare_resolve_bookmark(
            name,
            project.path,
            scan_result,
            candidates,
            vcs=vcs,
            emit=emit,
        ):
            msg = f"aborted resolve for {name}"
            raise WorkflowError(msg)
    return _run_candidates(name, project, scan_result, candidates, vcs=vcs, emit=emit)


def _select_resolve_candidates(scan_result: ScanResult) -> list[Finding]:
    vulns = [
        finding
        for finding in scan_result.vulnerabilities
        if _is_resolve_candidate(finding)
    ]
    updates = [
        finding for finding in scan_result.updates if _is_resolve_candidate(finding)
    ]
    return group_findings([*vulns, *updates])


def _is_resolve_candidate(finding: VulnFinding | UpdateFinding) -> bool:
    return is_eligible(finding) and (
        finding.update_status is None
        or (
            finding.flow is Workflow.RESOLVE
            and finding.update_status is UpdateStatus.FAILED
        )
    )


def _is_failed_resolve_finding(finding: Finding) -> bool:
    return (
        finding.update_status is UpdateStatus.FAILED
        and finding.flow is Workflow.RESOLVE
    )


def _is_ready_resolve_finding(finding: Finding) -> bool:
    return (
        finding.update_status is UpdateStatus.READY and finding.flow is Workflow.RESOLVE
    )


def _refuse_mixed_ownership(name: str, scan_result: ScanResult) -> None:
    pending = {
        finding.flow
        for finding in scan_result.findings
        if finding.update_status in (UpdateStatus.READY, UpdateStatus.FAILED)
    }
    if {Workflow.UPDATE, Workflow.RESOLVE} <= pending:
        msg = (
            "Resolve cannot take over pending updates while resolve progress also "
            f"exists for {name}. Run mm scan {name} to start again from main."
        )
        raise WorkflowError(msg)


def _has_update_progress(scan_result: ScanResult) -> bool:
    return any(
        finding.flow is Workflow.UPDATE
        and finding.update_status in (UpdateStatus.READY, UpdateStatus.FAILED)
        for finding in scan_result.findings
    )


def _take_over_update_progress(
    name: str, repo: Repository, scan_result: ScanResult
) -> None:
    """Move the accepted update tip and every update-owned row to resolve.

    Errors before the status save leave the bookmark and rows untouched. After it,
    every row is resolve-owned (accepted READY or pending), so the next run
    continues from the resolve bookmark; a failed deletion of the update bookmark
    is reported as WorkflowError.
    """
    update_bookmark = WORKFLOW_BOOKMARKS[Workflow.UPDATE]
    resolve_bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    try:
        if repo.has_changes():
            msg = (
                "Resolve cannot take over pending updates while "
                f"{repo.path} has uncommitted changes. Commit or discard them, "
                f"then run mm resolve {name} again."
            )
            raise WorkflowError(msg)
        if not repo.bookmark_exists(bookmark=update_bookmark):
            msg = (
                "Resolve cannot take over pending updates: bookmark "
                f"{update_bookmark} is missing. Run mm scan {name} to start again "
                "from main."
            )
            raise WorkflowError(msg)
        if repo.bookmark_exists(bookmark=resolve_bookmark):
            repo.delete_bookmark(bookmark=resolve_bookmark)
        repo.create_bookmark(bookmark=resolve_bookmark, revision=update_bookmark)
        repo.new_change(revision=resolve_bookmark)
        for finding in scan_result.findings:
            if finding.flow is Workflow.UPDATE:
                finding.flow = Workflow.RESOLVE
                if finding.update_status is UpdateStatus.FAILED:
                    finding.update_status = None
                    finding.failed_phase = None
        save_scan_results(name, scan_result)
        repo.delete_bookmark(bookmark=update_bookmark)
    except RevisionError as exc:
        msg = f"Cannot take over pending updates for {name}: {exc}"
        raise WorkflowError(msg) from exc


def _prepare_resolve_bookmark(
    name: str,
    project_path: Path,
    scan_result: ScanResult,
    candidates: list[Finding],
    *,
    vcs: VcsServices,
    emit: Emit,
) -> bool:
    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    repo = vcs.repository(project_path)
    try:
        if any(
            finding.update_status is UpdateStatus.READY
            and finding.flow is Workflow.RESOLVE
            for finding in scan_result.findings
        ):
            if not repo.bookmark_exists(bookmark=bookmark):
                msg = (
                    f"resolve bookmark '{bookmark}' is missing but in-progress "
                    "state exists — rescan or recover the bookmark manually"
                )
                raise WorkflowError(msg)
            if candidates:
                repo.new_change(revision=bookmark)
            return True

        if repo.bookmark_exists(bookmark=bookmark):
            repo.delete_bookmark(bookmark=bookmark)
        repo.create_bookmark(bookmark=bookmark, revision="main")
        repo.new_change(revision=bookmark)
    except RevisionError as exc:
        emit(OperationFailed(Operation.RESOLVE_SETUP, name, str(exc)))
        return False
    return True


def _run_candidates(
    name: str,
    project: ProjectConfig,
    scan_result: ScanResult,
    candidates: list[Finding],
    *,
    vcs: VcsServices,
    emit: Emit,
) -> Outcome:
    results = process_findings(
        candidates,
        project,
        flow=Workflow.RESOLVE,
        scan_result=scan_result,
        on_failure="stop",
        vcs=vcs,
        emit=emit,
    )
    if any(not result.passed for result in results) or any(
        _is_failed_resolve_finding(finding) for finding in scan_result.findings
    ):
        emit(ResolvePaused(name))
        return Outcome.FAILED

    blocked = scan_result.blocked_findings
    if blocked:
        emit(
            FindingsBlocked(
                tuple(
                    (finding.pkg_name, finding.blocked_reason or "")
                    for finding in blocked
                )
            )
        )
    if not any(_is_ready_resolve_finding(finding) for finding in scan_result.findings):
        return Outcome.SUCCEEDED
    return (
        Outcome.SUCCEEDED
        if flows.finalise_local_changes(
            project.path, scan_result, name, Workflow.RESOLVE, vcs=vcs, emit=emit
        )
        else Outcome.FAILED
    )


def _handle_continue(
    name: str,
    project: ProjectConfig,
    scan_result: ScanResult,
    *,
    vcs: VcsServices,
    emit: Emit,
) -> Outcome:
    _refuse_mixed_ownership(name, scan_result)
    if _has_update_progress(scan_result):
        msg = (
            f"Pending update work exists for {name}. Run mm resolve {name} "
            "without --continue to take it over first."
        )
        raise WorkflowError(msg)
    failed = group_findings(
        [
            finding
            for finding in scan_result.findings
            if _is_failed_resolve_finding(finding)
        ]
    )
    if not failed:
        msg = (
            f"No paused resolve failure is saved for {name}. Run mm resolve "
            f"{name} to start resolving."
        )
        raise WorkflowError(msg)
    repo = vcs.repository(project.path)
    repair_base = _check_resumable(
        name,
        repo,
        WORKFLOW_BOOKMARKS[Workflow.RESOLVE],
        scan_result.resolve_repair_base,
    )
    if not _retest_blockers(
        name,
        project,
        scan_result,
        failed,
        repair_base=repair_base,
        repo=repo,
        emit=emit,
    ):
        return Outcome.FAILED
    return _run_candidates(
        name,
        project,
        scan_result,
        _select_resolve_candidates(scan_result),
        vcs=vcs,
        emit=emit,
    )


def _check_resumable(
    name: str, repo: Repository, bookmark: str, saved: str | None
) -> str:
    try:
        repair_base = saved or repo.resolve_revision(revision=bookmark)
        if not repo.is_ancestor(ancestor=bookmark, descendant="@"):
            msg = f"--continue requires current jj change to descend from {bookmark}"
            raise WorkflowError(msg)
        if repo.has_changes():
            msg = (
                "--continue requires an empty current jj change — commit or discard "
                "manual changes first"
            )
            raise WorkflowError(msg)
        if repo.same_revision(left="@-", right=repair_base):
            msg = (
                f"--continue needs a committed repair on top of {bookmark}. Commit "
                f"the repair with jj commit, then run mm resolve {name} --continue "
                "again."
            )
            raise WorkflowError(msg)
    except RevisionError as exc:
        msg = f"Cannot inspect resolve work: {exc}"
        raise WorkflowError(msg) from exc
    return repair_base


def _retest_blockers(
    name: str,
    project: ProjectConfig,
    scan_result: ScanResult,
    failed: list[Finding],
    *,
    repair_base: str,
    repo: Repository,
    emit: Emit,
) -> bool:
    if not _repair_sets_saved_targets(project, failed, emit=emit):
        return False
    failed_phase = run_test_phases(project, project.path, emit=emit)
    passed = failed_phase is None
    for blocker in failed:
        blocker.flow = Workflow.RESOLVE
        if not passed:
            blocker.update_status = UpdateStatus.FAILED
            blocker.failed_phase = failed_phase
    if not passed:
        save_scan_results(name, scan_result)
        emit(
            BlockersStillFailing(
                failed_phase or "", tuple(blocker.pkg_name for blocker in failed)
            )
        )
        return False

    bookmark = WORKFLOW_BOOKMARKS[Workflow.RESOLVE]
    scan_result.resolve_repair_base = repair_base
    save_scan_results(name, scan_result)
    try:
        repo.set_bookmark(bookmark=bookmark, revision="@-")
    except RevisionError as exc:
        msg = f"could not move {bookmark} to the committed manual fix"
        raise WorkflowError(msg) from exc
    for blocker in failed:
        blocker.update_status = UpdateStatus.READY
        blocker.failed_phase = None
    scan_result.resolve_repair_base = None
    save_scan_results(name, scan_result)
    for blocker in failed:
        emit(
            FindingPassed(
                blocker.pkg_name,
                False,
                blocker.installed_version,
                blocker.target_version,
            )
        )
    return True


def _repair_sets_saved_targets(
    project: ProjectConfig, failed: list[Finding], *, emit: Emit
) -> bool:
    for blocker in failed:
        if blocker.gradle_target is None:
            continue
        block = validate_gradle_recovery(project, blocker.gradle_target)
        if block is not None:
            emit(
                FindingStepFailed(
                    FindingStepKind.PREPARE,
                    "The committed repair does not set the saved catalogue "
                    f"target: {block.reason}",
                )
            )
            return False
    return True
