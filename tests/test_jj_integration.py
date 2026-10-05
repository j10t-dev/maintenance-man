import shutil
import subprocess
from pathlib import Path

import pytest

from maintenance_man.vcs import (
    RevisionCheck,
    bookmark_exists,
    commit_current_change,
    create_or_reset_bookmark,
    current_change_has_changes,
    delete_bookmark,
    edit_new_change,
    exact_commit_id,
    is_ancestor,
    main_commit_id,
    promote_bookmark_to_main,
    refresh_working_copy_from_main,
    same_revision,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("jj") is None, reason="jj not installed"),
]


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, check=False, capture_output=True, text=True)


def _jj(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return run(["jj", *args], repo)


def init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    run(["jj", "git", "init", "--colocate"], repo)
    (repo / "README.md").write_text("initial\n")
    run(["jj", "commit", "-m", "initial"], repo)
    run(["jj", "bookmark", "create", "main", "-r", "@-"], repo)
    return repo


def test_commit_then_move_bookmark_to_finished_commit(tmp_path: Path):
    repo = init_repo(tmp_path)
    assert create_or_reset_bookmark("mm/update-dependencies", repo, "main") is True
    assert edit_new_change(repo, "mm/update-dependencies") is True
    (repo / "README.md").write_text("changed\n")
    assert current_change_has_changes(repo) is True
    assert commit_current_change(repo, "change readme") is True
    assert create_or_reset_bookmark("mm/update-dependencies", repo, "@-") is True
    assert bookmark_exists("mm/update-dependencies", repo) is True
    assert delete_bookmark("mm/update-dependencies", repo) is True


def test_promote_then_refresh_default_workspace_updates_files(tmp_path: Path):
    repo = init_repo(tmp_path)
    workspace = tmp_path / "workspace"

    assert (
        run(
            [
                "jj",
                "workspace",
                "add",
                "--name",
                "update",
                str(workspace),
                "-r",
                "main",
            ],
            repo,
        ).returncode
        == 0
    )
    assert create_or_reset_bookmark("mm/update-dependencies", repo, "main") is True
    assert edit_new_change(workspace, "mm/update-dependencies") is True
    (workspace / "README.md").write_text("updated\n")
    assert commit_current_change(workspace, "update readme") is True
    assert create_or_reset_bookmark("mm/update-dependencies", workspace, "@-") is True

    assert promote_bookmark_to_main(repo, "mm/update-dependencies") is True
    assert repo.joinpath("README.md").read_text() == "initial\n"

    assert refresh_working_copy_from_main(repo) is True

    assert repo.joinpath("README.md").read_text() == "updated\n"


def test_revision_relationship_helpers_with_real_jj_repo(tmp_path: Path):
    repo = init_repo(tmp_path)
    assert _jj(repo, "bookmark", "set", "main", "-r", "@").returncode == 0
    assert _jj(repo, "new", "main").returncode == 0
    assert _jj(repo, "describe", "-m", "child").returncode == 0
    assert _jj(repo, "bookmark", "set", "child", "-r", "@").returncode == 0

    assert same_revision(repo, "main", "main") == RevisionCheck(ok=True, value=True)
    assert same_revision(repo, "main", "child") == RevisionCheck(ok=True, value=False)
    assert is_ancestor(repo, "main", "child") == RevisionCheck(ok=True, value=True)
    assert is_ancestor(repo, "child", "main") == RevisionCheck(ok=True, value=False)


def test_main_commit_id_tracks_content_changes(tmp_path: Path):
    repo = init_repo(tmp_path)

    first = main_commit_id(repo)
    assert first.ok is True
    assert first.commit_id

    assert _jj(repo, "new", "main").returncode == 0
    (repo / "README.md").write_text("v2\n")
    assert _jj(repo, "commit", "-m", "v2").returncode == 0
    assert _jj(repo, "bookmark", "set", "main", "-r", "@-").returncode == 0

    second = main_commit_id(repo)
    assert second.ok is True
    assert second.commit_id != first.commit_id

    # No change between two resolves → stable identity (no spurious redeploy).
    third = main_commit_id(repo)
    assert third.commit_id == second.commit_id


def test_main_commit_id_changes_on_amend(tmp_path: Path):
    """Amending the deployed tip changes commit_id (why change_id was rejected)."""
    repo = init_repo(tmp_path)
    before = main_commit_id(repo)

    assert _jj(repo, "edit", "main").returncode == 0
    (repo / "README.md").write_text("amended\n")

    # The next main_commit_id call runs jj, which snapshots the working copy
    # and auto-amends the edited commit — that is what changes the commit_id.
    after = main_commit_id(repo)
    assert after.ok is True
    assert after.commit_id != before.commit_id


def test_main_commit_id_unresolved_without_bookmark(tmp_path: Path):
    repo = tmp_path / "repo-no-main"
    repo.mkdir()
    run(["jj", "git", "init", "--colocate"], repo)
    result = main_commit_id(repo)
    assert result.ok is False


def test_refresh_rebases_reusable_empty_working_copy(tmp_path: Path):
    repo = init_repo(tmp_path)
    assert _jj(repo, "bookmark", "set", "main", "-r", "@").returncode == 0
    assert _jj(repo, "new", "main").returncode == 0
    before = _jj(repo, "log", "-r", "@", "--no-graph", "-T", "change_id").stdout.strip()

    assert refresh_working_copy_from_main(repo) is True
    assert (
        _jj(repo, "log", "-r", "@", "--no-graph", "-T", "change_id").stdout.strip()
        == before
    )

    workspace = tmp_path / "advance-workspace"
    assert (
        _jj(
            repo, "workspace", "add", "--name", "advance", str(workspace), "-r", "main"
        ).returncode
        == 0
    )
    test_file = workspace / "sync.txt"
    test_file.write_text("sync\n")
    assert _jj(workspace, "describe", "-m", "advance main").returncode == 0
    assert _jj(workspace, "bookmark", "set", "main", "-r", "@").returncode == 0

    assert refresh_working_copy_from_main(repo) is True

    after = _jj(repo, "log", "-r", "@", "--no-graph", "-T", "change_id").stdout.strip()
    parent_bookmarks = _jj(
        repo, "log", "-r", "@-", "--no-graph", "-T", 'bookmarks.join(" ")'
    ).stdout.strip()

    assert after == before
    assert "main" in parent_bookmarks


@pytest.mark.parametrize("manager", ["bun", "uv", "mvn", "gradle"])
@pytest.mark.parametrize("finish", ["retry", "resolve"])
def test_shared_pending_stack_retry_or_resolve(
    tmp_path, monkeypatch, mm_home, manager, finish
):
    from maintenance_man import cli, updater
    from maintenance_man.models.config import ProjectConfig
    from maintenance_man.models.scan import UpdateStatus
    from tests.conftest import make_gradle_target, make_scan_result, make_update

    repo = init_repo(tmp_path)
    results_dir = mm_home / "scan-results"
    results_dir.mkdir(parents=True)
    rows = [
        make_update(
            pkg_name=name,
            gradle_target=(
                make_gradle_target(version_ref=name) if manager == "gradle" else None
            ),
        )
        for name in ("A", "B", "C")
    ]
    scan = make_scan_result(vulns=[], updates=rows)
    updater.save_scan_results("example", results_dir, scan)
    project = ProjectConfig(path=repo, package_manager=manager, test_unit="test")
    applied = []
    broken = True

    def apply(config, finding):
        applied.append(finding.pkg_name)
        (config.path / finding.pkg_name).write_text("applied\n")
        return updater.Applied()

    def test(config, path):
        return (False, "unit") if broken and (path / "B").exists() else (True, None)

    monkeypatch.setattr(updater, "apply_finding", apply)
    monkeypatch.setattr(updater, "run_test_phases", test)
    monkeypatch.setattr(cli, "run_test_phases", test)
    monkeypatch.setattr(cli, "validate_gradle_recovery", lambda *args: None)
    outcome = cli._update_batch("example", project, results_dir)
    assert outcome is not None
    results, failed = outcome
    assert failed
    assert [r.passed for r in results] == [True, False, True]
    assert applied == ["A", "B", "C"]
    saved = updater.load_scan_results("example", results_dir)
    assert [r.update_status for r in saved.updates] == [
        UpdateStatus.READY,
        UpdateStatus.FAILED,
        UpdateStatus.READY,
    ]
    assert not (repo / "A").exists()
    if finish == "retry":
        broken = False
        outcome = cli._update_batch("example", project, results_dir)
        assert outcome is not None
        results, failed = outcome
        assert not failed
        assert [r.pkg_name for r in results] == ["B"]
    else:
        cli._take_over_update_progress(repo, saved)
        assert edit_new_change(repo, "mm/resolve-dependencies")
        updater.save_scan_results("example", results_dir, saved)
        candidates = cli._ordered_resolve_candidates(saved, project)
        assert (
            cli._run_resolve_findings(
                "example", project, saved, results_dir, candidates
            )
            == 4
        )
        assert (repo / "A").exists() and (repo / "C").exists()
        (repo / "repair").write_text("manual fix\n")
        assert commit_current_change(repo, "fix B")
        broken = False
        assert cli._handle_resolve_continue("example", project, saved, results_dir) == 0
    assert applied == ["A", "B", "C", "B"]
    assert all((repo / name).read_text() == "applied\n" for name in ("A", "B", "C"))
    assert updater.load_scan_results("example", results_dir).updates == []
    assert same_revision(repo, "main", "@-").value


def test_local_promotion_refuses_diverged_main(tmp_path):
    repo = init_repo(tmp_path)
    assert create_or_reset_bookmark("mm/update-dependencies", repo, "main")
    assert edit_new_change(repo, "mm/update-dependencies")
    (repo / "A").write_text("update\n")
    assert commit_current_change(repo, "update A")
    assert create_or_reset_bookmark("mm/update-dependencies", repo, "@-")
    assert edit_new_change(repo, "main")
    (repo / "other").write_text("main changed\n")
    assert commit_current_change(repo, "other work")
    assert create_or_reset_bookmark("main", repo, "@-")
    before = exact_commit_id(repo, "main")
    assert not promote_bookmark_to_main(repo, "mm/update-dependencies")
    assert exact_commit_id(repo, "main") == before


def test_resolve_continue_requires_a_committed_repair(tmp_path, monkeypatch, mm_home):
    from maintenance_man import cli, updater
    from maintenance_man.models.config import ProjectConfig
    from maintenance_man.models.scan import UpdateStatus, Workflow
    from tests.conftest import make_scan_result, make_update

    repo = init_repo(tmp_path)
    assert create_or_reset_bookmark("mm/resolve-dependencies", repo, "main")
    assert edit_new_change(repo, "mm/resolve-dependencies")
    project = ProjectConfig(path=repo, package_manager="bun", test_unit="test")
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="unit",
            )
        ],
    )
    results_dir = mm_home / "scan-results"
    results_dir.mkdir(parents=True)
    updater.save_scan_results("example", results_dir, scan)
    monkeypatch.setattr(cli, "run_test_phases", lambda *args: (True, None))
    with pytest.raises(SystemExit) as outcome:
        cli._handle_resolve_continue("example", project, scan, results_dir)
    assert outcome.value.code == 1
    assert scan.updates[0].update_status == UpdateStatus.FAILED


def test_real_gradle_catalogue_uses_common_batch_and_promotes(
    tmp_path, monkeypatch, mm_home, gradle_project, capsys
):
    import sys

    from maintenance_man import cli, gradle, gradle_resolution, scanner, updater
    from maintenance_man.models.config import ProjectConfig
    from tests.conftest import (
        make_gradle_target,
        make_scan_result,
        make_update,
        make_vuln,
    )

    repo = init_repo(tmp_path)
    shutil.copytree(gradle_project.path, repo, dirs_exist_ok=True)
    assert commit_current_change(repo, "Gradle catalogue")
    assert create_or_reset_bookmark("main", repo, "@-")
    target = make_gradle_target()
    scan = make_scan_result(
        vulns=[make_vuln(gradle_target=target)],
        updates=[make_update(gradle_target=target)],
    )
    results_dir = mm_home / "scan-results"
    results_dir.mkdir(parents=True)
    updater.save_scan_results("android", results_dir, scan)
    project = ProjectConfig(
        path=repo,
        package_manager="gradle",
        test_unit=f"{sys.executable} -c 'assert True'",
        build_command="must-not-build",
    )
    calls = []

    def native(root, args, *, label):
        calls.append(args)
        report = root / "gradle/libs.versions.updates.toml"
        assert "2.8.5" in report.read_text()
        catalogue = root / "gradle/libs.versions.toml"
        catalogue.write_text(
            catalogue.read_text().replace('room = "2.8.4"', 'room = "2.8.5"')
        )

    def forbidden(*args, **kwargs):
        pytest.fail("update must only consume the saved scan")

    monkeypatch.setattr(gradle, "run_gradle", native)
    monkeypatch.setattr(scanner, "scan_project", forbidden)
    monkeypatch.setattr(cli, "scan_project", forbidden)
    monkeypatch.setattr(cli, "run_build", forbidden)
    monkeypatch.setattr(gradle, "discover_gradle_updates", forbidden)
    monkeypatch.setattr(gradle_resolution, "prepare_gradle_candidates", forbidden)
    outcome = cli._update_batch("android", project, results_dir)
    assert outcome is not None
    results, failed = outcome
    assert not failed
    assert [(r.pkg_name, r.kind, r.passed) for r in results] == [("room", "vuln", True)]
    assert calls == [["versionCatalogApplyUpdates", "--daemon", "--console=plain"]]
    assert 'room = "2.8.5"' in (repo / "gradle/libs.versions.toml").read_text()
    assert not (repo / "gradle/libs.versions.updates.toml").exists()
    cli._print_mass_update_summary([("android", results)])
    output = capsys.readouterr().out
    assert "Promoted android to local main" in output
    assert "Update Summary" in output and "room" in output and "PASS" in output


def test_resolve_continue_retries_same_repair_after_status_save_interruption(
    tmp_path, monkeypatch, mm_home
):
    from maintenance_man import cli, updater
    from maintenance_man.models.config import ProjectConfig
    from maintenance_man.models.scan import UpdateStatus, Workflow
    from tests.conftest import make_scan_result, make_update

    repo = init_repo(tmp_path)
    assert create_or_reset_bookmark("mm/resolve-dependencies", repo, "main")
    repair_base = exact_commit_id(repo, "mm/resolve-dependencies")
    assert edit_new_change(repo, "mm/resolve-dependencies")
    (repo / "B").write_text("manual repair\n")
    assert commit_current_change(repo, "repair B")
    repaired_tip = exact_commit_id(repo, "@-")
    project = ProjectConfig(path=repo, package_manager="bun", test_unit="test")
    scan = make_scan_result(
        vulns=[],
        updates=[
            make_update(
                pkg_name="B",
                update_status=UpdateStatus.FAILED,
                flow=Workflow.RESOLVE,
                failed_phase="unit",
            )
        ],
    )
    results_dir = mm_home / "scan-results"
    results_dir.mkdir(parents=True)
    updater.save_scan_results("example", results_dir, scan)
    monkeypatch.setattr(cli, "run_test_phases", lambda *args: (True, None))

    def interrupted_save(name, directory, current):
        if any(row.update_status == UpdateStatus.READY for row in current.updates):
            raise OSError("interrupted before READY was saved")
        updater.save_scan_results(name, directory, current)

    monkeypatch.setattr(cli, "save_scan_results", interrupted_save)
    with pytest.raises(OSError, match="interrupted"):
        cli._handle_resolve_continue("example", project, scan, results_dir)
    assert exact_commit_id(repo, "mm/resolve-dependencies") == repaired_tip
    saved = updater.load_scan_results("example", results_dir)
    assert saved.updates[0].update_status == UpdateStatus.FAILED
    assert saved.resolve_repair_base == repair_base
    monkeypatch.setattr(cli, "save_scan_results", updater.save_scan_results)
    monkeypatch.setattr(
        updater,
        "apply_finding",
        lambda *args: pytest.fail("repair must not be reapplied"),
    )
    assert cli._handle_resolve_continue("example", project, saved, results_dir) == 0
    assert exact_commit_id(repo, "main") == repaired_tip
    completed = updater.load_scan_results("example", results_dir)
    assert completed.updates == []
    assert completed.resolve_repair_base is None
