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
