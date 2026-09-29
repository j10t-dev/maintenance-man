import shutil
import subprocess
from pathlib import Path

import pytest

from maintenance_man.vcs import ExpectedRevisions, JjRepository, RevisionError
from maintenance_man.vcs_workflow import refresh_working_copy_from_main

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
    path = init_repo(tmp_path)
    repo = JjRepository(path)
    bookmark = "mm/update-dependencies"
    repo.create_bookmark(bookmark=bookmark, revision="main")
    repo.new_change(revision=bookmark)
    (path / "README.md").write_text("changed\n")
    assert repo.has_changes()
    repo.commit(message="change readme")
    repo.set_bookmark(bookmark=bookmark, revision="@-")
    assert repo.bookmark_exists(bookmark=bookmark)
    repo.delete_bookmark(bookmark=bookmark)
    assert not repo.bookmark_exists(bookmark=bookmark)


def test_promote_then_refresh_default_workspace_updates_files(tmp_path: Path):
    path = init_repo(tmp_path)
    repo = JjRepository(path)
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
            path,
        ).returncode
        == 0
    )
    base = repo.resolve_revision(revision="main")
    bookmark = "mm/update-dependencies"
    update = JjRepository(workspace)
    update.new_change(revision="main")
    update.create_bookmark(bookmark=bookmark, revision="main")
    (workspace / "README.md").write_text("updated\n")
    update.commit(message="update readme")
    update.set_bookmark(bookmark=bookmark, revision="@-")
    tip = update.resolve_revision(revision=bookmark)

    repo.promote_bookmark_to_main(
        bookmark=bookmark, expected=ExpectedRevisions(base=base, tip=tip)
    )
    assert path.joinpath("README.md").read_text() == "initial\n"

    refresh_working_copy_from_main(repo=repo)
    assert path.joinpath("README.md").read_text() == "updated\n"


def test_revision_relationship_methods_with_real_jj_repo(tmp_path: Path):
    path = init_repo(tmp_path)
    repo = JjRepository(path)
    assert _jj(path, "bookmark", "set", "main", "-r", "@").returncode == 0
    assert _jj(path, "new", "main").returncode == 0
    assert _jj(path, "describe", "-m", "child").returncode == 0
    assert _jj(path, "bookmark", "set", "child", "-r", "@").returncode == 0

    assert repo.same_revision(left="main", right="main")
    assert not repo.same_revision(left="main", right="child")
    assert repo.is_ancestor(ancestor="main", descendant="child")
    assert not repo.is_ancestor(ancestor="child", descendant="main")


def test_main_revision_tracks_content_changes(tmp_path: Path):
    path = init_repo(tmp_path)
    repo = JjRepository(path)
    first = repo.resolve_revision(revision="main")

    assert _jj(path, "new", "main").returncode == 0
    (path / "README.md").write_text("v2\n")
    assert _jj(path, "commit", "-m", "v2").returncode == 0
    assert _jj(path, "bookmark", "set", "main", "-r", "@-").returncode == 0

    second = repo.resolve_revision(revision="main")
    assert second != first
    assert repo.resolve_revision(revision="main") == second


def test_main_revision_changes_on_amend(tmp_path: Path):
    path = init_repo(tmp_path)
    repo = JjRepository(path)
    before = repo.resolve_revision(revision="main")

    assert _jj(path, "edit", "main").returncode == 0
    (path / "README.md").write_text("amended\n")

    after = repo.resolve_revision(revision="main")
    assert after != before


def test_resolve_main_raises_without_bookmark(tmp_path: Path):
    path = tmp_path / "repo-no-main"
    path.mkdir()
    run(["jj", "git", "init", "--colocate"], path)
    with pytest.raises(RevisionError):
        JjRepository(path).resolve_revision(revision="main")


def test_refresh_rebases_reusable_empty_working_copy(tmp_path: Path):
    path = init_repo(tmp_path)
    repo = JjRepository(path)
    assert _jj(path, "bookmark", "set", "main", "-r", "@").returncode == 0
    assert _jj(path, "new", "main").returncode == 0
    before = repo.change_id()

    refresh_working_copy_from_main(repo=repo)
    assert repo.change_id() == before

    repo.create_bookmark(bookmark="keep-empty", revision="@")
    assert _jj(path, "new", "main").returncode == 0
    (path / "sync.txt").write_text("sync\n")
    assert _jj(path, "describe", "-m", "advance main").returncode == 0
    assert _jj(path, "bookmark", "set", "main", "-r", "@").returncode == 0
    assert _jj(path, "edit", "keep-empty").returncode == 0
    repo.delete_bookmark(bookmark="keep-empty")

    refresh_working_copy_from_main(repo=repo)
    assert repo.change_id() == before
    assert "main" in repo.revision_bookmarks(revision="@-")


@pytest.mark.parametrize("mutation", ["none", "main", "tip", "conflict"])
def test_gradle_promotion_checks_exact_base_and_tip_in_operation(tmp_path, mutation):
    path = init_repo(tmp_path)
    repo = JjRepository(path)
    base = repo.resolve_revision(revision="main")
    (path / "README.md").write_text("accepted update\n")
    repo.commit(message="accepted update")
    tip = repo.resolve_revision(revision="@-")
    bookmark = "mm/update-dependencies"
    repo.create_bookmark(bookmark=bookmark, revision=tip)
    if mutation == "main":
        repo.set_bookmark(bookmark="main", revision=tip)
    elif mutation == "tip":
        assert (
            _jj(
                path, "bookmark", "set", bookmark, "-r", base, "--allow-backwards"
            ).returncode
            == 0
        )
    elif mutation == "conflict":
        assert _jj(path, "new", base).returncode == 0
        (path / "README.md").write_text("side\n")
        repo.commit(message="side")
        side = repo.resolve_revision(revision="@-")
        op = _jj(
            path, "op", "log", "--limit", "1", "--no-graph", "-T", "id"
        ).stdout.strip()
        assert _jj(path, "bookmark", "set", "main", "-r", tip).returncode == 0
        assert (
            _jj(path, "--at-op", op, "bookmark", "set", "main", "-r", side).returncode
            == 0
        )
        assert "conflict" in _jj(path, "bookmark", "list", "main").stdout
    before = _jj(path, "bookmark", "list", "main").stdout
    if mutation == "none":
        repo.promote_bookmark_to_main(
            bookmark=bookmark, expected=ExpectedRevisions(base=base, tip=tip)
        )
        assert repo.resolve_revision(revision="main") == tip
    else:
        with pytest.raises(RevisionError):
            repo.promote_bookmark_to_main(
                bookmark=bookmark, expected=ExpectedRevisions(base=base, tip=tip)
            )
        assert _jj(path, "bookmark", "list", "main").stdout == before


def test_gradle_tree_identity_tracks_content_not_commit_metadata(tmp_path):
    path = init_repo(tmp_path)
    repo = JjRepository(path)
    original = repo.tree_id(revision="main")
    assert original == repo.tree_id()
    assert _jj(path, "describe", "-m", "metadata only").returncode == 0
    assert original == repo.tree_id()
    (path / "README.md").write_text("different content\n")
    assert repo.tree_id() != original
    assert repo.tree_id(revision="main") == original
    (path / "README.md").write_text("initial\n")
    assert repo.tree_id() == original
