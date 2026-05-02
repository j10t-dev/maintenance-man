import shutil
import subprocess
from pathlib import Path

import pytest

from maintenance_man.vcs import (
    bookmark_exists,
    commit_current_change,
    create_or_reset_bookmark,
    current_change_has_changes,
    delete_bookmark,
    edit_new_change,
)

pytestmark = pytest.mark.skipif(shutil.which("jj") is None, reason="jj not installed")


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, check=False, capture_output=True, text=True)


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
