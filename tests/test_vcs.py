import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from maintenance_man.vcs import (
    GraphiteNotFoundError,
    RepoDirtyError,
    branch_slug,
    check_graphite_available,
    check_repo_clean,
    discard_changes,
    get_current_branch,
    gt_checkout,
    gt_create,
    gt_delete,
    reset_to_main,
    submit_stack,
    sync_graphite,
)


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# branch_slug
# ---------------------------------------------------------------------------


class TestBranchSlug:
    @pytest.mark.parametrize(
        ("input_name", "expected"),
        [
            pytest.param("express", "express", id="plain"),
            pytest.param("@types/bun", "types-bun", id="scoped-npm"),
            pytest.param("@babel/preset-env", "babel-preset-env", id="deeply-scoped"),
            pytest.param("lodash", "lodash", id="no-at-no-slash"),
        ],
    )
    def test_branch_slug(self, input_name: str, expected: str):
        assert branch_slug(input_name) == expected


# ---------------------------------------------------------------------------
# check_graphite_available
# ---------------------------------------------------------------------------


class TestCheckGraphiteAvailable:
    def test_gt_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "maintenance_man.vcs.shutil.which",
            lambda cmd: "/usr/bin/gt" if cmd == "gt" else None,
        )
        check_graphite_available()  # should not raise

    def test_gt_not_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("maintenance_man.vcs.shutil.which", lambda cmd: None)
        with pytest.raises(GraphiteNotFoundError):
            check_graphite_available()


# ---------------------------------------------------------------------------
# check_repo_clean
# ---------------------------------------------------------------------------


class TestCheckRepoClean:
    @patch("maintenance_man.vcs._run")
    def test_clean_repo(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="")
        check_repo_clean(tmp_path)  # should not raise

    @patch("maintenance_man.vcs._run")
    def test_dirty_repo(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout=" M src/file.py\n")
        with pytest.raises(RepoDirtyError):
            check_repo_clean(tmp_path)


# ---------------------------------------------------------------------------
# get_current_branch
# ---------------------------------------------------------------------------


class TestGetCurrentBranch:
    @patch("maintenance_man.vcs._run")
    def test_returns_branch_name(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="bump/pkg-a\n")
        assert get_current_branch(tmp_path) == "bump/pkg-a"

    @patch("maintenance_man.vcs._run")
    def test_strips_whitespace(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="  fix/some-pkg  \n")
        assert get_current_branch(tmp_path) == "fix/some-pkg"


# ---------------------------------------------------------------------------
# discard_changes
# ---------------------------------------------------------------------------


class TestDiscardChanges:
    @patch("maintenance_man.vcs._run")
    def test_runs_checkout_and_clean(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        discard_changes(tmp_path)
        assert mock_run.call_count == 2
        mock_run.assert_any_call(["git", "checkout", "--", "."], tmp_path)
        mock_run.assert_any_call(["git", "clean", "-fd"], tmp_path)


# ---------------------------------------------------------------------------
# reset_to_main
# ---------------------------------------------------------------------------


class TestResetToMain:
    @patch("maintenance_man.vcs.gt_checkout", return_value=True)
    @patch("maintenance_man.vcs._run")
    def test_restores_main_and_cleans(
        self, mock_run: MagicMock, mock_gt_co: MagicMock, tmp_path: Path,
    ):
        mock_run.return_value = _completed()
        reset_to_main(tmp_path)
        mock_run.assert_any_call(["git", "checkout", "main", "--", "."], tmp_path)
        mock_run.assert_any_call(["git", "clean", "-fd"], tmp_path)
        mock_gt_co.assert_called_once_with("main", tmp_path)


# ---------------------------------------------------------------------------
# gt_create
# ---------------------------------------------------------------------------


class TestGtCreate:
    @patch("maintenance_man.vcs._run")
    def test_success_first_try(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert gt_create("bump pkg-a", "bump/pkg-a", tmp_path) is True
        mock_run.assert_called_once_with(
            ["gt", "create", "bump/pkg-a", "-a", "-m", "bump pkg-a"],
            tmp_path,
            timeout=60,
        )

    @patch("maintenance_man.vcs._run")
    def test_non_duplicate_failure(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="some other error")
        assert gt_create("msg", "bump/pkg-a", tmp_path) is False

    @patch("maintenance_man.vcs._run")
    def test_stale_branch_delete_and_retry_succeeds(
        self, mock_run: MagicMock, tmp_path: Path,
    ):
        create_cmd = ["gt", "create", "bump/pkg-a", "-a", "-m", "msg"]
        mock_run.side_effect = [
            # First create — fails with "already exists"
            _completed(returncode=1, stderr="branch already exists"),
            # gt delete
            _completed(),
            # Retry create — succeeds
            _completed(),
        ]
        assert gt_create("msg", "bump/pkg-a", tmp_path) is True
        assert mock_run.call_count == 3

    @patch("maintenance_man.vcs._run")
    def test_stale_branch_retry_also_fails(
        self, mock_run: MagicMock, tmp_path: Path,
    ):
        mock_run.side_effect = [
            _completed(returncode=1, stderr="already exists"),
            _completed(),  # delete succeeds
            _completed(returncode=1, stderr="still broken"),  # retry fails
        ]
        assert gt_create("msg", "bump/pkg-a", tmp_path) is False


# ---------------------------------------------------------------------------
# gt_delete
# ---------------------------------------------------------------------------


class TestGtDelete:
    @patch("maintenance_man.vcs._run")
    def test_success(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert gt_delete("bump/pkg-a", tmp_path) is True
        mock_run.assert_called_once_with(
            ["gt", "delete", "-f", "bump/pkg-a"], tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_failure(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="not found")
        assert gt_delete("bump/pkg-a", tmp_path) is False


# ---------------------------------------------------------------------------
# gt_checkout
# ---------------------------------------------------------------------------


class TestGtCheckout:
    @patch("maintenance_man.vcs._run")
    def test_success(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert gt_checkout("bump/pkg-a", tmp_path) is True
        mock_run.assert_called_once_with(
            ["gt", "checkout", "bump/pkg-a"], tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_failure(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="no such branch")
        assert gt_checkout("bump/pkg-a", tmp_path) is False


# ---------------------------------------------------------------------------
# submit_stack
# ---------------------------------------------------------------------------


class TestSubmitStack:
    @patch("maintenance_man.vcs._run")
    def test_success_returns_stdout(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="PR #42 created")
        ok, output = submit_stack(tmp_path)
        assert ok is True
        assert output == "PR #42 created"
        mock_run.assert_called_once_with(
            ["gt", "submit", "--stack"], tmp_path, timeout=120,
        )

    @patch("maintenance_man.vcs._run")
    def test_failure_returns_stderr(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="auth failed")
        ok, output = submit_stack(tmp_path)
        assert ok is False
        assert output == "auth failed"


# ---------------------------------------------------------------------------
# sync_graphite
# ---------------------------------------------------------------------------


class TestSyncGraphite:
    @patch("maintenance_man.vcs._run")
    def test_deletes_merged_branches(self, mock_run: MagicMock, tmp_path: Path):
        def side_effect(cmd, *args, **kwargs):
            if cmd[:2] == ["gt", "sync"]:
                return _completed()
            if cmd[0] == "gh" and "--state" in cmd:
                state = cmd[cmd.index("--state") + 1]
                if state == "merged":
                    return _completed(stdout="bump/click\nbump/tornado\n")
                return _completed()
            if cmd[0] == "git" and "branch" in cmd:
                return _completed(
                    stdout="main\nbump/click\nbump/tornado\nbump/new-pkg\n"
                )
            if cmd[:2] == ["gt", "delete"]:
                return _completed()
            return _completed()

        mock_run.side_effect = side_effect
        assert sync_graphite(tmp_path) is True

        delete_calls = [
            c for c in mock_run.call_args_list
            if c[0][0][:2] == ["gt", "delete"]
        ]
        deleted = {c[0][0][3] for c in delete_calls}
        assert deleted == {"bump/click", "bump/tornado"}

    @patch("maintenance_man.vcs._run")
    def test_handles_gh_failure_gracefully(
        self, mock_run: MagicMock, tmp_path: Path,
    ):
        def side_effect(cmd, *args, **kwargs):
            if cmd[:2] == ["gt", "sync"]:
                return _completed()
            if cmd[0] == "gh":
                return _completed(returncode=1, stderr="auth error")
            return _completed()

        mock_run.side_effect = side_effect
        assert sync_graphite(tmp_path) is True

    @patch("maintenance_man.vcs._run")
    def test_falls_back_to_git_branch_delete(
        self, mock_run: MagicMock, tmp_path: Path,
    ):
        """When gt delete fails, falls back to git branch -D."""
        def side_effect(cmd, *args, **kwargs):
            if cmd[:2] == ["gt", "sync"]:
                return _completed()
            if cmd[0] == "gh" and "--state" in cmd:
                state = cmd[cmd.index("--state") + 1]
                if state == "closed":
                    return _completed(stdout="fix/vuln-1\n")
                return _completed()
            if cmd[0] == "git" and "--format=%(refname:short)" in cmd:
                return _completed(stdout="main\nfix/vuln-1\n")
            if cmd[:2] == ["gt", "delete"]:
                return _completed(returncode=1, stderr="not tracked")
            if cmd[:2] == ["git", "branch"] and "-D" in cmd:
                return _completed()
            return _completed()

        mock_run.side_effect = side_effect
        assert sync_graphite(tmp_path) is True

        git_delete = [
            c for c in mock_run.call_args_list
            if c[0][0][:2] == ["git", "branch"] and "-D" in c[0][0]
        ]
        assert len(git_delete) == 1
        assert "fix/vuln-1" in git_delete[0][0][0]

    @patch("maintenance_man.vcs._run")
    def test_ignores_non_prefixed_branches(
        self, mock_run: MagicMock, tmp_path: Path,
    ):
        """Branches not matching bump/ or fix/ prefixes are left alone."""
        def side_effect(cmd, *args, **kwargs):
            if cmd[:2] == ["gt", "sync"]:
                return _completed()
            if cmd[0] == "gh" and "--state" in cmd:
                return _completed(stdout="feature/cool-thing\nmain\n")
            if cmd[0] == "git" and "branch" in cmd:
                return _completed(stdout="main\nfeature/cool-thing\n")
            return _completed()

        mock_run.side_effect = side_effect
        assert sync_graphite(tmp_path) is True

        delete_calls = [
            c for c in mock_run.call_args_list
            if c[0][0][:2] == ["gt", "delete"] or (
                c[0][0][:2] == ["git", "branch"] and "-D" in c[0][0]
            )
        ]
        assert len(delete_calls) == 0
