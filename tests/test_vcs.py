import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from maintenance_man.vcs import (
    GitHubCLINotFoundError,
    RepoDirtyError,
    branch_slug,
    check_gh_available,
    check_repo_clean,
    create_worktree,
    discard_changes,
    ensure_on_main,
    get_current_branch,
    git_branch_exists,
    git_checkout,
    git_commit_all,
    git_create_branch,
    git_delete_branch,
    git_has_changes,
    git_merge_fast_forward,
    git_replace_branch,
    push_and_create_pr,
    remove_worktree,
    reset_to_main,
    sync_remote,
)


def _completed(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _deleted_branch_names(mock_run: MagicMock) -> set[str]:
    return {
        call_args[0][0][3]
        for call_args in mock_run.call_args_list
        if call_args[0][0][:2] == ["git", "branch"] and "-D" in call_args[0][0]
    }


def _sync_remote_side_effect(pr_state: str, stale_branch: str):
    """Build a `_run` side_effect where *stale_branch* appears in PR *pr_state*.

    The branch exists locally (alongside `main`) and its delete succeeds.
    """

    def side_effect(cmd, *args, **kwargs):
        if cmd[:2] == ["git", "fetch"]:
            return _completed()
        if cmd[0] == "gh" and "--state" in cmd:
            if cmd[cmd.index("--state") + 1] == pr_state:
                return _completed(stdout=f"{stale_branch}\n")
            return _completed()
        if cmd[0] == "git" and "--format=%(refname:short)" in cmd:
            return _completed(stdout=f"main\n{stale_branch}\n")
        if cmd[:2] == ["git", "branch"] and "-D" in cmd:
            return _completed()
        return _completed()

    return side_effect


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
# check_gh_available
# ---------------------------------------------------------------------------


class TestCheckGhAvailable:
    def test_gh_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "maintenance_man.vcs.shutil.which",
            lambda cmd: "/usr/bin/gh" if cmd == "gh" else None,
        )
        check_gh_available()  # should not raise

    def test_gh_not_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("maintenance_man.vcs.shutil.which", lambda cmd: None)
        with pytest.raises(GitHubCLINotFoundError):
            check_gh_available()


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
        mock_run.return_value = _completed(stdout="mm/update-dependencies\n")
        assert get_current_branch(tmp_path) == "mm/update-dependencies"

    @patch("maintenance_man.vcs._run")
    def test_strips_whitespace(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="  fix/some-pkg  \n")
        assert get_current_branch(tmp_path) == "fix/some-pkg"


# ---------------------------------------------------------------------------
# ensure_on_main
# ---------------------------------------------------------------------------


class TestEnsureOnMain:
    @patch("maintenance_man.vcs.git_checkout")
    @patch("maintenance_man.vcs.get_current_branch", return_value="main")
    def test_already_on_main(
        self, mock_branch: MagicMock, mock_checkout: MagicMock, tmp_path: Path
    ):
        assert ensure_on_main(tmp_path) is True
        mock_checkout.assert_not_called()

    @patch("maintenance_man.vcs.git_checkout", return_value=True)
    @patch("maintenance_man.vcs.get_current_branch", return_value="feat/x")
    def test_checks_out_main(
        self, mock_branch: MagicMock, mock_checkout: MagicMock, tmp_path: Path
    ):
        assert ensure_on_main(tmp_path) is True
        mock_checkout.assert_called_once_with("main", tmp_path)


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
    @patch("maintenance_man.vcs.git_checkout", return_value=True)
    @patch("maintenance_man.vcs._run")
    def test_restores_main_and_cleans(
        self,
        mock_run: MagicMock,
        mock_git_co: MagicMock,
        tmp_path: Path,
    ):
        mock_run.return_value = _completed()
        reset_to_main(tmp_path)
        mock_run.assert_any_call(["git", "checkout", "main", "--", "."], tmp_path)
        mock_run.assert_any_call(["git", "clean", "-fd"], tmp_path)
        mock_git_co.assert_called_once_with("main", tmp_path)


# ---------------------------------------------------------------------------
# git_checkout
# ---------------------------------------------------------------------------


class TestGitCheckout:
    @patch("maintenance_man.vcs._run")
    def test_success(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert git_checkout("mm/update-dependencies", tmp_path) is True
        mock_run.assert_called_once_with(
            ["git", "checkout", "mm/update-dependencies"],
            tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_failure(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="no such branch")
        assert git_checkout("mm/update-dependencies", tmp_path) is False


# ---------------------------------------------------------------------------
# git_create_branch
# ---------------------------------------------------------------------------


class TestGitCreateBranch:
    @patch("maintenance_man.vcs._run")
    def test_success_first_try(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert git_create_branch("mm/update-dependencies", tmp_path) is True
        mock_run.assert_called_once_with(
            ["git", "checkout", "-b", "mm/update-dependencies"],
            tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_non_duplicate_failure(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="some other error")
        assert git_create_branch("mm/update-dependencies", tmp_path) is False

    @patch("maintenance_man.vcs._run")
    def test_stale_branch_delete_and_retry_succeeds(
        self,
        mock_run: MagicMock,
        tmp_path: Path,
    ):
        mock_run.side_effect = [
            _completed(returncode=1, stderr="branch already exists"),
            _completed(),  # git branch -D
            _completed(),  # retry checkout -b
        ]
        assert git_create_branch("mm/update-dependencies", tmp_path) is True
        assert mock_run.call_count == 3

    @patch("maintenance_man.vcs._run")
    def test_stale_branch_retry_also_fails(
        self,
        mock_run: MagicMock,
        tmp_path: Path,
    ):
        mock_run.side_effect = [
            _completed(returncode=1, stderr="already exists"),
            _completed(),  # delete succeeds
            _completed(returncode=1, stderr="still broken"),  # retry fails
        ]
        assert git_create_branch("mm/update-dependencies", tmp_path) is False


# ---------------------------------------------------------------------------
# git_branch_exists
# ---------------------------------------------------------------------------


class TestGitBranchExists:
    @patch("maintenance_man.vcs._run")
    def test_branch_exists(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="mm/update-dependencies\n")
        assert git_branch_exists("mm/update-dependencies", tmp_path) is True
        mock_run.assert_called_once_with(
            ["git", "rev-parse", "--verify", "mm/update-dependencies"],
            tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_branch_does_not_exist(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(
            returncode=1, stderr="fatal: not a valid ref"
        )
        assert git_branch_exists("mm/update-dependencies", tmp_path) is False


# ---------------------------------------------------------------------------
# git_has_changes
# ---------------------------------------------------------------------------


class TestGitHasChanges:
    @patch("maintenance_man.vcs._run")
    def test_true_when_repo_has_changes(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout=" M src/file.py\n")
        assert git_has_changes(tmp_path) is True
        mock_run.assert_called_once_with(["git", "status", "--porcelain"], tmp_path)

    @patch("maintenance_man.vcs._run")
    def test_false_when_repo_is_clean(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="")
        assert git_has_changes(tmp_path) is False


# ---------------------------------------------------------------------------
# git_merge_fast_forward
# ---------------------------------------------------------------------------


class TestGitMergeFastForward:
    @patch("maintenance_man.vcs._run")
    def test_success(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert git_merge_fast_forward("mm/update-dependencies", tmp_path) is True
        mock_run.assert_called_once_with(
            ["git", "merge", "--ff-only", "mm/update-dependencies"],
            tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_not_fast_forwardable(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(
            returncode=1, stderr="fatal: Not possible to fast-forward"
        )
        assert git_merge_fast_forward("mm/update-dependencies", tmp_path) is False


# ---------------------------------------------------------------------------
# git_replace_branch
# ---------------------------------------------------------------------------


class TestGitReplaceBranch:
    @patch("maintenance_man.vcs.get_current_branch", return_value="feature/current")
    @patch("maintenance_man.vcs.git_create_branch", return_value=True)
    @patch("maintenance_man.vcs.git_delete_branch", return_value=True)
    @patch("maintenance_man.vcs.git_checkout", return_value=True)
    def test_success(
        self,
        mock_checkout: MagicMock,
        mock_delete: MagicMock,
        mock_create: MagicMock,
        _mock_branch: MagicMock,
        tmp_path: Path,
    ):
        assert git_replace_branch("mm/update-dependencies", tmp_path) is True
        mock_checkout.assert_called_once_with("main", tmp_path)
        mock_delete.assert_called_once_with("mm/update-dependencies", tmp_path)
        mock_create.assert_called_once_with("mm/update-dependencies", tmp_path)

    @patch("maintenance_man.vcs.get_current_branch", return_value="")
    @patch("maintenance_man.vcs.git_create_branch", return_value=True)
    @patch("maintenance_man.vcs.git_delete_branch", return_value=True)
    @patch("maintenance_man.vcs.git_checkout", return_value=True)
    def test_detached_head_skips_checkout_and_recreates_branch(
        self,
        mock_checkout: MagicMock,
        mock_delete: MagicMock,
        mock_create: MagicMock,
        _mock_branch: MagicMock,
        tmp_path: Path,
    ):
        assert git_replace_branch("mm/update-dependencies", tmp_path) is True
        mock_checkout.assert_not_called()
        mock_delete.assert_called_once_with("mm/update-dependencies", tmp_path)
        mock_create.assert_called_once_with("mm/update-dependencies", tmp_path)

    @patch("maintenance_man.vcs.get_current_branch", return_value="feature/current")
    @patch("maintenance_man.vcs.git_create_branch", return_value=True)
    @patch("maintenance_man.vcs.git_delete_branch", return_value=True)
    @patch("maintenance_man.vcs.git_checkout", return_value=False)
    def test_checkout_failure_aborts(
        self,
        mock_checkout: MagicMock,
        mock_delete: MagicMock,
        mock_create: MagicMock,
        _mock_branch: MagicMock,
        tmp_path: Path,
    ):
        assert git_replace_branch("mm/update-dependencies", tmp_path) is False
        mock_delete.assert_not_called()
        mock_create.assert_not_called()

    @patch("maintenance_man.vcs.get_current_branch", return_value="feature/current")
    @patch("maintenance_man.vcs.git_create_branch", return_value=True)
    @patch("maintenance_man.vcs.git_delete_branch", return_value=False)
    @patch("maintenance_man.vcs.git_checkout", return_value=True)
    def test_delete_failure_aborts(
        self,
        mock_checkout: MagicMock,
        mock_delete: MagicMock,
        mock_create: MagicMock,
        _mock_branch: MagicMock,
        tmp_path: Path,
    ):
        assert git_replace_branch("mm/update-dependencies", tmp_path) is False
        mock_delete.assert_called_once_with("mm/update-dependencies", tmp_path)
        mock_create.assert_not_called()

    @patch("maintenance_man.vcs.get_current_branch", return_value="feature/current")
    @patch("maintenance_man.vcs.git_create_branch", return_value=False)
    @patch("maintenance_man.vcs.git_delete_branch", return_value=True)
    @patch("maintenance_man.vcs.git_checkout", return_value=True)
    def test_create_failure_aborts(
        self,
        mock_checkout: MagicMock,
        mock_delete: MagicMock,
        mock_create: MagicMock,
        _mock_branch: MagicMock,
        tmp_path: Path,
    ):
        assert git_replace_branch("mm/update-dependencies", tmp_path) is False
        mock_create.assert_called_once_with("mm/update-dependencies", tmp_path)


# ---------------------------------------------------------------------------
# git_commit_all
# ---------------------------------------------------------------------------


class TestGitCommitAll:
    @patch("maintenance_man.vcs._run")
    def test_success_stages_all_changes_before_commit(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.side_effect = [
            _completed(),  # git add -A
            _completed(),  # git commit -m
        ]
        assert git_commit_all("bump pkg-a", tmp_path) is True
        assert mock_run.call_args_list == [
            call(["git", "add", "-A"], tmp_path),
            call(["git", "commit", "-m", "bump pkg-a"], tmp_path),
        ]

    @patch("maintenance_man.vcs._run")
    def test_add_failure_stops_before_commit(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="index locked")
        assert git_commit_all("bump pkg-a", tmp_path) is False
        assert mock_run.call_args_list == [
            call(["git", "add", "-A"], tmp_path),
        ]

    @patch("maintenance_man.vcs._run")
    def test_commit_failure(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.side_effect = [
            _completed(),
            _completed(returncode=1, stderr="nothing to commit"),
        ]
        assert git_commit_all("bump pkg-a", tmp_path) is False


# ---------------------------------------------------------------------------
# git_delete_branch
# ---------------------------------------------------------------------------


class TestGitDeleteBranch:
    @patch("maintenance_man.vcs._run")
    def test_success(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert git_delete_branch("mm/update-dependencies", tmp_path) is True
        mock_run.assert_called_once_with(
            ["git", "branch", "-D", "mm/update-dependencies"],
            tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_failure(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="not found")
        assert git_delete_branch("mm/update-dependencies", tmp_path) is False


# ---------------------------------------------------------------------------
# push_and_create_pr
# ---------------------------------------------------------------------------


class TestPushAndCreatePr:
    @patch(
        "maintenance_man.vcs.get_current_branch", return_value="mm/update-dependencies"
    )
    @patch("maintenance_man.vcs._run")
    def test_success_returns_pr_url(
        self, mock_run: MagicMock, _mock_branch: MagicMock, tmp_path: Path
    ):
        mock_run.side_effect = [
            _completed(),  # git push
            _completed(stdout="https://github.com/owner/repo/pull/42"),
        ]
        ok, output = push_and_create_pr(tmp_path)
        assert ok is True
        assert output == "https://github.com/owner/repo/pull/42"
        mock_run.assert_any_call(
            ["git", "push", "-u", "origin", "mm/update-dependencies"],
            tmp_path,
            timeout=120,
        )
        mock_run.assert_any_call(
            ["gh", "pr", "create", "--fill", "--head", "mm/update-dependencies"],
            tmp_path,
            timeout=60,
        )

    @patch(
        "maintenance_man.vcs.get_current_branch", return_value="mm/update-dependencies"
    )
    @patch("maintenance_man.vcs._run")
    def test_non_fast_forward_push_retries_with_force_with_lease(
        self, mock_run: MagicMock, _mock_branch: MagicMock, tmp_path: Path
    ):
        mock_run.side_effect = [
            _completed(returncode=1, stderr="non-fast-forward"),
            _completed(),
            _completed(stdout="https://github.com/owner/repo/pull/42"),
        ]
        ok, output = push_and_create_pr(tmp_path)
        assert ok is True
        assert output == "https://github.com/owner/repo/pull/42"
        assert mock_run.call_args_list[:2] == [
            call(
                ["git", "push", "-u", "origin", "mm/update-dependencies"],
                tmp_path,
                timeout=120,
            ),
            call(
                [
                    "git",
                    "push",
                    "--force-with-lease",
                    "-u",
                    "origin",
                    "mm/update-dependencies",
                ],
                tmp_path,
                timeout=120,
            ),
        ]

    @patch("maintenance_man.vcs.get_current_branch", return_value="feature/manual")
    @patch("maintenance_man.vcs._run")
    def test_non_managed_branch_does_not_force_push(
        self, mock_run: MagicMock, _mock_branch: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(returncode=1, stderr="non-fast-forward")
        ok, output = push_and_create_pr(tmp_path)
        assert ok is False
        assert output == "non-fast-forward"
        mock_run.assert_called_once_with(
            ["git", "push", "-u", "origin", "feature/manual"],
            tmp_path,
            timeout=120,
        )

    @patch(
        "maintenance_man.vcs.get_current_branch", return_value="mm/update-dependencies"
    )
    @patch("maintenance_man.vcs._run")
    def test_push_failure_returns_stderr(
        self, mock_run: MagicMock, _mock_branch: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(returncode=1, stderr="auth failed")
        ok, output = push_and_create_pr(tmp_path)
        assert ok is False
        assert output == "auth failed"

    @patch(
        "maintenance_man.vcs.get_current_branch", return_value="mm/update-dependencies"
    )
    @patch("maintenance_man.vcs._run")
    def test_force_with_lease_failure_returns_retry_stderr(
        self, mock_run: MagicMock, _mock_branch: MagicMock, tmp_path: Path
    ):
        mock_run.side_effect = [
            _completed(returncode=1, stderr="[rejected] non-fast-forward"),
            _completed(returncode=1, stderr="force-with-lease rejected"),
        ]
        ok, output = push_and_create_pr(tmp_path)
        assert ok is False
        assert output == "force-with-lease rejected"

    @patch(
        "maintenance_man.vcs.get_current_branch", return_value="mm/update-dependencies"
    )
    @patch("maintenance_man.vcs._run")
    def test_pr_already_exists(
        self, mock_run: MagicMock, _mock_branch: MagicMock, tmp_path: Path
    ):
        mock_run.side_effect = [
            _completed(),  # git push
            _completed(returncode=1, stderr="a pull request already exists"),
        ]
        ok, output = push_and_create_pr(tmp_path)
        assert ok is True

    @patch(
        "maintenance_man.vcs.get_current_branch", return_value="mm/update-dependencies"
    )
    @patch("maintenance_man.vcs._run")
    def test_pr_create_failure_returns_stderr(
        self, mock_run: MagicMock, _mock_branch: MagicMock, tmp_path: Path
    ):
        mock_run.side_effect = [
            _completed(),  # git push
            _completed(returncode=1, stderr="GraphQL: resource not accessible"),
        ]
        ok, output = push_and_create_pr(tmp_path)
        assert ok is False
        assert output == "GraphQL: resource not accessible"

    @patch("maintenance_man.vcs.get_current_branch", return_value="")
    def test_detached_head_fails(self, _mock_branch: MagicMock, tmp_path: Path):
        ok, output = push_and_create_pr(tmp_path)
        assert ok is False
        assert "detached" in output.lower()


# ---------------------------------------------------------------------------
# sync_remote
# ---------------------------------------------------------------------------


class TestSyncRemote:
    @patch("maintenance_man.vcs._run")
    def test_deletes_merged_branches(self, mock_run: MagicMock, tmp_path: Path):
        def side_effect(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "fetch"]:
                return _completed()
            if cmd[0] == "gh" and "--state" in cmd:
                state = cmd[cmd.index("--state") + 1]
                if state == "merged":
                    return _completed(
                        stdout="mm/update-dependencies\nmm/resolve-dependencies\n"
                    )
                return _completed()
            if cmd[0] == "git" and "--format=%(refname:short)" in cmd:
                return _completed(
                    stdout=(
                        "main\n"
                        "mm/update-dependencies\n"
                        "mm/resolve-dependencies\n"
                        "feature/keep-me\n"
                    )
                )
            if cmd[:2] == ["git", "branch"] and "-D" in cmd:
                return _completed()
            return _completed()

        mock_run.side_effect = side_effect
        assert sync_remote(tmp_path) is True

        assert _deleted_branch_names(mock_run) == {
            "mm/update-dependencies",
            "mm/resolve-dependencies",
        }

    @patch("maintenance_man.vcs._run")
    def test_handles_gh_failure_gracefully(
        self,
        mock_run: MagicMock,
        tmp_path: Path,
    ):
        def side_effect(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "fetch"]:
                return _completed()
            if cmd[0] == "gh":
                return _completed(returncode=1, stderr="auth error")
            return _completed()

        mock_run.side_effect = side_effect
        assert sync_remote(tmp_path) is True

    @patch("maintenance_man.vcs._run")
    def test_ignores_non_prefixed_branches(
        self,
        mock_run: MagicMock,
        tmp_path: Path,
    ):
        """Branches not matching managed prefixes are left alone."""

        def side_effect(cmd, *args, **kwargs):
            if cmd[:2] == ["git", "fetch"]:
                return _completed()
            if cmd[0] == "gh" and "--state" in cmd:
                return _completed(stdout="feature/cool-thing\nmain\n")
            if cmd[0] == "git" and "branch" in cmd:
                return _completed(stdout="main\nfeature/cool-thing\n")
            return _completed()

        mock_run.side_effect = side_effect
        assert sync_remote(tmp_path) is True

        assert _deleted_branch_names(mock_run) == set()

    @pytest.mark.parametrize(
        ("pr_state", "stale_branch"),
        [
            pytest.param("closed", "mm/update-dependencies", id="update-closed"),
            pytest.param("merged", "mm/resolve-dependencies", id="resolve-merged"),
        ],
    )
    @patch("maintenance_man.vcs._run")
    def test_deletes_stale_managed_branch(
        self,
        mock_run: MagicMock,
        pr_state: str,
        stale_branch: str,
        tmp_path: Path,
    ):
        mock_run.side_effect = _sync_remote_side_effect(pr_state, stale_branch)
        assert sync_remote(tmp_path) is True
        assert _deleted_branch_names(mock_run) == {stale_branch}


# ---------------------------------------------------------------------------
# create_worktree
# ---------------------------------------------------------------------------


class TestCreateWorktree:
    def test_success_returns_true(self):
        mock_run = MagicMock(return_value=_completed(0))
        with patch("maintenance_man.vcs._run", mock_run):
            result = create_worktree(Path("/repo"), Path("/tmp/wt"))
        assert result is True
        mock_run.assert_called_once_with(
            ["git", "worktree", "add", "--detach", "/tmp/wt", "main"],
            Path("/repo"),
            timeout=30,
        )

    def test_failure_returns_false(self):
        mock_run = MagicMock(
            return_value=_completed(1, stderr="fatal: branch already checked out")
        )
        with patch("maintenance_man.vcs._run", mock_run):
            result = create_worktree(Path("/repo"), Path("/tmp/wt"))
        assert result is False

    def test_can_attach_worktree_to_specific_branch(self):
        mock_run = MagicMock(return_value=_completed(0))
        with patch("maintenance_man.vcs._run", mock_run):
            result = create_worktree(
                Path("/repo"),
                Path("/tmp/wt"),
                branch="mm/update-dependencies",
                detach=False,
            )
        assert result is True
        mock_run.assert_called_once_with(
            [
                "git",
                "worktree",
                "add",
                "/tmp/wt",
                "mm/update-dependencies",
            ],
            Path("/repo"),
            timeout=30,
        )


# ---------------------------------------------------------------------------
# remove_worktree
# ---------------------------------------------------------------------------


class TestRemoveWorktree:
    def test_calls_git_worktree_remove(self):
        mock_run = MagicMock(return_value=_completed(0))
        with patch("maintenance_man.vcs._run", mock_run):
            remove_worktree(Path("/repo"), Path("/tmp/wt"))
        mock_run.assert_called_once_with(
            ["git", "worktree", "remove", "--force", "/tmp/wt"],
            Path("/repo"),
            timeout=30,
        )
