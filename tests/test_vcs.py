import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

import maintenance_man.vcs as vcs
from maintenance_man.vcs import (
    GitHubCLINotFoundError,
    JJCLINotFoundError,
    _main_bookmark_is_conflicted,
    assert_safe_workspace_path,
    bookmark_exists,
    bookmark_slug,
    check_gh_available,
    check_jj_available,
    commit_current_change,
    create_or_reset_bookmark,
    create_workspace,
    current_change_has_changes,
    current_label,
    delete_bookmark,
    discard_current_change,
    edit_new_change,
    ensure_main_bookmark,
    promote_bookmark_to_main,
    prune_stale_bookmarks,
    push_bookmark_and_create_pr,
    remove_workspace,
    resolve_bookmark_contains_current_change,
    sync_main,
    workspace_path_for_project,
)


def _completed(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestFinalVcsSurface:
    @pytest.mark.parametrize(
        "name",
        [
            "get_current_branch",
            "git_checkout",
            "ensure_on_main",
            "git_branch_exists",
            "git_create_branch",
            "git_replace_branch",
            "git_delete_branch",
            "git_merge_fast_forward",
            "git_commit_all",
            "git_has_changes",
            "discard_changes",
            "reset_to_main",
            "create_worktree",
            "remove_worktree",
            "branch_slug",
            "_clean_git_stderr",
            "_is_non_fast_forward_push",
            "_is_managed_update_branch",
            "prune_stale_branches",
            "push_and_create_pr",
        ],
    )
    def test_obsolete_git_mutation_helpers_are_removed(self, name: str):
        assert not hasattr(vcs, name)


class TestBookmarkSlug:
    @pytest.mark.parametrize(
        ("input_name", "expected"),
        [
            pytest.param("express", "express", id="plain"),
            pytest.param("@types/bun", "types-bun", id="scoped-npm"),
            pytest.param("@babel/preset-env", "babel-preset-env", id="deeply-scoped"),
            pytest.param("lodash", "lodash", id="no-at-no-slash"),
        ],
    )
    def test_bookmark_slug(self, input_name: str, expected: str):
        assert bookmark_slug(input_name) == expected


class TestCheckGhAvailable:
    def test_gh_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "maintenance_man.vcs.shutil.which",
            lambda cmd: "/usr/bin/gh" if cmd == "gh" else None,
        )
        check_gh_available()

    def test_gh_not_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("maintenance_man.vcs.shutil.which", lambda cmd: None)
        with pytest.raises(GitHubCLINotFoundError):
            check_gh_available()


class TestCheckJjAvailable:
    def test_jj_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "maintenance_man.vcs.shutil.which",
            lambda cmd: "/usr/bin/jj" if cmd == "jj" else None,
        )
        check_jj_available()

    def test_jj_not_on_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("maintenance_man.vcs.shutil.which", lambda cmd: None)
        with pytest.raises(JJCLINotFoundError, match="jj is required"):
            check_jj_available()


class TestCurrentLabel:
    @patch("maintenance_man.vcs._run")
    def test_prefers_bookmark_on_current_revision(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(stdout="mm/update-dependencies\n")
        assert current_label(tmp_path) == "mm/update-dependencies"

    @patch("maintenance_man.vcs._run")
    def test_uses_parent_bookmark_when_current_has_none(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.side_effect = [_completed(stdout=""), _completed(stdout="main\n")]
        assert current_label(tmp_path) == "main"

    @patch("maintenance_man.vcs._run")
    def test_falls_back_to_short_change_id(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.side_effect = [
            _completed(stdout=""),
            _completed(stdout=""),
            _completed(stdout="abcdef12\n"),
        ]
        assert current_label(tmp_path) == "@ abcdef12"

    @patch("maintenance_man.vcs._run", side_effect=RuntimeError("boom"))
    def test_never_raises(self, _mock_run: MagicMock, tmp_path: Path):
        assert current_label(tmp_path) == "unknown"


class TestBookmarkHelpers:
    @patch("maintenance_man.vcs._run")
    def test_bookmark_exists_true(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="main")
        assert bookmark_exists("main", tmp_path) is True
        mock_run.assert_called_once_with(
            ["jj", "bookmark", "list", "-T", "name", "main"], tmp_path
        )

    @patch("maintenance_man.vcs._run")
    def test_bookmark_exists_false_when_stdout_empty(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(returncode=0, stdout="")
        assert bookmark_exists("main", tmp_path) is False

    @patch("maintenance_man.vcs._run")
    def test_bookmark_exists_false_on_command_failure(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(returncode=1, stderr="template error")
        assert bookmark_exists("main", tmp_path) is False

    @patch("maintenance_man.vcs._run")
    def test_create_or_reset_bookmark_sets_revision(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed()
        assert (
            create_or_reset_bookmark("mm/update-dependencies", tmp_path, "main") is True
        )
        mock_run.assert_called_once_with(
            ["jj", "bookmark", "set", "mm/update-dependencies", "-r", "main"],
            tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_delete_bookmark(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert delete_bookmark("mm/update-dependencies", tmp_path) is True
        mock_run.assert_called_once_with(
            ["jj", "bookmark", "delete", "mm/update-dependencies"], tmp_path
        )

    @patch("maintenance_man.vcs._run")
    def test_promote_bookmark_to_main(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert promote_bookmark_to_main(tmp_path, "mm/update-dependencies") is True
        mock_run.assert_called_once_with(
            ["jj", "bookmark", "set", "main", "-r", "mm/update-dependencies"],
            tmp_path,
        )


class TestChangeHelpers:
    @patch("maintenance_man.vcs._run")
    def test_edit_new_change(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert edit_new_change(tmp_path, "mm/update-dependencies") is True
        mock_run.assert_called_once_with(
            ["jj", "new", "mm/update-dependencies"], tmp_path
        )

    @patch("maintenance_man.vcs._run")
    def test_commit_current_change(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed()
        assert commit_current_change(tmp_path, "bump pkg-a") is True
        mock_run.assert_called_once_with(["jj", "commit", "-m", "bump pkg-a"], tmp_path)

    @patch("maintenance_man.vcs._run")
    def test_current_change_has_changes(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="M pyproject.toml\n")
        assert current_change_has_changes(tmp_path) is True
        mock_run.assert_called_once_with(["jj", "diff", "--summary"], tmp_path)

    @patch("maintenance_man.vcs._run")
    def test_current_change_clean(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="")
        assert current_change_has_changes(tmp_path) is False

    @patch("maintenance_man.vcs._run")
    def test_diff_failure_is_treated_as_dirty(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(returncode=1, stderr="broken")
        assert current_change_has_changes(tmp_path) is True

    @patch("maintenance_man.vcs._run")
    def test_discard_current_change_restores_from_parent(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed()
        assert discard_current_change(tmp_path) is True
        mock_run.assert_called_once_with(["jj", "restore", "--from", "@-"], tmp_path)

    @patch("maintenance_man.vcs._run")
    def test_discard_current_change_reports_failure(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(returncode=1, stderr="restore failed")
        assert discard_current_change(tmp_path) is False


class TestResolveBookmarkContainsCurrentChange:
    @patch("maintenance_man.vcs._run")
    def test_true_when_revset_returns_current_change(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(stdout="abc\n")
        assert (
            resolve_bookmark_contains_current_change(
                tmp_path, "mm/resolve-dependencies"
            )
            is True
        )
        mock_run.assert_called_once_with(
            [
                "jj",
                "log",
                "-r",
                "mm/resolve-dependencies::@ & @",
                "--no-graph",
                "-T",
                "change_id",
            ],
            tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_false_when_revset_empty(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(stdout="")
        assert (
            resolve_bookmark_contains_current_change(
                tmp_path, "mm/resolve-dependencies"
            )
            is False
        )


class TestWorkspacePathSafety:
    def test_workspace_path_is_derived_from_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        root = tmp_path / ".mm" / "workspaces"
        monkeypatch.setattr("maintenance_man.vcs.MM_WORKSPACES", root)
        assert workspace_path_for_project("api/service") == root / "api_service"

    @pytest.mark.parametrize(
        "bad_path",
        [
            Path("/"),
            Path("/home/glykon/dev/example"),
            Path("/home/glykon/.mm"),
            Path("/home/glykon/.mm/workspaces"),
            Path("/home/glykon/.mm/workspaces/../config.toml"),
            Path("/home/glykon/.mm/workspaces/project/subdir"),
        ],
    )
    def test_refuses_unsafe_workspace_paths(
        self, bad_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(
            "maintenance_man.vcs.MM_WORKSPACES",
            Path("/home/glykon/.mm/workspaces"),
        )
        with pytest.raises(ValueError, match="refusing"):
            assert_safe_workspace_path(bad_path)

    def test_refuses_symlink_escape(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        root = tmp_path / ".mm" / "workspaces"
        outside = tmp_path / "outside"
        root.mkdir(parents=True)
        outside.mkdir()
        link = root / "project"
        link.symlink_to(outside, target_is_directory=True)
        monkeypatch.setattr("maintenance_man.vcs.MM_WORKSPACES", root)

        with pytest.raises(ValueError, match="outside"):
            assert_safe_workspace_path(link)

    def test_accepts_direct_child_workspace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        root = tmp_path / ".mm" / "workspaces"
        workspace = root / "project"
        workspace.mkdir(parents=True)
        monkeypatch.setattr("maintenance_man.vcs.MM_WORKSPACES", root)
        assert assert_safe_workspace_path(workspace) == workspace.resolve()


class TestWorkspaceHelpers:
    @patch("maintenance_man.vcs._run")
    def test_create_workspace_uses_derived_path_and_name(
        self, mock_run: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        root = tmp_path / ".mm" / "workspaces"
        monkeypatch.setattr("maintenance_man.vcs.MM_WORKSPACES", root)
        mock_run.return_value = _completed()

        assert create_workspace(Path("/repo"), "api/service", "main") is True

        mock_run.assert_called_once_with(
            [
                "jj",
                "workspace",
                "add",
                "--name",
                "mm-api_service",
                str(root / "api_service"),
                "-r",
                "main",
            ],
            Path("/repo"),
            timeout=30,
        )

    @patch("maintenance_man.vcs.shutil.rmtree")
    @patch("maintenance_man.vcs._run")
    def test_remove_workspace_forgets_then_deletes_safe_path(
        self,
        mock_run: MagicMock,
        mock_rmtree: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        root = tmp_path / ".mm" / "workspaces"
        workspace = root / "api"
        workspace.mkdir(parents=True)
        monkeypatch.setattr("maintenance_man.vcs.MM_WORKSPACES", root)
        mock_run.return_value = _completed()

        remove_workspace(Path("/repo"), "api")

        mock_run.assert_called_once_with(
            ["jj", "workspace", "forget", "mm-api"],
            Path("/repo"),
        )
        mock_rmtree.assert_called_once_with(workspace.resolve())


def _deleted_bookmark_names(mock_run: MagicMock) -> set[str]:
    return {
        call_args[0][0][3]
        for call_args in mock_run.call_args_list
        if call_args[0][0][:3] == ["jj", "bookmark", "delete"]
    }


class TestPruneStaleBookmarks:
    @patch("maintenance_man.vcs._run")
    def test_deletes_merged_managed_bookmarks(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        def side_effect(cmd, *args, **kwargs):
            if cmd[:3] == ["jj", "git", "fetch"]:
                return _completed()
            if cmd[0] == "gh" and "--state" in cmd:
                state = cmd[cmd.index("--state") + 1]
                if state == "merged":
                    return _completed(stdout="mm/update-dependencies\n")
                return _completed()
            if cmd[:3] == ["jj", "bookmark", "list"]:
                return _completed(
                    stdout="main: abc\nmm/update-dependencies: def\nfeature/keep: ghi\n"
                )
            if cmd[:3] == ["jj", "bookmark", "delete"]:
                return _completed()
            return _completed()

        mock_run.side_effect = side_effect
        assert prune_stale_bookmarks(tmp_path) is True
        assert _deleted_bookmark_names(mock_run) == {"mm/update-dependencies"}

    @patch("maintenance_man.vcs._run")
    def test_fetch_failure_returns_false(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="network error")
        assert prune_stale_bookmarks(tmp_path) is False


class TestPushBookmarkAndCreatePr:
    @patch("maintenance_man.vcs._run")
    def test_success_returns_pr_url(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.side_effect = [
            _completed(),
            _completed(stdout="https://github.com/owner/repo/pull/42"),
        ]
        ok, output = push_bookmark_and_create_pr(tmp_path, "mm/resolve-dependencies")
        assert ok is True
        assert output == "https://github.com/owner/repo/pull/42"
        mock_run.assert_any_call(
            [
                "jj",
                "git",
                "push",
                "--bookmark",
                "mm/resolve-dependencies",
                "--remote",
                "origin",
            ],
            tmp_path,
            timeout=120,
        )
        mock_run.assert_any_call(
            [
                "gh",
                "pr",
                "create",
                "--fill",
                "--head",
                "mm/resolve-dependencies",
                "--base",
                "main",
            ],
            tmp_path,
            timeout=60,
        )

    @patch("maintenance_man.vcs._run")
    def test_pr_already_exists_is_success(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.side_effect = [
            _completed(),
            _completed(returncode=1, stderr="a pull request already exists"),
        ]
        ok, output = push_bookmark_and_create_pr(tmp_path, "mm/resolve-dependencies")
        assert ok is True
        assert "already exists" in output.lower()

    @patch("maintenance_man.vcs._run")
    def test_push_failure_returns_stderr_and_does_not_create_pr(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(returncode=1, stderr="push rejected")
        ok, output = push_bookmark_and_create_pr(tmp_path, "mm/resolve-dependencies")
        assert ok is False
        assert output == "push rejected"
        assert mock_run.call_count == 1


class TestEnsureMainBookmark:
    @patch("maintenance_man.vcs.bookmark_exists", side_effect=[True])
    @patch("maintenance_man.vcs._run")
    def test_existing_main_is_ok(
        self, mock_run: MagicMock, _mock_exists: MagicMock, tmp_path: Path
    ):
        assert ensure_main_bookmark(tmp_path) is True
        mock_run.assert_not_called()

    @patch("maintenance_man.vcs.bookmark_exists", return_value=False)
    @patch("maintenance_man.vcs._run")
    def test_creates_main_from_origin_revision(
        self, mock_run: MagicMock, _mock_exists: MagicMock, tmp_path: Path
    ):
        mock_run.side_effect = [_completed(stdout="abc\n"), _completed()]
        assert ensure_main_bookmark(tmp_path) is True
        assert mock_run.call_args_list == [
            call(
                ["jj", "log", "-r", "main@origin", "--no-graph", "-T", "commit_id"],
                tmp_path,
            ),
            call(["jj", "bookmark", "create", "main", "-r", "main@origin"], tmp_path),
        ]

    @patch("maintenance_man.vcs.bookmark_exists", return_value=False)
    @patch("maintenance_man.vcs._run")
    def test_missing_main_and_origin_is_false(
        self, mock_run: MagicMock, _mock_exists: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(returncode=1, stderr="Revision not found")
        assert ensure_main_bookmark(tmp_path) is False
        mock_run.assert_called_once_with(
            ["jj", "log", "-r", "main@origin", "--no-graph", "-T", "commit_id"],
            tmp_path,
        )


class TestMainBookmarkConflictDetection:
    @patch("maintenance_man.vcs._run")
    def test_conflicted_when_template_returns_true(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(stdout="main true\n")
        assert _main_bookmark_is_conflicted(tmp_path) is True
        mock_run.assert_called_once_with(
            ["jj", "bookmark", "list", "-T", 'name ++ " " ++ conflict', "main"],
            tmp_path,
        )

    @patch("maintenance_man.vcs._run")
    def test_not_conflicted_when_template_returns_false(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(stdout="main false\n")
        assert _main_bookmark_is_conflicted(tmp_path) is False

    @patch("maintenance_man.vcs._run")
    def test_command_failure_is_treated_as_conflicted(
        self, mock_run: MagicMock, tmp_path: Path
    ):
        mock_run.return_value = _completed(returncode=1, stderr="template failed")
        assert _main_bookmark_is_conflicted(tmp_path) is True


class TestSyncMain:
    @patch("maintenance_man.vcs.ensure_main_bookmark", return_value=True)
    @patch("maintenance_man.vcs._main_bookmark_is_conflicted", return_value=False)
    @patch("maintenance_man.vcs._run")
    def test_fetches_then_pushes_main_bookmark(
        self,
        mock_run: MagicMock,
        _mock_conflict: MagicMock,
        _mock_ensure: MagicMock,
        tmp_path: Path,
    ):
        mock_run.return_value = _completed()
        ok, msg = sync_main(tmp_path)
        assert ok is True
        assert msg == ""
        assert mock_run.call_args_list == [
            call(
                ["jj", "git", "fetch", "--remote", "origin", "--branch", "main"],
                tmp_path,
                timeout=120,
            ),
            call(
                ["jj", "git", "push", "--bookmark", "main", "--remote", "origin"],
                tmp_path,
                timeout=120,
            ),
        ]

    @patch("maintenance_man.vcs._run")
    def test_fetch_failure(self, mock_run: MagicMock, tmp_path: Path):
        mock_run.return_value = _completed(returncode=1, stderr="network error")
        ok, msg = sync_main(tmp_path)
        assert ok is False
        assert "network error" in msg

    @patch("maintenance_man.vcs.ensure_main_bookmark", return_value=True)
    @patch("maintenance_man.vcs._main_bookmark_is_conflicted", return_value=True)
    @patch("maintenance_man.vcs._run")
    def test_conflicted_main_stops_before_push(
        self,
        mock_run: MagicMock,
        _mock_conflict: MagicMock,
        _mock_ensure: MagicMock,
        tmp_path: Path,
    ):
        mock_run.return_value = _completed()
        ok, msg = sync_main(tmp_path)
        assert ok is False
        assert "conflicted" in msg.lower()
        assert mock_run.call_count == 1
