import subprocess
from pathlib import Path

import pytest

from maintenance_man import vcs
from maintenance_man.gradle import GradleError
from maintenance_man.gradle_updates import gradle_evidence_workspace
from maintenance_man.vcs import Repository, RevisionError
from maintenance_man.vcs_workflow import VcsServices
from tests.conftest import completed, make_project
from tests.fake_vcs import FakeJjState
from tests.fakes import FakeCommands


@pytest.fixture
def temporary_workspace_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[FakeJjState, Repository, Path]:
    state = FakeJjState()
    path = tmp_path / "source"
    repo = state.seed_repository(path, files={"dep.txt": "version=1\n"})
    container = tmp_path / "allocated-proof"

    def allocate(*, prefix: str) -> str:
        assert prefix == "mm-proof-"
        container.mkdir()
        return str(container)

    monkeypatch.setattr(vcs.tempfile, "mkdtemp", allocate)
    return state, repo, container


def test_temporary_workspace_registration_failure_removes_owned_container(
    temporary_workspace_case: tuple[FakeJjState, Repository, Path],
):
    state, repo, container = temporary_workspace_case
    state.fail("add_workspace", error=RevisionError("registration failed"))
    entered = False
    with (
        pytest.raises(RevisionError, match="registration failed"),
        repo.temporary_workspace(revision="main"),
    ):
        entered = True
    assert entered is False
    assert not any(call.method == "forget_workspace" for call in state.attempts)
    assert not container.exists()


@pytest.mark.parametrize("mutation", ["replace", "symlink"])
def test_temporary_workspace_marker_tampering_prevents_deletion(
    temporary_workspace_case: tuple[FakeJjState, Repository, Path], mutation: str
):
    _state, repo, container = temporary_workspace_case
    with (
        pytest.raises(RevisionError, match="ownership marker changed"),
        repo.temporary_workspace(revision="main"),
    ):
        marker = container / ".mm-proof-owner"
        if mutation == "replace":
            marker.write_text("replacement", encoding="utf-8")
        else:
            marker.unlink()
            marker.symlink_to(container / "replacement")
    assert container.exists()


def test_temporary_workspace_body_error_keeps_cleanup_diagnostics(
    temporary_workspace_case: tuple[FakeJjState, Repository, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    state, repo, _container = temporary_workspace_case
    state.fail("forget_workspace", error=RevisionError("forget failed"))

    def fail_remove(_path: Path) -> None:
        msg = "remove failed"
        raise OSError(msg)

    monkeypatch.setattr(vcs.shutil, "rmtree", fail_remove)
    body_error = RuntimeError("caller")
    with (
        pytest.raises(RuntimeError) as caught,
        repo.temporary_workspace(revision="main"),
    ):
        raise body_error
    assert caught.value is body_error
    assert caught.value.__notes__ == [
        "forget workspace failed: forget failed; "
        "remove proof workspace failed: remove failed"
    ]


def test_temporary_workspace_propagates_unexpected_cleanup_error(
    temporary_workspace_case: tuple[FakeJjState, Repository, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    _state, repo, container = temporary_workspace_case
    unexpected = TypeError("unexpected cleanup failure")

    def fail_remove(_path: Path) -> None:
        raise unexpected

    with (
        pytest.raises(TypeError) as caught,
        monkeypatch.context() as cleanup_patch,
    ):
        cleanup_patch.setattr(vcs.shutil, "rmtree", fail_remove)
        with repo.temporary_workspace(revision="main"):
            pass
    assert caught.value is unexpected
    vcs.shutil.rmtree(container)


def test_temporary_workspace_cleanup_errors_raise_combined_revision_error(
    temporary_workspace_case: tuple[FakeJjState, Repository, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    state, repo, _container = temporary_workspace_case
    state.fail("forget_workspace", error=RevisionError("forget failed"))

    def fail_remove(_path: Path) -> None:
        msg = "remove failed"
        raise OSError(msg)

    monkeypatch.setattr(vcs.shutil, "rmtree", fail_remove)
    with (
        pytest.raises(RevisionError) as caught,
        repo.temporary_workspace(revision="main"),
    ):
        pass
    assert "forget failed" in str(caught.value)
    assert "remove failed" in str(caught.value)


@pytest.mark.parametrize("failing_step", ["add_workspace", "new_change"])
def test_proof_setup_error_survives_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing_step: str
) -> None:
    state = FakeJjState()
    repo = state.seed_repository(tmp_path / "source", files={"dep.txt": "1"})
    container = tmp_path / "allocated-proof"
    original = RevisionError("setup failed")
    state.fail(failing_step, error=original)

    def allocate(*, prefix: str) -> str:
        container.mkdir()
        return str(container)

    def remove_failed(path: Path) -> None:
        message = "busy"
        raise OSError(message)

    monkeypatch.setattr(vcs.tempfile, "mkdtemp", allocate)
    monkeypatch.setattr(vcs.shutil, "rmtree", remove_failed)
    with (
        pytest.raises(RevisionError) as caught,
        vcs._temporary_workspace(repo, revision="main", bind=state.repository),
    ):
        pytest.fail("setup must not reach the body")
    assert caught.value is original
    assert any("busy" in note for note in caught.value.__notes__)


def test_given_distinct_revision_ids_when_same_revision_runs_then_it_uses_two_log_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands = FakeCommands()
    monkeypatch.setattr(vcs, "run_captured", commands)
    commands.add(
        (
            "jj",
            "log",
            "-r",
            "main",
            "--no-graph",
            "-T",
            'commit_id ++ "\\n"',
        ),
        cwd=tmp_path,
        result=completed(stdout=f"{'a' * 40}\n"),
    )
    commands.add(
        (
            "jj",
            "log",
            "-r",
            "main@origin",
            "--no-graph",
            "-T",
            'commit_id ++ "\\n"',
        ),
        cwd=tmp_path,
        result=completed(stdout=f"{'b' * 40}\n"),
    )

    same = vcs.JjRepository(tmp_path).same_revision(left="main", right="main@origin")

    assert same is False
    assert len(commands.calls) == 2


@pytest.mark.parametrize("existing", [False, True], ids=["absent", "existing"])
def test_assert_safe_workspace_path_accepts_direct_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
) -> None:
    root = vcs.paths.workspaces_dir()
    root.mkdir(parents=True)
    child = root / "project"
    if existing:
        child.mkdir()

    assert vcs.assert_safe_workspace_path(child) == child.resolve()


@pytest.mark.parametrize("location", ["root", "outside", "nested"])
def test_assert_safe_workspace_path_rejects_unsafe_locations_without_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    root = vcs.paths.workspaces_dir()
    root.mkdir(parents=True)
    targets = {
        "root": root,
        "outside": tmp_path / "outside",
        "nested": root / "project" / "nested",
    }
    target = targets[location]
    target.mkdir(parents=True, exist_ok=True)
    marker = target / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError):
        vcs.assert_safe_workspace_path(target)

    assert marker.read_text(encoding="utf-8") == "keep"


def test_assert_safe_workspace_path_rejects_final_symlink_and_preserves_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = vcs.paths.workspaces_dir()
    sibling = root / "project-b"
    sibling.mkdir(parents=True)
    marker = sibling / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    candidate = root / "project-a"
    candidate.symlink_to(sibling, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        vcs.assert_safe_workspace_path(candidate)

    assert marker.read_text(encoding="utf-8") == "keep"
    assert candidate.is_symlink()


def _resolve_command(revision: str, *, read_only: bool = False) -> tuple[str, ...]:
    prefix = ("--ignore-working-copy", "--color", "never") if read_only else ()
    return (
        "jj",
        *prefix,
        "log",
        "-r",
        revision,
        "--no-graph",
        "-T",
        'commit_id ++ "\\n"',
    )


def _file_list_command(commit_id: str, filename: str) -> tuple[str, ...]:
    return (
        "jj",
        "--ignore-working-copy",
        "--color",
        "never",
        "file",
        "list",
        "-r",
        commit_id,
        "-T",
        'file_type ++ "\\n"',
        f"root-file:{filename}",
    )


def _revision_file_commands(tmp_path: Path, listing: str) -> FakeCommands:
    commands = FakeCommands()
    commands.add(
        _resolve_command("main", read_only=True),
        cwd=tmp_path,
        result=completed(stdout="a" * 40 + "\n"),
    )
    commands.add(
        _file_list_command("a" * 40, "dep.txt"),
        cwd=tmp_path,
        result=completed(stdout=listing),
    )
    return commands


class TestJjRepositoryBoundary:
    def test_command_launch_failure_is_a_revision_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        failure = FileNotFoundError(2, "No such file or directory", "jj")
        error = vcs.RevisionError("Could not run jj")
        error.__cause__ = failure
        commands = FakeCommands()
        commands.add(
            (
                "jj",
                "--ignore-working-copy",
                "--color",
                "never",
                "bookmark",
                "list",
                "-T",
                'if(remote == "origin" || !present, "", name ++ "\\n")',
            ),
            cwd=tmp_path,
            result=error,
        )
        monkeypatch.setattr(vcs, "run_captured", commands)
        with pytest.raises(vcs.RevisionError, match="Could not run jj") as caught:
            vcs.JjRepository(tmp_path).local_bookmarks()
        assert caught.value.__cause__ is failure
        ((actual_argv, cwd, kwargs),) = commands.calls
        assert actual_argv == (
            "jj",
            "--ignore-working-copy",
            "--color",
            "never",
            "bookmark",
            "list",
            "-T",
            'if(remote == "origin" || !present, "", name ++ "\\n")',
        )
        assert cwd == tmp_path
        assert kwargs == {
            "timeout": 30,
            "label": (
                "jj --ignore-working-copy --color never bookmark list -T "
                '\'if(remote == "origin" || !present, "", name ++ "\\n")\''
            ),
            "error": vcs.RevisionError,
        }

    def test_temporary_workspace_normalizes_allocation_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        repo = vcs.JjRepository(tmp_path)
        failure = OSError("allocation denied")

        def fail_allocate(*, prefix: str):
            assert prefix == "mm-proof-"
            raise failure

        monkeypatch.setattr(repo, "resolve_revision", lambda **kwargs: "a" * 40)
        monkeypatch.setattr(vcs.tempfile, "mkdtemp", fail_allocate)
        with (
            pytest.raises(
                vcs.RevisionError, match="allocate proof workspace"
            ) as caught,
            repo.temporary_workspace(revision="main"),
        ):
            pytest.fail("allocation failure must prevent entry")
        assert caught.value.__cause__ is failure

    def test_temporary_workspace_marker_failure_removes_allocated_container(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        repo = vcs.JjRepository(tmp_path)
        container = tmp_path / "proof-container"
        failure = OSError("marker denied")

        def allocate(*, prefix: str) -> str:
            assert prefix == "mm-proof-"
            container.mkdir()
            return str(container)

        original_write_text = Path.write_text

        def fail_marker(path: Path, data: str, **kwargs):
            if path.name == ".mm-proof-owner":
                raise failure
            return original_write_text(path, data, **kwargs)

        monkeypatch.setattr(repo, "resolve_revision", lambda **kwargs: "a" * 40)
        monkeypatch.setattr(vcs.tempfile, "mkdtemp", allocate)
        monkeypatch.setattr(Path, "write_text", fail_marker)
        with (
            pytest.raises(vcs.RevisionError, match="mark proof workspace") as caught,
            repo.temporary_workspace(revision="main"),
        ):
            pytest.fail("marker failure must prevent entry")
        assert caught.value.__cause__ is failure
        assert not container.exists()

    @pytest.mark.parametrize(
        ("stdout", "message"),
        [
            ("", "exactly one"),
            (f"{'a' * 40}\n{'b' * 40}\n", "exactly one"),
            ("not-a-commit\n", "malformed commit identity"),
            (f"{'A' * 40}\n", "malformed commit identity"),
        ],
    )
    def test_resolve_revision_rejects_invalid_identity(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        stdout: str,
        message: str,
    ):
        commands = FakeCommands()
        commands.add(
            ("jj", "log", "-r", "main", "--no-graph", "-T", 'commit_id ++ "\\n"'),
            cwd=tmp_path,
            result=completed(stdout=stdout),
        )
        monkeypatch.setattr(vcs, "run_captured", commands)
        with pytest.raises(vcs.RevisionError, match=message):
            vcs.JjRepository(tmp_path).resolve_revision(revision="main")

    @pytest.mark.parametrize("listing", ["file\nfile\n", "unknown\n", "\nfile\n"])
    def test_revision_file_rejects_malformed_listing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        listing: str,
    ):
        commands = _revision_file_commands(tmp_path, listing)
        monkeypatch.setattr(vcs, "run_captured", commands)
        with pytest.raises(vcs.RevisionError, match="Unexpected revision file listing"):
            vcs.JjRepository(tmp_path).revision_file(
                revision="main", filename="dep.txt"
            )

    @pytest.mark.parametrize(
        ("listing", "regular"),
        [
            ("", False),
            ("file\n", True),
            ("symlink\n", False),
            ("tree\n", False),
            ("conflict\n", False),
        ],
    )
    def test_revision_file_distinguishes_absence_and_regular_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        listing: str,
        regular: bool,
    ):
        commands = _revision_file_commands(tmp_path, listing)
        monkeypatch.setattr(vcs, "run_captured", commands)
        assert vcs.JjRepository(tmp_path).revision_file(
            revision="main", filename="dep.txt"
        ) == (vcs.RevisionFile(commit_id="a" * 40, is_regular=regular))

    @pytest.mark.parametrize("phase", ["resolve", "list"])
    @pytest.mark.parametrize("failure", ["rejected", "launch", "timeout"])
    def test_revision_file_inspection_failures_are_typed_not_absence(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        phase: str,
        failure: str,
    ):
        raised: BaseException | None = None
        commands = FakeCommands()
        resolve_command = _resolve_command("main", read_only=True)
        list_command = _file_list_command("a" * 40, "local.properties")
        if failure == "rejected":
            failed: subprocess.CompletedProcess[str] | BaseException = (
                vcs.RevisionError("jj file list failed (exit 1): file")
            )
        elif failure == "launch":
            raised = FileNotFoundError(2, "No such file or directory", "jj")
            failed = vcs.RevisionError("Could not run jj")
            failed.__cause__ = raised
        else:
            raised = subprocess.TimeoutExpired(
                list(resolve_command if phase == "resolve" else list_command), 30
            )
            failed = vcs.RevisionError("jj command timed out")
            failed.__cause__ = raised
        commands.add(
            resolve_command,
            cwd=tmp_path,
            result=failed if phase == "resolve" else completed(stdout="a" * 40 + "\n"),
        )
        if phase == "list":
            commands.add(list_command, cwd=tmp_path, result=failed)
        monkeypatch.setattr(vcs, "run_captured", commands)

        with pytest.raises(vcs.RevisionError) as caught:
            vcs.JjRepository(tmp_path).revision_file(
                revision="main", filename="local.properties"
            )

        expected = {
            "rejected": "failed (exit 1): file",
            "launch": "Could not run",
            "timeout": "timed out",
        }
        assert expected[failure] in str(caught.value)
        assert len(commands.calls) == (1 if phase == "resolve" else 2)
        expected_labels = {
            resolve_command: (
                "jj --ignore-working-copy --color never log -r main --no-graph "
                "-T 'commit_id ++ \"\\n\"'"
            ),
            list_command: (
                "jj --ignore-working-copy --color never file list -r "
                f"{'a' * 40} -T 'file_type ++ \"\\n\"' "
                "root-file:local.properties"
            ),
        }
        for argv, cwd, kwargs in commands.calls:
            assert cwd == tmp_path
            assert kwargs == {
                "timeout": 30,
                "label": expected_labels[argv],
                "error": vcs.RevisionError,
            }
        if raised is not None:
            assert caught.value.__cause__ is raised

    @pytest.mark.parametrize(
        "inspector", ["", "unfamiliar\n", '    root_tree: Conflict("a")\n']
    )
    def test_tree_id_rejects_malformed_or_conflicted_output(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        inspector: str,
    ):
        commands = FakeCommands()
        commands.add(
            _resolve_command("main"),
            cwd=tmp_path,
            result=completed(stdout="a" * 40 + "\n"),
        )
        commands.add(
            ("jj", "debug", "object", "commit", "a" * 40),
            cwd=tmp_path,
            result=completed(stdout=inspector),
        )
        monkeypatch.setattr(vcs, "run_captured", commands)
        with pytest.raises(vcs.RevisionError, match="Cannot identify"):
            vcs.JjRepository(tmp_path).tree_id(revision="main")

    @pytest.mark.parametrize(
        ("main_only", "arguments"),
        [
            (False, ["git", "fetch", "--remote", "origin"]),
            (True, ["git", "fetch", "--remote", "origin", "--branch", "main"]),
        ],
    )
    def test_fetch_uses_origin_and_remote_timeout(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        main_only: bool,
        arguments: list[str],
    ):
        repo = vcs.JjRepository(tmp_path)
        calls: list[tuple[list[str], int]] = []

        def run(command: list[str], *, timeout: int = 30):
            calls.append((command, timeout))
            return completed()

        monkeypatch.setattr(repo, "_run", run)
        repo.fetch(main_only=main_only)
        assert calls == [(arguments, 120)]

    @pytest.mark.parametrize(
        "expected",
        [
            vcs.ExpectedRevisions(base="base", tip="b" * 40),
            vcs.ExpectedRevisions(base="a" * 40, tip="tip"),
        ],
    )
    def test_guarded_mutation_rejects_invalid_revision_identity(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        expected: vcs.ExpectedRevisions,
    ):
        repo = vcs.JjRepository(tmp_path)
        monkeypatch.setattr(
            repo,
            "_run",
            lambda *args, **kwargs: pytest.fail("invalid guard reached mutation"),
        )
        with pytest.raises(vcs.RevisionError, match="Invalid expected revision"):
            repo.promote_bookmark_to_main(
                bookmark="mm/update-dependencies", expected=expected
            )


@pytest.mark.parametrize("phase", ["setup", "cleanup"])
def test_proof_translates_workspace_lifecycle_errors(tmp_path: Path, phase: str):
    state = FakeJjState()
    repo = state.seed_repository(tmp_path / "repo", files={"dep.txt": "one\n"})
    state.fail(
        "add_workspace" if phase == "setup" else "forget_workspace",
        error=vcs.RevisionError(f"{phase} denied"),
        path=repo.path,
    )
    services = VcsServices(repository=state.repository, code_host=state.code_host)
    message = "create" if phase == "setup" else "clean up"
    with (
        pytest.raises(GradleError, match=message) as caught,
        gradle_evidence_workspace(make_project(repo.path), "main", vcs=services),
    ):
        pass
    assert isinstance(caught.value.__cause__, vcs.RevisionError)


def test_proof_body_stays_primary_with_both_cleanup_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    state = FakeJjState()
    repo = state.seed_repository(tmp_path / "repo", files={"dep.txt": "one\n"})
    state.fail(
        "forget_workspace",
        error=vcs.RevisionError("forget denied"),
        path=repo.path,
    )
    original_remove = vcs.shutil.rmtree

    def fail_proof_remove(path: Path):
        if path.name.startswith("mm-proof-"):
            msg = "remove denied"
            raise OSError(msg)
        return original_remove(path)

    monkeypatch.setattr(vcs.shutil, "rmtree", fail_proof_remove)
    services = VcsServices(repository=state.repository, code_host=state.code_host)
    original = RuntimeError("body failed")
    with (
        pytest.raises(RuntimeError) as caught,
        gradle_evidence_workspace(make_project(repo.path), "main", vcs=services),
    ):
        raise original
    assert caught.value is original
    notes = "\n".join(caught.value.__notes__)
    assert "forget workspace failed: forget denied" in notes
    assert "remove proof workspace failed: remove denied" in notes
