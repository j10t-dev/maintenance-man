import subprocess
from pathlib import Path

import pytest

from maintenance_man import vcs
from maintenance_man.gradle import GradleError
from maintenance_man.gradle_updates import gradle_evidence_workspace
from maintenance_man.vcs_workflow import VcsServices
from tests.conftest import make_project
from tests.fake_vcs import FakeJjState


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestJjRepositoryBoundary:
    def test_command_launch_failure_is_a_revision_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        failure = FileNotFoundError(2, "No such file or directory", "jj")

        def fail(*args, **kwargs):
            raise failure

        monkeypatch.setattr("maintenance_man.process.subprocess.run", fail)
        with pytest.raises(vcs.RevisionError, match="Could not run jj") as caught:
            vcs.JjRepository(tmp_path).local_bookmarks()
        assert caught.value.__cause__ is failure

    def test_temporary_workspace_normalizes_allocation_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        repo = vcs.JjRepository(tmp_path)
        failure = OSError("allocation denied")

        def fail_allocate(*, prefix: str):
            assert prefix == "mm-gradle-proof-"
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
            assert prefix == "mm-gradle-proof-"
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
        repo = vcs.JjRepository(tmp_path)
        monkeypatch.setattr(repo, "local_bookmarks", lambda: frozenset())
        monkeypatch.setattr(
            repo, "_run", lambda arguments, **kwargs: _completed(stdout=stdout)
        )
        with pytest.raises(vcs.RevisionError, match=message):
            repo.resolve_revision(revision="main")

    @pytest.mark.parametrize("listing", ["file\nfile\n", "unknown\n", "\nfile\n"])
    def test_revision_file_rejects_malformed_listing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        listing: str,
    ):
        repo = vcs.JjRepository(tmp_path)
        monkeypatch.setattr(repo, "resolve_revision", lambda **kwargs: "a" * 40)
        monkeypatch.setattr(
            repo, "_run", lambda arguments, **kwargs: _completed(stdout=listing)
        )
        with pytest.raises(vcs.RevisionError, match="Unexpected revision file listing"):
            repo.revision_file(revision="main", filename="dep.txt")

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
        repo = vcs.JjRepository(tmp_path)
        monkeypatch.setattr(repo, "resolve_revision", lambda **kwargs: "a" * 40)
        monkeypatch.setattr(
            repo, "_run", lambda arguments, **kwargs: _completed(stdout=listing)
        )
        assert repo.revision_file(revision="main", filename="dep.txt") == (
            vcs.RevisionFile(commit_id="a" * 40, is_regular=regular)
        )

    @pytest.mark.parametrize("phase", ["resolve", "list"])
    @pytest.mark.parametrize("failure", ["rejected", "launch", "timeout"])
    def test_revision_file_inspection_failures_are_typed_not_absence(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        phase: str,
        failure: str,
    ):
        observed: list[str] = []
        raised: BaseException | None = None

        def run(command: list[str], **_kwargs):
            nonlocal raised
            if "bookmark" in command:
                return subprocess.CompletedProcess(command, 0, "", "")
            current = "resolve" if "log" in command else "list"
            observed.append(current)
            if current != phase:
                stdout = "a" * 40 + "\n" if current == "resolve" else "file\n"
                return subprocess.CompletedProcess(command, 0, stdout, "")
            if failure == "rejected":
                return subprocess.CompletedProcess(command, 1, "file\n", "")
            if failure == "launch":
                raised = FileNotFoundError(2, "No such file or directory", "jj")
            else:
                raised = subprocess.TimeoutExpired(command, 30)
            raise raised

        monkeypatch.setattr("maintenance_man.process.subprocess.run", run)

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
        assert observed == (["resolve"] if phase == "resolve" else ["resolve", "list"])
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
        repo = vcs.JjRepository(tmp_path)
        monkeypatch.setattr(repo, "resolve_revision", lambda **kwargs: "a" * 40)
        monkeypatch.setattr(
            repo, "_run", lambda arguments, **kwargs: _completed(stdout=inspector)
        )
        with pytest.raises(vcs.RevisionError, match="Cannot identify"):
            repo.tree_id(revision="main")

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
            return _completed()

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
        if path.name.startswith("mm-gradle-proof-"):
            raise OSError("remove denied")
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
