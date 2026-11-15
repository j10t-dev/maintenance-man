"""Drive the real mm executable in disposable repositories and a controlling PTY."""

import argparse
import errno
import fcntl
import json
import os
import pty
import select
import shlex
import shutil
import signal
import struct
import sys
import termios
import time
import tomllib
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO
from zipfile import ZipFile

from maintenance_man.config import load_config
from maintenance_man.models.scan import ScanResult
from maintenance_man.process import run_captured
from tests.support.findings import make_scan_result, make_update
from tests.support.repository import copy_jj_peer, copy_jj_repository, jj_environment


def main() -> None:
    """Launch, inspect, drive or clean only an owned verification run under /tmp."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("launch", "doctor", "drive", "cleanup"))
    parser.add_argument("run", type=Path)
    parser.add_argument(
        "--journey", choices=("update", "recovery", "noop"), default="update"
    )
    arguments = parser.parse_args()
    run = arguments.run.absolute()
    _validate_run_path(run)
    if arguments.action == "launch":
        _launch(run)
    else:
        _require_owned(run)
        _set_environment(run)
        actions = {
            "doctor": lambda: _doctor(run),
            "drive": lambda: _drive(run, arguments.journey),
            "cleanup": lambda: _cleanup(run),
        }
        actions[arguments.action]()


def _validate_run_path(run: Path) -> None:
    if run.parent != Path("/tmp") or not run.name.startswith("verify-mm-"):
        msg = "Use a new direct child of /tmp named verify-mm-<unique-run>."
        raise ValueError(msg)
    if run.is_symlink() or run.resolve() != run:
        msg = "The verification run path must not contain symlinks."
        raise ValueError(msg)


def _require_owned(run: Path) -> None:
    marker = run / "owner.json"
    expected = {"repository": str(ROOT), "uid": os.getuid()}
    if json.loads(marker.read_text()) != expected:
        msg = f"Unrecognised ownership marker: {marker}"
        raise ValueError(msg)
    for name in ("state", "evidence"):
        path = run / name
        if path.is_symlink() or path.resolve() != path:
            msg = f"Refusing redirected run directory: {path}"
            raise ValueError(msg)


def _launch(run: Path) -> None:
    run.mkdir(mode=0o700)
    _write_json(run / "owner.json", {"repository": str(ROOT), "uid": os.getuid()})
    (run / "evidence").mkdir()
    (run / "state").mkdir()
    (run / "state" / "jj-config.toml").write_text("", encoding="utf-8")
    _set_environment(run)
    try:
        _command(run, "init", _mm("init"))
        _seed_repository(run)
        _seed_config_and_scan(run)
        _snapshot(run, "baseline")
        _doctor(run)
    except BaseException:
        _cleanup(run)
        raise
    print(f"Ready: {run}. Evidence: {run / 'evidence'}")


def _set_environment(run: Path) -> None:
    state = run / "state"
    config = state / "jj-config.toml"
    for name in tuple(os.environ):
        if name.startswith("UV_"):
            os.environ.pop(name)
    os.environ.update(jj_environment())
    os.environ.update(
        MM_HOME=str(state / "mm"),
        JJ_CONFIG=str(config),
        UV_CACHE_DIR=str(state / "uv-cache"),
        UV_OFFLINE="1",
        UV_NO_CONFIG="1",
        UV_NO_INDEX="1",
        UV_FIND_LINKS=str(state / "wheels"),
        UV_PYTHON=sys.executable,
        UV_PYTHON_DOWNLOADS="never",
        UV_NO_MANAGED_PYTHON="1",
        MM_VERIFY_TEST_LOG=str(run / "evidence" / "test-runs.jsonl"),
        TERM="xterm-256color",
        NO_COLOR="1",
        COLUMNS="120",
    )


def _seed_repository(run: Path) -> None:
    state = run / "state"
    repository = copy_jj_repository(state / "project")
    copy_jj_peer(repository)
    _command(
        run, "bare-init", ["jj", "git", "init", "--no-colocate", str(state / "origin")]
    )
    origin = state / "origin" / ".jj" / "repo" / "store" / "git"
    for directory in ("project", "project-peer"):
        _jj(run, directory, "git", "remote", "set-url", "origin", str(origin))
    wheels = state / "wheels"
    wheels.mkdir()
    for version in ("1.0.0", "1.0.1"):
        _wheel(wheels, version)
    project = repository.path
    (project / ".gitignore").write_text(".venv/\n__pycache__/\n", encoding="utf-8")
    (project / "pyproject.toml").write_text(
        '[project]\nname = "mm-verification-fixture"\nversion = "0.1.0"\n'
        'requires-python = ">=3.14"\ndependencies = ["mm-proof-dep==1.0.0"]\n\n'
        f"[tool.uv]\nno-index = true\nfind-links = [{json.dumps(str(wheels))}]\n",
        encoding="utf-8",
    )
    (project / "check.py").write_text(CHECK_SCRIPT, encoding="utf-8")
    (project / "TODO.md").write_text("Check synthetic dependency update\n")
    _command(run, "fixture-sync", ["uv", "sync", "--offline"], cwd=project)
    _jj(run, "project", "commit", "-m", "synthetic uv project")
    _jj(run, "project", "git", "fetch", "--remote", "origin")
    _jj(run, "project", "bookmark", "set", "main", "-r", "@-")
    _jj(run, "project", "git", "push", "--bookmark", "main")
    _jj(run, "project-peer", "git", "fetch", "--remote", "origin")


def _wheel(directory: Path, version: str) -> None:
    metadata = f"mm_proof_dep-{version}.dist-info"
    files = {
        "mm_proof_dep/__init__.py": f'__version__ = "{version}"\n',
        f"{metadata}/METADATA": (
            f"Metadata-Version: 2.1\nName: mm-proof-dep\nVersion: {version}\n"
        ),
        f"{metadata}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: verify-mm\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    files[f"{metadata}/RECORD"] = "".join(f"{name},,\n" for name in files)
    with ZipFile(directory / f"mm_proof_dep-{version}-py3-none-any.whl", "w") as wheel:
        for name, content in files.items():
            wheel.writestr(name, content)


def _seed_config_and_scan(run: Path) -> None:
    home = run / "state" / "mm"
    (home / "config.toml").write_text(
        "[defaults]\nmin_version_age_days = 0\n\n[projects.fixture]\n"
        f"path = {json.dumps(str(run / 'state' / 'project'))}\n"
        'package_manager = "uv"\nscan_secrets = false\n'
        'test_unit = "uv run --locked --offline python check.py"\n',
        encoding="utf-8",
    )
    scan = make_scan_result(
        vulns=[], updates=[make_update(pkg_name="mm-proof-dep")], secrets=[]
    )
    scan.project_name = "fixture"
    (home / "scan-results").mkdir()
    (home / "scan-results" / "fixture.json").write_text(
        scan.model_dump_json(indent=2), encoding="utf-8"
    )


def _doctor(run: Path) -> None:
    state = run / "state"
    home = state / "mm"
    config = load_config(home / "config.toml")
    assert set(config.projects) == {"fixture"}
    project = config.projects["fixture"]
    assert project.path == state / "project"
    assert project.test_unit == "uv run --locked --offline python check.py"
    assert project.build_command is None and project.deploy_command is None
    origin = state / "origin" / ".jj" / "repo" / "store" / "git"
    assert "bare = true" in (origin / "config").read_text()
    for directory in ("project", "project-peer"):
        assert (state / directory).resolve() == state / directory
        remote = _jj(run, directory, "git", "remote", "list", readonly=True)
        assert remote.split() == ["origin", str(origin)], remote
    _read_scan(run)
    _command(
        run, "doctor-home", [sys.executable, "-c", HOME_CHECK, str(home), str(ROOT)]
    )
    _command(run, "doctor-version", _mm("--version"))
    _command(run, "doctor-list", _mm("list", "--detail"))
    _write_json(run / "evidence" / "doctor.json", {"healthy": True, "home": str(home)})
    print(f"Doctor passed: isolated fixture at {home}")


def _drive(run: Path, journey: str) -> None:
    if any(
        (run / "evidence" / name).exists() for name in ("before.json", "verdict.json")
    ):
        msg = "This run has already attempted a drive; launch a fresh run."
        raise ValueError(msg)
    try:
        _doctor(run)
        _snapshot(run, "before")
        _pty_command(run, "picker-cancel", ["update", "fixture"], ["invalid", "none"])
        _snapshot(run, "cancelled")
        _assert_cancelled(run)
        if journey == "noop":
            _drive_noop(run)
        else:
            _drive_promotion(run, journey)
        _write_json(
            run / "evidence" / "verdict.json", {"verdict": "PROVED", "journey": journey}
        )
    except BaseException:
        _cleanup(run)
        raise
    proved = "the failed no-op apply" if journey == "noop" else "local sync"
    print(f"PROVED {journey}, picker cancellation and {proved}: {run / 'evidence'}")


def _drive_promotion(run: Path, journey: str) -> None:
    if journey == "recovery":
        _drive_recovery(run)
    else:
        _pty_command(run, "update", ["update", "fixture"], ["1"])
    _snapshot(run, "updated")
    _assert_updated(run)
    _pty_command(run, "sync", ["sync", "fixture"], [])
    _jj(run, "project-peer", "git", "fetch", "--remote", "origin")
    _snapshot(run, "synced")
    assert _revision(run, "project-peer", "main@origin") == _saved_main(run, "updated")


def _assert_cancelled(run: Path) -> None:
    before = json.loads((run / "evidence" / "before.json").read_text())
    cancelled = json.loads((run / "evidence" / "cancelled.json").read_text())
    for key in ("main", "remote_main", "scan", "manifest", "lock"):
        assert cancelled[key] == before[key], f"Cancellation changed {key}"
    assert not (run / "evidence" / "test-runs.jsonl").exists()
    assert not (run / "state" / "mm" / "workspaces" / "fixture").exists()
    transcript = (run / "evidence" / "picker-cancel.terminal.txt").read_text()
    assert "Invalid selection: invalid" in transcript


def _drive_recovery(run: Path) -> None:
    project = run / "state" / "project"
    (project / "require-repair").write_text("require repair\n", encoding="utf-8")
    _jj(run, "project", "commit", "-m", "require synthetic compatibility repair")
    _jj(run, "project", "bookmark", "set", "main", "-r", "@-")
    before = _revision(run, "project", "main")
    _pty_command(run, "update-fails", ["update", "fixture"], ["1"], expected=4)
    _snapshot(run, "update-failed")
    assert _revision(run, "project", "main") == before
    scan = _read_scan(run)
    assert scan.updates[0].state is not None
    assert scan.updates[0].state.model_dump() == {
        "lifecycle": "failed",
        "flow": "update",
        "phase": "unit",
    }
    _pty_command(run, "resolve-pauses", ["resolve", "fixture"], [], expected=4)
    _snapshot(run, "resolve-paused")
    scan = _read_scan(run)
    assert scan.updates[0].state is not None
    assert scan.updates[0].state.model_dump() == {
        "lifecycle": "failed",
        "flow": "resolve",
        "phase": "unit",
    }
    (project / "repair.txt").write_text("synthetic compatibility repair\n")
    _jj(run, "project", "commit", "-m", "repair synthetic dependency compatibility")
    _pty_command(run, "resolve-continue", ["resolve", "fixture", "--continue"], [])


def _drive_noop(run: Path) -> None:
    project = run / "state" / "project"
    _command(run, "apply-by-hand", ["uv", "add", "mm-proof-dep==1.0.1"], cwd=project)
    _jj(run, "project", "commit", "-m", "apply the saved update by hand")
    _jj(run, "project", "bookmark", "set", "main", "-r", "@-")
    before = _revision(run, "project", "main")
    _pty_command(run, "update-noop", ["update", "fixture"], ["1"], expected=4)
    _snapshot(run, "update-noop")
    transcript = (run / "evidence" / "update-noop.terminal.txt").read_text()
    assert "changed no files" in transcript, transcript
    scan = _read_scan(run)
    assert scan.updates[0].state is not None
    assert scan.updates[0].state.model_dump() == {
        "lifecycle": "failed",
        "flow": "update",
        "phase": "apply",
    }
    assert _revision(run, "project", "main") == before


def _assert_updated(run: Path) -> None:
    assert _read_scan(run).updates == []
    updated = json.loads((run / "evidence" / "updated.json").read_text())
    committed = tomllib.loads(updated["main_manifest"])
    assert committed["project"]["dependencies"] == ["mm-proof-dep==1.0.1"], (
        "Committed main does not contain the dependency update"
    )
    assert _saved_main(run, "updated") != _saved_main(run, "before")
    assert _revision(run, "project-peer", "main@origin") == _saved_main(run, "before")
    manifest = tomllib.loads((run / "state" / "project" / "pyproject.toml").read_text())
    assert manifest["project"]["dependencies"] == ["mm-proof-dep==1.0.1"]
    assert not (run / "state" / "mm" / "workspaces" / "fixture").exists()
    runs = (run / "evidence" / "test-runs.jsonl").read_text().splitlines()
    assert json.loads(runs[-1])["version"] == "1.0.1"
    _command(
        run,
        "installed",
        ["uv", "run", "--locked", "--offline", "python", "check.py"],
        cwd=run / "state" / "project",
    )


def _snapshot(run: Path, label: str) -> None:
    _jj(run, "project-peer", "git", "fetch", "--remote", "origin")
    scan = _read_scan(run)
    state = {
        "main": _revision(run, "project", "main"),
        "remote_main": _revision(run, "project-peer", "main@origin"),
        "scan": scan.model_dump(mode="json"),
        "manifest": (run / "state" / "project" / "pyproject.toml").read_text(),
        "lock": (run / "state" / "project" / "uv.lock").read_text(),
        "bookmarks": _jj(run, "project", "bookmark", "list", readonly=True),
        "workspaces": _jj(run, "project", "workspace", "list", readonly=True),
        "main_manifest": _jj(
            run,
            "project",
            "file",
            "show",
            "-r",
            "main",
            "pyproject.toml",
            readonly=True,
        ),
    }
    _write_json(run / "evidence" / f"{label}.json", state)


def _read_scan(run: Path) -> ScanResult:
    return ScanResult.model_validate_json(
        (run / "state" / "mm" / "scan-results" / "fixture.json").read_bytes()
    )


def _saved_main(run: Path, label: str) -> str:
    return json.loads((run / "evidence" / f"{label}.json").read_text())["main"]


def _revision(run: Path, directory: str, revision: str) -> str:
    return _jj(
        run,
        directory,
        "log",
        "--no-graph",
        "-r",
        revision,
        "-T",
        "commit_id",
        readonly=True,
    ).strip()


def _jj(run: Path, directory: str, *arguments: str, readonly: bool = False) -> str:
    flags = ["--ignore-working-copy"] if readonly else []
    return _command(
        run,
        "jj",
        ["jj", "--color", "never", *flags, *arguments],
        cwd=run / "state" / directory,
    )


def _mm(*arguments: str) -> list[str]:
    return [sys.executable, str(ROOT / ".venv" / "bin" / "mm"), *arguments]


def _command(
    run: Path, label: str, command: list[str], *, cwd: Path | None = None
) -> str:
    cwd = cwd or ROOT
    result = run_captured(command, cwd, timeout=60, label=label, ok_codes=None)
    _event(
        run,
        label,
        {
            "command": command,
            "cwd": str(cwd),
            "exit": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        },
    )
    if result.returncode:
        msg = f"{shlex.join(command)} exited {result.returncode}: {result.stderr}"
        raise RuntimeError(msg)
    return result.stdout


def _pty_command(
    run: Path,
    label: str,
    arguments: list[str],
    replies: list[str],
    *,
    expected: int = 0,
) -> None:
    command = _mm(*arguments)
    pid, terminal = pty.fork()
    if pid == 0:
        os.chdir(ROOT)
        os.execv(command[0], command)
    transcript = run / "evidence" / f"{label}.terminal.txt"
    _event(run, label, {"command": command, "pid": pid, "pty": True})
    reaped = False
    try:
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        with transcript.open("wb") as output:
            _read_terminal(run, label, terminal, replies, output)
        _, status = os.waitpid(pid, 0)
        reaped = True
        code = os.waitstatus_to_exitcode(status)
        _event(run, label, {"exit": code, "expected": expected, "reaped_pid": pid})
        assert code == expected, transcript.read_text()
    except BaseException:
        if not reaped:
            _stop_process_group(pid)
        raise
    finally:
        os.close(terminal)


def _read_terminal(
    run: Path, label: str, terminal: int, replies: list[str], output: BinaryIO
) -> None:
    deadline = time.monotonic() + 90
    pending = bytearray()
    sent = 0
    while time.monotonic() < deadline:
        if not select.select([terminal], [], [], 0.1)[0]:
            continue
        try:
            chunk = os.read(terminal, 65536)
        except OSError as exc:
            if exc.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        output.write(chunk)
        output.flush()
        pending.extend(chunk)
        if b"(all): " in pending and sent < len(replies):
            reply = replies[sent]
            os.write(terminal, (reply + "\n").encode())
            _event(run, label, {"prompt": "Select updates", "reply": reply})
            pending.clear()
            sent += 1
    else:
        msg = f"PTY deadline exceeded: {label}"
        raise TimeoutError(msg)
    assert sent == len(replies), f"Picker did not consume all replies: {label}"


def _stop_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
        time.sleep(0.2)
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    with suppress(ChildProcessError):
        os.waitpid(pid, 0)


def _cleanup(run: Path) -> None:
    _require_owned(run)
    state = run / "state"
    if state.exists():
        shutil.rmtree(state)
    remaining = sorted(path.name for path in (run / "evidence").iterdir())
    _write_json(
        run / "evidence" / "cleanup.json",
        {
            "scratch_removed": not state.exists(),
            "evidence_retained": remaining,
            "processes": "PTY children synchronously reaped; no persistent services",
        },
    )
    print(f"Cleaned owned state. Evidence retained: {run / 'evidence'}")


def _event(run: Path, label: str, fields: dict[str, object]) -> None:
    with (run / "evidence" / "actions.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"label": label, **fields}) + "\n")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


ROOT = Path(__file__).resolve().parents[2]
HOME_CHECK = """
import sys
from pathlib import Path
from maintenance_man import paths
assert paths.mm_home() == Path(sys.argv[1])
assert Path(paths.__file__).resolve().is_relative_to(Path(sys.argv[2]) / "src")
print(paths.mm_home())
"""
CHECK_SCRIPT = """import json
import os
from pathlib import Path
import mm_proof_dep

with Path(os.environ["MM_VERIFY_TEST_LOG"]).open("a") as log:
    record = {"cwd": str(Path.cwd()), "version": mm_proof_dep.__version__}
    log.write(json.dumps(record) + "\\n")
assert mm_proof_dep.__version__ == "1.0.1"
assert not Path("require-repair").exists() or Path("repair.txt").is_file()
print("Synthetic dependency test passed: " + mm_proof_dep.__version__)
"""
