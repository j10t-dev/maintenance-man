import contextlib
import errno
import os
import pty
import select
import shlex
import signal
import subprocess
import sys
import time
from io import StringIO
from pathlib import Path

import pytest

from maintenance_man import output, process
from maintenance_man.process import (
    ProcessError,
    ToolNotFoundError,
    require_tool,
    run_captured,
    run_live,
    run_logged,
)
from tests.conftest import TerminalStream, completed


class _DomainError(Exception):
    pass


def _fake(result=None, *, raises=None, calls=None):
    def run(cmd, **kwargs):
        if calls is not None:
            calls.append((cmd, kwargs))
        if raises is not None:
            raise raises
        return result

    return run


def _host_venv(monkeypatch):
    monkeypatch.setenv("VIRTUAL_ENV", "/host/venv")
    monkeypatch.setenv("PATH", os.pathsep.join(["/host/venv/bin", "/usr/bin"]))


def _executable(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def test_require_tool_returns_the_absolute_path(tmp_path, monkeypatch):
    tool = _executable(tmp_path / "bin" / "mm-probe-tool")
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.setenv("PATH", str(tool.parent))
    found = require_tool("mm-probe-tool", "Install it from https://example.test/")
    assert found == tool
    assert found.is_absolute()


def test_missing_tool_names_the_executable_and_hint(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(
        ToolNotFoundError,
        match=(
            r"^mm-probe-tool is not installed or not on PATH\. "
            r"Install it from https://example\.test/$"
        ),
    ):
        require_tool("mm-probe-tool", "Install it from https://example.test/")


def test_tool_only_in_the_host_virtualenv_is_unavailable(tmp_path, monkeypatch):
    venv = tmp_path / "venv"
    _executable(venv / "bin" / "mm-probe-tool")
    monkeypatch.setenv("VIRTUAL_ENV", str(venv))
    monkeypatch.setenv("PATH", str(venv / "bin"))
    with pytest.raises(ToolNotFoundError):
        require_tool("mm-probe-tool", "hint")


def test_captured_run_is_isolated_and_non_interactive(tmp_path, monkeypatch):
    _host_venv(monkeypatch)
    calls = []
    result = completed(["tool", "--flag"], returncode=0, stdout="out", stderr="")
    monkeypatch.setattr(process.subprocess, "run", _fake(result, calls=calls))

    assert (
        run_captured(["tool", "--flag"], tmp_path, timeout=42, label="tool") is result
    )

    ((cmd, kwargs),) = calls
    assert cmd == ["tool", "--flag"]
    assert kwargs["cwd"] == tmp_path
    assert kwargs["timeout"] == 42
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs.get("shell", False) is False
    assert "VIRTUAL_ENV" not in kwargs["env"]
    assert kwargs["env"]["PATH"].split(os.pathsep) == ["/usr/bin"]


@pytest.mark.parametrize(
    "raised, cwd_given, expected",
    [
        (
            subprocess.TimeoutExpired(["tool"], 42),
            True,
            r"^tool timed out after 42s in .+$",
        ),
        (subprocess.TimeoutExpired(["tool"], 42), False, r"^tool timed out after 42s$"),
        (
            FileNotFoundError(2, "No such file or directory", "tool"),
            True,
            r"^Could not run tool in .+: .*No such file or directory",
        ),
        (
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
            True,
            r"^Could not run tool in .+: .*invalid start byte",
        ),
    ],
)
def test_captured_mechanical_failure_raises_selected_error(
    tmp_path, monkeypatch, raised, cwd_given, expected
):
    monkeypatch.setattr(process.subprocess, "run", _fake(raises=raised))
    with pytest.raises(_DomainError, match=expected) as caught:
        run_captured(
            ["tool"],
            tmp_path if cwd_given else None,
            timeout=42,
            label="tool",
            error=_DomainError,
        )
    assert caught.value.__cause__ is raised


@pytest.mark.parametrize(
    "stdout, stderr, expected",
    [
        ("", "  boom\n", "tool failed (exit 3): boom"),
        ("from stdout\n", "   \n", "tool failed (exit 3): from stdout"),
        ("", "", "tool failed (exit 3)"),
        ("", "x" * 10 + "y" * 2000, "tool failed (exit 3): " + "y" * 2000),
    ],
)
def test_captured_rejected_status_reports_label_status_and_diagnostic(
    tmp_path, monkeypatch, stdout, stderr, expected
):
    result = completed(["tool"], returncode=3, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(process.subprocess, "run", _fake(result))
    with pytest.raises(ProcessError) as caught:
        run_captured(["tool"], tmp_path, timeout=5, label="tool")
    assert str(caught.value) == expected
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("ok_codes, status", [(frozenset({0, 1}), 1), (None, 7)])
def test_captured_returns_accepted_statuses(tmp_path, monkeypatch, ok_codes, status):
    result = completed(["tool"], returncode=status, stdout="", stderr="")
    monkeypatch.setattr(process.subprocess, "run", _fake(result))
    assert (
        run_captured(["tool"], tmp_path, timeout=5, label="tool", ok_codes=ok_codes)
        is result
    )


def test_captured_runs_a_real_command(tmp_path):
    completed = run_captured(
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        tmp_path,
        timeout=30,
        label="python",
    )
    assert Path(completed.stdout.strip()).resolve() == tmp_path.resolve()


def test_live_run_executes_bash_syntax(tmp_path):
    run_live(
        "printf '%s\\n' 'a b' | tr ' ' '_' > out.txt && [[ -s out.txt ]]",
        tmp_path,
        timeout=30,
        label="shell",
    )
    assert (tmp_path / "out.txt").read_text() == "a_b\n"


@pytest.mark.parametrize(
    "command, fails",
    [
        ("false | true", False),
        ("true | false", True),
        ("set -o pipefail; false | true", True),
    ],
)
def test_live_run_uses_normal_pipeline_status(tmp_path, command, fails):
    if fails:
        with pytest.raises(ProcessError, match=r"^pipeline failed \(exit 1\)$"):
            run_live(command, tmp_path, timeout=30, label="pipeline")
    else:
        run_live(command, tmp_path, timeout=30, label="pipeline")


def test_live_run_strips_the_host_virtualenv(tmp_path, monkeypatch):
    monkeypatch.setenv("VIRTUAL_ENV", "/host/venv")
    run_live('test -z "${VIRTUAL_ENV:-}"', tmp_path, timeout=30, label="env")


def test_live_run_launch_failure_raises_selected_error(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(
        _DomainError, match=r"^Could not run build in .*missing: "
    ) as caught:
        run_live("true", missing, timeout=30, label="build", error=_DomainError)
    assert isinstance(caught.value.__cause__, OSError)


def test_live_run_timeout_raises_selected_error(tmp_path):
    with pytest.raises(
        _DomainError, match=r"^sleeper timed out after 1s in "
    ) as caught:
        run_live("sleep 60", tmp_path, timeout=1, label="sleeper", error=_DomainError)
    assert isinstance(caught.value.__cause__, subprocess.TimeoutExpired)


def test_given_broken_stderr_when_failed_logs_replay_then_the_write_error_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class BrokenStderr(StringIO):
        def write(self, value: str) -> int:
            raise BrokenPipeError

    monkeypatch.setattr(sys, "stderr", BrokenStderr())
    with pytest.raises(BrokenPipeError):
        run_logged(
            [sys.executable, "-c", "print('OUT'); raise SystemExit(7)"],
            tmp_path,
            timeout=5,
            label="child",
        )


@pytest.mark.parametrize("returncode", [0, 7])
def test_given_child_logs_when_build_runs_then_only_failed_logs_reach_stderr(
    tmp_path: Path, capfd: pytest.CaptureFixture[str], returncode: int
) -> None:
    command = shlex.join(
        [
            sys.executable,
            "-c",
            "import sys; print('OUT'); print('ERR', file=sys.stderr); "
            f"sys.exit({returncode})",
        ]
    )
    if returncode:
        with pytest.raises(
            ProcessError, match=rf"^child failed \(exit {returncode}\)$"
        ):
            run_live(command, tmp_path, timeout=5, label="child")
    else:
        run_live(command, tmp_path, timeout=5, label="child")

    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == ("OUT\nERR\n" if returncode else "")


def test_given_parser_output_when_command_succeeds_then_streams_remain_separate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = run_logged(
        [
            sys.executable,
            "-c",
            "import sys; print('{\"ok\": true}'); print('notice', file=sys.stderr)",
        ],
        tmp_path,
        timeout=5,
        label="child",
        capture=True,
    )

    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        '{"ok": true}\n',
        "notice\n",
    )
    assert capsys.readouterr() == ("", "")


def test_given_stdout_only_failure_when_logs_replay_then_stdout_appears_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(ProcessError, match=r"^child failed \(exit 3\)$"):
        run_logged(
            [sys.executable, "-c", "print('only stdout'); raise SystemExit(3)"],
            tmp_path,
            timeout=5,
            label="child",
        )

    assert capsys.readouterr() == ("", "only stdout\n")


def test_given_partial_output_when_child_times_out_then_logs_replay_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(ProcessError, match=r"^child timed out after 1s in ") as caught:
        run_logged(
            [
                sys.executable,
                "-c",
                "import time; print('partial', flush=True); time.sleep(30)",
            ],
            tmp_path,
            timeout=1,
            label="child",
        )

    assert isinstance(caught.value.__cause__, subprocess.TimeoutExpired)
    assert capsys.readouterr() == ("", "partial\n")


@pytest.mark.parametrize("returncode", [0, 7])
def test_given_verbose_command_when_child_waits_for_log_then_output_arrives_before_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int
) -> None:
    acknowledgement = tmp_path / "ack"

    class LogObserver(StringIO):
        def write(self, value: str) -> int:
            length = super().write(value)
            if "READY" in self.getvalue():
                acknowledgement.touch()
            return length

    logs = LogObserver()
    monkeypatch.setattr(sys, "stderr", logs)
    output.set_verbose(True)
    command = [
        sys.executable,
        "-c",
        "import pathlib,sys,time; print('READY', flush=True); "
        "deadline=time.monotonic()+3\n"
        "while not pathlib.Path('ack').exists():\n"
        " if time.monotonic()>deadline: sys.exit(99)\n"
        " time.sleep(0.01)\n"
        f"print('ERR', file=sys.stderr); sys.exit({returncode})",
    ]

    if returncode:
        with pytest.raises(
            ProcessError, match=rf"^child failed \(exit {returncode}\)$"
        ):
            run_logged(command, tmp_path, timeout=5, label="child", capture=True)
    else:
        result = run_logged(command, tmp_path, timeout=5, label="child", capture=True)
        assert (result.stdout, result.stderr) == ("READY\n", "ERR\n")

    assert logs.getvalue() == "READY\nERR\n"


def test_given_running_child_when_interrupted_then_child_exits_and_partial_logs_replay(
    tmp_path: Path,
) -> None:
    pidfile = tmp_path / "child.pid"
    child_code = (
        "import os,pathlib,signal,sys,time; "
        "signal.signal(signal.SIGTERM, "
        "lambda *_: (pathlib.Path('cleaned').touch(), sys.exit(0))); "
        "print('partial', flush=True); "
        "pathlib.Path('child.pid').write_text(str(os.getpid())); time.sleep(30)"
    )
    parent_code = (
        "import os,sys; from pathlib import Path; "
        "from maintenance_man.process import run_logged\n"
        "try:\n"
        f" run_logged([sys.executable, '-c', {child_code!r}], "
        f"Path({str(tmp_path)!r}), timeout=30, label='child')\n"
        "except KeyboardInterrupt: sys.exit(130)\n"
    )
    with subprocess.Popen(
        [sys.executable, "-c", parent_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as parent:
        try:
            deadline = time.monotonic() + 5
            while not pidfile.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert pidfile.exists()
            child_pid = int(pidfile.read_text())
            parent.send_signal(signal.SIGINT)
            stdout, stderr = parent.communicate(timeout=5)
            assert (parent.returncode, stdout, stderr) == (130, "", "partial\n")
            assert (tmp_path / "cleaned").exists()
            with pytest.raises(ProcessLookupError):
                os.kill(child_pid, 0)
        finally:
            if parent.poll() is None:
                parent.kill()
                parent.wait()
            if pidfile.exists():
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(pidfile.read_text()), signal.SIGKILL)


def test_given_bash_script_when_run_then_bash_expansion_and_environment_survive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MM_TEST_VALUE", "literal[red]")
    result = run_logged(
        'items=(one two); printf "%s:%s" "${items[1]}" "$MM_TEST_VALUE"',
        tmp_path,
        timeout=5,
        label="script",
        shell=True,
        capture=True,
    )
    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        "two:literal[red]",
        "",
    )


@pytest.mark.parametrize("verbose", [False, True])
@pytest.mark.parametrize("detached", [False, True])
def test_given_background_child_when_command_exits_then_logging_preserves_success(
    tmp_path: Path,
    verbose: bool,
    detached: bool,
) -> None:
    output.set_verbose(verbose)
    descendant = (
        "from pathlib import Path; import time\n"
        "deadline=time.monotonic()+10\n"
        "while not Path('release').exists() and time.monotonic()<deadline:\n"
        " time.sleep(0.01)\n"
        "Path('alive').touch()\n"
    )
    script = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}], "
        f"start_new_session={detached}); "
        "print('parent done', flush=True)"
    )
    try:
        result = run_logged(
            [sys.executable, "-c", script],
            tmp_path,
            timeout=5,
            label="child",
            capture=True,
        )
    finally:
        (tmp_path / "release").touch()
    assert (result.returncode, result.stdout) == (0, "parent done\n")
    deadline = time.monotonic() + 5
    while not (tmp_path / "alive").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert (tmp_path / "alive").exists()


def test_given_delayed_tty_failure_when_logs_replay_then_child_text_is_verbatim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stderr = TerminalStream()
    stdout = StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("COLUMNS", "40")
    payload = "\x1b[38;2;1;2;3m" + "LONG" * 40 + "\x1b[0m\t[red]literal\n"
    with pytest.raises(ProcessError, match=r"^child failed \(exit 7\)$"):
        run_logged(
            [
                sys.executable,
                "-c",
                f"import sys,time; time.sleep(0.7); sys.stderr.write({payload!r}); "
                "sys.exit(7)",
            ],
            tmp_path,
            timeout=5,
            label="child",
        )
    assert stderr.getvalue().count(payload) == 1
    assert stdout.getvalue() == ""


@pytest.mark.parametrize(
    "reply, expected", [(b"answer\n", b"RESULT:answer"), (b"\x03", b"INTERRUPTED")]
)
@pytest.mark.parametrize("shell", [False, True])
def test_given_controlling_terminal_when_child_prompts_then_input_and_ctrl_c_reach_it(
    tmp_path: Path,
    reply: bytes,
    expected: bytes,
    shell: bool,
) -> None:
    child_script = (
        "import os; fd=os.open('/dev/tty',os.O_RDWR); "
        "os.write(fd,b'READY\\n'); print(os.read(fd,100).decode().strip())"
    )
    command = [sys.executable, "-c", child_script]
    if shell:
        command = shlex.join(command) + "; exit $?"
    script = (
        "import os,sys; from pathlib import Path; "
        "from maintenance_man.process import run_logged\n"
        "try:\n"
        f" r=run_logged({command!r},Path({str(tmp_path)!r}),"
        f"timeout=3,label='child',capture=True,shell={shell})\n"
        " print('RESULT:'+r.stdout.strip(), flush=True)\n"
        "except KeyboardInterrupt: print('INTERRUPTED',flush=True)\n"
    )
    pid, master = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, "-c", script])
    data = b""
    sent = False
    try:
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            if not select.select([master], [], [], 0.1)[0]:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            data += chunk
            if b"READY" in data and not sent:
                os.write(master, reply)
                sent = True
        assert expected in data, data.decode(errors="replace")
    finally:
        os.close(master)
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


@pytest.mark.parametrize("verbose", [False, True])
def test_given_exit_130_when_run_then_return_code_is_preserved(
    tmp_path: Path,
    verbose: bool,
) -> None:
    output.set_verbose(verbose)
    with pytest.raises(ProcessError, match=r"^child failed \(exit 130\)$"):
        run_logged(
            [sys.executable, "-c", "import sys; sys.exit(130)"],
            tmp_path,
            timeout=5,
            label="child",
        )


@pytest.mark.parametrize(
    "stdin, shown",
    [(None, False), (subprocess.DEVNULL, True)],
    ids=["inherited", "devnull"],
)
def test_given_terminal_stdin_when_child_inherits_it_then_progress_stays_hidden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdin: int | None, shown: bool
) -> None:
    stderr = TerminalStream()
    monkeypatch.setattr(sys, "stderr", stderr)
    monkeypatch.setattr(sys, "stdin", TerminalStream())
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setattr(output, "_PROGRESS_DELAY_SECONDS", 0)

    run_logged(
        [sys.executable, "-c", "import time; time.sleep(0.2)"],
        tmp_path,
        timeout=5,
        label="child",
        stdin=stdin,
    )

    assert ("Running child" in stderr.getvalue()) is shown
