import os
import shlex
import signal
import subprocess
import sys
import time
from io import StringIO
from pathlib import Path

import pytest

from maintenance_man import output
from maintenance_man.deployer import BuildError, run_build
from maintenance_man.process import run_logged


@pytest.fixture(autouse=True)
def quiet_invocation():
    output.set_verbose(False)
    yield
    output.set_verbose(False)


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
        with pytest.raises(BuildError):
            run_build("api", command, tmp_path)
    else:
        run_build("api", command, tmp_path)

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
        cwd=tmp_path,
        timeout=5,
        capture=True,
    )

    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        '{"ok": true}\n',
        "notice\n",
    )
    assert capsys.readouterr() == ("", "")


def test_given_partial_output_when_child_times_out_then_logs_replay_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        run_logged(
            [
                sys.executable,
                "-c",
                "import time; print('partial', flush=True); time.sleep(30)",
            ],
            cwd=tmp_path,
            timeout=0.3,
        )

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
    result = run_logged(
        [
            sys.executable,
            "-c",
            "import pathlib,sys,time; print('READY', flush=True); "
            "deadline=time.monotonic()+3\n"
            "while not pathlib.Path('ack').exists():\n"
            " if time.monotonic()>deadline: sys.exit(99)\n"
            " time.sleep(0.01)\n"
            f"print('ERR', file=sys.stderr); sys.exit({returncode})",
        ],
        cwd=tmp_path,
        timeout=5,
        capture=True,
    )

    assert result.returncode == returncode
    assert logs.getvalue() == "READY\nERR\n"
    assert (result.stdout, result.stderr) == ("READY\n", "ERR\n")


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
        f"cwd=Path({str(tmp_path)!r}), timeout=30)\n"
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
                try:
                    os.kill(int(pidfile.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass


def test_given_bash_script_when_run_then_bash_expansion_and_environment_survive(
    tmp_path: Path,
) -> None:
    result = run_logged(
        'items=(one two); printf "%s:%s" "${items[1]}" "$MM_TEST_VALUE"',
        cwd=tmp_path,
        timeout=5,
        shell=True,
        env={**os.environ, "MM_TEST_VALUE": "literal[red]"},
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
            [sys.executable, "-c", script], cwd=tmp_path, timeout=5, capture=True
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
    from tests.test_output import TerminalStream

    stderr = TerminalStream()
    stdout = StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("COLUMNS", "40")
    payload = "\x1b[38;2;1;2;3m" + "LONG" * 40 + "\x1b[0m\t[red]literal\n"
    result = run_logged(
        [
            sys.executable,
            "-c",
            f"import sys,time; time.sleep(0.7); sys.stderr.write({payload!r}); "
            "sys.exit(7)",
        ],
        cwd=tmp_path,
        timeout=5,
    )
    assert result.returncode == 7
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
    import errno
    import pty
    import select

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
        f" r=run_logged({command!r},cwd=Path({str(tmp_path)!r}),"
        f"timeout=3,capture=True,shell={shell})\n"
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
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)


@pytest.mark.parametrize("verbose", [False, True])
def test_given_exit_130_when_run_then_return_code_is_preserved(
    tmp_path: Path,
    verbose: bool,
) -> None:
    output.set_verbose(verbose)
    result = run_logged(
        [sys.executable, "-c", "import sys; sys.exit(130)"], cwd=tmp_path, timeout=5
    )
    assert result.returncode == 130


@pytest.mark.parametrize(
    "stdin, shown",
    [(None, False), (subprocess.DEVNULL, True)],
    ids=["inherited", "devnull"],
)
def test_given_terminal_stdin_when_child_inherits_it_then_progress_stays_hidden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdin: int | None, shown: bool
) -> None:
    from tests.test_output import TerminalStream

    stderr = TerminalStream()
    monkeypatch.setattr(sys, "stderr", stderr)
    monkeypatch.setattr(sys, "stdin", TerminalStream())
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setattr(output, "_PROGRESS_DELAY_SECONDS", 0)

    run_logged(
        [sys.executable, "-c", "import time; time.sleep(0.2)"],
        cwd=tmp_path,
        timeout=5,
        stdin=stdin,
    )

    assert ("Running" in stderr.getvalue()) is shown
