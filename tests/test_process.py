import os
import subprocess
import sys
from pathlib import Path

import pytest

from maintenance_man import process
from maintenance_man.process import ProcessError, run_captured, run_live


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


def test_captured_run_is_isolated_and_non_interactive(tmp_path, monkeypatch):
    _host_venv(monkeypatch)
    calls = []
    completed = subprocess.CompletedProcess(["tool", "--flag"], 0, "out", "")
    monkeypatch.setattr(process.subprocess, "run", _fake(completed, calls=calls))

    assert (
        run_captured(["tool", "--flag"], tmp_path, timeout=42, label="tool")
        is completed
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
        (None, None, "tool failed (exit 3)"),
        ("", "x" * 10 + "y" * 2000, "tool failed (exit 3): " + "y" * 2000),
    ],
)
def test_captured_rejected_status_reports_label_status_and_diagnostic(
    tmp_path, monkeypatch, stdout, stderr, expected
):
    completed = subprocess.CompletedProcess(["tool"], 3, stdout, stderr)
    monkeypatch.setattr(process.subprocess, "run", _fake(completed))
    with pytest.raises(ProcessError) as caught:
        run_captured(["tool"], tmp_path, timeout=5, label="tool")
    assert str(caught.value) == expected
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("ok_codes, status", [(frozenset({0, 1}), 1), (None, 7)])
def test_captured_returns_accepted_statuses(tmp_path, monkeypatch, ok_codes, status):
    completed = subprocess.CompletedProcess(["tool"], status, "", "")
    monkeypatch.setattr(process.subprocess, "run", _fake(completed))
    assert (
        run_captured(["tool"], tmp_path, timeout=5, label="tool", ok_codes=ok_codes)
        is completed
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


def test_live_run_timeout_raises_selected_error(tmp_path, monkeypatch):
    raised = subprocess.TimeoutExpired("sleep 60", 5)
    monkeypatch.setattr(process.subprocess, "run", _fake(raises=raised))
    with pytest.raises(_DomainError, match=r"^deploy timed out after 5s in ") as caught:
        run_live("sleep 60", tmp_path, timeout=5, label="deploy", error=_DomainError)
    assert caught.value.__cause__ is raised


def test_live_run_inherits_standard_streams(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        process.subprocess,
        "run",
        _fake(subprocess.CompletedProcess("true", 0), calls=calls),
    )
    run_live("true", tmp_path, timeout=5, label="noop")
    ((command, kwargs),) = calls
    assert command == "true"
    assert kwargs["shell"] is True
    assert kwargs["executable"] == "/bin/bash"
    assert kwargs["cwd"] == tmp_path
    assert kwargs["timeout"] == 5
    assert not {"stdin", "stdout", "stderr", "capture_output"} & kwargs.keys()
