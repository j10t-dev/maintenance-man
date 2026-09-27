import os
import subprocess
import sys
from pathlib import Path

import pytest

from maintenance_man import process
from maintenance_man.process import ProcessError, run_captured


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
