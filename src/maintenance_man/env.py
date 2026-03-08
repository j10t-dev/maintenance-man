from __future__ import annotations

import os
from pathlib import Path


def project_env() -> dict[str, str]:
    """Return a copy of os.environ with venv isolation.

    Strips VIRTUAL_ENV and removes the venv bin/ directory from PATH.
    Prevents the host venv leaking into subprocess calls that run inside
    a target project directory (e.g. ``uv run``, ``uv add``, deploy scripts).
    """
    env = os.environ.copy()
    venv = env.pop("VIRTUAL_ENV", None)
    if venv:
        venv_bin = str(Path(venv) / "bin")
        path_dirs = env.get("PATH", "").split(os.pathsep)
        env["PATH"] = os.pathsep.join(d for d in path_dirs if d != venv_bin)
    return env
