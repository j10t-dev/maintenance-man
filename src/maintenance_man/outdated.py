import re
import subprocess
from collections.abc import Collection
from pathlib import Path

from packaging.utils import canonicalize_name
from pydantic import BaseModel, StrictStr, TypeAdapter, ValidationError

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import UpdateFinding, classify_semver
from maintenance_man.process import run_captured
from maintenance_man.uv_dependencies import UvDependencyError, get_uv_direct_dep_names


class OutdatedCheckError(Exception):
    pass


def uv_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `uv pip list --outdated --format json` and parse results."""
    _run(["uv", "sync", "--locked"], project, timeout=300, label="uv sync --locked")
    venv_python = Path(project.path) / ".venv" / "bin" / "python"
    cmd = ["uv", "pip", "list", "--outdated", "--format", "json"]
    if venv_python.exists():
        cmd += ["--python", str(venv_python)]
    completed = _run(cmd, project, timeout=120, label="uv pip list --outdated")

    try:
        entries = TypeAdapter(list[_UvRow]).validate_json(completed.stdout)
        direct_deps = get_uv_direct_dep_names(Path(project.path))
        return [
            _finding(entry.name, entry.version, entry.latest_version)
            for entry in entries
            if entry.version
            and entry.latest_version
            and entry.version != entry.latest_version
            and canonicalize_name(entry.name) in direct_deps
        ]
    except ValidationError as e:
        msg = f"Unexpected uv output: {e}"
        raise OutdatedCheckError(msg) from e
    except UvDependencyError as e:
        raise OutdatedCheckError(str(e)) from e


class _UvRow(BaseModel):
    name: StrictStr
    version: StrictStr
    latest_version: StrictStr


def bun_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `bun outdated` without progress output and parse the table output."""
    cmd = ["bun", "outdated", "--no-progress"]
    completed = _run(cmd, project, timeout=120, label="bun outdated", ok_codes=None)

    if completed.returncode != 0 and not completed.stdout.strip():
        msg = (
            f"bun outdated failed (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
        raise OutdatedCheckError(msg)
    if not completed.stdout.strip():
        return []

    return [
        _finding(package, current, latest)
        for package, current, latest in _parse_bun_table(completed.stdout)
        if current != latest
    ]


def mvn_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `mvn versions:display-dependency-updates` and parse text output."""
    cmd = [
        "mvn",
        "versions:display-dependency-updates",
        "-DprocessDependencyManagement=false",
    ]
    completed = _run(
        cmd, project, timeout=300, label="mvn versions:display-dependency-updates"
    )

    return [
        _finding(**match.groupdict())
        for line in completed.stdout.splitlines()
        if (match := _MVN_UPDATE_RE.match(line))
    ]


def _run(
    cmd: list[str],
    project: ProjectConfig,
    *,
    timeout: int,
    label: str,
    **options: Collection[int] | None,
) -> subprocess.CompletedProcess[str]:
    return run_captured(
        cmd,
        project.path,
        timeout=timeout,
        label=label,
        error=OutdatedCheckError,
        **options,
    )


def _finding(name: str, installed: str, latest: str) -> UpdateFinding:
    return UpdateFinding(
        pkg_name=name,
        installed_version=installed,
        latest_version=latest,
        semver_tier=classify_semver(installed, latest),
    )


def _parse_bun_table(output: str) -> list[tuple[str, str, str]]:
    """Parse bun outdated table output into (package, current, latest) rows."""
    lines = (line.strip() for line in output.strip().splitlines())
    table_lines = (line for line in lines if line.startswith("|") and "---" not in line)

    rows = []
    for line in table_lines:
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if len(cells) < 4 or cells[0].lower() == "package":
            continue
        rows.append((re.sub(r"\s*\(\w+\)$", "", cells[0]), cells[1], cells[3]))
    return rows


_MVN_UPDATE_RE = re.compile(
    r"^\[INFO\]\s+"
    r"(?P<name>\S+:\S+)"
    r"\s+\.+\s+"
    r"(?P<installed>\S+)"
    r"\s+->\s+"
    r"(?P<latest>\S+)"
)
