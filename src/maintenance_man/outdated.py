import json
import re
from pathlib import Path

from pydantic import ValidationError

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import UpdateFinding, classify_semver
from maintenance_man.process import run_captured
from maintenance_man.uv_dependencies import (
    UvDependencyError,
    get_uv_direct_dep_names,
    normalise_pkg_name,
)


class OutdatedCheckError(Exception):
    pass


def _get_uv_direct_dep_names(project_path: Path) -> set[str]:
    try:
        return get_uv_direct_dep_names(project_path)
    except UvDependencyError as e:
        raise OutdatedCheckError(str(e)) from e


def uv_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `uv pip list --outdated --format json` and parse results."""
    run_captured(
        ["uv", "sync", "--locked"],
        project.path,
        timeout=300,
        label="uv sync --locked",
        error=OutdatedCheckError,
    )
    venv_python = Path(project.path) / ".venv" / "bin" / "python"
    cmd = ["uv", "pip", "list", "--outdated", "--format", "json"]
    if venv_python.exists():
        cmd += ["--python", str(venv_python)]
    completed = run_captured(
        cmd,
        project.path,
        timeout=120,
        label="uv pip list --outdated",
        error=OutdatedCheckError,
    )

    try:
        entries = json.loads(completed.stdout)
    except json.JSONDecodeError as e:
        msg = f"Failed to parse uv output: {e}"
        raise OutdatedCheckError(msg) from e

    if not isinstance(entries, list) or not all(
        isinstance(entry, dict)
        and all(
            isinstance(entry.get(key), str)
            for key in ("name", "version", "latest_version")
        )
        for entry in entries
    ):
        msg = (
            "Unexpected uv output: expected a list of objects with string "
            "name, version and latest_version"
        )
        raise OutdatedCheckError(msg)

    direct_deps = _get_uv_direct_dep_names(Path(project.path))

    try:
        return [
            UpdateFinding(
                pkg_name=entry["name"],
                installed_version=entry["version"],
                latest_version=entry["latest_version"],
                semver_tier=classify_semver(entry["version"], entry["latest_version"]),
            )
            for entry in entries
            if (cur := entry.get("version"))
            and (lat := entry.get("latest_version"))
            and cur != lat
            and normalise_pkg_name(entry["name"]) in direct_deps
        ]
    except ValidationError as e:
        msg = f"Unexpected uv output: {e}"
        raise OutdatedCheckError(msg) from e


def bun_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `bun outdated` without progress output and parse the table output."""
    cmd = ["bun", "outdated", "--no-progress"]
    completed = run_captured(
        cmd,
        project.path,
        timeout=120,
        label="bun outdated",
        error=OutdatedCheckError,
        ok_codes=None,
    )

    if completed.returncode != 0 and not completed.stdout.strip():
        msg = (
            f"bun outdated failed (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
        raise OutdatedCheckError(msg)
    if not completed.stdout.strip():
        return []

    rows = _parse_bun_table(completed.stdout)
    return [
        UpdateFinding(
            pkg_name=row["package"],
            installed_version=row["current"],
            latest_version=row["latest"],
            semver_tier=classify_semver(row["current"], row["latest"]),
        )
        for row in rows
        if row["current"] != row["latest"]
    ]


def mvn_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `mvn versions:display-dependency-updates` and parse text output."""
    cmd = [
        "mvn",
        "versions:display-dependency-updates",
        "-DprocessDependencyManagement=false",
    ]
    completed = run_captured(
        cmd,
        project.path,
        timeout=300,
        label="mvn versions:display-dependency-updates",
        error=OutdatedCheckError,
    )

    return [
        UpdateFinding(
            pkg_name=m.group(1),
            installed_version=m.group(2),
            latest_version=m.group(3),
            semver_tier=classify_semver(m.group(2), m.group(3)),
        )
        for line in completed.stdout.splitlines()
        if (m := _MVN_UPDATE_RE.match(line))
    ]


def _parse_bun_table(output: str) -> list[dict[str, str]]:
    """Parse bun outdated table output into list of dicts."""
    lines = (line.strip() for line in output.strip().splitlines())
    table_lines = (line for line in lines if line.startswith("|") and "---" not in line)

    rows = []
    for line in table_lines:
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if len(cells) < 4 or cells[0].lower() == "package":
            continue
        rows.append(
            {
                "package": re.sub(r"\s*\(\w+\)$", "", cells[0]),
                "current": cells[1],
                "update": cells[2],
                "latest": cells[3],
            }
        )
    return rows


_MVN_UPDATE_RE = re.compile(
    r"^\[INFO\]\s+"
    r"(\S+:\S+)"  # groupId:artifactId
    r"\s+\.+\s+"  # dot padding
    r"(\S+)"  # current version
    r"\s+->\s+"  # arrow
    r"(\S+)"  # new version
)
