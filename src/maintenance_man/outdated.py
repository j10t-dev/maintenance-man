import json
import re
import subprocess
import tomllib
from pathlib import Path

from packaging.version import InvalidVersion, Version

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import SemverTier, UpdateFinding


class OutdatedCheckError(Exception):
    pass


def get_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run the appropriate outdated check for the project's package manager."""
    checker = _CHECKERS.get(project.package_manager)
    if checker is None:
        raise OutdatedCheckError(
            f"No outdated checker for package manager: {project.package_manager}"
        )
    return checker(project)


def classify_semver(installed: str, latest: str) -> SemverTier:
    """Compare two version strings and return the semver tier of the change."""
    try:
        old = Version(installed)
        new = Version(latest)
    except InvalidVersion:
        return SemverTier.UNKNOWN

    if old == new:
        return SemverTier.UNKNOWN

    match (old.major != new.major, old.minor != new.minor):
        case (True, _):
            return SemverTier.MAJOR
        case (_, True):
            return SemverTier.MINOR
        case _:
            return SemverTier.PATCH


_PEP503_NORMALISE_RE = re.compile(r"[-_.]+")


def _normalise_pkg_name(name: str) -> str:
    """Normalise a package name per PEP 503 (lowercase, collapse separators)."""
    return _PEP503_NORMALISE_RE.sub("-", name).lower()


_PEP508_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")


def _get_uv_direct_dep_names(project_path: Path) -> set[str]:
    """Read pyproject.toml and return normalised names of all direct dependencies."""
    pyproject_path = project_path / "pyproject.toml"
    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
    except (FileNotFoundError, tomllib.TOMLDecodeError) as e:
        raise OutdatedCheckError(f"Failed to read {pyproject_path}: {e}") from e

    names: set[str] = set()

    for spec in data.get("project", {}).get("dependencies", []):
        if m := _PEP508_NAME_RE.match(spec):
            names.add(_normalise_pkg_name(m.group(1)))

    for group_entries in data.get("dependency-groups", {}).values():
        for entry in group_entries:
            if isinstance(entry, str) and (m := _PEP508_NAME_RE.match(entry)):
                names.add(_normalise_pkg_name(m.group(1)))

    return names


def uv_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `uv pip list --outdated --format json` and parse results."""
    venv_python = Path(project.path) / ".venv" / "bin" / "python"
    cmd = ["uv", "pip", "list", "--outdated", "--format", "json"]
    if venv_python.exists():
        cmd += ["--python", str(venv_python)]
    completed = _run_checked(
        cmd,
        cwd=project.path,
        timeout=120,
        label="uv pip list --outdated",
    )

    try:
        entries = json.loads(completed.stdout)
    except json.JSONDecodeError as e:
        raise OutdatedCheckError(f"Failed to parse uv output: {e}") from e

    direct_deps = _get_uv_direct_dep_names(Path(project.path))

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
        and _normalise_pkg_name(entry["name"]) in direct_deps
    ]


def bun_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `bun outdated` and parse the table output."""
    cmd = ["bun", "outdated"]
    completed = _run_checked(
        cmd,
        cwd=project.path,
        timeout=120,
        label="bun outdated",
        allow_nonzero_with_stdout=True,
    )

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
    completed = _run_checked(
        cmd,
        cwd=project.path,
        timeout=300,
        label="mvn versions:display-dependency-updates",
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


_CHECKERS = {
    "bun": bun_outdated,
    "uv": uv_outdated,
    "mvn": mvn_outdated,
}


def _run_checked(
    cmd: list[str],
    cwd: str | Path,
    timeout: int,
    *,
    label: str,
    allow_nonzero_with_stdout: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with common error handling."""
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise OutdatedCheckError(f"{label} timed out") from e

    if completed.returncode != 0:
        if allow_nonzero_with_stdout and completed.stdout.strip():
            return completed
        raise OutdatedCheckError(
            f"{label} failed (exit {completed.returncode}): {completed.stderr.strip()}"
        )
    return completed


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
                "package": re.sub(r"\s*\(dev\)$", "", cells[0]),
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
