import json
import re
import subprocess

from packaging.version import InvalidVersion, Version

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import UpdateFinding, SemverTier


class OutdatedCheckError(Exception):
    pass


def classify_semver(installed: str, latest: str) -> SemverTier:
    """Compare two version strings and return the semver tier of the change."""
    try:
        old = Version(installed)
        new = Version(latest)
    except InvalidVersion:
        return SemverTier.UNKNOWN
    
    if old == new:
        return SemverTier.UNKNOWN
    
    # Version objects have .major, .minor, .micro attributes
    if old.major != new.major:
        return SemverTier.MAJOR
    if old.minor != new.minor:
        return SemverTier.MINOR
    return SemverTier.PATCH

def uv_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `uv pip list --outdated --format json` and parse results."""
    try:
        completed = subprocess.run(
            ["uv", "pip", "list", "--outdated", "--format", "json"],
            capture_output=True,
            text=True,
            cwd=project.path,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise OutdatedCheckError("uv pip list --outdated timed out")

    if completed.returncode != 0:
        raise OutdatedCheckError(
            f"uv pip list --outdated failed (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )

    try:
        entries = json.loads(completed.stdout)
    except json.JSONDecodeError as e:
        raise OutdatedCheckError(f"Failed to parse uv output: {e}") from e

    return [
        UpdateFinding(
            pkg_name=entry["name"],
            installed_version=entry["version"],
            latest_version=entry["latest_version"],
            semver_tier=classify_semver(entry["version"], entry["latest_version"]),
        )
        for entry in entries
        if entry.get("version") and entry.get("latest_version") 
           and entry["version"] != entry["latest_version"]
    ]


def _parse_bun_table(output: str) -> list[dict[str, str]]:
    """Parse bun outdated table output into list of dicts."""
    lines = (line.strip() for line in output.strip().splitlines())
    table_lines = (
        line for line in lines 
        if line.startswith("|") and "---" not in line
    )
    
    rows = []
    for line in table_lines:
        cells = [c.strip() for c in line.split("|") if c.strip()]
        if len(cells) >= 4 and cells[0].lower() != "package":
            rows.append({
                "package": cells[0],
                "current": cells[1],
                "update": cells[2],
                "latest": cells[3],
            })
    return rows


def bun_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `bun outdated` and parse the table output."""
    try:
        completed = subprocess.run(
            ["bun", "outdated"],
            capture_output=True,
            text=True,
            cwd=project.path,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise OutdatedCheckError("bun outdated timed out")

    if completed.returncode != 0 and not completed.stdout.strip():
        raise OutdatedCheckError(
            f"bun outdated failed (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
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


_MVN_UPDATE_RE = re.compile(
    r"^\[INFO\]\s+"
    r"(\S+:\S+)"  # groupId:artifactId
    r"\s+\.+\s+"  # dot padding
    r"(\S+)"  # current version
    r"\s+->\s+"  # arrow
    r"(\S+)"  # new version
)


def mvn_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `mvn versions:display-dependency-updates` and parse text output."""
    try:
        completed = subprocess.run(
            [
                "mvn",
                "versions:display-dependency-updates",
                "-DprocessDependencyManagement=false",
            ],
            capture_output=True,
            text=True,
            cwd=project.path,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise OutdatedCheckError("mvn versions:display-dependency-updates timed out")

    if completed.returncode != 0:
        raise OutdatedCheckError(
            f"mvn versions:display-dependency-updates failed "
            f"(exit {completed.returncode}): {completed.stderr.strip()}"
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


def get_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run the appropriate outdated check for the project's package manager."""
    checker = _CHECKERS.get(project.package_manager)
    if checker is None:
        raise OutdatedCheckError(
            f"No outdated checker for package manager: {project.package_manager}"
        )
    return checker(project)
