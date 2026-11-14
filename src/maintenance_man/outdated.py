import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name
from pydantic import BaseModel, StrictStr, TypeAdapter, ValidationError

from maintenance_man.bun_dependencies import (
    BunDependencyError,
    registry_declared_bun_names,
    resolved_bun_versions,
)
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
    """Run `bun outdated` and return updates of registry-declared packages.

    Raises OutdatedCheckError when the command fails or writes to standard error,
    when its output is not the banner and pipe table, or when a reported current
    version differs from the one `bun pm ls` resolves.
    """
    cmd = ["bun", "outdated", "--no-progress"]
    completed = _run(cmd, project, timeout=120, label="bun outdated")
    if error_lines := _non_blank_lines(completed.stderr):
        msg = f"bun outdated: unexpected standard error: {error_lines[0]!r}"
        raise OutdatedCheckError(msg)
    rows = _parse_bun_report(completed.stdout)
    if not rows:
        return []

    declared, resolved = _read_bun_dependencies(Path(project.path))
    findings = []
    for name, current, latest in rows:
        if name not in declared:
            continue
        if current != (resolved_version := resolved.get(name)):
            msg = (
                f"bun outdated: {name} is at {current}, "
                f"but bun pm ls resolves {resolved_version or 'nothing'}"
            )
            raise OutdatedCheckError(msg)
        if current != latest:
            findings.append(_finding(name, current, latest))
    return findings


def mvn_outdated(project: ProjectConfig) -> list[UpdateFinding]:
    """Run `mvn versions:display-dependency-updates` and return the updates listed
    in each execution's Dependencies section.

    Raises OutdatedCheckError when the output holds no execution of the goal, when
    a line inside an execution is not part of its report, when a section of
    newer versions lists no row, or when a section, no-updates or row line appears
    outside an execution.
    """
    cmd = [
        "mvn",
        "-B",
        "-ntp",
        "-Dstyle.color=never",
        "versions:display-dependency-updates",
        "-DprocessDependencyManagement=false",
        "-Dversions.outputLineWidth=1000",
    ]
    completed = _run(
        cmd, project, timeout=300, label="mvn versions:display-dependency-updates"
    )

    report = _MavenReport()
    for line in completed.stdout.splitlines():
        report.read(line)
    return report.finish()


def _run(
    cmd: list[str], project: ProjectConfig, *, timeout: int, label: str
) -> subprocess.CompletedProcess[str]:
    return run_captured(
        cmd, project.path, timeout=timeout, label=label, error=OutdatedCheckError
    )


def _finding(name: str, installed: str, latest: str) -> UpdateFinding:
    return UpdateFinding(
        pkg_name=name,
        installed_version=installed,
        latest_version=latest,
        semver_tier=classify_semver(installed, latest),
    )


def _non_blank_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _parse_bun_report(stdout: str) -> list[tuple[str, str, str]]:
    """(package, current, latest) for each row of the table after the banner."""
    lines = _non_blank_lines(stdout)
    if not lines:
        msg = "bun outdated: unrecognised output: no banner"
        raise OutdatedCheckError(msg)
    banner, *table = lines
    if not banner.startswith("bun outdated v"):
        raise _unrecognised_bun_line(banner)
    if not table:
        return []
    if len(table) < 5:
        msg = "bun outdated: unrecognised output: table shorter than five lines"
        raise OutdatedCheckError(msg)
    # After the header bun prints a separator before every row.
    body = table[2:-1]
    for separator in (table[0], table[-1], *body[0::2]):
        if not _BUN_SEPARATOR_RE.fullmatch(separator):
            raise _unrecognised_bun_line(separator)
    if _bun_cells(table[1])[:4] != ["Package", "Current", "Update", "Latest"]:
        raise _unrecognised_bun_line(table[1])
    if len(body) % 2:
        raise _unrecognised_bun_line(body[-1])
    return [_parse_bun_row(line) for line in body[1::2]]


def _parse_bun_row(line: str) -> tuple[str, str, str]:
    cells = _bun_cells(line)
    if (
        not line.startswith("|")
        or _BUN_SEPARATOR_RE.fullmatch(line)
        or len(cells) < 4
        or not all((cells[0], cells[1], cells[3]))
    ):
        raise _unrecognised_bun_line(line)
    return re.sub(r"\s*\(\w+\)$", "", cells[0]), cells[1], cells[3]


def _bun_cells(line: str) -> list[str]:
    return [
        cell.strip() for cell in line.removeprefix("|").removesuffix("|").split("|")
    ]


def _unrecognised_bun_line(line: str) -> OutdatedCheckError:
    return OutdatedCheckError(f"bun outdated: unrecognised output line: {line!r}")


def _read_bun_dependencies(project_path: Path) -> tuple[set[str], dict[str, str]]:
    try:
        return (
            registry_declared_bun_names(project_path),
            resolved_bun_versions(project_path),
        )
    except BunDependencyError as e:
        raise OutdatedCheckError(str(e)) from e


_BUN_SEPARATOR_RE = re.compile(r"[|-]+")


@dataclass
class _MavenSection:
    name: str
    line: str
    rows: int = 0


@dataclass
class _MavenReport:
    """Reads the report line by line. Outside an execution of the goal, section,
    no-updates and row lines raise and other lines are ignored; inside one, every
    line must start with [INFO] and belong to the report."""

    findings: list[UpdateFinding] = field(default_factory=list)
    saw_execution: bool = False
    in_execution: bool = False
    section: _MavenSection | None = None

    def read(self, line: str) -> None:
        is_info = line.startswith("[INFO]")
        text = line.removeprefix("[INFO]").strip()
        if self.in_execution and is_info and text.startswith("---"):
            self._close_section()
            self.in_execution = False
        if self.in_execution:
            self._read_execution_line(line, text, is_info=is_info)
        else:
            self._read_outside_line(line, text, is_info=is_info)

    def finish(self) -> list[UpdateFinding]:
        self._close_section()
        if not self.saw_execution:
            msg = f"{_MVN_ERROR}: no display-dependency-updates execution"
            raise OutdatedCheckError(msg)
        return self.findings

    def _read_outside_line(self, line: str, text: str, *, is_info: bool) -> None:
        if is_info and _MVN_EXECUTION_RE.match(text):
            self.in_execution = True
            self.saw_execution = True
        elif any(
            pattern.match(text)
            for pattern in (_MVN_NO_UPDATES_RE, _MVN_SECTION_RE, _MVN_ROW_RE)
        ):
            raise _unrecognised_maven_line(line)

    def _read_execution_line(self, line: str, text: str, *, is_info: bool) -> None:
        if not is_info:
            raise _unrecognised_maven_line(line)
        if self.section is not None:
            if row := _MVN_ROW_RE.match(text):
                self._add_row(self.section, row)
                return
            self._close_section()
        if not text or _MVN_NO_UPDATES_RE.match(text):
            return
        if section := _MVN_SECTION_RE.match(text):
            self.section = _MavenSection(section["section"], line)
            return
        raise _unrecognised_maven_line(line)

    def _add_row(self, section: _MavenSection, row: re.Match[str]) -> None:
        section.rows += 1
        if section.name == "Dependencies":
            self.findings.append(_finding(**row.groupdict()))

    def _close_section(self) -> None:
        if self.section is not None and not self.section.rows:
            raise _unrecognised_maven_line(self.section.line)
        self.section = None


def _unrecognised_maven_line(line: str) -> OutdatedCheckError:
    return OutdatedCheckError(f"{_MVN_ERROR} line: {line!r}")


_MVN_ERROR = "mvn versions:display-dependency-updates: unrecognised output"
_MVN_EXECUTION_RE = re.compile(
    r"^--- \S+:display-dependency-updates \([^)]*\) @ .+ ---$"
)
_MVN_NO_UPDATES_RE = re.compile(
    r"^No dependencies in (?P<section>.+) have newer versions\.$"
)
_MVN_SECTION_RE = re.compile(
    r"^The following dependencies in (?P<section>.+) have newer versions:$"
)
_MVN_ROW_RE = re.compile(
    r"^(?P<name>\S+:\S+)\s+\.+\s+(?P<installed>\S+)\s+->\s+(?P<latest>\S+)$"
)
