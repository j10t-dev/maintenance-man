"""How mm writes its own state files, and scan-result and activity persistence."""

import json
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from maintenance_man import paths
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.scan import ScanResult


class NoScanResultsError(Exception):
    """Raised when no scan results exist for a project."""


def atomic_write_text(
    path: Path, text: str, *, durable: bool = False, mode: int = 0o666
) -> None:
    """Replace *path* with *text* atomically.

    Raises OSError. Never leaves a temporary file behind and never removes
    *path*. With *durable*, fsyncs the file before and the directory after
    the replace; a directory fsync failure leaves *path* already replaced.
    """
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            if durable:
                stream.flush()
                os.fsync(stream.fileno())
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    if durable:
        fsync_dir(path.parent)


def fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_scan_results(project_name: str) -> ScanResult:
    """Load scan results JSON for a project. Raises NoScanResultsError if missing."""
    results_file = paths.project_file(paths.scan_results_dir(), project_name, ".json")
    try:
        data = json.loads(results_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise NoScanResultsError(
            f"No scan results found for '{project_name}'. "
            f"Run 'mm scan {project_name}' first."
        ) from None
    return ScanResult.model_validate(data)


def save_scan_results(project_name: str, scan_result: ScanResult) -> None:
    """Write scan results (with update statuses) back to disk."""
    paths.scan_results_dir().mkdir(parents=True, exist_ok=True)
    results_file = paths.project_file(paths.scan_results_dir(), project_name, ".json")
    atomic_write_text(results_file, scan_result.model_dump_json(indent=2))


def load_activity(path: Path) -> dict[str, ProjectActivity]:
    """Load activity data from JSON. Returns empty dict on any error."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return {k: ProjectActivity(**v) for k, v in raw.items()}
    except Exception:
        return {}


def record_activity(
    path: Path,
    project: str,
    event_type: Literal["build", "deploy"],
    *,
    success: bool,
    branch: str,
    commit_id: str | None = None,
) -> None:
    """Record a build/deploy event. Fire-and-forget — never raises."""
    try:
        activity = load_activity(path)
        proj = activity.get(project, ProjectActivity())
        event = ActivityEvent(
            timestamp=datetime.now(UTC),
            success=success,
            branch=branch,
            commit_id=commit_id,
        )
        if event_type == "build":
            proj.last_build = event
        else:
            proj.last_deploy = event
        activity[project] = proj
        serialised = {k: v.model_dump(mode="json") for k, v in activity.items()}
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, json.dumps(serialised, indent=2))
    except Exception:
        pass
