"""How mm writes its own state files, and scan-result and activity persistence."""

import json
import os
import secrets
from pathlib import Path
from typing import Literal

from pydantic import TypeAdapter, ValidationError

from maintenance_man import paths
from maintenance_man.clock import utc_now
from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.models.scan import ScanResult


class NoScanResultsError(Exception):
    """Raised when no scan results exist for a project."""


class CorruptScanResultsError(Exception):
    """A scan file that exists but cannot be used; the project needs a rescan."""

    def __init__(self, project_name: str, detail: str) -> None:
        super().__init__(f"corrupt scan results for {project_name}: {detail}")
        self.project_name = project_name
        self.detail = detail


def atomic_write_text(path: Path, text: str) -> None:
    """Replace *path* with *text* atomically.

    Raises OSError. Never leaves a temporary file behind and never removes
    *path*.
    """
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def load_scan_results(project_name: str) -> ScanResult:
    """Load the saved scan for *project_name*.

    A missing file is NoScanResultsError; a file that cannot be read, decoded or
    validated is CorruptScanResultsError.
    """
    results_file = paths.project_file(paths.scan_results_dir(), project_name, ".json")
    try:
        return ScanResult.model_validate_json(results_file.read_bytes())
    except FileNotFoundError:
        msg = (
            f"No scan results found for '{project_name}'. "
            f"Run 'mm scan {project_name}' first."
        )
        raise NoScanResultsError(msg) from None
    except ValidationError as e:
        raise CorruptScanResultsError(project_name, _first_error(e)) from e
    except OSError as e:
        raise CorruptScanResultsError(project_name, str(e)) from e


def _first_error(error: ValidationError) -> str:
    first = error.errors()[0]
    location = ".".join(str(part) for part in first["loc"])
    return f"{location}: {first['msg']}" if location else first["msg"]


def save_scan_results(project_name: str, scan_result: ScanResult) -> None:
    """Write scan results (with update statuses) back to disk."""
    paths.scan_results_dir().mkdir(parents=True, exist_ok=True)
    results_file = paths.project_file(paths.scan_results_dir(), project_name, ".json")
    atomic_write_text(results_file, scan_result.model_dump_json(indent=2))


def load_activity(path: Path) -> dict[str, ProjectActivity]:
    """Load activity data, returning empty data for I/O or validation failures."""
    try:
        return _ACTIVITY.validate_json(path.read_bytes())
    except OSError, ValueError:
        return {}


def record_activity(
    path: Path,
    project_name: str,
    event_type: Literal["build", "deploy"],
    *,
    success: bool,
    branch: str,
    commit_id: str | None = None,
) -> None:
    """Record an event, ignoring persistence and data-validation failures."""
    try:
        activity = load_activity(path)
        proj = activity.get(project_name, ProjectActivity())
        event = ActivityEvent(
            timestamp=utc_now(),
            success=success,
            branch=branch,
            commit_id=commit_id,
        )
        if event_type == "build":
            proj.last_build = event
        else:
            proj.last_deploy = event
        activity[project_name] = proj
        serialised = {k: v.model_dump(mode="json") for k, v in activity.items()}
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, json.dumps(serialised, indent=2))
    except OSError, ValueError:
        pass


_ACTIVITY = TypeAdapter(dict[str, ProjectActivity])
