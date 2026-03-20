import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, field_validator


class ActivityEvent(BaseModel):
    timestamp: datetime
    success: bool
    branch: str

    @field_validator("timestamp", mode="before")
    @classmethod
    def _truncate_to_minutes(cls, v: datetime) -> datetime:
        if isinstance(v, datetime):
            return v.replace(second=0, microsecond=0)
        return v


class ProjectActivity(BaseModel):
    last_build: ActivityEvent | None = None
    last_deploy: ActivityEvent | None = None


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
) -> None:
    """Record a build/deploy event. Fire-and-forget — never raises."""
    try:
        activity = load_activity(path)
        proj = activity.get(project, ProjectActivity())
        event = ActivityEvent(
            timestamp=datetime.now(timezone.utc),
            success=success,
            branch=branch,
        )
        if event_type == "build":
            proj.last_build = event
        else:
            proj.last_deploy = event
        activity[project] = proj
        serialised = {k: v.model_dump(mode="json") for k, v in activity.items()}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(serialised, indent=2), encoding="utf-8")
    except Exception:
        pass
