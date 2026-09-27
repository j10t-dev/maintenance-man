from datetime import datetime

from pydantic import BaseModel, field_validator


class ActivityEvent(BaseModel):
    timestamp: datetime
    success: bool
    branch: str
    commit_id: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def _truncate_to_minutes(cls, v: datetime) -> datetime:
        if isinstance(v, datetime):
            return v.replace(second=0, microsecond=0)
        return v


class ProjectActivity(BaseModel):
    last_build: ActivityEvent | None = None
    last_deploy: ActivityEvent | None = None
