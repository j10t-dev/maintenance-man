"""Registry publication facts shared by package-manager age checks."""

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

type Registry = Literal["pypi", "npm"]
type PublicationSource = Literal["pypi", "npm", "central"]


class RegistryFact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    registry: Registry
    package: str
    version: str
    timestamp: datetime
    checked_at: datetime

    @field_validator("timestamp", "checked_at")
    @classmethod
    def utc_date(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            msg = "publication dates require a timezone"
            raise ValueError(msg)
        return value.astimezone(UTC)
