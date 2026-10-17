"""Registry publication facts shared by package-manager age checks."""

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict

type Registry = Literal["pypi", "npm"]
type PublicationSource = Literal["pypi", "npm", "central"]


def _utc_date(value: datetime) -> datetime:
    if value.tzinfo is None:
        msg = "publication dates require a timezone"
        raise ValueError(msg)
    return value.astimezone(UTC)


type UtcDatetime = Annotated[datetime, AfterValidator(_utc_date)]


class RegistryFact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    registry: Registry
    package: str
    version: str
    timestamp: UtcDatetime
    checked_at: UtcDatetime
