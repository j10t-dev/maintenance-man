"""Injectable UTC clock for time-sensitive decisions."""

from collections.abc import Callable
from datetime import UTC, datetime

type Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)
