"""Controllable time for publication and Gradle lifecycle scenarios."""

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class FakeClock:
    """Time advances only when the test requests it."""

    current: datetime

    def __call__(self) -> datetime:
        """Return the current test time."""
        return self.current

    def advance(self, delta: timedelta) -> None:
        """Move subsequent clock readings by the supplied duration."""
        self.current += delta
