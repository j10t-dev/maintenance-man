from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from maintenance_man.models.publication import RegistryFact

_FACT: dict[str, Any] = {
    "registry": "pypi",
    "package": "requests",
    "version": "2.31.0",
    "timestamp": datetime(2025, 12, 31, 1, tzinfo=timezone(timedelta(hours=1))),
    "checked_at": datetime(2026, 1, 1, tzinfo=UTC),
}


def test_registry_fact_stores_utc():
    fact = RegistryFact(**_FACT)
    assert fact.timestamp == datetime(2025, 12, 31, tzinfo=UTC)
    assert fact.timestamp.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "change",
    [
        {"timestamp": datetime(2025, 12, 31)},
        {"checked_at": datetime(2026, 1, 1)},
        {"registry": "central"},
        {"source": "bun"},
    ],
)
def test_registry_fact_rejects_invalid_values(change):
    with pytest.raises(ValidationError):
        RegistryFact(**(_FACT | change))
