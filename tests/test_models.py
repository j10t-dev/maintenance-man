from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from maintenance_man.models.gradle import content_identity
from maintenance_man.models.publication import RegistryFact
from maintenance_man.models.scan import (
    SemverTier,
    Severity,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    Workflow,
)

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


def test_content_identity_keeps_canonical_bytes():
    class Probe(BaseModel):
        at: datetime
        path: Path
        tags: frozenset[str]
        values: tuple[int, ...]
        phase: Workflow
        nested: dict[str, int]

    value = Probe(
        at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        path=Path("gradle/libs.versions.toml"),
        tags=frozenset({"z", "a"}),
        values=(2, 1),
        phase=Workflow.UPDATE,
        nested={"b": 2, "a": 1},
    )
    assert content_identity(value) == (
        "e318569d6e758716db6146f979d2c5fd7bb87482206c54f75125e5e2170dc852"
    )


class TestWorkflow:
    def test_flow_members_are_string_values(self):
        assert Workflow.UPDATE == "update"
        assert Workflow.RESOLVE == "resolve"


class TestUpdateStatus:
    def test_vuln_finding_default_status_is_none(self):
        v = VulnFinding(
            vuln_id="CVE-2024-0001",
            pkg_name="some-pkg",
            installed_version="1.0.0",
            fixed_version="1.0.1",
            severity=Severity.HIGH,
            title="Test vuln",
            description="desc",
            status="fixed",
        )
        assert v.update_status is None

    def test_update_finding_default_status_is_none(self):
        u = UpdateFinding(
            pkg_name="pkg-a",
            installed_version="1.0.0",
            latest_version="1.0.1",
            semver_tier=SemverTier.PATCH,
        )
        assert u.update_status is None

    def test_vuln_finding_accepts_all_statuses(self):
        for status in UpdateStatus:
            v = VulnFinding(
                vuln_id="CVE-2024-0001",
                pkg_name="some-pkg",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                severity=Severity.HIGH,
                title="Test vuln",
                description="desc",
                status="fixed",
                update_status=status,
            )
            assert v.update_status == status

    def test_update_finding_serialises_null_status(self):
        u = UpdateFinding(
            pkg_name="pkg-a",
            installed_version="1.0.0",
            latest_version="1.0.1",
            semver_tier=SemverTier.PATCH,
        )
        data = u.model_dump()
        assert "update_status" in data
        assert data["update_status"] is None
