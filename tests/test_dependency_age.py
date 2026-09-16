import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from maintenance_man.dependency_age import (
    check_gradle_update_age,
    evaluate_gradle_group_age,
    filter_by_age,
    gradle_lookup_coordinate,
)
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    SemverTier,
    UpdateFinding,
)
from tests.conftest import make_gradle_member, make_gradle_target

_PATCH_FETCH = "maintenance_man.dependency_age._fetch_json"
_PATCH_SUBRUN = "maintenance_man.dependency_age.subprocess.run"
_PATCH_NOW = "maintenance_man.dependency_age._utcnow"
_PATCH_CACHE_DIR = "maintenance_man.dependency_age._pypi_cache_dir"


def _bun_info_result(published_iso: str) -> subprocess.CompletedProcess[str]:
    """Build a fake ``bun info`` CompletedProcess with a Published line."""
    return subprocess.CompletedProcess(
        args=["bun", "info", "pkg@version"],
        returncode=0,
        stdout=f"pkg@version | MIT\nPublished: {published_iso}\n",
        stderr="",
    )


_FROZEN_NOW = datetime(2026, 1, 30, tzinfo=timezone.utc)


def _make_update(pkg: str, latest: str = "2.0.0") -> UpdateFinding:
    return UpdateFinding(
        pkg_name=pkg,
        installed_version="1.0.0",
        latest_version=latest,
        semver_tier=SemverTier.MINOR,
    )


class TestFilterByAge:
    def test_returns_all_when_min_age_is_zero(self):
        """Age gating disabled -- all updates pass through, no HTTP calls."""
        updates = [_make_update("lodash"), _make_update("express")]
        result = filter_by_age(updates, manager="bun", min_age_days=0)
        assert len(result) == 2
        assert all(u.published_date is None for u in result)

    def test_empty_updates_returns_empty(self):
        result = filter_by_age([], manager="bun", min_age_days=7)
        assert result == []

    def test_filters_young_npm_package(self):
        """Package published 2 days ago, min_age=7 -- filtered out."""
        updates = [_make_update("lodash", "4.17.21")]
        two_days_ago = "2026-01-28T00:00:00.000Z"

        with (
            patch(_PATCH_SUBRUN, return_value=_bun_info_result(two_days_ago)),
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            result = filter_by_age(updates, manager="bun", min_age_days=7)

        assert len(result) == 0

    def test_keeps_old_npm_package(self):
        """Package published 30 days ago, min_age=7 -- passes."""
        updates = [_make_update("lodash", "4.17.21")]
        thirty_days_ago = "2025-12-31T00:00:00.000Z"

        with (
            patch(_PATCH_SUBRUN, return_value=_bun_info_result(thirty_days_ago)),
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            result = filter_by_age(updates, manager="bun", min_age_days=7)

        assert len(result) == 1
        assert result[0].published_date is not None

    def test_keeps_update_on_registry_error(self):
        """If registry lookup fails, keep the update (fail open)."""
        updates = [_make_update("unknown-pkg")]

        with patch(_PATCH_SUBRUN, side_effect=Exception("network error")):
            result = filter_by_age(updates, manager="bun", min_age_days=7)

        assert len(result) == 1
        assert result[0].published_date is None

    def test_pypi_lookup(self, tmp_path):
        """Test PyPI registry lookup for uv packages (cache miss path)."""
        updates = [_make_update("requests", "2.31.0")]
        thirty_days_ago = "2025-12-31T00:00:00"

        pypi_data = {
            "urls": [{"upload_time_iso_8601": thirty_days_ago}],
        }

        with (
            patch(_PATCH_CACHE_DIR, return_value=tmp_path),
            patch(_PATCH_FETCH, return_value=pypi_data),
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            result = filter_by_age(updates, manager="uv", min_age_days=7)

        assert len(result) == 1
        assert result[0].published_date is not None

    def test_pypi_cache_hit(self, tmp_path):
        """Second lookup should hit the dbm cache — no additional HTTP call."""
        updates = [_make_update("requests", "2.31.0")]
        thirty_days_ago = "2025-12-31T00:00:00"

        pypi_data = {
            "urls": [{"upload_time_iso_8601": thirty_days_ago}],
        }

        with (
            patch(_PATCH_CACHE_DIR, return_value=tmp_path),
            patch(_PATCH_FETCH, return_value=pypi_data) as mock_fetch,
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            filter_by_age(updates, manager="uv", min_age_days=7)
            assert mock_fetch.call_count == 1

            result = filter_by_age(updates, manager="uv", min_age_days=7)
            assert mock_fetch.call_count == 1  # no additional call

        assert len(result) == 1
        assert result[0].published_date is not None

    def test_maven_central_lookup(self):
        """Test Maven Central registry lookup for mvn packages."""
        updates = [_make_update("org.slf4j:slf4j-api", "2.0.16")]
        thirty_days_ago_ms = int(
            datetime(2025, 12, 31, tzinfo=timezone.utc).timestamp() * 1000
        )

        maven_data = {"response": {"docs": [{"timestamp": thirty_days_ago_ms}]}}

        with (
            patch(_PATCH_FETCH, return_value=maven_data),
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            result = filter_by_age(updates, manager="mvn", min_age_days=7)

        assert len(result) == 1
        assert result[0].published_date is not None


_OLD = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _dates(mapping, monkeypatch):
    """Substitute Maven Central lookup with a coordinate -> date|None|raise map."""

    def _lookup(pkg: str, version: str):
        outcome = mapping[pkg]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(
        "maintenance_man.dependency_age._get_maven_publish_date", _lookup
    )


@pytest.mark.parametrize(
    "kind, coordinate, expected",
    [
        ("library", "androidx.room:room-runtime", "androidx.room:room-runtime"),
        (
            "plugin",
            "com.google.devtools.ksp",
            "com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin",
        ),
    ],
)
def test_lookup_coordinate_uses_plugin_markers(kind, coordinate, expected):
    member = make_gradle_member(kind=kind, coordinate=coordinate)

    assert gradle_lookup_coordinate(member) == expected


class TestGradleGroupAge:
    def test_all_members_old_enough_is_eligible(self, monkeypatch):
        target = make_gradle_target()
        _dates(
            {
                "androidx.room:room-runtime": _OLD,
                "androidx.room:room-compiler": _OLD,
                "androidx.room:room-testing": _OLD + timedelta(days=1),
            },
            monkeypatch,
        )

        block, published = evaluate_gradle_group_age(target, 7)

        assert block is None
        assert published == _OLD + timedelta(days=1)

    @pytest.mark.parametrize(
        "third_outcome, reason_fragment",
        [
            (None, "no Maven Central publication date"),
            (RuntimeError("network down"), "publication lookup failed"),
        ],
    )
    def test_one_member_without_evidence_blocks_the_group(
        self, monkeypatch, third_outcome, reason_fragment
    ):
        target = make_gradle_target()
        _dates(
            {
                "androidx.room:room-runtime": _OLD,
                "androidx.room:room-compiler": _OLD,
                "androidx.room:room-testing": third_outcome,
            },
            monkeypatch,
        )

        block = check_gradle_update_age(target, 7)

        assert block is not None
        assert block.kind == "age"
        assert reason_fragment in block.reason
        assert "androidx.room:room-testing" in block.reason

    def test_too_recent_member_blocks_the_group(self, monkeypatch):
        now = datetime.now(timezone.utc)
        target = make_gradle_target()
        _dates(
            {
                "androidx.room:room-runtime": _OLD,
                "androidx.room:room-compiler": _OLD,
                "androidx.room:room-testing": now - timedelta(days=2),
            },
            monkeypatch,
        )

        block = check_gradle_update_age(target, 7)

        assert block is not None
        assert block.kind == "age"
        assert "2 day(s) ago" in block.reason
        assert "minimum is 7" in block.reason

    def test_member_published_exactly_at_cutoff_blocks_the_group(self, monkeypatch):
        """A publication exactly ``minimum_age_days`` old is not yet old enough.

        Matches ``filter_by_age``'s existing ``>=`` semantics: pinned so a
        future refactor to ``>`` fails the suite instead of passing silently.
        """
        fixed_now = datetime(2024, 2, 1, tzinfo=timezone.utc)
        monkeypatch.setattr("maintenance_man.dependency_age._utcnow", lambda: fixed_now)
        target = make_gradle_target()
        exactly_at_cutoff = fixed_now - timedelta(days=7)
        _dates(
            {
                "androidx.room:room-runtime": _OLD,
                "androidx.room:room-compiler": _OLD,
                "androidx.room:room-testing": exactly_at_cutoff,
            },
            monkeypatch,
        )

        block = check_gradle_update_age(target, 7)

        assert block is not None
        assert block.kind == "age"
        assert "androidx.room:room-testing" in block.reason
        assert "7 day(s) ago" in block.reason
        assert "minimum is 7" in block.reason

    def test_zero_waiting_period_allows_recent_but_not_unknown(self, monkeypatch):
        now = datetime.now(timezone.utc)
        target = make_gradle_target(
            members=[make_gradle_member(alias="room-runtime")], version_ref=None
        )
        _dates({"androidx.room:room-runtime": now - timedelta(hours=1)}, monkeypatch)

        assert check_gradle_update_age(target, 0) is None

        _dates({"androidx.room:room-runtime": None}, monkeypatch)
        block = check_gradle_update_age(target, 0)

        assert block is not None and block.kind == "age"

    def test_plugin_member_is_looked_up_by_marker_coordinate(self, monkeypatch):
        seen: list[str] = []

        def _lookup(pkg: str, version: str):
            seen.append(pkg)
            return _OLD

        monkeypatch.setattr(
            "maintenance_man.dependency_age._get_maven_publish_date", _lookup
        )
        target = GradleUpdateTarget(
            version_ref="ksp",
            members=[
                GradleMember(
                    kind="plugin",
                    alias="ksp",
                    coordinate="com.google.devtools.ksp",
                    installed_version="2.3.10",
                )
            ],
            target_version="2.3.12",
        )

        assert check_gradle_update_age(target, 7) is None
        assert seen == ["com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin"]

    def test_empty_member_list_blocks_instead_of_raising(self):
        """A target with no members (e.g. malformed historical scan JSON) must
        block for a rescan, not raise out of ``max()`` on an empty sequence.
        """
        target = GradleUpdateTarget(
            version_ref="room", members=[], target_version="2.8.5"
        )

        block, published = evaluate_gradle_group_age(target, 7)

        assert block is not None
        assert block.kind == "age"
        assert "no members" in block.reason
        assert published is None
