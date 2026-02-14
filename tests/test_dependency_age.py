import subprocess
from datetime import datetime, timezone
from unittest.mock import patch

from maintenance_man.dependency_age import filter_by_age
from maintenance_man.models.scan import UpdateFinding, SemverTier

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
