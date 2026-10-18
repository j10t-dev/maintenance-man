import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from maintenance_man.models.activity import ActivityEvent, ProjectActivity
from maintenance_man.storage import load_activity, record_activity

_NOW = datetime(2026, 3, 20, 12, 0, tzinfo=UTC)
_RECORDED = ActivityEvent(timestamp=_NOW, success=False, branch="feat/x")
_EARLIER = ActivityEvent(
    timestamp=datetime(2026, 3, 20, 9, 0, tzinfo=UTC), success=True, branch="main"
)
_EARLIER_JSON = {"timestamp": "2026-03-20T09:00:00Z", "success": True, "branch": "main"}


@pytest.fixture(autouse=True)
def _fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("maintenance_man.storage.utc_now", lambda: _NOW)


class TestActivityEvent:
    def test_timestamp_truncated_to_minutes(self):
        """Seconds and microseconds stripped from timestamp."""
        event = ActivityEvent(
            timestamp=datetime(2026, 3, 20, 14, 32, 45, 123456, tzinfo=UTC),
            success=True,
            branch="main",
        )
        assert event.timestamp == datetime(2026, 3, 20, 14, 32, tzinfo=UTC)
        assert event.timestamp.second == 0
        assert event.timestamp.microsecond == 0


class TestLoadActivity:
    def test_returns_empty_dict_when_file_missing(self, tmp_path: Path):
        result = load_activity(tmp_path / "activity.json")
        assert result == {}

    def test_loads_valid_activity(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        data = {
            "myapp": {
                "last_build": {
                    "timestamp": "2026-03-20T14:32:00Z",
                    "success": True,
                    "branch": "main",
                },
            },
        }
        path.write_text(json.dumps(data))
        result = load_activity(path)
        assert "myapp" in result
        assert result["myapp"].last_build is not None
        assert result["myapp"].last_build.success is True


class TestRecordActivity:
    @pytest.mark.parametrize(
        ("event_type", "expected"),
        [
            (
                "build",
                {"myapp": ProjectActivity(last_build=_RECORDED)},
            ),
            (
                "deploy",
                {"myapp": ProjectActivity(last_deploy=_RECORDED)},
            ),
        ],
    )
    def test_given_event_type_when_recorded_then_only_that_event_is_set(
        self, tmp_path: Path, event_type, expected
    ):
        path = tmp_path / "activity.json"

        record_activity(path, "myapp", event_type, success=False, branch="feat/x")

        assert load_activity(path) == expected

    @pytest.mark.parametrize(
        ("existing", "project", "event_type", "expected"),
        [
            pytest.param(
                {"myapp": {"last_build": _EARLIER_JSON}},
                "myapp",
                "deploy",
                {"myapp": ProjectActivity(last_build=_EARLIER, last_deploy=_RECORDED)},
                id="same-project-keeps-the-other-event",
            ),
            pytest.param(
                {"app-a": {"last_build": _EARLIER_JSON}},
                "app-b",
                "deploy",
                {
                    "app-a": ProjectActivity(last_build=_EARLIER),
                    "app-b": ProjectActivity(last_deploy=_RECORDED),
                },
                id="other-projects-are-kept",
            ),
            pytest.param(
                {"myapp": {"last_build": _EARLIER_JSON}},
                "myapp",
                "build",
                {"myapp": ProjectActivity(last_build=_RECORDED)},
                id="same-event-type-is-overwritten",
            ),
        ],
    )
    def test_given_saved_activity_when_recorded_then_one_event_is_merged(
        self, tmp_path: Path, existing, project, event_type, expected
    ):
        path = tmp_path / "activity.json"
        path.write_text(json.dumps(existing), encoding="utf-8")

        record_activity(path, project, event_type, success=False, branch="feat/x")

        assert load_activity(path) == expected

    def test_silently_handles_unwritable_path(self, tmp_path: Path):
        """record_activity must not raise even if the file can't be written."""
        path = tmp_path / "nonexistent-dir" / "activity.json"
        # Should not raise
        record_activity(path, "myapp", "build", success=True, branch="main")


class TestCommitId:
    def test_records_commit_id_on_deploy(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(
            path, "myapp", "deploy", success=True, branch="main", commit_id="abc123"
        )
        result = load_activity(path)
        assert result["myapp"].last_deploy is not None
        assert result["myapp"].last_deploy.commit_id == "abc123"

    def test_legacy_record_without_commit_id_loads_as_none(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        data = {
            "myapp": {
                "last_deploy": {
                    "timestamp": "2026-03-20T15:01:00Z",
                    "success": True,
                    "branch": "main",
                }
            }
        }
        path.write_text(json.dumps(data))
        result = load_activity(path)
        assert result["myapp"].last_deploy is not None
        assert result["myapp"].last_deploy.commit_id is None
