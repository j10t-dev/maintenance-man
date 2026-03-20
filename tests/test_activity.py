import json
from datetime import datetime, timezone
from pathlib import Path

from maintenance_man.models.activity import (
    ActivityEvent,
    load_activity,
    record_activity,
)

_TS = datetime(2026, 3, 20, 14, 32, tzinfo=timezone.utc)


class TestActivityEvent:
    def test_timestamp_truncated_to_minutes(self):
        """Seconds and microseconds stripped from timestamp."""
        event = ActivityEvent(
            timestamp=datetime(2026, 3, 20, 14, 32, 45, 123456, tzinfo=timezone.utc),
            success=True,
            branch="main",
        )
        assert event.timestamp == datetime(2026, 3, 20, 14, 32, tzinfo=timezone.utc)
        assert event.timestamp.second == 0
        assert event.timestamp.microsecond == 0


class TestLoadActivity:
    def test_returns_empty_dict_when_file_missing(self, tmp_path: Path):
        result = load_activity(tmp_path / "activity.json")
        assert result == {}

    def test_returns_empty_dict_when_file_corrupt(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        path.write_text("NOT JSON")
        result = load_activity(path)
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
    def test_records_build_event(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "myapp", "build", success=True, branch="main")
        result = load_activity(path)
        assert result["myapp"].last_build is not None
        assert result["myapp"].last_build.success is True
        assert result["myapp"].last_build.branch == "main"
        assert result["myapp"].last_deploy is None

    def test_records_deploy_event(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "myapp", "deploy", success=False, branch="feat/x")
        result = load_activity(path)
        assert result["myapp"].last_deploy is not None
        assert result["myapp"].last_deploy.success is False
        assert result["myapp"].last_deploy.branch == "feat/x"

    def test_preserves_existing_data(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "myapp", "build", success=True, branch="main")
        record_activity(path, "myapp", "deploy", success=True, branch="main")
        result = load_activity(path)
        assert result["myapp"].last_build is not None
        assert result["myapp"].last_deploy is not None

    def test_preserves_other_projects(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "app-a", "build", success=True, branch="main")
        record_activity(path, "app-b", "deploy", success=True, branch="main")
        result = load_activity(path)
        assert "app-a" in result
        assert "app-b" in result

    def test_overwrites_previous_event(self, tmp_path: Path):
        path = tmp_path / "activity.json"
        record_activity(path, "myapp", "build", success=True, branch="main")
        record_activity(path, "myapp", "build", success=False, branch="feat/x")
        result = load_activity(path)
        assert result["myapp"].last_build.success is False
        assert result["myapp"].last_build.branch == "feat/x"

    def test_silently_handles_unwritable_path(self, tmp_path: Path):
        """record_activity must not raise even if the file can't be written."""
        path = tmp_path / "nonexistent-dir" / "activity.json"
        # Should not raise
        record_activity(path, "myapp", "build", success=True, branch="main")
