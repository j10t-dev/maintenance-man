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
        assert event == ActivityEvent(
            timestamp=datetime(2026, 3, 20, 14, 32, tzinfo=UTC),
            success=True,
            branch="main",
        )


class TestLoadActivity:
    def test_returns_empty_dict_when_file_missing(self, tmp_path: Path):
        result = load_activity(tmp_path / "activity.json")
        assert result == {}


class TestRecordActivity:
    @pytest.mark.parametrize(
        ("event_type", "commit_id", "expected"),
        [
            ("build", None, {"myapp": ProjectActivity(last_build=_RECORDED)}),
            ("deploy", None, {"myapp": ProjectActivity(last_deploy=_RECORDED)}),
            (
                "deploy",
                "abc123",
                {
                    "myapp": ProjectActivity(
                        last_deploy=_RECORDED.model_copy(update={"commit_id": "abc123"})
                    )
                },
            ),
        ],
        ids=["build", "deploy", "deploy-with-commit-id"],
    )
    def test_given_event_type_when_recorded_then_only_that_event_is_set(
        self, tmp_path: Path, event_type, commit_id, expected
    ):
        path = tmp_path / "activity.json"

        record_activity(
            path,
            "myapp",
            event_type,
            success=False,
            branch="feat/x",
            commit_id=commit_id,
        )

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
