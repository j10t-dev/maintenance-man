import os
import stat
from pathlib import Path

import pytest

from maintenance_man import paths, storage
from maintenance_man.models.scan import (
    UpdateStatus,
    Workflow,
)
from maintenance_man.storage import (
    NoScanResultsError,
    atomic_write_text,
    load_activity,
    load_scan_results,
    record_activity,
    save_scan_results,
)
from tests.support.findings import make_scan_result, make_update


def _temporaries(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.endswith(".tmp"))


def test_atomic_write_replaces_content(tmp_path):
    target = tmp_path / "state.json"
    target.write_text("old")
    atomic_write_text(target, "new")
    assert target.read_text() == "new"
    assert _temporaries(tmp_path) == []


def test_failed_replace_keeps_old_content(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    target.write_text("old")

    def fail(src, dst):
        msg = "disk full"
        raise OSError(msg)

    monkeypatch.setattr(storage.os, "replace", fail)
    with pytest.raises(OSError, match="disk full"):
        atomic_write_text(target, "new")
    assert target.read_text() == "old"
    assert _temporaries(tmp_path) == []


def test_save_creates_directory_and_round_trips():
    result = make_scan_result(
        updates=[make_update(update_status=UpdateStatus.READY, flow=Workflow.UPDATE)]
    )
    save_scan_results("vulnerable", result)
    assert load_scan_results("vulnerable") == result


def test_given_ready_update_row_when_saved_then_json_text_names_status_and_flow():
    result = make_scan_result(
        updates=[make_update(update_status=UpdateStatus.READY, flow=Workflow.UPDATE)]
    )

    save_scan_results("vulnerable", result)

    text = (paths.scan_results_dir() / "vulnerable.json").read_text(encoding="utf-8")
    assert '"update_status": "ready"' in text
    assert '"flow": "update"' in text


def test_given_umask_when_new_file_written_then_mode_follows_it(tmp_path):
    previous = os.umask(0o022)
    try:
        atomic_write_text(tmp_path / "state.json", "x")
    finally:
        os.umask(previous)

    assert stat.S_IMODE((tmp_path / "state.json").stat().st_mode) == 0o644


def test_scan_results_reject_empty_name():
    with pytest.raises(ValueError):
        save_scan_results("", make_scan_result())
    with pytest.raises(ValueError):
        load_scan_results("")


def test_save_replaces_symlink_and_leaves_target(tmp_path):
    scan_dir = paths.scan_results_dir()
    scan_dir.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text("keep")
    (scan_dir / "vulnerable.json").symlink_to(outside)
    save_scan_results("vulnerable", make_scan_result())
    assert not (scan_dir / "vulnerable.json").is_symlink()
    assert outside.read_text() == "keep"


def test_record_activity_replaces_symlink_and_leaves_target(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    path = tmp_path / "activity.json"
    path.symlink_to(outside)
    record_activity(path, "demo", "build", success=True, branch="main")
    assert not path.is_symlink()
    assert outside.read_text() == "{}"


def test_given_bug_when_recording_then_record_activity_propagates_programming_errors(
    tmp_path, monkeypatch
):
    def fail_load(_path: Path):
        msg = "bug"
        raise TypeError(msg)

    monkeypatch.setattr(storage, "load_activity", fail_load)

    with pytest.raises(TypeError, match="bug"):
        record_activity(
            tmp_path / "activity.json",
            "demo",
            "build",
            success=True,
            branch="main",
        )


def test_given_bad_json_when_loading_then_load_activity_returns_empty_on_invalid_json(
    tmp_path,
):
    path = tmp_path / "activity.json"
    path.write_text("{", encoding="utf-8")

    assert load_activity(path) == {}


def test_given_invalid_shape_when_activity_is_loaded_then_type_error_propagates(
    tmp_path,
):
    path = tmp_path / "activity.json"
    path.write_text('{"x": 1}', encoding="utf-8")

    with pytest.raises(TypeError):
        load_activity(path)


def test_given_invalid_fields_when_activity_is_loaded_then_empty_data_is_returned(
    tmp_path,
):
    path = tmp_path / "activity.json"
    path.write_text('{"x": {"last_build": {"timestamp": "invalid"}}}', encoding="utf-8")

    assert load_activity(path) == {}


# -- load_scan_results --


class TestLoadScanResults:
    def test_load_missing(self, scan_results_dir: Path):
        with pytest.raises(NoScanResultsError, match="nonexistent"):
            load_scan_results("nonexistent")
