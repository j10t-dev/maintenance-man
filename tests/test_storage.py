import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from maintenance_man import paths, storage
from maintenance_man.models.scan import (
    ScanResult,
    SemverTier,
    UpdateFinding,
    UpdateStatus,
)
from maintenance_man.storage import (
    NoScanResultsError,
    atomic_write_text,
    load_scan_results,
    record_activity,
    save_scan_results,
)
from tests.conftest import make_scan_result, make_update, make_vuln


@pytest.fixture()
def scan_result() -> ScanResult:
    return ScanResult(
        project="myapp",
        scanned_at=datetime.now(tz=UTC),
        trivy_target="/tmp/myapp",
        vulnerabilities=[make_vuln()],
        updates=[make_update(semver_tier=SemverTier.MAJOR)],
    )


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
        raise OSError("disk full")

    monkeypatch.setattr(storage.os, "replace", fail)
    with pytest.raises(OSError, match="disk full"):
        atomic_write_text(target, "new")
    assert target.read_text() == "old"
    assert _temporaries(tmp_path) == []


@pytest.mark.parametrize("durable, expected", [(False, []), (True, [False, True])])
def test_fsync_only_when_durable(tmp_path, monkeypatch, durable, expected):
    synced: list[bool] = []
    real_fsync = os.fsync

    def record(fd):
        synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        real_fsync(fd)

    monkeypatch.setattr(storage.os, "fsync", record)
    atomic_write_text(tmp_path / "ledger.json", "{}", durable=durable)
    assert synced == expected


@pytest.mark.parametrize("kwargs, expected", [({}, 0o644), ({"mode": 0o600}, 0o600)])
def test_new_file_mode_follows_umask(tmp_path, kwargs, expected):
    previous = os.umask(0o022)
    try:
        atomic_write_text(tmp_path / "state.json", "x", **kwargs)
    finally:
        os.umask(previous)
    assert stat.S_IMODE((tmp_path / "state.json").stat().st_mode) == expected


def test_save_creates_directory_and_round_trips():
    result = make_scan_result()
    save_scan_results("vulnerable", result)
    assert load_scan_results("vulnerable") == result


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


# -- save_scan_results --


class TestSaveScanResults:
    def test_writes_json_to_disk(self, scan_results_dir: Path, scan_result: ScanResult):
        save_scan_results("myapp", scan_result)

        data = json.loads((scan_results_dir / "myapp.json").read_text(encoding="utf-8"))
        assert data["project"] == "myapp"

    def test_preserves_update_status(self, scan_results_dir: Path):
        result = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=UTC),
            trivy_target="/tmp/myapp",
            updates=[
                UpdateFinding(
                    pkg_name="pkg-a",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    semver_tier=SemverTier.PATCH,
                    update_status=UpdateStatus.COMPLETED,
                ),
            ],
        )
        save_scan_results("myapp", result)

        data = json.loads((scan_results_dir / "myapp.json").read_text(encoding="utf-8"))
        assert data["updates"][0]["update_status"] == "completed"


# -- load_scan_results --


class TestLoadScanResults:
    def test_load_existing(self, scan_results_dir: Path):
        result = ScanResult(
            project="myapp",
            scanned_at=datetime.now(tz=UTC),
            trivy_target="/tmp/myapp",
        )
        (scan_results_dir / "myapp.json").write_text(
            result.model_dump_json(indent=2), encoding="utf-8"
        )
        loaded = load_scan_results("myapp")
        assert loaded.project == "myapp"

    def test_load_missing(self, scan_results_dir: Path):
        with pytest.raises(NoScanResultsError, match="nonexistent"):
            load_scan_results("nonexistent")
