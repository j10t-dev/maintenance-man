import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from maintenance_man.gradle import GradleError, parse_catalogue
from maintenance_man.gradle_resolution import (
    collect_gradle_resolution,
    generate_gradle_report,
    parse_resolution_report,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import CompleteResolution, IncompleteResolution

FIXTURE = Path(__file__).parent / "fixtures/gradle/resolution/empty.json"


def report_payload():
    return json.loads(FIXTURE.read_text())


@pytest.mark.parametrize(
    "change,expected",
    [
        ("empty", CompleteResolution),
        ("unresolved", IncompleteResolution),
        ("missing", IncompleteResolution),
        ("selection", IncompleteResolution),
    ],
)
def test_selected_scope_completeness(change, expected):
    value = report_payload()
    if change == "unresolved":
        value["scopes"][0]["unresolved"] = ["g:a:1.0 could not resolve"]
    elif change == "missing":
        value["scopes"] = []
    elif change == "selection":
        value["selection_errors"] = ["root direct task missing"]
    result = parse_resolution_report(json.dumps(value))
    assert isinstance(result, expected)
    assert len(result.report.selected_scopes) == 1


@pytest.mark.parametrize(
    "change", ["schema", "reference", "duplicate", "url", "version"]
)
def test_malformed_report_is_boundary_error(change):
    value = report_payload()
    if change == "schema":
        value["schema_version"] = 2
    elif change == "reference":
        value["scopes"][0]["edges"] = [
            {
                "source": "root",
                "target": "missing",
                "requested": "g:a:1",
                "constraint": False,
            }
        ]
    elif change == "duplicate":
        value["selected_scopes"] *= 2
    elif change == "url":
        value["repositories"][0]["url"] = "https://user:secret@example.org/maven"
    else:
        value["producer_versions"] = {}
    with pytest.raises(GradleError):
        parse_resolution_report(json.dumps(value))


def make_project(tmp_path):
    (tmp_path / "gradle").mkdir()
    (tmp_path / "gradle/libs.versions.toml").write_text('[versions]\nx = "1.0"\n')
    return ProjectConfig(path=tmp_path, package_manager="gradle")


def fixture_runner(root, args, *, label):
    assert args[0] == "mmGradleReport"
    assert "--rerun-tasks" in args and "--no-build-cache" in args
    owned = root / ".mm-gradle-inventory"
    assert (owned / ".mm-owned").is_file()
    assert (owned / "gradle-report.gradle").read_text().startswith("import ")
    (owned / "bom.json").write_text(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"group":"g","name":"a","version":"1.0","purl":"pkg:maven/g/a@1.0"}]}'
    )
    value = report_payload()
    value["scopes"][0]["components"].append(
        {
            "id": "a",
            "kind": "module",
            "module": {"group": "g", "artifact": "a", "version": "1.0"},
            "variants": ["runtime"],
        }
    )
    value["scopes"][0]["edges"].append(
        {"source": "root", "target": "a", "requested": "g:a:1.0", "constraint": False}
    )
    value["catalogue_digest"] = hashlib.sha256(
        (root / "gradle/libs.versions.toml").read_bytes()
    ).hexdigest()
    (owned / "report.json").write_text(json.dumps(value))
    return subprocess.CompletedProcess(args, 0, "", "")


def test_capture_reads_before_cleanup_and_returns_durable_models(tmp_path):
    project = make_project(tmp_path)
    with patch(
        "maintenance_man.gradle_resolution.run_gradle", side_effect=fixture_runner
    ):
        with generate_gradle_report(project) as (bom, resolution):
            assert bom.is_file()
            assert isinstance(resolution, CompleteResolution)
        assert not (tmp_path / ".mm-gradle-inventory").exists()
        result = collect_gradle_resolution(
            project, parse_catalogue(tmp_path / "gradle/libs.versions.toml")
        )
    assert isinstance(result, CompleteResolution)
    assert result.report.scopes[0].components[0].kind == "root"


def test_unmarked_output_is_never_reclaimed(tmp_path):
    project = make_project(tmp_path)
    owned = tmp_path / ".mm-gradle-inventory"
    owned.mkdir()
    (owned / "caller.txt").write_text("keep")
    with patch("maintenance_man.gradle_resolution.run_gradle") as runner:
        with pytest.raises(GradleError):
            with generate_gradle_report(project):
                pass
    runner.assert_not_called()
    assert (owned / "caller.txt").read_text() == "keep"
