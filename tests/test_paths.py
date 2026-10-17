from pathlib import Path

import pytest

from maintenance_man import paths, vcs
from maintenance_man.gradle import GradleError
from maintenance_man.gradle_updates import gradle_run_path


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "elsewhere"
    monkeypatch.setattr(paths, "MM_HOME", home)
    return home


def test_tests_run_under_an_isolated_home(tmp_path):
    assert paths.mm_home() == tmp_path / ".mm"
    assert paths.mm_home() != Path.home() / ".mm"


@pytest.mark.parametrize(
    "accessor, relative",
    [
        ("mm_home", ""),
        ("config_path", "config.toml"),
        ("scan_results_dir", "scan-results"),
        ("activity_path", "activity.json"),
        ("workspaces_dir", "workspaces"),
        ("gradle_runs_dir", "gradle-runs"),
        ("gradle_contexts_dir", "gradle-contexts"),
        ("publications_dir", "publications"),
    ],
)
def test_accessors_follow_redirected_home(home, accessor, relative):
    assert getattr(paths, accessor)() == home / relative


def test_workspace_path_follows_redirected_home(home):
    assert vcs.workspace_path_for_project("api/service") == (
        home / "workspaces" / "api_service"
    )


@pytest.mark.parametrize(
    "project, suffix, name",
    [
        ("api/service", "", "api_service"),
        ("a\\b", ".json", "a_b.json"),
        ("../x", ".json", "__x.json"),
        (".", ".json", "..json"),
    ],
)
def test_project_file_sanitises(tmp_path, project, suffix, name):
    assert paths.project_file(tmp_path, project, suffix) == tmp_path / name


@pytest.mark.parametrize("project, suffix", [("", ""), ("", ".json"), (".", "")])
def test_project_file_rejects(tmp_path, project, suffix):
    with pytest.raises(ValueError):
        paths.project_file(tmp_path, project, suffix)


@pytest.mark.parametrize("project", ["", "."])
def test_workspace_path_rejects_degenerate_names(home, project):
    with pytest.raises(ValueError):
        vcs.workspace_path_for_project(project)


def test_gradle_run_path(home):
    assert gradle_run_path("demo") == home / "gradle-runs" / "demo.json"
    with pytest.raises(GradleError, match="Invalid Gradle run path"):
        gradle_run_path("")
