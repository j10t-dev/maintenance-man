import os
import subprocess
import sys
from pathlib import Path

import pytest

from maintenance_man import paths, vcs


@pytest.mark.parametrize("relative", [False, True])
def test_cli_init_uses_explicit_mm_home_without_changing_user_home(tmp_path, relative):
    home = tmp_path / "isolated-mm"
    configured = home.name if relative else str(home)
    script = """
import sys
from pathlib import Path
from maintenance_man import paths
assert paths.mm_home() == Path(sys.argv[1]), paths.mm_home()
assert Path.home() == Path(sys.argv[2])
from maintenance_man.cli import main
main(["init"])
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(home), str(Path.home())],
        cwd=tmp_path,
        env=os.environ | {"MM_HOME": configured},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (home / "config.toml").is_file()


@pytest.mark.parametrize("configured", [None, ""])
def test_new_process_defaults_to_user_mm_directory(configured):
    environment = os.environ.copy()
    environment.pop("MM_HOME", None)
    if configured is not None:
        environment["MM_HOME"] = configured
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from maintenance_man.paths import mm_home; print(mm_home())",
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.strip() == str(Path.home() / ".mm")


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
