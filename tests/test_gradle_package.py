import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest


@pytest.mark.integration
@pytest.mark.parametrize("repositories", ["implicit", "explicit", "custom"])
def test_real_gradle_reports_effective_plugin_repositories(tmp_path, repositories):
    executable = os.environ.get("MM_GRADLE_EXECUTABLE") or shutil.which("gradle")
    if not executable:
        pytest.skip("Set MM_GRADLE_EXECUTABLE to an installed Gradle executable")
    declaration = {
        "implicit": "",
        "explicit": "pluginManagement { repositories { gradlePluginPortal() } }",
        "custom": (
            "pluginManagement { repositories { maven { "
            "url = uri('https://example.invalid/maven') } } }"
        ),
    }[repositories]
    (tmp_path / "settings.gradle").write_text(declaration)
    # Only repository reporting is exercised; no plugins or artifacts are fetched.
    (tmp_path / "build.gradle").write_text("tasks.register('cyclonedxBom')\n")
    (tmp_path / "gradle").mkdir()
    (tmp_path / "gradle/libs.versions.toml").write_text("[versions]\n")
    owned = tmp_path / ".mm-gradle-inventory"
    owned.mkdir()
    (owned / ".mm-owned").write_text("")
    script = (
        Path(__file__).resolve().parents[1]
        / "src/maintenance_man/resources/gradle-report.gradle"
    )
    subprocess.run(
        [
            executable,
            "mmGradleReport",
            "--init-script",
            str(script),
            "--offline",
            "--no-daemon",
            "--console=plain",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    report = json.loads((owned / "report.json").read_text())
    assert [row for row in report["repositories"] if row["domain"] == "plugin"] == [
        {
            "project_path": ":",
            "domain": "plugin",
            "url": (
                "https://example.invalid/maven"
                if repositories == "custom"
                else "https://plugins.gradle.org/m2"
            ),
        },
    ]


@pytest.mark.integration
def test_wheel_installs_gradle_report_resource(tmp_path):
    root = Path(__file__).resolve().parents[1]
    wheel_dir = tmp_path / "dist"
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheel_dir)],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    environment = tmp_path / "venv"
    subprocess.run(
        ["uv", "venv", str(environment)], check=True, capture_output=True, text=True
    )
    interpreter = environment / "bin/python"
    subprocess.run(
        ["uv", "pip", "install", "--python", str(interpreter), str(wheels[0])],
        check=True,
        capture_output=True,
        text=True,
    )
    probe = (
        "from importlib.resources import files; "
        "s=files('maintenance_man.resources')"
        ".joinpath('gradle-report.gradle').read_text(); "
        "assert 'mmGradleReport' in s; assert 'mmGradleValidateCandidates' in s; "
        "print('installed resource available')"
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [str(interpreter), "-I", "-c", probe],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == "installed resource available"


@pytest.mark.integration
def test_real_gradle_producer_and_native_intervals(tmp_path):
    wrapper = os.environ.get("MM_GRADLE_WRAPPER")
    if not wrapper:
        pytest.skip("Set MM_GRADLE_WRAPPER to an existing executable wrapper")
    source = Path(wrapper).resolve().parent
    root = tmp_path / "project"
    root.mkdir()
    shutil.copyfile(source / "gradlew", root / "gradlew")
    (root / "gradlew").chmod(0o755)
    shutil.copytree(source / "gradle/wrapper", root / "gradle/wrapper")
    repository = tmp_path / "repository"
    for version in ("1.0", "2.0"):
        directory = repository / "g/a" / version
        directory.mkdir(parents=True)
        (directory / f"a-{version}.pom").write_text(
            f"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>{version}</version></project>"
        )
        with zipfile.ZipFile(directory / f"a-{version}.jar", "w"):
            pass
    (repository / "g/a/maven-metadata.xml").write_text(
        "<metadata><groupId>g</groupId><artifactId>a</artifactId><versioning><versions><version>1.0</version><version>2.0</version></versions></versioning></metadata>"
    )
    plugin_id = "mm.fixture.plugin"
    artifact = plugin_id + ".gradle.plugin"
    marker_root = repository / plugin_id.replace(".", "/") / artifact
    for version in ("1.0", "2.0"):
        directory = marker_root / version
        directory.mkdir(parents=True)
        (directory / f"{artifact}-{version}.pom").write_text(
            f"<project><modelVersion>4.0.0</modelVersion><groupId>{plugin_id}</groupId><artifactId>{artifact}</artifactId><version>{version}</version><packaging>pom</packaging><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>"
        )
    (marker_root / "maven-metadata.xml").write_text(
        f"<metadata><groupId>{plugin_id}</groupId><artifactId>{artifact}</artifactId><versioning><versions><version>1.0</version><version>2.0</version></versions></versioning></metadata>"
    )
    uri = repository.as_uri()
    (root / "settings.gradle").write_text(
        f"pluginManagement {{ repositories {{ maven {{ url = uri('{uri}') }}; "
        "gradlePluginPortal() } }\nrootProject.name = 'mm-producer-fixture'\n"
        "include ':app'\n"
    )
    (root / "build.gradle").write_text(
        "plugins { id 'java'; id 'org.cyclonedx.bom' version '3.4.1' }\n"
        "allprojects { group = 'fixture'; apply plugin: 'org.cyclonedx.bom' }\n"
        + f"allprojects {{ repositories {{ maven {{ url = uri('{uri}') }} }} }}\n"
        + f"repositories {{ maven {{ url = uri('{uri}') }} }}\n"
        + "dependencies { implementation 'g:a:1.0' }\n"
        + "dependencies { implementation project(':app') }\n"
        + "tasks.named('cyclonedxBom') { "
        "jsonOutput = layout.projectDirectory.file('.mm-gradle-inventory/bom.json'); "
        "xmlOutput.unsetConvention() }\n"
    )
    (root / "gradle.properties").write_text("org.gradle.parallel=true\n")
    (root / "app").mkdir()
    (root / "app/build.gradle").write_text("plugins { id 'java-library' }\n")
    (root / "gradle/libs.versions.toml").write_text(
        '[versions]\nartifact = "1.0"\n[libraries]\n'
        'artifact = { module = "g:a", version.ref = "artifact" }\n'
    )
    owned = root / ".mm-gradle-inventory"
    owned.mkdir()
    (owned / ".mm-owned").write_text("")
    from importlib.resources import files

    script = owned / "gradle-report.gradle"
    script.write_bytes(
        files("maintenance_man.resources").joinpath("gradle-report.gradle").read_bytes()
    )
    command = [
        str(root / "gradlew"),
        "mmGradleReport",
        "--init-script",
        str(script),
        "--no-daemon",
        "--console=plain",
        "--rerun-tasks",
        "--no-build-cache",
    ]
    subprocess.run(
        command, cwd=root, check=True, capture_output=True, text=True, timeout=900
    )
    report = json.loads((owned / "report.json").read_text())
    assert report["schema_version"] == 1
    assert report["selection_errors"] == []
    assert {
        "project_path": ":app",
        "module": {"group": "fixture", "artifact": "app", "version": "unspecified"},
    } in report["local_projects"]
    from maintenance_man.gradle_resolution import parse_resolution_report
    from maintenance_man.scanner import _inventory_modules

    inventory = (owned / "bom.json").read_bytes()
    assert "project_path=%3Aapp" in inventory.decode()
    modules = _inventory_modules(
        inventory, parse_resolution_report(json.dumps(report)).report
    )
    assert [(m.coordinate, m.version) for m in modules] == [("g:a", "1.0")]
    assert any(
        component["module"] == {"group": "g", "artifact": "a", "version": "1.0"}
        for scope in report["scopes"]
        for component in scope["components"]
    )
    requests = [
        {
            "request_id": str(index),
            "group_key": "ref:a",
            "alias": "a",
            "project_path": ":",
            "kind": "library",
            "coordinate": "g:a",
            "installed_version": old,
            "candidate_version": candidate,
        }
        for index, (old, candidate) in enumerate(
            (("1.0", "2.0"), ("2.0", "1.0"), ("1.0", "1.0"))
        )
    ]
    requests.append(
        {
            "request_id": "3",
            "group_key": "plugin:fixture",
            "alias": "fixture",
            "project_path": ":",
            "kind": "plugin",
            "coordinate": plugin_id,
            "installed_version": "1.0",
            "candidate_version": "2.0",
        }
    )
    requests.append(
        {
            "request_id": "4",
            "group_key": "ref:a",
            "alias": "a",
            "project_path": ":",
            "kind": "library",
            "coordinate": "g:a",
            "installed_version": "1.0",
            "candidate_version": "2.5",
        }
    )
    requests.append(
        {
            "request_id": "5",
            "group_key": "ref:a",
            "alias": "a",
            "project_path": ":app",
            "kind": "library",
            "coordinate": "g:a",
            "installed_version": "1.0",
            "candidate_version": "2.0",
        }
    )
    requests.extend(
        [
            {**requests[5], "request_id": "6", "project_path": ":missing"},
            {**requests[3], "request_id": "7", "project_path": ":app"},
        ]
    )
    (owned / "candidate-requests.json").write_text(
        json.dumps({"schema_version": 1, "requests": requests})
    )
    command[1] = "mmGradleValidateCandidates"
    subprocess.run(
        command, cwd=root, check=True, capture_output=True, text=True, timeout=900
    )
    from maintenance_man.models.gradle import CandidateValidationBatch

    batch = CandidateValidationBatch.model_validate_json(
        (owned / "candidate-validation.json").read_text()
    )
    assert [row.kind for row in batch.results] == [
        "library",
        "library",
        "library",
        "plugin",
        "library",
        "library",
        "library",
        "plugin",
    ]
    results = {
        row["request_id"]: row
        for row in json.loads((owned / "candidate-validation.json").read_text())[
            "results"
        ]
    }
    assert results["0"]["selected_version"] == "2.0" and results["0"]["reason"] is None
    assert results["1"]["reason"] is not None
    assert results["2"]["reason"] is not None
    assert results["3"]["selected_version"] == "2.0" and results["3"][
        "implementation"
    ] == {"group": "g", "artifact": "a", "version": "1.0"}
    assert results["4"]["selected_version"] is None
    assert results["4"]["reason"] is not None
    assert results["5"]["selected_version"] == "2.0"
    assert results["5"]["reason"] is None
    assert len(results) == len(requests)
    assert results["6"]["selected_version"] is None
    assert results["6"]["reason"] is not None
    assert results["7"]["selected_version"] is None
    assert results["7"]["reason"] is not None
