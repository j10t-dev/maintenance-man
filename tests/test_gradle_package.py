import json
import os
import shutil
import subprocess
import zipfile
from importlib.resources import files
from pathlib import Path

import pytest

from maintenance_man.gradle_inventory import inventory_scopes, load_inventory
from maintenance_man.gradle_resolution import _REPORT_ARGS, parse_resolution_report
from maintenance_man.models.gradle import CandidateValidationBatch, ModuleId


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
    output = tmp_path / "output"
    output.mkdir()
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
            f"-Pmm.reportDirectory={output}",
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
    report = json.loads((output / "report.json").read_text())
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


_PLUGIN_ID = "mm.fixture.plugin"


def _write_local_maven_repository(repository: Path) -> None:
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
    artifact = _PLUGIN_ID + ".gradle.plugin"
    marker_root = repository / _PLUGIN_ID.replace(".", "/") / artifact
    for version in ("1.0", "2.0"):
        directory = marker_root / version
        directory.mkdir(parents=True)
        (directory / f"{artifact}-{version}.pom").write_text(
            f"<project><modelVersion>4.0.0</modelVersion><groupId>{_PLUGIN_ID}</groupId><artifactId>{artifact}</artifactId><version>{version}</version><packaging>pom</packaging><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>"
        )
    (marker_root / "maven-metadata.xml").write_text(
        f"<metadata><groupId>{_PLUGIN_ID}</groupId><artifactId>{artifact}</artifactId><versioning><versions><version>1.0</version><version>2.0</version></versions></versioning></metadata>"
    )


def _prepare_gradle_project(root: Path, source: Path, repository: Path) -> None:
    root.mkdir()
    shutil.copyfile(source / "gradlew", root / "gradlew")
    (root / "gradlew").chmod(0o755)
    shutil.copytree(source / "gradle/wrapper", root / "gradle/wrapper")
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
        "xmlOutput = layout.projectDirectory.file('.mm-gradle-inventory/bom.xml') }\n"
        + "allprojects { tasks.matching { it.name == 'cyclonedxDirectBom' }"
        ".configureEach { xmlOutput = "
        "layout.projectDirectory.file('.mm-gradle-inventory/direct.xml') } }\n"
    )
    (root / "gradle.properties").write_text(
        "org.gradle.parallel=true\norg.gradle.configuration-cache=true\n"
    )
    (root / "app").mkdir()
    (root / "app/build.gradle").write_text("plugins { id 'java-library' }\n")
    (root / "gradle/libs.versions.toml").write_text(
        '[versions]\nartifact = "1.0"\n[libraries]\n'
        'artifact = { module = "g:a", version.ref = "artifact" }\n'
    )


_VALIDATION_REQUESTS = [
    ("library", ":", "1.0", "2.0", "2.0", None),
    ("library", ":", "2.0", "1.0", None, "Native metadata validation failed"),
    ("library", ":", "1.0", "1.0", None, "Native metadata validation failed"),
    ("plugin", ":", "1.0", "2.0", "2.0", None),
    ("library", ":", "1.0", "2.5", None, "Native metadata validation failed"),
    ("library", ":app", "1.0", "2.0", "2.0", None),
    ("library", ":missing", "1.0", "2.0", None, "Native metadata validation failed"),
    ("plugin", ":app", "1.0", "2.0", None, "Native metadata validation failed"),
]


@pytest.mark.integration
def test_real_gradle_producer_and_native_intervals(tmp_path, mm_home):
    wrapper = os.environ.get("MM_GRADLE_WRAPPER")
    if not wrapper:
        pytest.skip("Set MM_GRADLE_WRAPPER to an existing executable wrapper")
    source = Path(wrapper).resolve().parent
    root = tmp_path / "project"
    repository = tmp_path / "repository"
    _write_local_maven_repository(repository)
    _prepare_gradle_project(root, source, repository)
    output = mm_home / "gradle-report-integration"
    output.mkdir(parents=True)
    script = Path(
        str(files("maintenance_man.resources").joinpath("gradle-report.gradle"))
    )
    command = [
        str(root / "gradlew"),
        "mmGradleReport",
        "--init-script",
        str(script),
        f"-Pmm.reportDirectory={output}",
        *_REPORT_ARGS,
    ]
    subprocess.run(
        command, cwd=root, check=True, capture_output=True, text=True, timeout=900
    )
    report = json.loads((output / "report.json").read_text())
    assert report["schema_version"] == 1
    assert report["selection_errors"] == []
    assert {
        "project_path": ":app",
        "module": {"group": "fixture", "artifact": "app", "version": "unspecified"},
    } in report["local_projects"]

    assert "project_path=%3Aapp" in (output / "bom.json").read_text()
    scopes = inventory_scopes(
        load_inventory(output / "bom.json"),
        parse_resolution_report((output / "report.json").read_text()),
    )
    assert [(module.coordinate, module.version) for module in scopes] == [
        ("g:a", "1.0")
    ]
    assert any(
        component["module"] == {"group": "g", "artifact": "a", "version": "1.0"}
        for scope in report["scopes"]
        for component in scope["components"]
    )

    requests = [
        {
            "request_id": str(index),
            "group_key": "plugin:fixture" if kind == "plugin" else "ref:a",
            "alias": "fixture" if kind == "plugin" else "a",
            "project_path": path,
            "kind": kind,
            "coordinate": _PLUGIN_ID if kind == "plugin" else "g:a",
            "installed_version": installed,
            "candidate_version": candidate,
        }
        for index, (kind, path, installed, candidate, _, _) in enumerate(
            _VALIDATION_REQUESTS
        )
    ]
    (output / "candidate-requests.json").write_text(
        json.dumps({"schema_version": 1, "requests": requests})
    )
    command[1] = "mmGradleValidateCandidates"
    subprocess.run(
        command, cwd=root, check=True, capture_output=True, text=True, timeout=900
    )
    batch = CandidateValidationBatch.model_validate_json(
        (output / "candidate-validation.json").read_text()
    )
    results = {row.request_id: row for row in batch.results}

    assert len(results) == len(requests)
    for index, (*_, selected, reason) in enumerate(_VALIDATION_REQUESTS):
        result = results[str(index)]
        assert result.selected_version == selected
        assert (result.reason is None) is (reason is None)
        if reason is not None:
            assert result.reason is not None and result.reason.startswith(reason)
    assert results["3"].implementation == ModuleId(
        group="g", artifact="a", version="1.0"
    )
    assert not (root / ".mm-gradle-inventory").exists()
    assert [
        path
        for path in root.rglob("*")
        if path.suffix in {".json", ".xml"} and ".gradle" not in path.parts
    ] == []
