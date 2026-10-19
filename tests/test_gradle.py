import hashlib
import re
import subprocess
import tomllib
from pathlib import Path

import pytest

from maintenance_man import paths
from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GRADLE_REPORT_MARKER_RELPATH,
    GRADLE_UPDATE_REPORT_RELPATH,
    GradleError,
    ReportProposal,
    _owned_update_report,
    apply_gradle_update,
    discover_gradle_updates,
    parse_catalogue,
    parse_update_report,
    render_selected_report,
    validate_gradle_recovery,
    workspace_environment_reason,
)
from maintenance_man.gradle_resolution import generate_gradle_report
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    GradleBlock,
    GradleMember,
    GradleUpdateTarget,
    SemverTier,
    normalise_alias,
)
from tests.support.findings import make_gradle_target
from tests.support.gradle import (
    GRADLE_FIXTURES,
    catalogue_apply_runner,
    fixture_runner,
    report_directory,
)
from tests.support.process import completed


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned_outputs(root: Path) -> list[Path]:
    """The adapter-owned update report and its marker under *root*."""
    owned = (GRADLE_UPDATE_REPORT_RELPATH, GRADLE_REPORT_MARKER_RELPATH)
    return [root / relpath for relpath in owned if (root / relpath).exists()]


def report_directories() -> list[Path]:
    """The Gradle report directories currently under the mm home."""
    return list(paths.mm_home().glob("gradle-report-*"))


def _fake_gradle(
    report: str | None,
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    mutate_catalogue: bool = False,
    timeout: bool = False,
):
    """Return a run_logged substitute that behaves like the real wrapper."""

    def _run(cmd, cwd, **kwargs):
        if timeout:
            msg = f"{kwargs['label']} timed out after {kwargs['timeout']}s"
            raise GradleError(msg)
        root = Path(cwd)
        if report is not None:
            (root / GRADLE_UPDATE_REPORT_RELPATH).write_text(report, encoding="utf-8")
        if mutate_catalogue:
            catalogue = root / "gradle" / "libs.versions.toml"
            catalogue.write_text(
                catalogue.read_text(encoding="utf-8").replace("2.8.4", "2.8.5"),
                encoding="utf-8",
            )
        if returncode:
            msg = f"{kwargs['label']} failed (exit {returncode})"
            raise GradleError(msg)
        return completed(cmd, returncode=0, stdout=stdout, stderr=stderr)

    return _run


def _report_fixture(name: str) -> str:
    return (GRADLE_FIXTURES / name).read_text(encoding="utf-8")


def _clean_report() -> str:
    return _report_fixture("updates-clean.toml")


_ROOM_ALIASES = {"room-runtime", "room-compiler", "room-testing"}


def _differs(*keys: str) -> str:
    """The exact apply-verification refusal naming *keys*, as a regex."""
    return (
        re.escape(
            "versionCatalogApplyUpdates did not produce exactly the selected change; "
            f"differs at: {', '.join(keys)}"
        )
        + "$"
    )


_NO_UPDATES_OUTPUT = "There are no updates available\n"


class TestParseCatalogue:
    @pytest.mark.parametrize(
        "kind, alias, coordinate, version_ref, inline_version, unsupported",
        [
            (
                "library",
                "room-runtime",
                "androidx.room:room-runtime",
                "room",
                None,
                None,
            ),
            ("library", "gson", "com.google.code.gson:gson", None, "2.11.0", None),
            ("library", "compose-ui", "androidx.compose.ui:ui", None, None, None),
            ("plugin", "ksp", "com.google.devtools.ksp", "ksp", None, None),
            (
                "plugin",
                "kotlin-compose",
                "org.jetbrains.kotlin.plugin.compose",
                "kotlin",
                None,
                None,
            ),
        ],
    )
    def test_supported_declarations(
        self, kind, alias, coordinate, version_ref, inline_version, unsupported
    ):
        catalogue = parse_catalogue(GRADLE_FIXTURES / "libs.versions.toml")
        entry = catalogue.entries[(kind, normalise_alias(alias))]

        assert entry.coordinate == coordinate
        assert entry.version_ref == version_ref
        assert entry.inline_version == inline_version
        assert entry.unsupported == unsupported

    def test_rich_version_reference_is_unsupported(self):
        catalogue = parse_catalogue(GRADLE_FIXTURES / "libs.versions.toml")

        assert catalogue.versions["okhttp"].value is None
        assert "rich version" in (catalogue.versions["okhttp"].unsupported or "")


def _library_version(catalogue):
    entry = catalogue.entry("library", "lib")
    assert entry is not None
    version = catalogue.version_of(entry)
    assert version is not None
    return entry.coordinate, version.value, version.unsupported is not None


@pytest.mark.parametrize(
    "parser, text, summarise, expected",
    [
        (
            parse_catalogue,
            '[versions]\nv = "1.2"\n[libraries]\n'
            'lib = { module = "g:lib", version.ref = "v" }\n',
            _library_version,
            ("g:lib", "1.2", False),
        ),
        (
            parse_catalogue,
            '[versions]\nv = { strictly = "1.2" }\n[libraries]\n'
            'lib = { module = "g:lib", version.ref = "v" }\n',
            _library_version,
            ("g:lib", None, True),
        ),
        (
            parse_update_report,
            '[libraries]\nlib = "g:lib:2"\n[plugins]\np = "org.example:3"\n',
            list,
            [
                ReportProposal("library", "lib", "g:lib", "2"),
                ReportProposal("plugin", "p", "org.example", "3"),
            ],
        ),
    ],
    ids=["catalogue-simple-version", "catalogue-rich-version", "report-proposals"],
)
def test_given_toml_file_when_parsed_then_declarations_are_preserved(
    tmp_path, parser, text, summarise, expected
):
    path = tmp_path / "input.toml"
    path.write_text(text, encoding="utf-8")

    assert summarise(parser(path)) == expected


@pytest.mark.parametrize(
    "parser, content, message, cause",
    [
        (
            parse_catalogue,
            b"[versions\nroom = ",
            "Failed to parse version catalogue {path}: ",
            tomllib.TOMLDecodeError,
        ),
        (
            parse_catalogue,
            b"[versions]\nv =\n",
            "Failed to parse version catalogue {path}: ",
            tomllib.TOMLDecodeError,
        ),
        (
            parse_catalogue,
            b"libraries = []\n",
            "malformed [libraries] table in {path}",
            type(None),
        ),
        (
            parse_catalogue,
            b"plugins = false\n",
            "malformed [plugins] table in {path}",
            type(None),
        ),
        (
            parse_catalogue,
            b"versions = ''\n",
            "malformed [versions] table in {path}",
            type(None),
        ),
        (
            parse_catalogue,
            b"\xff",
            "Failed to parse version catalogue {path}: ",
            UnicodeDecodeError,
        ),
        (
            parse_catalogue,
            None,
            "Version catalogue not found: {path}",
            FileNotFoundError,
        ),
        (
            parse_update_report,
            b'[libraries]\nlib = "g:a"\n',
            "malformed library entry 'lib' in {path}: expected "
            "'group:artifact:version', got 'g:a'",
            type(None),
        ),
        (
            parse_update_report,
            b'[plugins]\np = "id:1:extra"\n',
            "malformed plugin entry 'p' in {path}: expected "
            "'plugin.id:version', got 'id:1:extra'",
            type(None),
        ),
        (
            parse_update_report,
            b"[libraries\nlib = ",
            "malformed version catalogue update report {path}: ",
            tomllib.TOMLDecodeError,
        ),
        (
            parse_update_report,
            b"libraries = false\n",
            "malformed [libraries] table in {path}",
            type(None),
        ),
        (
            parse_update_report,
            b"plugins = []\n",
            "malformed [plugins] table in {path}",
            type(None),
        ),
        (
            parse_update_report,
            b"libraries = ''\n",
            "malformed [libraries] table in {path}",
            type(None),
        ),
        (
            parse_update_report,
            b"\xff",
            "malformed version catalogue update report {path}: ",
            UnicodeDecodeError,
        ),
        (
            parse_update_report,
            None,
            "malformed version catalogue update report {path}: ",
            FileNotFoundError,
        ),
    ],
    ids=[
        "catalogue-invalid-toml",
        "catalogue-incomplete-value",
        "catalogue-falsey-libraries",
        "catalogue-falsey-plugins",
        "catalogue-falsey-versions",
        "catalogue-invalid-utf8",
        "catalogue-missing",
        "report-library-entry",
        "report-plugin-entry",
        "report-invalid-toml",
        "report-falsey-libraries",
        "report-falsey-plugins",
        "report-falsey-empty-string",
        "report-invalid-utf8",
        "report-missing",
    ],
)
def test_given_unusable_toml_file_when_parsed_then_gradle_error_names_path_and_cause(
    tmp_path, parser, content, message, cause
):
    path = tmp_path / "input.toml"
    if content is not None:
        path.write_bytes(content)

    with pytest.raises(GradleError) as caught:
        parser(path)

    assert str(caught.value).startswith(message.format(path=path))
    assert type(caught.value.__cause__) is cause


class TestDiscoverGradleUpdates:
    def test_groups_shared_references_and_keeps_catalogue_pristine(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        catalogue_path = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        before = _digest(catalogue_path)
        monkeypatch.setattr(
            "maintenance_man.gradle.run_logged", _fake_gradle(_clean_report())
        )

        findings = discover_gradle_updates(gradle_project)
        by_name = {f.pkg_name: f for f in findings}

        assert _digest(catalogue_path) == before
        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()

        room = by_name["room"]
        assert room.state is None
        assert room.installed_version == "2.8.4"
        assert room.latest_version == "2.8.5"
        assert room.semver_tier == SemverTier.PATCH
        assert room.gradle_target is not None
        assert room.gradle_target.version_ref == "room"
        assert [(m.kind, m.alias) for m in room.gradle_target.members] == [
            ("library", "room-runtime"),
            ("library", "room-compiler"),
            ("library", "room-testing"),
        ]

        kotlin = by_name["kotlin"]
        assert kotlin.gradle_target is not None
        assert [(m.kind, m.alias) for m in kotlin.gradle_target.members] == [
            ("library", "kotlin-stdlib"),
            ("plugin", "kotlin-compose"),
        ]
        assert kotlin.latest_version == "2.4.20"

        gson = by_name["com.google.code.gson:gson"]
        assert gson.gradle_target is not None
        assert gson.gradle_target.version_ref is None
        assert len(gson.gradle_target.members) == 1
        assert gson.latest_version == "2.12.0"

        ksp = by_name["ksp"]
        assert ksp.gradle_target is not None
        assert [m.kind for m in ksp.gradle_target.members] == ["plugin"]
        assert ksp.latest_version == "2.3.12"

    def test_report_alias_with_control_character_is_rejected(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        """A quoted TOML key can smuggle control characters into findings."""
        report = _report_fixture("updates-unsafe.toml")
        monkeypatch.setattr("maintenance_man.gradle.run_logged", _fake_gradle(report))

        with pytest.raises(GradleError, match="unsafe"):
            discover_gradle_updates(gradle_project)

        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()

    @pytest.mark.parametrize(
        "report, blocked_name, kind, reason_fragment, members",
        [
            (
                _report_fixture("updates-conflict.toml"),
                "room",
                "conflict",
                "conflicting proposed versions",
                _ROOM_ALIASES,
            ),
            (
                _report_fixture("updates-incomplete.toml"),
                "room",
                "conflict",
                "incomplete proposal",
                _ROOM_ALIASES,
            ),
            (
                _report_fixture("updates-unmatched.toml"),
                "retrofit",
                "mapping",
                "not in the source catalogue",
                None,
            ),
            (
                _report_fixture("updates-unmatched.toml"),
                "room-runtime",
                "mapping",
                "does not match the catalogue",
                _ROOM_ALIASES,
            ),
            (_clean_report(), "okhttp", "mapping", "rich version", None),
            (
                '[libraries]\ncompose-ui = "androidx.compose.ui:ui:1.9.0"\n',
                "compose-ui",
                "mapping",
                "BOM managed",
                None,
            ),
        ],
        ids=[
            "conflicting-versions",
            "incomplete-group",
            "alias-not-in-catalogue",
            "coordinate-mismatch",
            "rich-version",
            "bom-managed",
        ],
    )
    def test_unsafe_reports_block_rather_than_edit(
        self,
        gradle_project,
        monkeypatch,
        report,
        blocked_name,
        kind,
        reason_fragment,
        members,
    ):
        monkeypatch.setattr("maintenance_man.gradle.run_logged", _fake_gradle(report))

        blocked = {
            f.pkg_name: f
            for f in discover_gradle_updates(gradle_project)
            if isinstance(f.state, GradleBlock)
        }

        state = blocked[blocked_name].state
        assert isinstance(state, GradleBlock)
        assert state.kind == kind
        assert reason_fragment in state.reason
        target = blocked[blocked_name].gradle_target
        if members is None:
            assert target is None
        else:
            assert target is not None
            assert target.version_ref == "room"
            assert target.target_version == "2.8.4"
            assert {m.alias for m in target.members} == members

    def test_a_marked_leftover_report_is_reclaimed_and_build_files_survive(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        """A killed run must not brick every later scan."""
        root = Path(gradle_project.path)
        (root / GRADLE_UPDATE_REPORT_RELPATH).write_text("# stale\n", encoding="utf-8")
        (root / GRADLE_REPORT_MARKER_RELPATH).write_bytes(b"")
        (root / "build").mkdir()
        (root / "build" / "caller.txt").write_bytes(b"caller build output")
        monkeypatch.setattr(
            "maintenance_man.gradle.run_logged", _fake_gradle(_clean_report())
        )

        assert discover_gradle_updates(gradle_project)

        assert owned_outputs(root) == []
        assert (root / "build" / "caller.txt").read_bytes() == b"caller build output"

    @pytest.mark.parametrize(
        "env, local_properties, workspace_properties, expected",
        [
            ({"ANDROID_HOME": "/opt/android"}, True, False, None),
            ({"ANDROID_SDK_ROOT": "/opt/android"}, True, False, None),
            ({}, False, False, None),
            ({}, True, False, "ANDROID_HOME or ANDROID_SDK_ROOT"),
            ({}, True, True, "ANDROID_HOME or ANDROID_SDK_ROOT"),
        ],
        ids=[
            "android-home",
            "sdk-root",
            "no-local-properties",
            "untracked-local-properties",
            "leftover-workspace-properties-are-not-evidence",
        ],
    )
    def test_workspace_environment_reason(
        self,
        gradle_project: ProjectConfig,
        monkeypatch,
        tmp_path,
        env,
        local_properties,
        workspace_properties,
        expected,
    ):
        """The workspace holds tracked files only; local.properties is not one."""
        monkeypatch.setattr("maintenance_man.gradle.project_env", lambda: dict(env))
        source = Path(gradle_project.path)
        if local_properties:
            (source / "local.properties").write_text(
                "sdk.dir=/opt/a\n", encoding="utf-8"
            )
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        if workspace_properties:
            (workspace / "local.properties").write_text("sdk.dir=/opt/a\n")

        reason = workspace_environment_reason(source, workspace)

        if expected is None:
            assert reason is None
        else:
            assert reason is not None and expected in reason

    @pytest.mark.parametrize(
        "runner, expected",
        [
            (_fake_gradle(None), "produced no report"),
            (
                _fake_gradle(_clean_report(), returncode=1),
                r"failed \(exit 1\)",
            ),
            (_fake_gradle(_clean_report(), timeout=True), "timed out"),
            (
                _fake_gradle(_clean_report(), mutate_catalogue=True),
                "discovery must leave the source catalogue unchanged",
            ),
            (_fake_gradle("[libraries]\nroom-runtime = 12\n"), "malformed"),
            (_fake_gradle("libraries = false\n"), "table"),
            (
                _fake_gradle(None, stdout="Warning: " + _NO_UPDATES_OUTPUT),
                "produced no report",
            ),
            (
                _fake_gradle(None, stdout=_NO_UPDATES_OUTPUT, returncode=1),
                r"failed \(exit 1\)",
            ),
            (
                _fake_gradle(None, stdout=_NO_UPDATES_OUTPUT, mutate_catalogue=True),
                "discovery must leave the source catalogue unchanged",
            ),
        ],
        ids=[
            "no-report",
            "nonzero-exit",
            "timeout",
            "catalogue-mutated",
            "malformed-report",
            "falsey-report-table",
            "no-updates-signal-with-prefix",
            "no-updates-signal-with-nonzero-exit",
            "no-updates-signal-with-mutated-catalogue",
        ],
    )
    def test_given_failed_discovery_when_run_then_it_raises_and_releases_outputs(
        self, gradle_project: ProjectConfig, monkeypatch, runner, expected
    ):
        monkeypatch.setattr("maintenance_man.gradle.run_logged", runner)

        with pytest.raises(GradleError, match=expected):
            discover_gradle_updates(gradle_project)

        assert owned_outputs(Path(gradle_project.path)) == []

    @pytest.mark.parametrize(
        "stdout, stderr",
        [
            ("\n" + _NO_UPDATES_OUTPUT, ""),
            ("", "\n" + _NO_UPDATES_OUTPUT),
        ],
    )
    def test_no_updates_signal_without_report_returns_empty(
        self, gradle_project, monkeypatch, stdout, stderr
    ):
        root = Path(gradle_project.path)
        before = (root / GRADLE_CATALOGUE_RELPATH).read_bytes()
        runner = _fake_gradle(None, stdout=stdout, stderr=stderr)
        monkeypatch.setattr("maintenance_man.gradle.run_logged", runner)

        assert discover_gradle_updates(gradle_project) == []
        assert (root / GRADLE_CATALOGUE_RELPATH).read_bytes() == before
        assert owned_outputs(root) == []

    def test_missing_wrapper_raises_before_any_command(
        self, gradle_project, monkeypatch
    ):
        (Path(gradle_project.path) / "gradlew").unlink()
        monkeypatch.setattr(
            "maintenance_man.gradle.run_logged",
            lambda *a, **k: pytest.fail("wrapper check must run first"),
        )

        with pytest.raises(GradleError, match="Gradle wrapper"):
            discover_gradle_updates(gradle_project)


def _arrange_report_file(root, tmp_path):
    report = root / GRADLE_UPDATE_REPORT_RELPATH
    report.write_bytes(b"# caller owned\n")
    return root, {report: b"# caller owned\n"}


def _arrange_report_symlink(root, tmp_path):
    elsewhere = root / "elsewhere.toml"
    elsewhere.write_bytes(b"# elsewhere\n")
    (root / GRADLE_UPDATE_REPORT_RELPATH).symlink_to(elsewhere)
    return root, {elsewhere: b"# elsewhere\n"}


def _arrange_marker_symlink(root, tmp_path):
    elsewhere = root / "elsewhere.marker"
    elsewhere.write_bytes(b"# elsewhere\n")
    (root / GRADLE_REPORT_MARKER_RELPATH).symlink_to(elsewhere)
    return root, {elsewhere: b"# elsewhere\n"}


def _arrange_gradle_directory_symlink(root, tmp_path):
    outside = tmp_path / "outside-gradle"
    (root / "gradle").rename(outside)
    (root / "gradle").symlink_to(outside, target_is_directory=True)
    report = outside / "libs.versions.updates.toml"
    marker = outside / ".mm-owned-report"
    report.write_bytes(b"external report bytes")
    marker.write_bytes(b"external marker bytes")
    return root, {report: b"external report bytes", marker: b"external marker bytes"}


def _arrange_project_symlink(root, tmp_path):
    link = tmp_path / "project-symlink"
    link.symlink_to(root, target_is_directory=True)
    report = root / "gradle" / "libs.versions.updates.toml"
    marker = root / "gradle" / ".mm-owned-report"
    report.write_bytes(b"external report bytes")
    marker.write_bytes(b"external marker bytes")
    return link, {report: b"external report bytes", marker: b"external marker bytes"}


def _discover(project):
    discover_gradle_updates(project)


def _apply(project):
    """Apply reports a drifted catalogue as a block; a block refuses like an error."""
    block = apply_gradle_update(project, make_gradle_target())
    if block is not None:
        raise GradleError(block.reason)


@pytest.mark.parametrize(
    "operation, arguments",
    [
        pytest.param(
            _discover,
            ["versionCatalogUpdate", "--interactive", "--no-daemon", "--console=plain"],
            id="discovery",
        ),
        pytest.param(
            _apply,
            ["versionCatalogApplyUpdates", "--no-daemon", "--console=plain"],
            id="application",
        ),
    ],
)
def test_given_gradle_task_when_run_then_the_wrapper_gets_the_approved_arguments(
    gradle_project, monkeypatch, operation, arguments
):
    calls: list[tuple[list[str], Path, dict]] = []
    runners = {
        "versionCatalogUpdate": _fake_gradle(_clean_report()),
        "versionCatalogApplyUpdates": catalogue_apply_runner(
            {'room = "2.8.4"': 'room = "2.8.5"'}
        ),
    }

    def _record(cmd, cwd, **kwargs):
        calls.append((cmd, cwd, kwargs))
        return runners[cmd[1]](cmd, cwd, **kwargs)

    monkeypatch.setattr("maintenance_man.gradle.run_logged", _record)
    operation(gradle_project)

    cmd, cwd, kwargs = calls[0]
    assert cmd == [str(Path(gradle_project.path) / "gradlew"), *arguments]
    assert Path(cwd) == Path(gradle_project.path)
    assert kwargs["timeout"] == 900
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["capture"] is True


@pytest.mark.parametrize("operation", [_discover, _apply], ids=["discover", "apply"])
@pytest.mark.parametrize(
    "arrange, refused",
    [
        pytest.param(
            _arrange_report_file,
            "version catalogue update report",
            id="unmarked-report-file",
        ),
        pytest.param(
            _arrange_report_symlink,
            "version catalogue update report",
            id="report-symlink",
        ),
        pytest.param(
            _arrange_marker_symlink,
            "version catalogue update report",
            id="marker-symlink",
        ),
        pytest.param(
            _arrange_gradle_directory_symlink,
            "Gradle report directory",
            id="symlinked-gradle-directory",
        ),
        pytest.param(
            _arrange_project_symlink,
            "Gradle project directory",
            id="symlinked-project-directory",
        ),
    ],
)
def test_given_caller_owned_report_path_when_run_then_it_refuses_and_keeps_its_bytes(
    gradle_project, monkeypatch, tmp_path, operation, arrange, refused
):
    monkeypatch.setattr(
        "maintenance_man.gradle.run_logged",
        lambda *a, **k: pytest.fail("must refuse before running"),
    )
    root = Path(gradle_project.path)
    project_path, kept = arrange(root, tmp_path)
    symlinks = [
        path
        for path in (
            root / "gradle",
            root / GRADLE_UPDATE_REPORT_RELPATH,
            root / GRADLE_REPORT_MARKER_RELPATH,
            project_path,
        )
        if path.is_symlink()
    ]

    with pytest.raises(
        GradleError, match=f"Refusing to overwrite an existing {refused} at "
    ):
        operation(gradle_project.model_copy(update={"path": project_path}))

    assert {path: path.read_bytes() for path in kept} == kept
    assert all(path.is_symlink() for path in symlinks)


def _report_wrapper(*, returncode: int = 0):
    """run_logged substitute that writes a valid BOM and exits *returncode*."""

    def _run(cmd, cwd, **kwargs):
        bom = report_directory(cmd) / "bom.json"
        bom.write_text(
            (GRADLE_FIXTURES / "bom.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        if returncode:
            msg = f"{kwargs['label']} failed (exit {returncode})"
            raise GradleError(msg)
        return completed(cmd, returncode=0, stdout="", stderr="")

    return _run


class TestGradleReportDirectory:
    def test_failed_wrapper_is_an_error_not_a_clean_scan(
        self, gradle_project, monkeypatch
    ):
        monkeypatch.setattr(
            "maintenance_man.gradle.run_logged", _report_wrapper(returncode=1)
        )

        with (
            pytest.raises(GradleError, match=r"failed \(exit 1\)$"),
            generate_gradle_report(gradle_project),
        ):
            pytest.fail("failed wrapper must not yield an inventory")

        assert report_directories() == []

    def test_caller_exception_propagates_unchanged(self, gradle_project, monkeypatch):
        monkeypatch.setattr(
            "maintenance_man.gradle_resolution.run_gradle", fixture_runner
        )
        error = OSError("caller failure")
        with pytest.raises(OSError) as caught, generate_gradle_report(gradle_project):
            raise error
        assert caught.value is error
        assert report_directories() == []


def test_report_generation_refuses_catalogue_mutation(gradle_project, monkeypatch):
    root = Path(gradle_project.path)

    def mutating(root_arg, args, *, label):
        completed = fixture_runner(root_arg, args, label=label)
        catalogue = root / GRADLE_CATALOGUE_RELPATH
        catalogue.write_text(catalogue.read_text() + "# drift\n")
        return completed

    monkeypatch.setattr("maintenance_man.gradle_resolution.run_gradle", mutating)
    with (
        pytest.raises(GradleError, match="Catalogue changed during report generation"),
        generate_gradle_report(gradle_project),
    ):
        pytest.fail("mutated catalogue must not yield a report")
    assert report_directories() == []


class TestRenderSelectedReport:
    def test_renders_only_the_selected_group_with_quoted_keys(self):
        target = GradleUpdateTarget(
            version_ref="kotlin",
            members=[
                GradleMember(
                    kind="library",
                    alias="kotlin-stdlib",
                    coordinate="org.jetbrains.kotlin:kotlin-stdlib",
                    installed_version="2.4.10",
                ),
                GradleMember(
                    kind="plugin",
                    alias="kotlin-compose",
                    coordinate="org.jetbrains.kotlin.plugin.compose",
                    installed_version="2.4.10",
                ),
            ],
            target_version="2.4.20",
        )

        assert render_selected_report(target) == (
            "[libraries]\n"
            '"kotlin-stdlib" = "org.jetbrains.kotlin:kotlin-stdlib:2.4.20"\n'
            "\n"
            "[plugins]\n"
            '"kotlin-compose" = "org.jetbrains.kotlin.plugin.compose:2.4.20"\n'
        )

    @pytest.mark.parametrize(
        "alias, version",
        [
            ("room\nruntime", "2.8.5"),
            ("room\x00runtime", "2.8.5"),
            ("", "2.8.5"),
            ("room-runtime", "2.8.5\nx"),
            ("room-runtime", ""),
        ],
    )
    def test_unsafe_text_is_rejected(self, alias, version):
        target = GradleUpdateTarget(
            members=[
                GradleMember(
                    kind="library",
                    alias=alias,
                    coordinate="g:a",
                    installed_version="1.0",
                )
            ],
            target_version=version,
        )

        with pytest.raises(GradleError, match="unsafe"):
            render_selected_report(target)


class TestApplyBlocks:
    @pytest.mark.parametrize(
        "replacements,kind,reason",
        [
            (
                {
                    'room-testing = { group = "androidx.room", name = '
                    '"room-testing", version.ref = "room" }\n': ""
                },
                "stale",
                "the catalogue no longer declares library 'room-testing'; "
                "rescan required",
            ),
            (
                {
                    'room-compiler = { group = "androidx.room", name = '
                    '"room-compiler", version.ref = "room" }': (
                        'room-compiler = { group = "androidx.room", name = '
                        '"room-compiler", version = "2.8.4" }'
                    )
                },
                "stale",
                "'room-compiler' no longer shares version reference 'room'; "
                "rescan required",
            ),
            (
                {
                    'junit = { group = "junit", name = "junit", '
                    'version.ref = "junit" }': (
                        'junit = { group = "androidx.room", name = '
                        '"room-ktx", version.ref = "room" }'
                    )
                },
                "stale",
                "version reference 'room' now covers a different set of aliases; "
                "rescan required",
            ),
            (
                {
                    'room = "2.8.4"': 'room = "9.9.9"',
                    'room-runtime = { group = "androidx.room", name = '
                    '"room-runtime", version.ref = "room" }\n': "",
                },
                "stale",
                "the catalogue no longer declares library 'room-runtime'; "
                "rescan required",
            ),
            (
                {
                    'group = "androidx.room", name = "room-runtime"': (
                        'group = "example.changed", name = "room-runtime"'
                    ),
                    'room = "2.8.4"': 'room = { strictly = "2.8.4" }',
                },
                "stale",
                "'room-runtime' now resolves to example.changed:room-runtime, not "
                "androidx.room:room-runtime; rescan required",
            ),
            (
                {
                    'room-runtime = { group = "androidx.room", name = '
                    '"room-runtime", version.ref = "room" }': (
                        'room-runtime = { module = "androidx.room:room-runtime", '
                        'version = { strictly = "2.8.4" } }'
                    )
                },
                "mapping",
                "'room-runtime' uses a rich version declaration, which mm does "
                "not edit",
            ),
            (
                {'room = "2.8.4"': 'room = { strictly = "2.8.4" }'},
                "mapping",
                "'room-runtime' no longer has a simple catalogue version; resolve "
                "manually",
            ),
            (
                {'room = "2.8.4"': 'room = "2.8.9"'},
                "stale",
                "'room-runtime' is at 2.8.9, expected 2.8.4; the catalogue no "
                "longer matches the scan; note that an uncommitted catalogue edit "
                "is not visible in the update workspace. Rescan required",
            ),
            (
                {
                    "room-runtime = {": "room_runtime = {",
                    'room = "2.8.4"': 'room = { strictly = "2.8.4" }',
                },
                "mapping",
                "'room-runtime' no longer has a simple catalogue version; resolve "
                "manually",
            ),
            (
                {
                    "room-runtime = {": "room_runtime = {",
                    'room = "2.8.4"': 'room = "2.8.9"',
                },
                "stale",
                "'room-runtime' is at 2.8.9, expected 2.8.4; the catalogue no "
                "longer matches the scan; note that an uncommitted catalogue edit "
                "is not visible in the update workspace. Rescan required",
            ),
        ],
    )
    def test_given_drifted_member_when_applied_then_first_block_and_no_owned_files(
        self, gradle_project, monkeypatch, replacements, kind, reason
    ):
        catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
        text = catalogue.read_text(encoding="utf-8")
        for old, new in replacements.items():
            text = text.replace(old, new, 1)
        catalogue.write_text(text, encoding="utf-8")

        monkeypatch.setattr(
            "maintenance_man.gradle.run_logged",
            lambda *a, **k: pytest.fail("no command may run"),
        )

        block = apply_gradle_update(gradle_project, make_gradle_target())

        assert block is not None
        assert block.kind == kind
        assert block.reason == reason
        assert owned_outputs(Path(gradle_project.path)) == []


class TestApplyGradleUpdate:
    def test_applies_the_group_and_verifies_the_semantic_change(
        self, gradle_project, monkeypatch
    ):
        catalogue = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        reports: list[str] = []
        applier = catalogue_apply_runner({'room = "2.8.4"': 'room = "2.8.5"'})

        def _run(cmd, cwd, **kwargs):
            report = Path(cwd) / GRADLE_UPDATE_REPORT_RELPATH
            reports.append(report.read_text(encoding="utf-8"))
            return applier(cmd, cwd, **kwargs)

        monkeypatch.setattr("maintenance_man.gradle.run_logged", _run)

        assert apply_gradle_update(gradle_project, make_gradle_target()) is None
        assert 'room = "2.8.5"' in catalogue.read_text(encoding="utf-8")
        assert 'kotlin = "2.4.10"' in catalogue.read_text(encoding="utf-8")
        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()
        assert reports[0].splitlines()[0] == "[libraries]"
        assert '"room-testing" = "androidx.room:room-testing:2.8.5"' in reports[0]
        assert "kotlin" not in reports[0]

    @pytest.mark.parametrize(
        "edits, returncode, expected",
        [
            ({}, 1, r"failed \(exit 1\)"),
            (
                {},
                0,
                _differs(
                    "library room-compiler",
                    "library room-runtime",
                    "library room-testing",
                    "version room",
                ),
            ),
            (
                {
                    'room = "2.8.4"': 'room = "2.8.5"',
                    'kotlin = "2.4.10"': 'kotlin = "2.4.20"',
                },
                0,
                _differs(
                    "library kotlin-stdlib", "plugin kotlin-compose", "version kotlin"
                ),
            ),
            (
                {
                    'room = "2.8.4"': 'room = "2.8.5"',
                    'gson = "com.google.code.gson:gson:2.11.0"': (
                        'gson = "com.google.code.gson:gson:2.12.0"'
                    ),
                },
                0,
                _differs("library gson"),
            ),
            (
                {
                    'room = "2.8.4"': 'room = "2.8.5"',
                    'kotlin = "2.4.10"': 'kotlin = "2.4.20"',
                    'gson = "com.google.code.gson:gson:2.11.0"': (
                        'gson = "com.google.code.gson:gson:2.12.0"'
                    ),
                },
                0,
                _differs(
                    "library gson",
                    "library kotlin-stdlib",
                    "plugin kotlin-compose",
                    "version kotlin",
                ),
            ),
            (
                {
                    'room = "2.8.4"': 'room = "2.8.5"',
                    'junit = { group = "junit", name = "junit", '
                    'version.ref = "junit" }\n': "",
                },
                0,
                _differs("library junit"),
            ),
            (
                {
                    'room = "2.8.4"': 'room = "2.8.5"',
                    'room = ["room-runtime"]': 'room = ["gson"]',
                },
                0,
                _differs("preserved sections"),
            ),
            (
                {
                    'room = "2.8.4"': 'room = "2.8.5"',
                    'strictly = "1.0"': 'strictly = "2.0"',
                },
                0,
                _differs("preserved rich_versions"),
            ),
        ],
        ids=[
            "nonzero-exit",
            "no-change",
            "other-version-reference",
            "other-inline-library",
            "several-other-changes",
            "removed-alias",
            "rewritten-bundle",
            "rewritten-rich-version",
        ],
    )
    def test_unsafe_application_raises_after_mutation_may_have_begun(
        self, gradle_project, monkeypatch, edits, returncode, expected
    ):
        catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
        catalogue.write_text(
            catalogue.read_text()
            + '\n[bundles]\nroom = ["room-runtime"]\n\n[versions.rich]\n'
            'strictly = "1.0"\n'
        )
        monkeypatch.setattr(
            "maintenance_man.gradle.run_logged",
            catalogue_apply_runner(edits, returncode=returncode),
        )

        with pytest.raises(GradleError, match=expected):
            apply_gradle_update(gradle_project, make_gradle_target())

        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()


_FIXTURE_CATALOGUE = (GRADLE_FIXTURES / "libs.versions.toml").read_text(
    encoding="utf-8"
)
_SHARED_CATALOGUE = (
    '[versions]\nshared = "1.0.1"\n'
    '[libraries]\nruntime = { module = "org.example:library", '
    'version.ref = "shared" }\n'
    '[plugins]\nbuild = { id = "org.example.plugin", version.ref = "shared" }\n'
)


def _fixture_target(*, installed_mismatch: bool = False, reverse: bool = False):
    target = make_gradle_target()
    if installed_mismatch:
        target.members[1].installed_version = "9.9.9"
    if reverse:
        target.members.reverse()
    return target


def _shared_target(*, plugin_installed: str, reverse: bool = False):
    members = [
        GradleMember(
            kind="library",
            alias="runtime",
            coordinate="org.example:library",
            installed_version="1.0.0",
        ),
        GradleMember(
            kind="plugin",
            alias="build",
            coordinate="org.example.plugin",
            installed_version=plugin_installed,
        ),
    ]
    return GradleUpdateTarget(
        version_ref="shared",
        target_version="1.0.1",
        members=members[::-1] if reverse else members,
    )


@pytest.mark.parametrize(
    "catalogue, target, expected",
    [
        pytest.param(
            _FIXTURE_CATALOGUE,
            _fixture_target(),
            "expected 2.8.5",
            id="not-yet-repaired",
        ),
        pytest.param(
            _FIXTURE_CATALOGUE.replace('room = "2.8.4"', 'room = "2.8.5"'),
            _fixture_target(),
            None,
            id="completed-manual-repair",
        ),
        pytest.param(
            _FIXTURE_CATALOGUE.replace('room = "2.8.4"', 'room = "2.9.0"'),
            _fixture_target(),
            "expected 2.8.5",
            id="different-manual-fix",
        ),
        *(
            pytest.param(
                _FIXTURE_CATALOGUE.replace('room = "2.8.4"', 'room = "2.8.5"'),
                _fixture_target(installed_mismatch=True, reverse=reverse),
                "installed",
                id=f"fixture-installed-history-mismatch-reverse-{reverse}",
            )
            for reverse in (False, True)
        ),
        *(
            pytest.param(
                _SHARED_CATALOGUE,
                _shared_target(
                    plugin_installed="1.0.0" if consistent else "9.9.9", reverse=reverse
                ),
                None if consistent else "installed",
                id=f"library-plugin-{'consistent' if consistent else 'mismatch'}"
                f"-reverse-{reverse}",
            )
            for consistent in (False, True)
            for reverse in (False, True)
        ),
    ],
)
def test_given_catalogue_when_recovery_validated_then_only_the_intended_versions_pass(
    gradle_project, catalogue, target, expected
):
    (Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH).write_text(
        catalogue, encoding="utf-8"
    )

    block = validate_gradle_recovery(gradle_project, target)

    if expected is None:
        assert block is None
    else:
        assert block is not None and block.kind == "stale"
        assert expected in block.reason


@pytest.mark.parametrize(
    "target",
    [
        make_gradle_target(version_ref=None, members=[]),
        make_gradle_target(version_ref=None),
        make_gradle_target(members=[make_gradle_target().members[0]] * 2),
    ],
)
def test_invalid_historical_target_shape_blocks_without_a_command(
    gradle_project, monkeypatch, target
):
    monkeypatch.setattr(
        "maintenance_man.gradle.run_logged",
        lambda *a, **k: pytest.fail("unsafe target must not apply"),
    )
    block = apply_gradle_update(gradle_project, target)
    assert block is not None
    assert block.kind == "stale"


@pytest.mark.parametrize("operation", ["report", "discovery"])
def test_missing_wrapper_interpreter_is_gradle_error_and_cleans_owned_artifacts(
    gradle_project, operation
):
    root = Path(gradle_project.path)
    (root / "gradlew").write_text("#!/definitely/missing/mm-interpreter\n")
    with pytest.raises(GradleError, match=r"gradlew.*No such file"):
        if operation == "report":
            with generate_gradle_report(gradle_project):
                pytest.fail("unlaunchable wrapper cannot yield inventory")
        else:
            discover_gradle_updates(gradle_project)
    if operation == "report":
        assert report_directories() == []
    else:
        assert owned_outputs(root) == []


@pytest.mark.parametrize("complete", [False, True])
def test_shared_reference_completeness_distinguishes_library_and_plugin_alias(
    gradle_project, monkeypatch, complete
):
    root = Path(gradle_project.path)
    (root / GRADLE_CATALOGUE_RELPATH).write_text(
        '[versions]\nshared = "1.0.0"\n'
        '[libraries]\nsame = { module = "org.example:library", '
        'version.ref = "shared" }\n'
        '[plugins]\nsame = { id = "org.example.plugin", version.ref = "shared" }\n'
    )
    report = '[libraries]\nsame = "org.example:library:1.0.1"\n'
    if complete:
        report += '[plugins]\nsame = "org.example.plugin:1.0.1"\n'
    monkeypatch.setattr("maintenance_man.gradle.run_logged", _fake_gradle(report))
    findings = discover_gradle_updates(gradle_project)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.gradle_target is not None
    assert {(m.kind, m.alias) for m in finding.gradle_target.members} == {
        ("library", "same"),
        ("plugin", "same"),
    }
    if complete:
        assert finding.state is None
        assert finding.gradle_target.target_version == "1.0.1"
    else:
        assert isinstance(finding.state, GradleBlock)
        assert finding.state.kind == "conflict"
        assert "plugin" in finding.state.reason
        assert finding.gradle_target.target_version == "1.0.0"


@pytest.mark.parametrize("replacement", ["symlink", "file"])
def test_report_cleanup_rechecks_parent_after_wrapper_launch(
    gradle_project, tmp_path, monkeypatch, replacement
):
    root = Path(gradle_project.path)
    outside = tmp_path / "outside"
    outside.mkdir()
    report = outside / "libs.versions.updates.toml"
    marker = outside / ".mm-owned-report"
    report.write_bytes(b"external report")
    marker.write_bytes(b"external marker")

    def run(cmd, cwd, **kwargs):
        (root / "gradle").rename(tmp_path / "original-gradle")
        if replacement == "symlink":
            (root / "gradle").symlink_to(outside, target_is_directory=True)
        else:
            (root / "gradle").write_bytes(b"caller file")
        msg = f"{kwargs['label']} failed (exit 1)"
        raise GradleError(msg)

    monkeypatch.setattr("maintenance_man.gradle.run_logged", run)
    with pytest.raises(
        GradleError,
        match="Refusing to overwrite an existing Gradle report directory at ",
    ):
        discover_gradle_updates(gradle_project)
    assert report.read_bytes() == b"external report"
    assert marker.read_bytes() == b"external marker"
    if replacement == "file":
        assert (root / "gradle").read_bytes() == b"caller file"


@pytest.mark.parametrize("phase", ["claim", "marker", "cleanup"])
def test_report_lifecycle_filesystem_errors_are_gradle_errors(
    gradle_project, monkeypatch, phase
):
    root = Path(gradle_project.path)
    report = root / GRADLE_UPDATE_REPORT_RELPATH
    marker = root / GRADLE_REPORT_MARKER_RELPATH
    if phase == "claim":
        report.write_bytes(b"owned leftover")
        marker.write_bytes(b"")
    if phase == "marker":
        write = Path.write_bytes

        def fail(path, content):
            if path == marker:
                msg = "report marker denied"
                raise PermissionError(msg)
            return write(path, content)

        monkeypatch.setattr(Path, "write_bytes", fail)
        monkeypatch.setattr(
            "maintenance_man.gradle.run_logged",
            lambda *args, **kwargs: pytest.fail("marker failure must not launch"),
        )
    else:
        unlink = Path.unlink

        def fail(path, *args, **kwargs):
            if path == report:
                msg = "report unlink denied"
                raise PermissionError(msg)
            return unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail)
        monkeypatch.setattr(
            "maintenance_man.gradle.run_logged", _fake_gradle(_clean_report())
        )
    with pytest.raises(GradleError, match="denied"):
        discover_gradle_updates(gradle_project)
    if phase == "marker":
        assert not report.exists()
        assert not marker.exists()
    elif phase == "claim":
        assert report.read_bytes() == b"owned leftover"
        assert marker.exists()
    else:
        assert report.exists()
        assert marker.exists()


@pytest.mark.parametrize("resource", ["report-directory", "report"])
@pytest.mark.parametrize(
    "exception",
    [
        PermissionError("caller permission error"),
        ValueError("caller programming error"),
    ],
)
def test_owned_context_cleanup_preserves_caller_exception(
    gradle_project, monkeypatch, resource, exception
):
    root = Path(gradle_project.path)
    monkeypatch.setattr("maintenance_man.gradle_resolution.run_gradle", fixture_runner)
    context = (
        generate_gradle_report(gradle_project)
        if resource == "report-directory"
        else _owned_update_report(root)
    )
    with pytest.raises(type(exception)) as caught, context as output:
        if isinstance(output, Path):
            output.write_bytes(b"owned report")
        raise exception
    assert caught.value is exception
    assert owned_outputs(root) == []
    assert report_directories() == []


@pytest.mark.parametrize("read", ["digest", "report", "inventory"])
def test_adapter_filesystem_read_failure_is_actionable_and_releases_outputs(
    gradle_project, monkeypatch, read
):
    root = Path(gradle_project.path)
    if read == "inventory":
        monkeypatch.setattr(
            "maintenance_man.gradle_resolution.run_gradle", fixture_runner
        )
    else:
        monkeypatch.setattr(
            "maintenance_man.gradle.run_logged", _fake_gradle(_clean_report())
        )
    reads_bytes = read in {"digest", "inventory"}
    method = Path.read_bytes if reads_bytes else Path.read_text
    blocked = {
        "digest": root / GRADLE_CATALOGUE_RELPATH,
        "report": root / GRADLE_UPDATE_REPORT_RELPATH,
        "inventory": None,
    }[read]

    def fail(path, *args, **kwargs):
        if path == blocked or (blocked is None and path.name == "bom.json"):
            msg = "read denied"
            raise PermissionError(msg)
        return method(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes" if reads_bytes else "read_text", fail)
    with pytest.raises(GradleError, match="read denied"):
        if read == "inventory":
            with generate_gradle_report(gradle_project):
                pytest.fail("failed validation must not yield")
        else:
            discover_gradle_updates(gradle_project)
    assert owned_outputs(root) == []
    assert report_directories() == []
