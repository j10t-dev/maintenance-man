import hashlib
import subprocess
from pathlib import Path

import pytest

from maintenance_man.gradle import (
    GRADLE_INVENTORY_MARKER_RELPATH,
    GRADLE_INVENTORY_RELPATH,
    GRADLE_REPORT_MARKER_RELPATH,
    GRADLE_UPDATE_REPORT_RELPATH,
    GradleError,
    claim_owned_dir,
    discover_gradle_updates,
    normalise_alias,
    parse_catalogue,
    workspace_environment_reason,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import SemverTier
from tests.conftest import GRADLE_FIXTURES


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fake_gradle(
    report: str | None,
    *,
    returncode: int = 0,
    stderr: str = "",
    mutate_catalogue: bool = False,
    timeout: bool = False,
):
    """Return a subprocess.run substitute that behaves like the real wrapper."""

    def _run(cmd, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 300))
        root = Path(kwargs["cwd"])
        if report is not None:
            (root / GRADLE_UPDATE_REPORT_RELPATH).write_text(report, encoding="utf-8")
        if mutate_catalogue:
            catalogue = root / "gradle" / "libs.versions.toml"
            catalogue.write_text(
                catalogue.read_text(encoding="utf-8").replace("2.8.4", "2.8.5"),
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(cmd, returncode, stdout="", stderr=stderr)

    return _run


def _clean_report() -> str:
    return (GRADLE_FIXTURES / "updates-clean.toml").read_text(encoding="utf-8")


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

    def test_missing_catalogue_raises(self, tmp_path):
        with pytest.raises(GradleError, match="not found"):
            parse_catalogue(tmp_path / "gradle" / "libs.versions.toml")

    def test_malformed_catalogue_raises(self, tmp_path):
        bad = tmp_path / "libs.versions.toml"
        bad.write_text("[versions\nroom = ", encoding="utf-8")

        with pytest.raises(GradleError, match="Failed to parse"):
            parse_catalogue(bad)


class TestDiscoverGradleUpdates:
    def test_groups_shared_references_and_keeps_catalogue_pristine(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        catalogue_path = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        before = _digest(catalogue_path)
        monkeypatch.setattr(subprocess, "run", _fake_gradle(_clean_report()))

        findings = discover_gradle_updates(gradle_project)
        by_name = {f.pkg_name: f for f in findings}

        assert _digest(catalogue_path) == before
        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()

        room = by_name["room"]
        assert room.blocked_reason is None
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

    def test_rich_version_group_is_blocked_not_flattened(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        monkeypatch.setattr(subprocess, "run", _fake_gradle(_clean_report()))

        blocked = {
            f.pkg_name: f
            for f in discover_gradle_updates(gradle_project)
            if f.blocked_reason
        }

        assert blocked["okhttp"].gradle_block_kind == "mapping"
        assert blocked["okhttp"].gradle_target is None
        assert blocked["okhttp"].blocked_reason is not None
        assert "rich version" in blocked["okhttp"].blocked_reason

    def test_bom_managed_child_is_not_a_target(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        monkeypatch.setattr(subprocess, "run", _fake_gradle(_clean_report()))

        names = {f.pkg_name for f in discover_gradle_updates(gradle_project)}

        assert "androidx.compose.ui:ui" not in names
        assert "compose-ui" not in names

    def test_bom_managed_child_proposal_is_blocked_not_a_target(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        """compose-ui has no catalogue version; a proposal for it must block."""
        report = '[libraries]\ncompose-ui = "androidx.compose.ui:ui:1.9.0"\n'
        monkeypatch.setattr(subprocess, "run", _fake_gradle(report))

        blocked = {
            f.pkg_name: f
            for f in discover_gradle_updates(gradle_project)
            if f.blocked_reason
        }

        assert blocked["compose-ui"].gradle_block_kind == "mapping"
        assert (reason := blocked["compose-ui"].blocked_reason) is not None
        assert "BOM managed" in reason
        assert blocked["compose-ui"].gradle_target is None

    def test_report_alias_with_control_character_is_rejected(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        """A quoted TOML key can smuggle control characters into findings."""
        report = (GRADLE_FIXTURES / "updates-unsafe.toml").read_text(encoding="utf-8")
        monkeypatch.setattr(subprocess, "run", _fake_gradle(report))

        with pytest.raises(GradleError, match="unsafe"):
            discover_gradle_updates(gradle_project)

        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()

    @pytest.mark.parametrize(
        "report_fixture, blocked_name, kind, reason_fragment",
        [
            (
                "updates-conflict.toml",
                "room",
                "conflict",
                "conflicting proposed versions",
            ),
            ("updates-incomplete.toml", "room", "conflict", "incomplete proposal"),
            (
                "updates-unmatched.toml",
                "retrofit",
                "mapping",
                "not in the source catalogue",
            ),
            (
                "updates-unmatched.toml",
                "room-runtime",
                "mapping",
                "does not match the catalogue",
            ),
        ],
    )
    def test_unsafe_reports_block_rather_than_edit(
        self,
        gradle_project,
        monkeypatch,
        report_fixture,
        blocked_name,
        kind,
        reason_fragment,
    ):
        report = (GRADLE_FIXTURES / report_fixture).read_text(encoding="utf-8")
        monkeypatch.setattr(subprocess, "run", _fake_gradle(report))

        blocked = {
            f.pkg_name: f
            for f in discover_gradle_updates(gradle_project)
            if f.blocked_reason
        }

        assert blocked[blocked_name].gradle_block_kind == kind
        assert (reason := blocked[blocked_name].blocked_reason) is not None
        assert reason_fragment in reason
        target = blocked[blocked_name].gradle_target
        if blocked_name == "retrofit":
            assert target is None
        else:
            assert target is not None
            assert target.version_ref == "room"
            assert target.target_version == "2.8.4"
            assert {m.alias for m in target.members} == {
                "room-runtime",
                "room-compiler",
                "room-testing",
            }

    def test_existing_report_is_a_collision_not_an_overwrite(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        existing = Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH
        existing.write_text("# caller owned\n", encoding="utf-8")
        monkeypatch.setattr(subprocess, "run", _fake_gradle(_clean_report()))

        with pytest.raises(GradleError, match="Refusing to overwrite"):
            discover_gradle_updates(gradle_project)

        assert existing.read_text(encoding="utf-8") == "# caller owned\n"

    def test_report_symlink_is_rejected(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        target = Path(gradle_project.path) / "elsewhere.toml"
        target.write_text("# elsewhere\n", encoding="utf-8")
        (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).symlink_to(target)
        monkeypatch.setattr(subprocess, "run", _fake_gradle(_clean_report()))

        with pytest.raises(GradleError, match="Refusing to overwrite"):
            discover_gradle_updates(gradle_project)

        assert target.read_text(encoding="utf-8") == "# elsewhere\n"

    def test_a_marked_leftover_report_is_reclaimed_not_a_collision(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        """A killed run must not brick every later scan."""
        root = Path(gradle_project.path)
        (root / GRADLE_UPDATE_REPORT_RELPATH).write_text("# stale\n", encoding="utf-8")
        (root / GRADLE_REPORT_MARKER_RELPATH).write_bytes(b"")
        monkeypatch.setattr(subprocess, "run", _fake_gradle(_clean_report()))

        assert discover_gradle_updates(gradle_project)

        assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
        assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()

    def test_a_marked_leftover_inventory_is_reclaimed(
        self, gradle_project: ProjectConfig
    ):
        root = Path(gradle_project.path)
        (root / GRADLE_INVENTORY_RELPATH).mkdir()
        (root / GRADLE_INVENTORY_MARKER_RELPATH).write_bytes(b"")
        (root / GRADLE_INVENTORY_RELPATH / "bom.json").write_text(
            "{}", encoding="utf-8"
        )

        claim_owned_dir(root / GRADLE_INVENTORY_RELPATH, "Gradle inventory directory")

        assert not (root / GRADLE_INVENTORY_RELPATH).exists()

    def test_an_unmarked_inventory_directory_is_a_collision(
        self, gradle_project: ProjectConfig
    ):
        root = Path(gradle_project.path)
        (root / GRADLE_INVENTORY_RELPATH).mkdir()
        (root / GRADLE_INVENTORY_RELPATH / "mine.json").write_text(
            "{}", encoding="utf-8"
        )

        with pytest.raises(GradleError, match="Refusing to overwrite"):
            claim_owned_dir(
                root / GRADLE_INVENTORY_RELPATH, "Gradle inventory directory"
            )

        assert (root / GRADLE_INVENTORY_RELPATH / "mine.json").is_file()

    @pytest.mark.parametrize(
        "env, local_properties, expected",
        [
            ({"ANDROID_HOME": "/opt/android"}, True, None),
            ({"ANDROID_SDK_ROOT": "/opt/android"}, True, None),
            ({}, False, None),
            ({}, True, "ANDROID_HOME or ANDROID_SDK_ROOT"),
        ],
    )
    def test_workspace_environment_reason(
        self,
        gradle_project: ProjectConfig,
        monkeypatch,
        tmp_path,
        env,
        local_properties,
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
                _fake_gradle(_clean_report(), returncode=1, stderr="boom"),
                r"failed \(exit 1\)",
            ),
            (_fake_gradle(_clean_report(), timeout=True), "timed out"),
            (
                _fake_gradle(_clean_report(), mutate_catalogue=True),
                "discovery must leave the source catalogue unchanged",
            ),
            (_fake_gradle("[libraries]\nroom-runtime = 12\n"), "malformed"),
        ],
    )
    def test_execution_and_output_failures_raise(
        self, gradle_project: ProjectConfig, monkeypatch, runner, expected
    ):
        monkeypatch.setattr(subprocess, "run", runner)

        with pytest.raises(GradleError, match=expected):
            discover_gradle_updates(gradle_project)

        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()

    def test_missing_wrapper_raises_before_any_command(
        self, gradle_project, monkeypatch
    ):
        (Path(gradle_project.path) / "gradlew").unlink()
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **k: pytest.fail("wrapper check must run first"),
        )

        with pytest.raises(GradleError, match="Gradle wrapper"):
            discover_gradle_updates(gradle_project)

    def test_invokes_the_project_wrapper_with_the_approved_arguments(
        self, gradle_project: ProjectConfig, monkeypatch
    ):
        calls: list[tuple[list[str], dict]] = []
        runner = _fake_gradle(_clean_report())

        def _record(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return runner(cmd, **kwargs)

        monkeypatch.setattr(subprocess, "run", _record)
        discover_gradle_updates(gradle_project)

        cmd, kwargs = calls[0]
        assert cmd == [
            str(Path(gradle_project.path) / "gradlew"),
            "versionCatalogUpdate",
            "--interactive",
            "--no-daemon",
            "--console=plain",
        ]
        assert Path(kwargs["cwd"]) == Path(gradle_project.path)
        assert kwargs["timeout"] == 900
        assert kwargs["stdin"] is subprocess.DEVNULL
