import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from maintenance_man.gradle import (
    GRADLE_CATALOGUE_RELPATH,
    GRADLE_INVENTORY_BOM_RELPATH,
    GRADLE_INVENTORY_MARKER_RELPATH,
    GRADLE_INVENTORY_RELPATH,
    GRADLE_REPORT_MARKER_RELPATH,
    GRADLE_UPDATE_REPORT_RELPATH,
    GradleError,
    apply_gradle_update,
    claim_owned_dir,
    discover_gradle_updates,
    generate_gradle_inventory,
    normalise_alias,
    parse_catalogue,
    render_selected_report,
    resolve_gradle_vulnerability_target,
    validate_gradle_recovery,
    validate_gradle_target,
    workspace_environment_reason,
)
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.scan import (
    GradleBlock,
    GradleMember,
    GradleUpdateTarget,
    SemverTier,
)
from tests.conftest import GRADLE_FIXTURES, make_gradle_target, make_vuln


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fake_gradle(
    report: str | None,
    *,
    returncode: int = 0,
    stdout: str = "",
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
        return subprocess.CompletedProcess(
            cmd, returncode, stdout=stdout, stderr=stderr
        )

    return _run


def _clean_report() -> str:
    return (GRADLE_FIXTURES / "updates-clean.toml").read_text(encoding="utf-8")


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
        monkeypatch.setattr(subprocess, "run", runner)

        assert discover_gradle_updates(gradle_project) == []
        assert (root / GRADLE_CATALOGUE_RELPATH).read_bytes() == before
        assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
        assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()

    @pytest.mark.parametrize(
        "runner, expected",
        [
            (
                _fake_gradle(None, stdout="Warning: " + _NO_UPDATES_OUTPUT),
                "produced no report",
            ),
            (
                _fake_gradle(None, stdout=_NO_UPDATES_OUTPUT, returncode=1),
                r"failed \(exit 1\)",
            ),
            (
                _fake_gradle(
                    None,
                    stdout=_NO_UPDATES_OUTPUT,
                    mutate_catalogue=True,
                ),
                "discovery must leave the source catalogue unchanged",
            ),
        ],
    )
    def test_no_updates_signal_cannot_hide_discovery_failures(
        self, gradle_project, monkeypatch, runner, expected
    ):
        monkeypatch.setattr(subprocess, "run", runner)

        with pytest.raises(GradleError, match=expected):
            discover_gradle_updates(gradle_project)

        root = Path(gradle_project.path)
        assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
        assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()

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


class TestGenerateGradleInventory:
    def _wrapper_writing(self, fixture: str | None, *, returncode: int = 0):
        def _run(cmd, **kwargs):
            root = Path(kwargs["cwd"])
            if fixture is not None:
                bom = root / GRADLE_INVENTORY_BOM_RELPATH
                bom.parent.mkdir(parents=True, exist_ok=True)
                bom.write_text(
                    (GRADLE_FIXTURES / fixture).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            return subprocess.CompletedProcess(
                cmd, returncode, stdout="", stderr="boom"
            )

        return _run

    def test_yields_a_validated_inventory_and_releases_it(
        self, gradle_project, monkeypatch
    ):
        calls: list[list[str]] = []

        def _record(cmd, **kwargs):
            calls.append(cmd)
            return self._wrapper_writing("bom.json")(cmd, **kwargs)

        monkeypatch.setattr(subprocess, "run", _record)
        root = Path(gradle_project.path)

        with generate_gradle_inventory(gradle_project) as bom:
            assert bom == root / GRADLE_INVENTORY_BOM_RELPATH
            assert json.loads(bom.read_text())["specVersion"] == "1.6"

        assert not (root / GRADLE_INVENTORY_RELPATH).exists()
        assert calls[0][1:] == [
            "cyclonedxBom",
            "--no-daemon",
            "--console=plain",
            "--rerun-tasks",
            "--no-build-cache",
        ]

    @pytest.mark.parametrize(
        "fixture, returncode, expected",
        [
            (None, 0, "produced no inventory"),
            ("bom-empty.json", 0, "no components"),
            ("bom-non-maven.json", 0, "no Maven components"),
            ("bom.json", 1, r"failed \(exit 1\)"),
        ],
    )
    def test_unusable_inventory_is_an_error_not_a_clean_scan(
        self, gradle_project, monkeypatch, fixture, returncode, expected
    ):
        monkeypatch.setattr(
            subprocess, "run", self._wrapper_writing(fixture, returncode=returncode)
        )

        with pytest.raises(GradleError, match=expected):
            with generate_gradle_inventory(gradle_project):
                pytest.fail("unusable inventory must not be yielded")

        assert not (Path(gradle_project.path) / GRADLE_INVENTORY_RELPATH).exists()

    @pytest.mark.parametrize(
        "spec, accepted",
        [("1.5", True), ("1.6", True), ("1.7", True), ("1.4", False), ("junk", False)],
    )
    def test_spec_version_is_a_floor_not_an_equality(
        self, gradle_project, monkeypatch, spec, accepted
    ):
        """A CycloneDX patch bump must not brick every Gradle scan."""
        document = json.loads((GRADLE_FIXTURES / "bom.json").read_text())
        document["specVersion"] = spec

        def _run(cmd, **kwargs):
            bom = Path(kwargs["cwd"]) / GRADLE_INVENTORY_BOM_RELPATH
            bom.parent.mkdir(parents=True, exist_ok=True)
            bom.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _run)

        if accepted:
            with generate_gradle_inventory(gradle_project) as bom:
                assert bom.is_file()
        else:
            with pytest.raises(GradleError, match="1.5 or later"):
                with generate_gradle_inventory(gradle_project):
                    pytest.fail("unsupported spec version must not be yielded")

    def test_malformed_inventory_json_is_an_error(self, gradle_project, monkeypatch):
        def _run(cmd, **kwargs):
            bom = Path(kwargs["cwd"]) / GRADLE_INVENTORY_BOM_RELPATH
            bom.parent.mkdir(parents=True, exist_ok=True)
            bom.write_text("{not json", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _run)

        with pytest.raises(GradleError, match="malformed CycloneDX inventory"):
            with generate_gradle_inventory(gradle_project):
                pytest.fail("unreachable")

    def test_existing_inventory_directory_is_a_collision(
        self, gradle_project, monkeypatch
    ):
        owned = Path(gradle_project.path) / GRADLE_INVENTORY_RELPATH
        owned.mkdir()
        (owned / "keep.txt").write_text("caller owned\n", encoding="utf-8")
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: pytest.fail("must refuse before running")
        )

        with pytest.raises(GradleError, match="Refusing to overwrite"):
            with generate_gradle_inventory(gradle_project):
                pytest.fail("unreachable")

        assert (owned / "keep.txt").read_text(encoding="utf-8") == "caller owned\n"

    @pytest.mark.parametrize(
        "document",
        [
            [],
            None,
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [None]},
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": {"purl": "pkg:maven/g/a@1"},
            },
        ],
    )
    def test_malformed_inventory_structure_is_a_gradle_error(
        self, gradle_project, monkeypatch, document
    ):
        def _run(cmd, **kwargs):
            bom = Path(kwargs["cwd"]) / GRADLE_INVENTORY_BOM_RELPATH
            bom.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _run)
        with pytest.raises(GradleError, match="malformed CycloneDX inventory"):
            with generate_gradle_inventory(gradle_project):
                pytest.fail("malformed inventory must not be yielded")
        assert not (Path(gradle_project.path) / GRADLE_INVENTORY_RELPATH).exists()

    @pytest.mark.parametrize("symlink_marker", [False, True])
    def test_inventory_symlinks_preserve_caller_bytes(
        self, gradle_project, monkeypatch, tmp_path, symlink_marker
    ):
        inventory = Path(gradle_project.path) / GRADLE_INVENTORY_RELPATH
        caller = tmp_path / "caller"
        caller.mkdir()
        keep = caller / "keep.txt"
        keep.write_bytes(b"caller bytes\n")
        if symlink_marker:
            inventory.mkdir()
            (inventory / "keep.txt").write_bytes(b"inventory caller bytes\n")
            (inventory / ".mm-owned").symlink_to(keep)
        else:
            inventory.symlink_to(caller, target_is_directory=True)
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: pytest.fail("must refuse before running")
        )
        with pytest.raises(GradleError, match="Refusing to overwrite"):
            with generate_gradle_inventory(gradle_project):
                pytest.fail("caller inventory must not be yielded")
        assert keep.read_bytes() == b"caller bytes\n"
        if symlink_marker:
            assert (inventory / "keep.txt").read_bytes() == b"inventory caller bytes\n"
        else:
            assert inventory.is_symlink()

    def test_body_exception_still_releases_the_inventory(
        self, gradle_project, monkeypatch
    ):
        monkeypatch.setattr(subprocess, "run", self._wrapper_writing("bom.json"))

        with pytest.raises(ValueError):
            with generate_gradle_inventory(gradle_project):
                raise ValueError("caller failed")

        assert not (Path(gradle_project.path) / GRADLE_INVENTORY_RELPATH).exists()


class TestResolveGradleVulnerabilityTarget:
    @pytest.mark.parametrize(
        "pkg_name, fixed, kind, reason_fragment",
        [
            ("com.squareup.okhttp3:okhttp", "4.12.1", "mapping", "rich version"),
            (
                "org.jetbrains:annotations",
                "24.0.0",
                "mapping",
                "no catalogue library owns",
            ),
            ("androidx.compose.ui:ui", "1.9.1", "mapping", "platform/BOM managed"),
            (
                "androidx.room:room-runtime",
                "2.8.5, 2.9.0",
                "conflict",
                "single exact fix version",
            ),
            (
                "androidx.room:room-runtime",
                ">=2.8.5",
                "conflict",
                "single exact fix version",
            ),
            (
                "com.google.devtools.ksp",
                "2.3.12",
                "mapping",
                "no catalogue library owns",
            ),
        ],
    )
    def test_unsafe_advisories_are_blocked(
        self, gradle_project, pkg_name, fixed, kind, reason_fragment
    ):
        finding = make_vuln(pkg_name=pkg_name, fixed_version=fixed)

        outcome = resolve_gradle_vulnerability_target(gradle_project, finding)

        assert isinstance(outcome, GradleBlock)
        assert outcome.kind == kind
        assert reason_fragment in outcome.reason

    def test_shared_reference_advisory_resolves_the_whole_group(self, gradle_project):
        finding = make_vuln(
            pkg_name="androidx.room:room-compiler",
            installed_version="2.8.4",
            fixed_version="2.8.5",
        )

        outcome = resolve_gradle_vulnerability_target(gradle_project, finding)

        assert isinstance(outcome, GradleUpdateTarget)
        assert outcome.version_ref == "room"
        assert outcome.target_version == "2.8.5"
        assert [m.alias for m in outcome.members] == [
            "room-runtime",
            "room-compiler",
            "room-testing",
        ]

    def test_inline_advisory_resolves_one_member(self, gradle_project):
        finding = make_vuln(
            pkg_name="com.google.code.gson:gson",
            installed_version="2.11.0",
            fixed_version="2.12.0",
        )

        outcome = resolve_gradle_vulnerability_target(gradle_project, finding)

        assert isinstance(outcome, GradleUpdateTarget)
        assert outcome.version_ref is None
        assert [m.alias for m in outcome.members] == ["gson"]


@pytest.mark.parametrize(
    "first_version, second_version, blocked",
    [
        ('version = "1.0"', 'version = "1.0"', True),
        ('version = "1.0"', 'version = "1.1"', True),
        ('version.ref = "shared-version"', 'version.ref = "shared_version"', False),
        ('version.ref = "shared-version"', 'version.ref = "independent"', True),
    ],
)
def test_advisory_mapping_distinguishes_independent_alias_identity(
    gradle_project, first_version, second_version, blocked
):
    catalogue = Path(gradle_project.path) / "gradle/libs.versions.toml"
    catalogue.write_text(
        '[versions]\nshared-version = "1.0"\nindependent = "1.0"\n'
        "[libraries]\n"
        f'first = {{ module = "g:artifact", {first_version} }}\n'
        f'second = {{ module = "g:artifact", {second_version} }}\n',
        encoding="utf-8",
    )
    outcome = resolve_gradle_vulnerability_target(
        gradle_project,
        make_vuln(pkg_name="g:artifact", installed_version="1.0", fixed_version="2.0"),
    )
    if blocked:
        assert isinstance(outcome, GradleBlock)
        assert outcome.kind == "conflict"
    else:
        assert isinstance(outcome, GradleUpdateTarget)
        assert [member.alias for member in outcome.members] == ["first", "second"]


def test_inventory_cleanup_failure_is_an_error(gradle_project, monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", TestGenerateGradleInventory()._wrapper_writing("bom.json")
    )

    def _cannot_remove(*args, **kwargs):
        if not kwargs.get("ignore_errors"):
            raise PermissionError("cleanup denied")

    monkeypatch.setattr("maintenance_man.gradle.shutil.rmtree", _cannot_remove)
    with pytest.raises(GradleError, match="cleanup denied"):
        with generate_gradle_inventory(gradle_project) as bom:
            assert bom.is_file()


def _apply_wrapper(edits: dict[str, str] | None = None, *, returncode: int = 0):
    """Substitute that performs the plugin's catalogue edit from the report."""

    def _run(cmd, **kwargs):
        root = Path(kwargs["cwd"])
        catalogue = root / "gradle" / "libs.versions.toml"
        text = catalogue.read_text(encoding="utf-8")
        for old, new in (edits or {}).items():
            text = text.replace(old, new, 1)
        catalogue.write_text(text, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, returncode, stdout="", stderr="boom")

    return _run


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


class TestValidateGradleTarget:
    def test_unchanged_catalogue_is_valid(self, gradle_project):
        assert validate_gradle_target(gradle_project, make_gradle_target()) is None

    @pytest.mark.parametrize(
        "old, new, reason_fragment",
        [
            ('room = "2.8.4"', 'room = "2.8.9"', "expected 2.8.4"),
            (
                'room-testing = { group = "androidx.room", name = '
                '"room-testing", version.ref = "room" }\n',
                "",
                "no longer declares",
            ),
            (
                'room-compiler = { group = "androidx.room", name = '
                '"room-compiler", version.ref = "room" }',
                'room-compiler = { group = "androidx.room", name = '
                '"room-compiler", version = "2.8.4" }',
                "no longer shares version reference",
            ),
            (
                'junit = { group = "junit", name = "junit", version.ref = "junit" }',
                'junit = { group = "androidx.room", name = '
                '"room-ktx", version.ref = "room" }',
                "covers a different set of aliases",
            ),
        ],
    )
    def test_drifted_catalogue_is_stale(
        self, gradle_project, old, new, reason_fragment
    ):
        catalogue = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        catalogue.write_text(
            catalogue.read_text(encoding="utf-8").replace(old, new, 1), encoding="utf-8"
        )

        block = validate_gradle_target(gradle_project, make_gradle_target())

        assert block is not None
        assert block.kind == "stale"
        assert reason_fragment in block.reason


class TestApplyGradleUpdate:
    def test_applies_the_group_and_verifies_the_semantic_change(
        self, gradle_project, monkeypatch
    ):
        catalogue = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        reports: list[str] = []
        applier = _apply_wrapper({'room = "2.8.4"': 'room = "2.8.5"'})

        def _run(cmd, **kwargs):
            report = Path(kwargs["cwd"]) / GRADLE_UPDATE_REPORT_RELPATH
            reports.append(report.read_text(encoding="utf-8"))
            return applier(cmd, **kwargs)

        monkeypatch.setattr(subprocess, "run", _run)

        assert apply_gradle_update(gradle_project, make_gradle_target()) is None
        assert 'room = "2.8.5"' in catalogue.read_text(encoding="utf-8")
        assert 'kotlin = "2.4.10"' in catalogue.read_text(encoding="utf-8")
        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()
        assert reports[0].splitlines()[0] == "[libraries]"
        assert '"room-testing" = "androidx.room:room-testing:2.8.5"' in reports[0]
        assert "kotlin" not in reports[0]

    def test_drift_before_the_report_is_written_blocks_without_running_the_task(
        self, gradle_project, monkeypatch
    ):
        catalogue = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        catalogue.write_text(
            catalogue.read_text(encoding="utf-8").replace(
                'room = "2.8.4"', 'room = "2.8.7"'
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: pytest.fail("no command may run")
        )

        block = apply_gradle_update(gradle_project, make_gradle_target())

        assert block is not None and block.kind == "stale"
        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()

    @pytest.mark.parametrize(
        "edits, returncode, expected",
        [
            ({}, 1, r"failed \(exit 1\)"),
            ({}, 0, "expected '2.8.5'"),
            (
                {
                    'room = "2.8.4"': 'room = "2.8.5"',
                    'kotlin = "2.4.10"': 'kotlin = "2.4.20"',
                },
                0,
                "unexpected change to 'kotlin-stdlib'",
            ),
            (
                {
                    'room = "2.8.4"': 'room = "2.8.5"',
                    'gson = "com.google.code.gson:gson:2.11.0"': (
                        'gson = "com.google.code.gson:gson:2.12.0"'
                    ),
                },
                0,
                "unexpected change to 'gson'",
            ),
            (
                {
                    'room = "2.8.4"': 'room = "2.8.5"',
                    'junit = { group = "junit", name = "junit", '
                    'version.ref = "junit" }\n': "",
                },
                0,
                "added or removed catalogue aliases",
            ),
        ],
    )
    def test_unsafe_application_raises_after_mutation_may_have_begun(
        self, gradle_project, monkeypatch, edits, returncode, expected
    ):
        monkeypatch.setattr(
            subprocess, "run", _apply_wrapper(edits, returncode=returncode)
        )

        with pytest.raises(GradleError, match=expected):
            apply_gradle_update(gradle_project, make_gradle_target())

        assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()

    def test_invokes_the_approved_apply_arguments(self, gradle_project, monkeypatch):
        calls: list[list[str]] = []
        applier = _apply_wrapper({'room = "2.8.4"': 'room = "2.8.5"'})

        def _run(cmd, **kwargs):
            calls.append(cmd)
            return applier(cmd, **kwargs)

        monkeypatch.setattr(subprocess, "run", _run)
        apply_gradle_update(gradle_project, make_gradle_target())

        assert calls[0][1:] == [
            "versionCatalogApplyUpdates",
            "--no-daemon",
            "--console=plain",
        ]


class TestValidateGradleRecovery:
    def test_requires_the_intended_versions_to_be_present(self, gradle_project):
        block = validate_gradle_recovery(gradle_project, make_gradle_target())

        assert block is not None and block.kind == "stale"
        assert "expected 2.8.5" in block.reason

    def test_accepts_a_completed_manual_repair(self, gradle_project):
        catalogue = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        catalogue.write_text(
            catalogue.read_text(encoding="utf-8").replace(
                'room = "2.8.4"', 'room = "2.8.5"'
            ),
            encoding="utf-8",
        )

        assert validate_gradle_recovery(gradle_project, make_gradle_target()) is None

    def test_rejects_a_different_manual_fix(self, gradle_project):
        catalogue = Path(gradle_project.path) / "gradle" / "libs.versions.toml"
        catalogue.write_text(
            catalogue.read_text(encoding="utf-8").replace(
                'room = "2.8.4"', 'room = "2.9.0"'
            ),
            encoding="utf-8",
        )

        block = validate_gradle_recovery(gradle_project, make_gradle_target())

        assert block is not None and block.kind == "stale"


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
        subprocess, "run", lambda *a, **k: pytest.fail("unsafe target must not apply")
    )
    block = apply_gradle_update(gradle_project, target)
    assert block is not None
    assert block.kind == "stale"


@pytest.mark.parametrize(
    "old, new",
    [
        ('room = ["room-runtime"]', 'room = ["gson"]'),
        ('strictly = "1.0"', 'strictly = "2.0"'),
    ],
)
def test_application_preserves_bundles_and_rich_declarations(
    gradle_project, monkeypatch, old, new
):
    catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        catalogue.read_text()
        + '\n[bundles]\nroom = ["room-runtime"]\n\n[versions.rich]\nstrictly = "1.0"\n'
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        _apply_wrapper({'room = "2.8.4"': 'room = "2.8.5"', old: new}),
    )
    with pytest.raises(GradleError):
        apply_gradle_update(gradle_project, make_gradle_target())


def test_apply_execution_oserror_is_an_adapter_error(gradle_project, monkeypatch):
    def unavailable(cmd, **kwargs):
        raise OSError("wrapper unavailable")

    monkeypatch.setattr(subprocess, "run", unavailable)
    with pytest.raises(GradleError, match="wrapper unavailable"):
        apply_gradle_update(gradle_project, make_gradle_target())


@pytest.mark.parametrize("operation", ["inventory", "discovery"])
def test_missing_wrapper_interpreter_is_gradle_error_and_cleans_owned_artifacts(
    gradle_project, operation
):
    root = Path(gradle_project.path)
    (root / "gradlew").write_text("#!/definitely/missing/mm-interpreter\n")
    with pytest.raises(GradleError, match=r"gradlew.*No such file"):
        if operation == "inventory":
            with generate_gradle_inventory(gradle_project):
                pytest.fail("unlaunchable wrapper cannot yield inventory")
        else:
            discover_gradle_updates(gradle_project)
    assert not (root / GRADLE_INVENTORY_RELPATH).exists()
    assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
    assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()


def test_prospective_workspace_properties_are_not_sdk_evidence(
    gradle_project, tmp_path, monkeypatch
):
    monkeypatch.setattr("maintenance_man.gradle.project_env", lambda: {})
    source = Path(gradle_project.path)
    (source / "local.properties").write_text("sdk.dir=/opt/android\n")
    workspace = tmp_path / "leftover"
    workspace.mkdir()
    (workspace / "local.properties").write_text("sdk.dir=/opt/android\n")
    assert workspace_environment_reason(source, workspace) is not None


@pytest.mark.parametrize("outputs", [True, False])
def test_reclaim_owned_outputs_preserves_unrelated_build_files(gradle_project, outputs):
    from maintenance_man.gradle import reclaim_gradle_outputs

    root = Path(gradle_project.path)
    inventory = root / GRADLE_INVENTORY_RELPATH
    inventory.mkdir()
    (root / GRADLE_INVENTORY_MARKER_RELPATH).write_bytes(b"")
    (root / GRADLE_REPORT_MARKER_RELPATH).write_bytes(b"")
    if outputs:
        (root / GRADLE_UPDATE_REPORT_RELPATH).write_bytes(b"generated report")
        (inventory / "bom.json").write_bytes(b"generated inventory")
    build = root / "build"
    build.mkdir()
    (build / "caller.txt").write_bytes(b"caller build output")
    reclaim_gradle_outputs(root)
    assert not inventory.exists()
    assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
    assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()
    assert (build / "caller.txt").read_bytes() == b"caller build output"


@pytest.mark.parametrize("owned_path", ["report", "inventory"])
def test_reclaim_unmarked_outputs_preserves_caller_bytes(gradle_project, owned_path):
    from maintenance_man.gradle import reclaim_gradle_outputs

    root = Path(gradle_project.path)
    path = root / (
        GRADLE_UPDATE_REPORT_RELPATH
        if owned_path == "report"
        else GRADLE_INVENTORY_RELPATH
    )
    if owned_path == "inventory":
        path.mkdir()
        path = path / "caller.json"
    path.write_bytes(b"caller bytes")
    with pytest.raises(GradleError, match="Refusing to overwrite"):
        reclaim_gradle_outputs(root)
    assert path.read_bytes() == b"caller bytes"


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
    monkeypatch.setattr(subprocess, "run", _fake_gradle(report))
    findings = discover_gradle_updates(gradle_project)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.gradle_target is not None
    assert {(m.kind, m.alias) for m in finding.gradle_target.members} == {
        ("library", "same"),
        ("plugin", "same"),
    }
    if complete:
        assert finding.blocked_reason is None
        assert finding.gradle_target.target_version == "1.0.1"
    else:
        assert finding.gradle_block_kind == "conflict"
        assert finding.blocked_reason and "plugin" in finding.blocked_reason
        assert finding.gradle_target.target_version == "1.0.0"


@pytest.mark.parametrize("operation", ["discovery", "apply", "inventory"])
@pytest.mark.parametrize("parent", ["gradle", "project"])
def test_owned_output_parent_symlink_refuses_before_external_mutation(
    gradle_project, tmp_path, monkeypatch, operation, parent
):
    root = Path(gradle_project.path)
    if parent == "gradle":
        original = root / "gradle"
        outside = tmp_path / "outside-gradle"
        original.rename(outside)
        original.symlink_to(outside, target_is_directory=True)
    else:
        original = tmp_path / "project-symlink"
        original.symlink_to(root, target_is_directory=True)
        gradle_project = gradle_project.model_copy(update={"path": original})
        outside = root / "gradle"
    report = outside / "libs.versions.updates.toml"
    marker = outside / ".mm-owned-report"
    report.write_bytes(b"external report bytes")
    marker.write_bytes(b"external marker bytes")
    commands = []

    def run(cmd, **kwargs):
        commands.append(cmd)
        return subprocess.CompletedProcess(
            cmd, 1, stdout="", stderr="unexpected command"
        )

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(GradleError):
        if operation == "discovery":
            discover_gradle_updates(gradle_project)
        elif operation == "apply":
            apply_gradle_update(gradle_project, make_gradle_target())
        else:
            with generate_gradle_inventory(gradle_project):
                pytest.fail("symlink parent cannot yield inventory")
    assert commands == []
    assert report.read_bytes() == b"external report bytes"
    assert marker.read_bytes() == b"external marker bytes"
    assert original.is_symlink()


def test_discovery_keeps_active_owned_inventory_context(gradle_project, monkeypatch):
    root = Path(gradle_project.path)

    def run(cmd, **kwargs):
        if cmd[1] == "cyclonedxBom":
            (root / GRADLE_INVENTORY_BOM_RELPATH).write_bytes(
                (GRADLE_FIXTURES / "bom.json").read_bytes()
            )
        else:
            assert cmd[1] == "versionCatalogUpdate"
            (root / GRADLE_UPDATE_REPORT_RELPATH).write_text(_clean_report())
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    with generate_gradle_inventory(gradle_project) as bom:
        before = bom.read_bytes()
        assert discover_gradle_updates(gradle_project)
        assert bom.read_bytes() == before
        assert (root / GRADLE_INVENTORY_MARKER_RELPATH).is_file()
    assert not (root / GRADLE_INVENTORY_RELPATH).exists()


def test_report_cleanup_rechecks_parent_after_wrapper_launch(
    gradle_project, tmp_path, monkeypatch
):
    root = Path(gradle_project.path)
    outside = tmp_path / "outside"
    outside.mkdir()
    report = outside / "libs.versions.updates.toml"
    marker = outside / ".mm-owned-report"
    report.write_bytes(b"external report")
    marker.write_bytes(b"external marker")

    def run(cmd, **kwargs):
        (root / "gradle").rename(tmp_path / "original-gradle")
        (root / "gradle").symlink_to(outside, target_is_directory=True)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="wrapper failed")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(GradleError):
        discover_gradle_updates(gradle_project)
    assert report.exists()
    assert report.read_bytes() == b"external report"
    assert marker.read_bytes() == b"external marker"


@pytest.mark.parametrize("phase", ["mkdir", "marker", "claim"])
def test_inventory_setup_filesystem_error_is_gradle_error_and_cleans_new_directory(
    gradle_project, monkeypatch, phase
):
    root = Path(gradle_project.path)
    inventory = root / GRADLE_INVENTORY_RELPATH
    marker = root / GRADLE_INVENTORY_MARKER_RELPATH
    if phase == "claim":
        inventory.mkdir()
        marker.write_bytes(b"")
        (inventory / "bom.json").write_bytes(b"old inventory")

        def fail(*args, **kwargs):
            raise PermissionError("claim denied")

        monkeypatch.setattr("maintenance_man.gradle.shutil.rmtree", fail)
    elif phase == "mkdir":
        mkdir = Path.mkdir

        def fail(path, *args, **kwargs):
            if path == inventory:
                raise PermissionError("mkdir denied")
            return mkdir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", fail)
    else:
        write = Path.write_bytes

        def fail(path, content):
            if path == marker:
                raise PermissionError("marker denied")
            return write(path, content)

        monkeypatch.setattr(Path, "write_bytes", fail)

    def forbidden(*args, **kwargs):
        pytest.fail("setup failure must not launch wrapper")

    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(GradleError, match="denied"):
        with generate_gradle_inventory(gradle_project):
            pytest.fail("setup failure must not yield")
    if phase == "claim":
        assert (inventory / "bom.json").read_bytes() == b"old inventory"
        assert marker.exists()
    else:
        assert not inventory.exists()


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
                raise PermissionError("report marker denied")
            return write(path, content)

        monkeypatch.setattr(Path, "write_bytes", fail)
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *args, **kwargs: pytest.fail("marker failure must not launch"),
        )
    else:
        unlink = Path.unlink

        def fail(path, *args, **kwargs):
            if path == report:
                raise PermissionError("report unlink denied")
            return unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail)
        monkeypatch.setattr(subprocess, "run", _fake_gradle(_clean_report()))
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


@pytest.mark.parametrize("resource", ["inventory", "report"])
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
    from maintenance_man.gradle import _owned_update_report

    root = Path(gradle_project.path)
    monkeypatch.setattr(
        subprocess, "run", TestGenerateGradleInventory()._wrapper_writing("bom.json")
    )
    context = (
        generate_gradle_inventory(gradle_project)
        if resource == "inventory"
        else _owned_update_report(root)
    )
    with pytest.raises(type(exception)) as caught:
        with context as output:
            if resource == "report":
                output.write_bytes(b"owned report")
            raise exception
    assert caught.value is exception
    assert not (root / GRADLE_INVENTORY_RELPATH).exists()
    assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
    assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()


@pytest.mark.parametrize("read", ["digest", "report", "inventory"])
def test_adapter_filesystem_read_failure_is_actionable_and_releases_outputs(
    gradle_project, monkeypatch, read
):
    root = Path(gradle_project.path)
    if read == "inventory":
        monkeypatch.setattr(
            subprocess,
            "run",
            TestGenerateGradleInventory()._wrapper_writing("bom.json"),
        )
    else:
        monkeypatch.setattr(subprocess, "run", _fake_gradle(_clean_report()))
    method = Path.read_bytes if read == "digest" else Path.read_text
    blocked = root / (
        GRADLE_CATALOGUE_RELPATH
        if read == "digest"
        else GRADLE_UPDATE_REPORT_RELPATH
        if read == "report"
        else GRADLE_INVENTORY_BOM_RELPATH
    )

    def fail(path, *args, **kwargs):
        if path == blocked:
            raise PermissionError("read denied")
        return method(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes" if read == "digest" else "read_text", fail)
    with pytest.raises(GradleError, match="read denied"):
        if read == "inventory":
            with generate_gradle_inventory(gradle_project):
                pytest.fail("failed validation must not yield")
        else:
            discover_gradle_updates(gradle_project)
    assert not (root / GRADLE_INVENTORY_RELPATH).exists()
    assert not (root / GRADLE_UPDATE_REPORT_RELPATH).exists()
    assert not (root / GRADLE_REPORT_MARKER_RELPATH).exists()


@pytest.mark.parametrize("reverse", [False, True])
def test_shared_target_non_advisory_installed_history_mismatch_blocks_manual_recovery(
    gradle_project, reverse
):
    target = make_gradle_target()
    target.members[1].installed_version = "9.9.9"
    if reverse:
        target.members.reverse()
    catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        catalogue.read_text().replace('room = "2.8.4"', 'room = "2.8.5"')
    )
    block = validate_gradle_recovery(gradle_project, target)
    assert block is not None
    assert block.kind == "stale"
    assert "installed" in block.reason


@pytest.mark.parametrize("consistent", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_library_plugin_shared_history_validates_before_manual_recovery(
    gradle_project, consistent, reverse
):
    root = Path(gradle_project.path)
    catalogue = root / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(
        '[versions]\nshared = "1.0.0"\n'
        '[libraries]\nruntime = { module = "org.example:library", '
        'version.ref = "shared" }\n'
        '[plugins]\nbuild = { id = "org.example.plugin", version.ref = "shared" }\n'
    )
    vuln = make_vuln(
        pkg_name="org.example:library", installed_version="1.0.0", fixed_version="1.0.1"
    )
    target = resolve_gradle_vulnerability_target(gradle_project, vuln)
    assert isinstance(target, GradleUpdateTarget)
    if not consistent:
        target.members[1].installed_version = "9.9.9"
    if reverse:
        target.members.reverse()
    target = GradleUpdateTarget.model_validate(target.model_dump())
    catalogue.write_text(
        catalogue.read_text().replace('shared = "1.0.0"', 'shared = "1.0.1"')
    )
    block = validate_gradle_recovery(gradle_project, target)
    if consistent:
        assert block is None
    else:
        assert block is not None and block.kind == "stale"
        assert "installed" in block.reason


@pytest.mark.parametrize("table", ["libraries", "plugins", "versions"])
@pytest.mark.parametrize("value", ["false", "[]", "''"])
def test_present_falsey_catalogue_table_is_not_defaulted(gradle_project, table, value):
    catalogue = Path(gradle_project.path) / GRADLE_CATALOGUE_RELPATH
    catalogue.write_text(f"{table} = {value}\n")
    with pytest.raises(GradleError, match="table"):
        parse_catalogue(catalogue)


@pytest.mark.parametrize("table", ["libraries", "plugins"])
@pytest.mark.parametrize("value", ["false", "[]", "''"])
def test_present_falsey_report_table_is_not_a_clean_discovery(
    gradle_project, monkeypatch, table, value
):
    monkeypatch.setattr(subprocess, "run", _fake_gradle(f"{table} = {value}\n"))
    with pytest.raises(GradleError, match="table"):
        discover_gradle_updates(gradle_project)
    assert not (Path(gradle_project.path) / GRADLE_UPDATE_REPORT_RELPATH).exists()


def test_wrapper_output_decode_failure_is_gradle_error(gradle_project, monkeypatch):
    def run(*args, **kwargs):
        raise UnicodeDecodeError("utf8", b"\xff", 0, 1, "invalid")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(GradleError, match="gradlew"):
        discover_gradle_updates(gradle_project)
    assert not (Path(gradle_project.path) / GRADLE_REPORT_MARKER_RELPATH).exists()


@pytest.mark.parametrize("parser", ["catalogue", "report"])
def test_toml_invalid_utf8_is_gradle_error(tmp_path, parser):
    from maintenance_man.gradle import parse_update_report

    path = tmp_path / "invalid.toml"
    path.write_bytes(b"\xff")
    with pytest.raises(GradleError):
        (parse_catalogue if parser == "catalogue" else parse_update_report)(path)
