"""Gradle report fixtures and a runner that writes their owned outputs."""

import hashlib
import json
import tomllib
from pathlib import Path

from maintenance_man.gradle import (
    GRADLE_INVENTORY_BOM_RELPATH,
    GRADLE_INVENTORY_MARKER_RELPATH,
    GRADLE_INVENTORY_RELPATH,
    GRADLE_UPDATE_REPORT_RELPATH,
    GradleError,
)
from tests.support.process import completed
from tests.support.projects import FIXTURES_DIR


def report_payload():
    """Read a fresh copy of the empty Gradle resolution report."""
    return json.loads(FIXTURE.read_text())


def fixture_runner(root, args, *, label):
    """Write the report and inventory expected from an owned Gradle report command."""
    assert args[0] == "mmGradleReport"
    assert "--rerun-tasks" in args and "--no-build-cache" in args
    owned = root / GRADLE_INVENTORY_RELPATH
    assert (root / GRADLE_INVENTORY_MARKER_RELPATH).is_file()
    assert (owned / "gradle-report.gradle").read_text().startswith("import ")
    (root / GRADLE_INVENTORY_BOM_RELPATH).write_text(
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
    return completed(tuple(args))


def catalogue_apply_runner(edits: dict[str, str] | None = None, *, returncode: int = 0):
    """Stand in for versionCatalogApplyUpdates: apply the given literal catalogue
    edits, or with no edits, move every version reference the selected update
    report names to its proposed version."""

    def _run(cmd, cwd, **kwargs):
        root = Path(cwd)
        catalogue = root / "gradle" / "libs.versions.toml"
        text = catalogue.read_text(encoding="utf-8")
        if edits is None:
            text = _apply_report(root / GRADLE_UPDATE_REPORT_RELPATH, text)
        else:
            for old, new in edits.items():
                text = text.replace(old, new, 1)
        catalogue.write_text(text, encoding="utf-8")
        if returncode:
            msg = f"{kwargs['label']} failed (exit {returncode})"
            raise GradleError(msg)
        return completed(cmd, returncode=0, stdout="", stderr="")

    return _run


def catalogue_apply_task(edits: dict[str, str] | None = None):
    """Stand in for run_gradle's versionCatalogApplyUpdates, editing the catalogue
    as catalogue_apply_runner does."""
    apply = catalogue_apply_runner(edits)

    def run(root, args, *, label=None):
        return apply(
            [str(root / "gradlew"), *args], root, label=f"./gradlew {label or args[0]}"
        )

    return run


def _apply_report(report: Path, text: str) -> str:
    updates = tomllib.loads(report.read_text(encoding="utf-8"))
    catalogue = tomllib.loads(text)
    for section in ("libraries", "plugins"):
        for alias, notation in updates.get(section, {}).items():
            ref = catalogue[section][alias]["version"]["ref"]
            old = catalogue["versions"][ref]
            new = notation.rsplit(":", 1)[1]
            text = text.replace(f'{ref} = "{old}"', f'{ref} = "{new}"', 1)
    return text


GRADLE_FIXTURES = FIXTURES_DIR / "gradle"


FIXTURE = GRADLE_FIXTURES / "resolution" / "empty.json"
