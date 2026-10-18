"""Gradle report fixtures and a runner that writes their owned outputs."""

import json
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path

from maintenance_man.gradle import GRADLE_UPDATE_REPORT_RELPATH, GradleError
from maintenance_man.gradle_resolution import GRADLE_REPORT_DIRECTORY_PROPERTY
from maintenance_man.models.gradle import (
    GradleCandidate,
    LocalProjectIdentity,
    ModuleId,
    PublicationRequest,
    RepositoryDeclaration,
    ResolutionEdge,
    ResolutionReport,
    ResolvedComponent,
    ScopeId,
    ScopeResolution,
)
from maintenance_man.models.scan import GradleUpdateTarget
from tests.support.findings import make_gradle_target
from tests.support.process import completed
from tests.support.projects import FIXTURES_DIR


def make_gradle_candidate(
    target: GradleUpdateTarget | None = None,
    vulnerability_indices: tuple[int, ...] = (),
    publication_requests: tuple[PublicationRequest, ...] = (),
) -> GradleCandidate:
    """Build an ordinary candidate for *target*, with scenario-specific overrides."""
    return GradleCandidate(
        target=target or make_gradle_target(),
        vulnerability_indices=vulnerability_indices,
        publication_requests=publication_requests,
    )


def make_resolution_report(
    *,
    scopes: Mapping[str, Sequence[str]],
    repositories: Sequence[RepositoryDeclaration] = (),
    local_projects: Sequence[LocalProjectIdentity] = (),
) -> ResolutionReport:
    """A complete report with one runtime scope per project path in *scopes*; each
    listed ``group:artifact:version`` is resolved directly from that scope's root."""
    results = []
    for project_path, coordinates in scopes.items():
        components = [ResolvedComponent(id="root", kind="root", module=None)]
        edges = []
        for number, coordinate in enumerate(coordinates):
            group, artifact, version = coordinate.split(":")
            module = ModuleId(group=group, artifact=artifact, version=version)
            components.append(
                ResolvedComponent(id=str(number), kind="module", module=module)
            )
            edges.append(
                ResolutionEdge(
                    source="root",
                    target=str(number),
                    requested=coordinate,
                    constraint=False,
                )
            )
        scope = ScopeId(
            project_path=project_path,
            domain="project",
            configuration="runtimeClasspath",
        )
        results.append(
            ScopeResolution(
                scope=scope,
                components=tuple(components),
                edges=tuple(edges),
                unresolved=(),
            )
        )
    return ResolutionReport(
        schema_version=1,
        repositories=tuple(repositories),
        selected_scopes=tuple(result.scope for result in results),
        scopes=tuple(results),
        local_projects=tuple(local_projects),
    )


def report_payload():
    """Read a fresh copy of the empty Gradle resolution report."""
    return json.loads(FIXTURE.read_text())


def report_directory(args: Sequence[str]) -> Path:
    """The report directory an init-script task received as its Gradle property."""
    prefix = f"-P{GRADLE_REPORT_DIRECTORY_PROPERTY}="
    return Path(
        next(arg.removeprefix(prefix) for arg in args if arg.startswith(prefix))
    )


def fixture_runner(root, args, *, label):
    """Write the report and inventory expected from a Gradle report command."""
    assert args[0] == "mmGradleReport"
    assert "--rerun-tasks" in args and "--no-build-cache" in args
    directory = report_directory(args)
    assert (directory / "gradle-report.gradle").read_text().startswith("import ")
    (directory / "bom.json").write_text(
        '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"group":"g","name":"a","version":"1.0","purl":"pkg:maven/g/a@1.0"}]}'
    )
    value = report_payload()
    value["scopes"][0]["components"].append(
        {
            "id": "a",
            "kind": "module",
            "module": {"group": "g", "artifact": "a", "version": "1.0"},
        }
    )
    value["scopes"][0]["edges"].append(
        {"source": "root", "target": "a", "requested": "g:a:1.0", "constraint": False}
    )
    (directory / "report.json").write_text(json.dumps(value))
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
