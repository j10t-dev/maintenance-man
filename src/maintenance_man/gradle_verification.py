import hashlib
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from maintenance_man.gradle import GradleError
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    ComparisonContext,
    ComparisonResult,
    CompleteResolution,
    GradleCandidate,
    GradleSnapshot,
    IncomparableComparison,
    RejectedComparison,
    VerifiedComparison,
)
from maintenance_man.models.scan import Severity

_MARKER = ".mm-comparison-owner"
_POLICY_FILES = ("trivy.yaml", "trivy.yml", ".trivyignore.yaml", ".trivyignore.yml")
_SEVERITY = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
    Severity.UNKNOWN: 0,
}


def _digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise GradleError(f"Comparison input is not a regular file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _policy(project: ProjectConfig) -> bytes:
    overridden = sorted(key for key in os.environ if key.startswith("TRIVY_"))
    if overridden:
        raise GradleError(
            "Automatic comparison cannot freeze Trivy environment: "
            + ", ".join(overridden)
        )
    for filename in _POLICY_FILES:
        path = Path(project.path) / filename
        if path.exists() or path.is_symlink():
            raise GradleError(
                f"Automatic comparison cannot freeze custom policy: {path}"
            )
    ignore = Path(project.path) / ".trivyignore"
    if ignore.is_symlink():
        raise GradleError("Refusing symlinked Trivy ignore input")
    return ignore.read_bytes() if ignore.exists() else b""


def _run(command: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=600
        )
    except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired) as exc:
        raise GradleError(f"Comparison context command failed: {exc}") from exc
    if result.returncode != 0:
        raise GradleError(f"Comparison context command failed: {result.stderr.strip()}")
    return result.stdout


def _database_digests(cache: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for directory in ("db", "java-db"):
        base = cache / directory
        if base.is_symlink() or not base.is_dir():
            raise GradleError(f"Missing private Trivy database: {directory}")
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise GradleError("Symlink in private Trivy database")
            if path.is_file():
                result[str(path.relative_to(cache))] = _digest(path)
    if "db/trivy.db" not in result or "java-db/trivy-java.db" not in result:
        raise GradleError("Private Trivy databases are incomplete")
    return result


def initialize_comparison_context(
    project: ProjectConfig, resolution: CompleteResolution, run_cache_parent: Path
) -> ComparisonContext:
    policy = _policy(project)
    if run_cache_parent.is_symlink():
        raise GradleError("Refusing symlinked comparison cache parent")
    run_cache_parent.mkdir(parents=True, exist_ok=True)
    cache = Path(tempfile.mkdtemp(prefix="gradle-comparison-", dir=run_cache_parent))
    token = uuid.uuid4().hex
    (cache / _MARKER).write_text(token, encoding="utf-8")
    try:
        (cache / "config.json").write_text("{}\n", encoding="utf-8")
        (cache / "ignore").write_bytes(policy)
        executable = shutil.which("trivy")
        if executable is None:
            raise GradleError("Trivy is not installed")
        executable_path = Path(executable).resolve(strict=True)
        version = _run([str(executable_path), "--version"], cache).strip()
        common = [
            str(executable_path),
            "--cache-dir",
            str(cache),
            "--config",
            str(cache / "config.json"),
        ]
        _run([*common, "image", "--download-db-only"], cache)
        _run([*common, "image", "--download-java-db-only"], cache)
        digests = _database_digests(cache)
        digests["config.json"] = _digest(cache / "config.json")
        digests["ignore"] = _digest(cache / "ignore")
        digests["binary:" + str(executable_path)] = _digest(executable_path)
        flags = (
            "sbom",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--cache-dir",
            str(cache),
            "--config",
            str(cache / "config.json"),
            "--ignorefile",
            str(cache / "ignore"),
        )
        return ComparisonContext(
            scanner_version=version,
            loaded_input_digests=digests,
            selected_scopes=resolution.report.selected_scopes,
            producer_versions=resolution.report.producer_versions,
            scanner_flags=flags,
            created_at=datetime.now(timezone.utc),
            private_cache_path=cache,
            owner_token=token,
        )
    except BaseException:
        if not cache.is_symlink() and (cache / _MARKER).read_text() == token:
            shutil.rmtree(cache)
        raise


def context_inputs_valid(
    context: ComparisonContext, project: ProjectConfig, now: datetime
) -> bool:
    if now.tzinfo is None or context.created_at.tzinfo is None:
        return False
    if not timedelta(0) <= now - context.created_at < timedelta(hours=24):
        return False
    cache = context.private_cache_path
    try:
        if cache.is_symlink() or (cache / _MARKER).is_symlink():
            return False
        if (cache / _MARKER).read_text() != context.owner_token:
            return False
        if (
            hashlib.sha256(_policy(project)).hexdigest()
            != context.loaded_input_digests["ignore"]
        ):
            return False
        actual = _database_digests(cache)
        actual["config.json"] = _digest(cache / "config.json")
        actual["ignore"] = _digest(cache / "ignore")
        for key in context.loaded_input_digests:
            if key.startswith("binary:"):
                actual[key] = _digest(Path(key.removeprefix("binary:")))
        return actual == context.loaded_input_digests
    except OSError, KeyError, GradleError:
        return False


def release_comparison_context(context: ComparisonContext) -> None:
    cache = context.private_cache_path
    if not cache.exists() and not cache.is_symlink():
        return
    marker = cache / _MARKER
    if cache.is_symlink() or marker.is_symlink() or not marker.is_file():
        raise GradleError("Refusing unowned comparison cache cleanup")
    if marker.read_text() != context.owner_token:
        raise GradleError("Comparison cache ownership changed")
    shutil.rmtree(cache)


def compare_gradle_snapshots(
    before: GradleSnapshot, after: GradleSnapshot, candidate: GradleCandidate
) -> ComparisonResult:
    if before.context_identity != after.context_identity:
        return IncomparableComparison(reasons=("scanner inputs changed",))
    left, right = before.resolution.report, after.resolution.report
    if (
        frozenset(left.selected_scopes) != frozenset(right.selected_scopes)
        or left.producer_versions != right.producer_versions
    ):
        return IncomparableComparison(reasons=("scope coverage or producer changed",))
    old = {item.key: item for item in before.findings}
    new = {item.key: item for item in after.findings}
    unknown = tuple(
        str(key)
        for key in old.keys() & new.keys()
        if (
            old[key].has_unknown != new[key].has_unknown
            or (
                (old[key].has_unknown or new[key].has_unknown)
                and old[key].severity != new[key].severity
            )
        )
    )
    if unknown:
        return IncomparableComparison(reasons=("UNKNOWN severity changed", *unknown))
    regressions = [f"new finding: {key}" for key in new.keys() - old.keys()]
    for key in old.keys() & new.keys():
        if _SEVERITY[new[key].severity] > _SEVERITY[old[key].severity]:
            regressions.append(f"severity increased: {key}")
        if len(new[key].affected_versions) > len(old[key].affected_versions):
            regressions.append(f"affected version count increased: {key}")
    if regressions:
        return RejectedComparison(reasons=tuple(sorted(regressions)))
    removed = frozenset(old.keys() - new.keys())
    requested = frozenset(
        key
        for key in old
        if key.advisory_id in candidate.requested_advisories
        and key.coordinate in candidate.requested_coordinates
    )
    if "security" in candidate.origins:
        if "ordinary" not in candidate.origins and not requested:
            return RejectedComparison(
                reasons=("candidate has no scoped requested findings",)
            )
        if "ordinary" not in candidate.origins and not requested <= removed:
            return RejectedComparison(
                reasons=("security-only candidate did not fix all requested findings",)
            )
    return VerifiedComparison(removed=removed, residual=frozenset(new))
