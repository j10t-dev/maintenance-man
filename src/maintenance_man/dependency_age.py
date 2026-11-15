"""Release dates for the age policy:
exact Maven POMs (mvn and Gradle), PyPI JSON and `bun info`."""

import functools
import hashlib
import http.client
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Literal, Self

from packaging.utils import canonicalize_name
from packaging.version import Version
from pydantic import BaseModel, ConfigDict, StrictStr

from maintenance_man.clock import Clock, utc_now
from maintenance_man.models.gradle import (
    AgeBlock,
    GradleCandidate,
    ModuleId,
    PublicationEvidence,
    PublicationFact,
    PublicationRequest,
    RepositoryDeclaration,
    RepositoryId,
    UtcDatetime,
)
from maintenance_man.models.scan import GradleMember, UpdateFinding
from maintenance_man.process import ProcessError, run_captured
from maintenance_man.storage import atomic_write_text

type Transport = Callable[[str, str, str], tuple[bytes, Mapping[str, str], str] | None]
type _CacheKey = tuple[str | int, ...]


class PublicationLookupContext:
    """Publication lookups for one scan: eight workers, an in-flight table per
    fact kind, and the 24-hour cache under *cache_dir* for Maven and PyPI facts."""

    def __init__(
        self,
        cache_dir: Path,
        transport: Transport | None = None,
        clock: Clock = utc_now,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.transport = transport or _publication_http
        self.clock = clock
        self.pool = ThreadPoolExecutor(max_workers=8)
        self.lock = threading.Lock()
        self.maven: dict[_CacheKey, Future[PublicationFact | AgeBlock | None]] = {}
        self.registry: dict[_CacheKey, Future[RegistryFact | AgeBlock | None]] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.pool.shutdown(wait=True, cancel_futures=True)

    def submit(
        self, repository: RepositoryId, module: ModuleId
    ) -> Future[PublicationFact | AgeBlock | None]:
        """Schedule one exact POM lookup; a repeated lookup shares its future."""
        return self._schedule(
            self.maven,
            _maven_key(repository, module),
            f"{module.coordinate}:{module.version}",
            PublicationFact,
            functools.partial(self._maven_fact, repository, module),
        )

    def submit_registry(
        self, registry: Registry, package: str, version: str, project_path: Path
    ) -> Future[RegistryFact | AgeBlock | None]:
        """Schedule one exact registry lookup; npm runs `bun info` in
        *project_path* and is never cached."""
        lookup = (
            functools.partial(self._pypi_fact, package, version)
            if registry == "pypi"
            else functools.partial(self._npm_fact, package, version, project_path)
        )
        return self._schedule(
            self.registry,
            _registry_key(registry, package, version),
            f"{package}:{version}",
            RegistryFact if registry == "pypi" else None,
            lookup,
        )

    def prefetch(self, requests: Iterable[PublicationRequest]) -> None:
        """Schedule every routable module in the publication requests."""
        for request in requests:
            for module in (request.module, request.marker_implementation):
                if not (request.routing_supported and module is not None):
                    continue
                for repository in request.repositories:
                    self.submit(repository, module)

    def _schedule[F: (PublicationFact, RegistryFact)](
        self,
        table: dict[_CacheKey, Future[F | AgeBlock | None]],
        key: _CacheKey,
        label: str,
        cached: type[F] | None,
        lookup: Callable[[], F | None],
    ) -> Future[F | AgeBlock | None]:
        with self.lock:
            if key not in table:
                table[key] = self.pool.submit(
                    functools.partial(self._run, key, label, cached, lookup)
                )
            return table[key]

    def _run[F: (PublicationFact, RegistryFact)](
        self,
        key: _CacheKey,
        label: str,
        cached: type[F] | None,
        lookup: Callable[[], F | None],
    ) -> F | AgeBlock | None:
        try:
            fact = self._cached(key, cached) if cached is not None else None
            if fact is not None:
                return fact
            fact = lookup()
            if fact is None:
                return None
            if fact.timestamp > self.clock():
                msg = "future publication timestamp"
                raise PublicationError(msg)
            if cached is not None:
                self._store(key, fact)
            return fact
        except _LOOKUP_ERRORS as error:
            reason = (
                str(error)
                if isinstance(error, PublicationError)
                else "publication lookup failed"
            )
            return AgeBlock(reason=f"{label}: {reason}")

    def _cached[F: (PublicationFact, RegistryFact)](
        self, key: _CacheKey, model: type[F]
    ) -> F | None:
        try:
            fact = model.model_validate_json(self._path(key).read_bytes())
        except OSError, ValueError:
            return None
        if (
            _fact_key(fact) != key
            or fact.timestamp > self.clock()
            or not timedelta(0) <= self.clock() - fact.checked_at < timedelta(hours=24)
        ):
            return None
        return fact

    def _store(self, key: _CacheKey, fact: PublicationFact | RegistryFact) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            atomic_write_text(self._path(key), fact.model_dump_json())
        except OSError:
            return

    def _path(self, key: _CacheKey) -> Path:
        digest = hashlib.sha256(json.dumps(key).encode()).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _maven_fact(
        self, repository: RepositoryId, module: ModuleId
    ) -> PublicationFact | None:
        suffix = _artifact_suffix(module)
        response = self.transport(f"{_ROOTS[repository]}/{suffix}", repository, suffix)
        if response is None:
            return None
        body, headers, final_url = response
        _public_url(final_url, repository, suffix)
        implementation = _pom_identity(body, module)
        return PublicationFact(
            repository=repository,
            module=module,
            artifact_digest=hashlib.sha256(body).hexdigest(),
            timestamp=_last_modified(headers),
            checked_at=self.clock(),
            implementation=implementation,
        )

    def _pypi_fact(self, package: str, version: str) -> RegistryFact | None:
        quote = functools.partial(urllib.parse.quote, safe="")
        suffix = f"pypi/{quote(package)}/{quote(version)}/json"
        url = f"https://pypi.org/{suffix}"
        response = self.transport(url, "pypi", suffix)
        if response is None:
            return None
        body, _, final_url = response
        if final_url != url:
            msg = "PyPI response URL changed"
            raise PublicationError(msg)
        return RegistryFact(
            registry="pypi",
            package=package,
            version=version,
            timestamp=_pypi_upload_time(body, package, version),
            checked_at=self.clock(),
        )

    def _npm_fact(
        self, package: str, version: str, project_path: Path
    ) -> RegistryFact | None:
        timestamp = _npm_timestamp(package, version, project_path)
        if timestamp is None:
            return None
        return RegistryFact(
            registry="npm",
            package=package,
            version=version,
            timestamp=timestamp,
            checked_at=self.clock(),
        )


def filter_registry_updates_by_age(
    updates: list[UpdateFinding],
    source: PublicationSource,
    project_path: Path,
    min_age_days: int,
    context: PublicationLookupContext,
) -> list[UpdateFinding]:
    """Drop updates whose known release is younger than *min_age_days*; an unknown
    date keeps the update eligible and undated. Every lookup is submitted before
    any result is awaited."""
    if not updates or min_age_days == 0:
        return list(updates)
    cutoff = context.clock() - timedelta(days=min_age_days)
    pending = [
        (update, _release_lookup(update, source, project_path, context))
        for update in updates
    ]
    kept = []
    for update, future in pending:
        result = future.result() if future is not None else None
        published = (
            result.timestamp
            if isinstance(result, PublicationFact | RegistryFact)
            else None
        )
        if published is None or published <= cutoff:
            kept.append(update.model_copy(update={"published_date": published}))
    return kept


def publication_request(
    module: ModuleId,
    repositories: Sequence[RepositoryDeclaration],
    *,
    implementation: ModuleId | None = None,
) -> PublicationRequest:
    """Build a ``PublicationRequest`` from resolved repository declarations.

    Any repository outside the trusted roots withholds routing support for
    the whole request rather than silently dropping it.
    """
    ids = tuple(trusted_repository(r.url) for r in repositories)
    return PublicationRequest(
        module=module,
        repositories=tuple(dict.fromkeys(r for r in ids if r)),
        routing_supported=bool(ids) and all(ids),
        marker_implementation=implementation,
    )


def evaluate_gradle_candidate_age(
    candidate: GradleCandidate,
    minimum_age_days: int,
    context: PublicationLookupContext,
    now: datetime,
) -> AgeBlock | datetime:
    """Return an ``AgeBlock`` unless every publication request is proven old enough,
    else the youngest evidence timestamp across the requests.

    Exact-artifact evidence is required even when ``minimum_age_days`` is zero:
    an unresolved lookup withholds the candidate rather than passing it.
    """
    requests = candidate.publication_requests
    if not requests:
        return AgeBlock(reason="candidate has no publication requests")
    timestamps = []
    for request in requests:
        result = lookup_gradle_publication(request, context)
        if isinstance(result, AgeBlock):
            return result
        if minimum_age_days and result.timestamp > now - timedelta(
            days=minimum_age_days
        ):
            return AgeBlock(
                reason=f"publication younger than required {minimum_age_days} days"
            )
        timestamps.append(result.timestamp)
    return max(timestamps)


def member_module(member: GradleMember, version: str) -> ModuleId | None:
    """Return the Maven module published for a valid Gradle member."""
    if member.kind == "plugin":
        return ModuleId(
            group=member.coordinate,
            artifact=f"{member.coordinate}.gradle.plugin",
            version=version,
        )
    return _maven_module(member.coordinate, version)


def lookup_gradle_publication(
    request: PublicationRequest, context: PublicationLookupContext
) -> AgeBlock | PublicationEvidence:
    """Resolve *request* to aggregate evidence, or an ``AgeBlock`` withholding it."""
    if not request.routing_supported or not request.repositories:
        return AgeBlock(reason="unsupported or missing scoped repository routing")
    modules = [request.module]
    if request.marker_implementation is not None:
        modules.append(request.marker_implementation)
    futures = [
        (module, context.submit(repository, module))
        for module in modules
        for repository in request.repositories
    ]
    facts = []
    for module, future in futures:
        result = future.result()
        if isinstance(result, AgeBlock):
            return result
        if result is not None:
            if (
                module == request.module
                and result.implementation != request.marker_implementation
            ):
                return AgeBlock(
                    reason="marker implementation disagrees with native resolution"
                )
            facts.append(result)
    for module in modules:
        selected = [fact for fact in facts if fact.module == module]
        if not selected:
            return AgeBlock(
                reason=f"no trusted exact POM for {module.coordinate}:{module.version}"
            )
        if len({fact.artifact_digest for fact in selected}) != 1:
            return AgeBlock(
                reason=(
                    f"conflicting artifact content for "
                    f"{module.coordinate}:{module.version}"
                )
            )
    return PublicationEvidence(facts=tuple(facts))


def trusted_repository(url: str | None) -> RepositoryId | None:
    """Return the trust-policy repository id for an exact-root URL, or None."""
    if url is None:
        return None
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return None
    return _ALIASES.get(url.rstrip("/"))


type Registry = Literal["pypi", "npm"]
"""A package registry dated by its own release API; Maven repositories are not
registries."""

type PublicationSource = Registry | Literal["central"]
"""Where an update's release date comes from: a registry, or Maven Central's
exact POM."""


class RegistryFact(BaseModel):
    """One registry release's publication time; unlike a Maven fact it has no
    content digest, and npm facts are never written to the cache."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    registry: Registry
    package: str
    version: str
    timestamp: UtcDatetime
    checked_at: UtcDatetime


class PublicationError(Exception):
    """Publication evidence could not be trusted or obtained."""


_LOOKUP_ERRORS = (
    http.client.HTTPException,
    OSError,
    ValueError,
    OverflowError,
    KeyError,
    TypeError,
    ET.ParseError,
    urllib.error.URLError,
    PublicationError,
    ProcessError,
)

_ROOTS = {
    "central": "https://repo.maven.apache.org/maven2",
    "google": "https://dl.google.com/dl/android/maven2",
    "portal": "https://plugins.gradle.org/m2",
}
_ALIASES: dict[str, RepositoryId] = {
    "https://repo.maven.apache.org/maven2": "central",
    "https://repo1.maven.org/maven2": "central",
    "https://dl.google.com/dl/android/maven2": "google",
    "https://maven.google.com": "google",
    "https://plugins.gradle.org/m2": "portal",
}
_TRUSTED_HOSTS = {
    "central": {"repo.maven.apache.org", "repo1.maven.org"},
    "google": {"dl.google.com"},
    "pypi": {"pypi.org"},
    "portal": {
        "plugins.gradle.org",
        "plugins-artifacts.gradle.org",
        "repo.maven.apache.org",
        "repo1.maven.org",
    },
}
_MAX_BYTES = 1024 * 1024


def _maven_key(repository: RepositoryId, module: ModuleId) -> _CacheKey:
    """The cache identity of one exact POM's fact."""
    return (
        1,
        repository,
        module.group,
        module.artifact,
        module.version,
        "last_modified",
    )


def _registry_key(registry: Registry, package: str, version: str) -> _CacheKey:
    """The cache identity of one registry release's fact."""
    return ("registry", registry, package, version)


def _fact_key(fact: PublicationFact | RegistryFact) -> _CacheKey:
    if isinstance(fact, PublicationFact):
        return _maven_key(fact.repository, fact.module)
    return _registry_key(fact.registry, fact.package, fact.version)


def _artifact_suffix(module: ModuleId) -> str:
    """Return the exact Maven-layout POM path for *module*."""
    parts = (module.group, module.artifact, module.version)
    if any(
        not p or "/" in p or "\\" in p or "${" in p or p in (".", "..") for p in parts
    ):
        msg = "unsupported artifact identity"
        raise PublicationError(msg)
    quote = functools.partial(urllib.parse.quote, safe="")
    return "/".join(
        [
            *(quote(p) for p in module.group.split(".")),
            quote(module.artifact),
            quote(module.version),
            quote(f"{module.artifact}-{module.version}.pom"),
        ]
    )


def _public_url(url: str, repository: str, suffix: str) -> None:
    """Raise unless *url* is a trusted redirect target for *repository*.

    ``suffix`` pins the exact artifact path so a redirect cannot silently
    substitute a different coordinate or version.
    """
    parsed = urllib.parse.urlsplit(url)
    allowed = _TRUSTED_HOSTS[repository]
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        msg = "untrusted publication redirect"
        raise PublicationError(msg)
    if not parsed.path.endswith("/" + suffix):
        msg = "redirect changed exact artifact path"
        raise PublicationError(msg)


def _pom_identity(body: bytes, module: ModuleId) -> ModuleId | None:
    """Validate literal POM coordinates, including group/version from a parent.

    Property expansion is unsupported, and so is any encoding but UTF-8: UTF-16
    or UTF-32 could hide the entity-declaration guard, so they fail before
    parsing. Returns the plugin marker's exact implementation ``ModuleId`` when
    present.
    """
    text = body.decode("utf-8-sig")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        msg = "POM entity declarations are unsupported"
        raise PublicationError(msg)
    root = ET.fromstring(text)
    if root.tag not in ("project", "{http://maven.apache.org/POM/4.0.0}project"):
        msg = "invalid POM root"
        raise PublicationError(msg)
    ns = "{http://maven.apache.org/POM/4.0.0}" if root.tag.startswith("{") else ""

    if _pom_coordinate(root, ns, inherit=True) != module:
        msg = "POM identity mismatch"
        raise PublicationError(msg)
    implementation = None
    if module.artifact.endswith(".gradle.plugin"):
        dependencies = root.findall(ns + "dependencies/" + ns + "dependency")
        if len(dependencies) != 1:
            msg = "unsupported plugin marker mapping"
            raise PublicationError(msg)
        implementation = _pom_coordinate(dependencies[0], ns)
    return implementation


def _pom_coordinate(
    node: ET.Element, namespace: str, *, inherit: bool = False
) -> ModuleId:
    values = []
    for field in ("groupId", "artifactId", "version"):
        matches = node.findall(namespace + field)
        if not matches and inherit and field in {"groupId", "version"}:
            parents = node.findall(namespace + "parent")
            if len(parents) == 1:
                parent = _pom_coordinate(parents[0], namespace)
                values.append(parent.group if field == "groupId" else parent.version)
                continue
        value = (matches[0].text or "").strip() if len(matches) == 1 else ""
        if not value or "${" in value:
            msg = "unresolved or ambiguous POM identity"
            raise PublicationError(msg)
        values.append(value)
    return ModuleId(group=values[0], artifact=values[1], version=values[2])


def _last_modified(headers: Mapping[str, str]) -> datetime:
    raw = {name.lower(): value for name, value in headers.items()}.get("last-modified")
    if raw is None:
        msg = "publication timestamp missing"
        raise PublicationError(msg)
    timestamp = parsedate_to_datetime(raw)
    if timestamp.tzinfo is None:
        msg = "publication timestamp lacks timezone"
        raise PublicationError(msg)
    return timestamp


def _pypi_upload_time(body: bytes, package: str, version: str) -> datetime:
    release = _PypiRelease.model_validate_json(body)
    if canonicalize_name(release.info.name) != canonicalize_name(package) or Version(
        release.info.version
    ) != Version(version):
        msg = "PyPI identity mismatch"
        raise PublicationError(msg)
    uploads = [
        _as_utc(upload.upload_time_iso_8601)
        for upload in release.urls
        if upload.upload_time_iso_8601 is not None
    ]
    if not uploads:
        msg = "PyPI upload time missing"
        raise PublicationError(msg)
    return min(uploads)


class _PypiInfo(BaseModel):
    name: StrictStr
    version: StrictStr


class _PypiUpload(BaseModel):
    upload_time_iso_8601: StrictStr | None = None


class _PypiRelease(BaseModel):
    info: _PypiInfo
    urls: list[_PypiUpload]


def _as_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _npm_timestamp(package: str, version: str, project_path: Path) -> datetime | None:
    completed = run_captured(
        ["bun", "info", f"{package}@{version}"],
        project_path,
        timeout=30,
        label="bun info",
        ok_codes=None,
    )
    value = next(
        (
            line.removeprefix("Published:").strip()
            for line in completed.stdout.splitlines()
            if line.startswith("Published:")
        ),
        None,
    )
    return _as_utc(value) if value else None


def _release_lookup(
    update: UpdateFinding,
    source: PublicationSource,
    project_path: Path,
    context: PublicationLookupContext,
) -> (
    Future[PublicationFact | AgeBlock | None]
    | Future[RegistryFact | AgeBlock | None]
    | None
):
    if source != "central":
        return context.submit_registry(
            source, update.pkg_name, update.latest_version, project_path
        )
    module = _maven_module(update.pkg_name, update.latest_version)
    return None if module is None else context.submit("central", module)


def _maven_module(coordinate: str, version: str) -> ModuleId | None:
    group, separator, artifact = coordinate.partition(":")
    if not group or not separator or not artifact or ":" in artifact:
        return None
    return ModuleId(group=group, artifact=artifact, version=version)


class _PinnedRedirects(urllib.request.HTTPRedirectHandler):
    """Follow at most five redirects in total, each to a trusted host and the same
    artifact path, closing every redirect response unread; the pypi root never
    redirects. The sixth redirect, and one without a Location, fail as HTTP 302."""

    max_redirections = 5

    def __init__(self, repository: str, suffix: str) -> None:
        super().__init__()
        self.repository = repository
        self.suffix = suffix
        self.followed = 0

    def http_error_302(self, req, fp, code, msg, headers):
        fp.close()
        location = headers.get("Location") or headers.get("URI")
        if location is None:
            return None
        if self.repository == "pypi":
            message = "publication redirect limit or invalid redirect"
            raise PublicationError(message)
        if self.followed >= self.max_redirections:
            raise urllib.error.HTTPError(
                req.full_url, code, self.inf_msg + msg, headers, fp
            )
        target = urllib.parse.urljoin(req.full_url, location)
        _public_url(target, self.repository, self.suffix)
        self.followed += 1
        new = self.redirect_request(req, fp, code, msg, headers, target)
        if new is None:
            return None
        return self.parent.open(new, timeout=req.timeout)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _publication_http(
    url: str, repository: str, suffix: str
) -> tuple[bytes, Mapping[str, str], str] | None:
    """Fetch *url* within the trust bounds: pinned redirects, 3 seconds per socket
    operation and 1 MiB. A 404 is absence."""
    _public_url(url, repository, suffix)
    opener = urllib.request.build_opener(_PinnedRedirects(repository, suffix))
    try:
        response = opener.open(url, timeout=3)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return None
        msg = f"publication HTTP {error.code}"
        raise PublicationError(msg) from error
    with response:
        if response.status != 200:
            msg = f"publication HTTP {response.status}"
            raise PublicationError(msg)
        body = response.read(_MAX_BYTES + 1)
        if len(body) > _MAX_BYTES:
            msg = "publication response exceeds limit"
            raise PublicationError(msg)
        return body, dict(response.headers.items()), response.url
