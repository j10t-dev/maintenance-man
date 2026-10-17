import functools
import hashlib
import http.client
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Annotated

from packaging.version import Version
from pydantic import BaseModel, Field, StrictInt, StrictStr, ValidationError

from maintenance_man.clock import Clock, utc_now
from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    AgeBlock,
    CompleteResolution,
    ModuleId,
    PublicationEvidence,
    PublicationFact,
    PublicationRequest,
    RepositoryId,
)
from maintenance_man.models.publication import (
    PublicationSource,
    Registry,
    RegistryFact,
)
from maintenance_man.models.scan import GradleMember, UpdateFinding
from maintenance_man.process import ProcessError, run_captured
from maintenance_man.storage import atomic_write_text
from maintenance_man.uv_dependencies import normalise_pkg_name


class PublicationLookupContext:
    """Publication lookups for one scan or Gradle flow: pool, dedupe and cache."""

    def __init__(self, cache_dir, transport=None, clock: Clock = utc_now):
        self.cache_dir = Path(cache_dir)
        self.transport = transport or _publication_http
        self.clock = clock
        self.pool = ThreadPoolExecutor(max_workers=8)
        self.lock = threading.Lock()
        self.inflight = {}
        self.results = {}
        self.requests = 0
        self.cache_hits = 0
        self.seconds = 0.0

    def __enter__(self):
        self.started = time.monotonic()
        return self

    def __exit__(self, *args):
        self.pool.shutdown(wait=True, cancel_futures=True)
        logging.getLogger(__name__).info(
            "Publication lookup %.3fs; requests=%d cache_hits=%d worker_seconds=%.3f",
            time.monotonic() - self.started,
            self.requests,
            self.cache_hits,
            self.seconds,
        )

    def _count(self):
        with self.lock:
            self.requests += 1

    def _key(self, repository, module):
        return (repository, module.group, module.artifact, module.version)

    def _path(self, parts):
        digest = hashlib.sha256(json.dumps(parts).encode()).hexdigest()
        return self.cache_dir / (digest + ".json")

    def _fresh(self, checked_at):
        return timedelta(0) <= self.clock() - checked_at < timedelta(hours=24)

    def _cached(self, key):
        if key[0] == "registry":
            _, registry, package, version = key
            if registry == "npm":
                return None
            try:
                fact = RegistryFact.model_validate_json(self._path(key).read_bytes())
            except OSError, ValueError:
                return None
            if (
                (fact.registry, fact.package, fact.version)
                != (registry, package, version)
                or fact.timestamp > self.clock()
                or not self._fresh(fact.checked_at)
            ):
                return None
            with self.lock:
                self.cache_hits += 1
            return fact

        repository, group, artifact, version = key
        module = ModuleId(group=group, artifact=artifact, version=version)
        for method in ("last_modified", "central_timestamp"):
            try:
                fact = PublicationFact.model_validate_json(
                    self._path((1, *key, method)).read_bytes()
                )
                suffix = _artifact_suffix(module)
                _public_url(fact.source_url, repository, suffix)
                if (
                    fact.repository != repository
                    or fact.module != module
                    or fact.method != method
                    or fact.timestamp > self.clock()
                    or not self._fresh(fact.checked_at)
                ):
                    continue
                with self.lock:
                    self.cache_hits += 1
                return fact
            except OSError, ValueError, ValidationError, PublicationError:
                continue
        return None

    def _submit(self, key, project_path=None):
        with self.lock:
            prior = self.inflight.get(key)
            if prior is not None:
                if not prior.done():
                    return prior
                value = prior.result()
                if not isinstance(
                    value, (PublicationFact, RegistryFact)
                ) or self._fresh(value.checked_at):
                    return prior
            future = self.pool.submit(self._fetch, key, project_path)
            self.inflight[key] = future
            return future

    def submit(
        self, repository: RepositoryId, module: ModuleId
    ) -> Future[PublicationFact | AgeBlock | None]:
        """Schedule one exact Maven publication lookup with in-context deduplication."""
        key = self._key(repository, module)
        return self._submit(key)

    def submit_registry(
        self, registry: Registry, package: str, version: str, project_path: Path
    ) -> Future[RegistryFact | AgeBlock | None]:
        """Schedule one exact registry lookup, using *project_path* for npm."""
        key = ("registry", registry, package, version)
        return self._submit(key, project_path)

    def prefetch(self, requests):
        """Schedule every routable module in the publication requests."""
        for request in requests:
            for module in (request.module, request.marker_implementation):
                if not (request.routing_supported and module is not None):
                    continue
                for repository in request.repositories:
                    self.submit(repository, module)

    def _publication_timestamp(self, repository, module, headers):
        raw = headers.get("last-modified")
        if raw is not None:
            timestamp = parsedate_to_datetime(raw)
            if timestamp.tzinfo is None:
                msg = "publication timestamp lacks timezone"
                raise PublicationError(msg)
            return "last_modified", timestamp
        if repository != "central":
            msg = "publication timestamp missing"
            raise PublicationError(msg)
        query = urllib.parse.urlencode(
            {
                "q": (
                    f'g:"{module.group}" AND a:"{module.artifact}" '
                    f'AND v:"{module.version}"'
                ),
                "rows": 20,
                "wt": "json",
            }
        )
        result = self.transport(
            "https://search.maven.org/solrsearch/select?" + query,
            repository,
            None,
            self._count,
        )
        if result is None:
            msg = "Central timestamp unavailable"
            raise PublicationError(msg)
        return "central_timestamp", _parse_central_timestamp(result[0], module)

    def _store(self, path, fact):
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            atomic_write_text(path, fact.model_dump_json())
        except OSError:
            # Evidence was verified live; disk errors cannot supply evidence.
            pass

    def _lookup_failed(self, label, error):
        logging.getLogger(__name__).debug(
            "Publication lookup failed for %s", label, exc_info=True
        )
        reason = (
            str(error)
            if isinstance(error, PublicationError)
            else "publication lookup failed"
        )
        return AgeBlock(reason=f"{label}: {reason}")

    def _fetch(self, key, project_path=None):
        started = time.monotonic()
        try:
            if cached := self._cached(key):
                return cached
            if key[0] == "registry":
                fact = self._registry_lookup(key, project_path)
            else:
                fact = self._pom_lookup(key)
            if fact is None:
                return None
            if fact.timestamp > self.clock():
                msg = "future publication timestamp"
                raise PublicationError(msg)
            if isinstance(fact, PublicationFact):
                self._store(self._path((1, *key, fact.method)), fact)
            elif fact.registry == "pypi":
                self._store(self._path(key), fact)
            return fact
        except _LOOKUP_ERRORS as error:
            if key[0] == "registry":
                label = f"{key[2]}:{key[3]}"
            else:
                label = f"{key[1]}:{key[2]}:{key[3]}"
            return self._lookup_failed(label, error)
        finally:
            with self.lock:
                self.seconds += time.monotonic() - started

    def _pom_lookup(self, key):
        repository, group, artifact, version = key
        module = ModuleId(group=group, artifact=artifact, version=version)
        suffix = _artifact_suffix(module)
        url = _ROOTS[repository] + "/" + suffix
        response = self.transport(url, repository, suffix, self._count)
        if response is None:
            return None
        body, headers, final_url = response
        _public_url(final_url, repository, suffix)
        if len(body) > _MAX_BYTES:
            msg = "POM exceeds size limit"
            raise PublicationError(msg)
        implementation = _pom_identity(body, module)
        headers = {name.lower(): value for name, value in headers.items()}
        method, timestamp = self._publication_timestamp(repository, module, headers)
        return PublicationFact(
            repository=repository,
            module=module,
            source_url=final_url,
            method=method,
            artifact_digest=hashlib.sha256(body).hexdigest(),
            timestamp=timestamp.astimezone(UTC),
            checked_at=self.clock(),
            implementation=implementation,
        )

    def _pypi_timestamp(self, package, version):
        quote = functools.partial(urllib.parse.quote, safe="")
        suffix = f"pypi/{quote(package)}/{quote(version)}/json"
        url = "https://pypi.org/" + suffix
        response = self.transport(url, "pypi", suffix, self._count)
        if response is None:
            return None
        body, _headers, final_url = response
        if final_url != url:
            msg = "PyPI response URL changed"
            raise PublicationError(msg)
        if len(body) > _MAX_BYTES:
            msg = "PyPI response exceeds size limit"
            raise PublicationError(msg)
        return _pypi_timestamp(body, package, version)

    def _registry_lookup(self, key, project_path):
        _, registry, package, version = key
        if registry == "pypi":
            timestamp = self._pypi_timestamp(package, version)
        else:
            self._count()
            timestamp = _npm_timestamp(package, version, project_path)
        if timestamp is None:
            return None
        return RegistryFact(
            registry=registry,
            package=package,
            version=version,
            timestamp=timestamp.astimezone(UTC),
            checked_at=self.clock(),
        )

    def evidence_for(self, candidate):
        """Return the aggregate evidence already looked up for *candidate*.

        Only requests that resolved to full ``PublicationEvidence`` (never a
        block) are returned, for receipt persistence after a passed check.
        """
        return tuple(
            self.results[r.model_dump_json()]
            for r in candidate.publication_requests
            if isinstance(self.results.get(r.model_dump_json()), PublicationEvidence)
        )


def filter_gradle_updates_by_age(
    updates: list[UpdateFinding],
    project: ProjectConfig,
    resolution: CompleteResolution,
    min_age_days: int,
    context: PublicationLookupContext,
) -> list[UpdateFinding]:
    """Filter known young catalogue proposals; unknown dates remain eligible.

    Scan-time lookups use catalogue coordinates and declared repositories only.
    Native candidate validation remains part of the update workflow.
    """
    if (
        not updates
        or min_age_days == 0
        or project.gradle_repository_routing != "standard-public"
    ):
        return list(updates)
    cutoff = context.clock() - timedelta(days=min_age_days)
    return _filter_by_age(
        updates,
        lambda update: (
            _gradle_members(update, resolution, context),
            len(update.gradle_target.members) if update.gradle_target else 0,
        ),
        cutoff,
    )


def filter_registry_updates_by_age(
    updates: list[UpdateFinding],
    source: PublicationSource,
    project_path: Path,
    min_age_days: int,
    context: PublicationLookupContext,
) -> list[UpdateFinding]:
    """Filter known young registry releases; unknown dates remain eligible."""
    if not updates or min_age_days == 0:
        return list(updates)
    cutoff = context.clock() - timedelta(days=min_age_days)
    return _filter_by_age(
        updates,
        lambda update: (
            _registry_members(update, source, project_path, context),
            1,
        ),
        cutoff,
    )


def publication_request(module, repositories, *, implementation=None):
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


def evaluate_gradle_candidate_age(candidate, minimum_age_days, context, now):
    """Return an ``AgeBlock`` unless every publication request is proven old enough.

    Exact-artifact evidence is required even when ``minimum_age_days`` is zero:
    an unresolved lookup withholds the candidate rather than passing it.
    """
    if now.tzinfo is None or minimum_age_days < 0:
        msg = "current UTC date and nonnegative minimum age required"
        raise ValueError(msg)
    requests = candidate.publication_requests
    if not requests:
        return AgeBlock(reason="candidate has no publication requests")
    context.prefetch(requests)
    for request in requests:
        result = lookup_gradle_publication(request, context)
        if isinstance(result, AgeBlock):
            return result
        if result.timestamp > now:
            return AgeBlock(reason="publication evidence is in the future")
        if minimum_age_days and result.timestamp > now - timedelta(
            days=minimum_age_days
        ):
            return AgeBlock(
                reason=f"publication younger than required {minimum_age_days} days"
            )
    return None


def member_module(member: GradleMember, version: str) -> ModuleId | None:
    """Return the Maven module published for a valid Gradle member."""
    if member.kind == "plugin":
        return ModuleId(
            group=member.coordinate,
            artifact=f"{member.coordinate}.gradle.plugin",
            version=version,
        )
    return _maven_module(member.coordinate, version)


def lookup_gradle_publication(request, context):
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
    result = PublicationEvidence(facts=tuple(facts))
    context.results[request.model_dump_json()] = result
    return result


def trusted_repository(url):
    """Return the trust-policy repository id for an exact-root URL, or None."""
    if not isinstance(url, str):
        return None
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return None
    return _ALIASES.get(url.rstrip("/"))


_ROOTS = {
    "central": "https://repo.maven.apache.org/maven2",
    "google": "https://dl.google.com/dl/android/maven2",
    "portal": "https://plugins.gradle.org/m2",
}
_ALIASES = {
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
# Largest epoch-millisecond value datetime.fromtimestamp can convert without
# raising OverflowError: datetime.max (year 9999) in UTC, in milliseconds.
_MAX_EPOCH_MS = 253402300799000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PublicationError(Exception):
    """Publication evidence could not be trusted or obtained."""


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        msg = "publication lookup timed out"
        raise PublicationError(msg)
    return remaining


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


def _public_url(url, repository, suffix=None):
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
    if suffix is not None and not parsed.path.endswith("/" + suffix):
        msg = "redirect changed exact artifact path"
        raise PublicationError(msg)


def _publication_http(url, repository, suffix, count):
    """Fetch *url* under the 15-second/five-redirect/1 MiB trust bounds."""
    deadline = time.monotonic() + 15
    opener = urllib.request.build_opener(_NoRedirect())
    for redirects in range(6):
        if suffix is not None:
            _public_url(url, repository, suffix)
        elif urllib.parse.urlsplit(url).netloc != "search.maven.org":
            msg = "untrusted Central timestamp endpoint"
            raise PublicationError(msg)
        remaining = _remaining(deadline)
        count()
        try:
            response = opener.open(
                urllib.request.Request(url), timeout=min(remaining, 3.0)
            )
        except urllib.error.HTTPError as error:
            if error.code == 404:
                error.close()
                return None
            if error.code in (301, 302, 303, 307, 308):
                location = error.headers.get("Location")
                error.close()
                if (
                    suffix is None
                    or repository == "pypi"
                    or redirects == 5
                    or not location
                ):
                    msg = "publication redirect limit or invalid redirect"
                    raise PublicationError(msg) from error
                url = urllib.parse.urljoin(url, location)
                _public_url(url, repository, suffix)
                continue
            error.close()
            msg = f"publication HTTP {error.code}"
            raise PublicationError(msg) from error
        with response:
            if response.status != 200:
                msg = f"publication HTTP {response.status}"
                raise PublicationError(msg)
            body = _read_publication_body(response, deadline)
            return body, dict(response.headers.items()), url
    msg = "publication redirect limit"
    raise PublicationError(msg)


def _read_publication_body(response, deadline):
    chunks = []
    size = 0
    while size <= _MAX_BYTES:
        if response.fp is None:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            msg = "publication lookup timed out"
            raise PublicationError(msg)
        # HTTPResponse.read1 performs at most one underlying read.
        # Bound that read by the remaining operation deadline.
        response.fp.raw._sock.settimeout(remaining)  # noqa: SLF001 http.client exposes no public socket accessor
        chunk = response.read1(min(65536, _MAX_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    body = b"".join(chunks)
    if len(body) > _MAX_BYTES or time.monotonic() > deadline:
        msg = "publication response exceeds limit"
        raise PublicationError(msg)
    return body


def _pom_coordinate(node, namespace, *, inherit=False):
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


def _pom_identity(body, module):
    """Validate literal POM coordinates, including group/version from a parent.

    Property expansion remains unsupported. Returns the plugin marker's exact
    implementation ``ModuleId`` when present.
    """
    # UTF-16/32 could hide the lexical declaration guard: unsupported encodings
    # fail closed before parsing. UTF-8 POMs are the supported trust-v1 format.
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


def _parse_central_timestamp(body, module):
    try:
        docs = _CentralResponse.model_validate_json(body).response.docs
    except ValidationError as e:
        reason = (
            "Central timestamp missing"
            if any(
                error["loc"] == ("response", "docs") and error["type"] == "too_short"
                for error in e.errors()
            )
            else "invalid Central timestamp"
        )
        raise PublicationError(reason) from e
    dates = []
    for doc in docs:
        if (doc.g, doc.a, doc.v) != (
            module.group,
            module.artifact,
            module.version,
        ):
            msg = "Central timestamp identity mismatch"
            raise PublicationError(msg)
        dates.append(datetime.fromtimestamp(doc.timestamp / 1000, UTC))
    return max(dates)


class _CentralDoc(BaseModel):
    g: StrictStr
    a: StrictStr
    v: StrictStr
    timestamp: Annotated[StrictInt, Field(gt=0, le=_MAX_EPOCH_MS)]


class _CentralDocs(BaseModel):
    docs: Annotated[list[_CentralDoc], Field(min_length=1)]


class _CentralResponse(BaseModel):
    response: _CentralDocs


def _registry_timestamp(value):
    if not isinstance(value, str):
        msg = "invalid registry timestamp"
        raise PublicationError(msg)
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _pypi_release(body: bytes) -> _PypiRelease:
    """Decode one PyPI release document at the registry boundary."""
    try:
        return _PypiRelease.model_validate_json(body)
    except ValidationError as e:
        errors = e.errors()
        if any(error["type"] == "json_invalid" for error in errors):
            msg = "publication lookup failed"
        elif any(error["loc"][-1:] == ("upload_time_iso_8601",) for error in errors):
            msg = "invalid registry timestamp"
        else:
            msg = "unexpected PyPI response shape"
        raise PublicationError(msg) from e


class _PypiInfo(BaseModel):
    name: StrictStr
    version: StrictStr


class _PypiUpload(BaseModel):
    upload_time_iso_8601: StrictStr | None = None


class _PypiRelease(BaseModel):
    info: _PypiInfo
    urls: list[_PypiUpload]


def _pypi_timestamp(body, package, version):
    release = _pypi_release(body)
    if normalise_pkg_name(release.info.name) != normalise_pkg_name(package) or Version(
        release.info.version
    ) != Version(version):
        msg = "PyPI identity mismatch"
        raise PublicationError(msg)
    uploads = [
        _registry_timestamp(upload.upload_time_iso_8601)
        for upload in release.urls
        if upload.upload_time_iso_8601 is not None
    ]
    if not uploads:
        msg = "PyPI upload time missing"
        raise PublicationError(msg)
    return min(uploads)


def _npm_timestamp(package, version, project_path):
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
    return _registry_timestamp(value) if value else None


def _artifact_suffix(module):
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


type _Member = (
    tuple[Future[PublicationFact | AgeBlock | None], ...]
    | tuple[Future[RegistryFact | AgeBlock | None], ...]
)


def _filter_by_age(
    updates: list[UpdateFinding],
    schedule: Callable[[UpdateFinding], tuple[list[_Member], int]],
    cutoff: datetime,
) -> list[UpdateFinding]:
    """Apply the one scan age rule; every update is scheduled before any wait."""
    pending = [(update, *schedule(update)) for update in updates]
    assessed = (
        _assess_publication(update, members, expected, cutoff)
        for update, members, expected in pending
    )
    return [update for update in assessed if update is not None]


def _assess_publication(
    update: UpdateFinding,
    members: list[_Member],
    expected: int,
    cutoff: datetime,
) -> UpdateFinding | None:
    dates: list[datetime] = []
    complete = bool(members) and len(members) == expected
    for futures in members:
        results = [future.result() for future in futures]
        known = [
            result
            for result in results
            if isinstance(result, (PublicationFact, RegistryFact))
        ]
        digests = {
            result.artifact_digest
            for result in known
            if isinstance(result, PublicationFact)
        }
        dates.extend(fact.timestamp for fact in known)
        if (
            not known
            or any(isinstance(result, AgeBlock) for result in results)
            or len(digests) > 1
        ):
            complete = False
    if dates and max(dates) >= cutoff:
        return None
    return update.model_copy(
        update={"published_date": max(dates) if complete else None}
    )


def _maven_module(coordinate: str, version: str) -> ModuleId | None:
    group, separator, artifact = coordinate.partition(":")
    if not group or not separator or not artifact or ":" in artifact:
        return None
    return ModuleId(group=group, artifact=artifact, version=version)


def _gradle_members(
    update: UpdateFinding,
    resolution: CompleteResolution,
    context: PublicationLookupContext,
) -> list[_Member]:
    requests: list[_Member] = []
    if update.gradle_target is None:
        return requests
    for member in update.gradle_target.members:
        module = member_module(member, update.latest_version)
        if module is None:
            continue
        repositories = tuple(
            repository
            for repository in resolution.report.repositories
            if repository.domain == member.kind
        )
        request = publication_request(module, repositories)
        if request.routing_supported:
            requests.append(
                tuple(
                    context.submit(repository, module)
                    for repository in request.repositories
                )
            )
    return requests


def _registry_members(
    update: UpdateFinding,
    source: PublicationSource,
    project_path: Path,
    context: PublicationLookupContext,
) -> list[_Member]:
    if source != "central":
        return [
            (
                context.submit_registry(
                    source, update.pkg_name, update.latest_version, project_path
                ),
            )
        ]
    module = _maven_module(update.pkg_name, update.latest_version)
    if module is None:
        return []
    return [(context.submit("central", module),)]
