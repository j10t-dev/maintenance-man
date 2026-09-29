import dbm
import functools
import hashlib
import http.client
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

from pydantic import ValidationError

from maintenance_man.models.config import ProjectConfig
from maintenance_man.models.gradle import (
    AgeBlock,
    CompleteResolution,
    ModuleId,
    PublicationEvidence,
    PublicationFact,
    PublicationRequest,
)
from maintenance_man.models.scan import (
    UpdateFinding,
)
from maintenance_man.process import ProcessError, run_captured
from maintenance_man.storage import atomic_write_text


def filter_by_age(
    updates: list[UpdateFinding],
    lookup: Callable[[str, str], datetime | None],
    min_age_days: int,
) -> list[UpdateFinding]:
    """Filter out updates where the target version is younger than min_age_days.

    Sets published_date on each update. Returns only updates that pass the age gate.
    If min_age_days is 0, returns all updates unmodified (no registry lookups).
    """
    if min_age_days == 0 or not updates:
        return list(updates)

    cutoff = _utcnow() - timedelta(days=min_age_days)

    def _lookup_one(update: UpdateFinding) -> tuple[UpdateFinding, datetime | None]:
        try:
            return update, lookup(update.pkg_name, update.latest_version)
        except Exception:
            return update, None

    pool = ThreadPoolExecutor(max_workers=8)
    try:
        lookups = list(pool.map(_lookup_one, updates))
    finally:
        pool.shutdown(cancel_futures=True)

    result: list[UpdateFinding] = []
    for update, pub_date in lookups:
        if pub_date is not None:
            update = update.model_copy(update={"published_date": pub_date})
            if pub_date >= cutoff:
                continue
        result.append(update)

    return result


def get_npm_publish_date(
    pkg: str,
    version: str,
    project_path: Path,
) -> datetime | None:
    """Fetch publish date via ``bun info``."""
    try:
        completed = run_captured(
            ["bun", "info", f"{pkg}@{version}"],
            project_path,
            timeout=30,
            label="bun info",
            ok_codes=None,
        )
    except ProcessError:
        return None

    ts = next(
        (
            line.removeprefix("Published:").strip()
            for line in completed.stdout.splitlines()
            if line.startswith("Published:")
        ),
        None,
    )
    return datetime.fromisoformat(ts) if ts else None


def get_pypi_publish_date(pkg: str, version: str) -> datetime | None:
    """Look up publish date, checking a local dbm cache before hitting PyPI."""
    key = f"{pkg}:{version}"
    cache_file = str(_pypi_cache_dir() / "pypi-publish-dates")

    with _pypi_cache_lock:
        try:
            with dbm.open(cache_file, "c") as db:
                if cached := db.get(key.encode()):
                    return datetime.fromisoformat(cached.decode())
        except OSError:
            pass

    quote = functools.partial(urllib.parse.quote, safe="")
    data = _fetch_json(f"https://pypi.org/pypi/{quote(pkg)}/{quote(version)}/json")

    ts = next(
        (
            u.get("upload_time_iso_8601")
            for u in data.get("urls", [])
            if u.get("upload_time_iso_8601")
        ),
        None,
    )
    if ts is None:
        return None

    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)

    with _pypi_cache_lock:
        try:
            with dbm.open(cache_file, "c") as db:
                db[key] = dt.isoformat()
        except OSError:
            pass

    return dt


def get_maven_publish_date(pkg: str, version: str) -> datetime | None:
    """Fetch publish date from Maven Central.

    pkg is in the format "groupId:artifactId".
    """
    group_id, artifact_id = pkg.split(":", 1)
    quote = functools.partial(urllib.parse.quote, safe="")
    url = (
        f"https://search.maven.org/solrsearch/select?"
        f"q=g:{quote(group_id)}+AND+a:{quote(artifact_id)}+AND+v:{quote(version)}"
        f"&rows=1&wt=json"
    )
    data = _fetch_json(url)
    if (docs := data.get("response", {}).get("docs", [])) and (
        ts_ms := docs[0].get("timestamp")
    ):
        return datetime.fromtimestamp(ts_ms / 1000, tz=UTC)
    return None


def _utcnow() -> datetime:
    """Return current UTC time. Extracted for testability."""
    return datetime.now(UTC)


def _fetch_json(url: str) -> dict:
    """Fetch JSON from a URL using stdlib urllib."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _pypi_cache_dir() -> Path:
    """Return (and create) the maintenance-man cache directory."""
    base = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
    d = base / "maintenance-man"
    d.mkdir(parents=True, exist_ok=True)
    return d


_pypi_cache_lock = threading.Lock()


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
_REDIRECT_HOSTS = {
    "central": {"repo.maven.apache.org", "repo1.maven.org"},
    "google": {"dl.google.com"},
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


def trusted_repository(url):
    """Return the trust-policy repository id for an exact-root URL, or None."""
    if not isinstance(url, str):
        return None
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return None
    return _ALIASES.get(url.rstrip("/"))


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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PublicationError(Exception):
    """Publication evidence could not be trusted or obtained."""


def _public_url(url, repository, suffix=None):
    """Raise unless *url* is a trusted redirect target for *repository*.

    ``suffix`` pins the exact artifact path so a redirect cannot silently
    substitute a different coordinate or version.
    """
    parsed = urllib.parse.urlsplit(url)
    allowed = _REDIRECT_HOSTS[repository]
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise PublicationError("untrusted publication redirect")
    if suffix is not None and not parsed.path.endswith("/" + suffix):
        raise PublicationError("redirect changed exact artifact path")


def _publication_http(url, repository, suffix, count):
    """Fetch *url* under the 15-second/five-redirect/1 MiB trust bounds."""
    opener = urllib.request.build_opener(_NoRedirect())
    deadline = time.monotonic() + 15
    for redirects in range(6):
        if suffix is not None:
            _public_url(url, repository, suffix)
        elif urllib.parse.urlsplit(url).netloc != "search.maven.org":
            raise PublicationError("untrusted Central timestamp endpoint")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PublicationError("publication lookup timed out")
        count()
        try:
            response = opener.open(urllib.request.Request(url), timeout=remaining)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                error.close()
                return None
            if error.code in (301, 302, 303, 307, 308):
                location = error.headers.get("Location")
                error.close()
                if suffix is None or redirects == 5 or not location:
                    raise PublicationError(
                        "publication redirect limit or invalid redirect"
                    ) from error
                url = urllib.parse.urljoin(url, location)
                _public_url(url, repository, suffix)
                continue
            error.close()
            raise PublicationError(f"publication HTTP {error.code}") from error
        with response:
            if response.status != 200:
                raise PublicationError(f"publication HTTP {response.status}")
            body = _read_publication_body(response, deadline)
            return body, dict(response.headers.items()), url
    raise PublicationError("publication redirect limit")


def _read_publication_body(response, deadline):
    chunks = []
    size = 0
    while size <= _MAX_BYTES:
        if response.fp is None:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PublicationError("publication lookup timed out")
        # HTTPResponse.read1 performs at most one underlying read.
        # Bound that read by the remaining operation deadline.
        response.fp.raw._sock.settimeout(remaining)
        chunk = response.read1(min(65536, _MAX_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    body = b"".join(chunks)
    if len(body) > _MAX_BYTES or time.monotonic() > deadline:
        raise PublicationError("publication response exceeds limit")
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
            raise PublicationError("unresolved or ambiguous POM identity")
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
        raise PublicationError("POM entity declarations are unsupported")
    root = ET.fromstring(text)
    if root.tag not in ("project", "{http://maven.apache.org/POM/4.0.0}project"):
        raise PublicationError("invalid POM root")
    ns = "{http://maven.apache.org/POM/4.0.0}" if root.tag.startswith("{") else ""

    if _pom_coordinate(root, ns, inherit=True) != module:
        raise PublicationError("POM identity mismatch")
    implementation = None
    if module.artifact.endswith(".gradle.plugin"):
        dependencies = root.findall(ns + "dependencies/" + ns + "dependency")
        if len(dependencies) != 1:
            raise PublicationError("unsupported plugin marker mapping")
        implementation = _pom_coordinate(dependencies[0], ns)
    return implementation


def _parse_central_timestamp(body, module):
    data = json.loads(body)
    docs = data["response"]["docs"]
    if not isinstance(docs, list) or not docs:
        raise PublicationError("Central timestamp missing")
    dates = []
    for doc in docs:
        if (doc["g"], doc["a"], doc["v"]) != (
            module.group,
            module.artifact,
            module.version,
        ):
            raise PublicationError("Central timestamp identity mismatch")
        milliseconds = doc["timestamp"]
        if (
            isinstance(milliseconds, bool)
            or not isinstance(milliseconds, int)
            or not 0 < milliseconds <= _MAX_EPOCH_MS
        ):
            raise PublicationError("invalid Central timestamp")
        dates.append(datetime.fromtimestamp(milliseconds / 1000, UTC))
    return max(dates)


class PublicationLookupContext:
    """Command-scoped cache, shared pool and disk cache for publication facts."""

    def __init__(self, cache_dir, transport=None, now=_utcnow):
        self.cache_dir = Path(cache_dir)
        self.transport = transport or _publication_http
        self.now = now
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
            "Gradle publication %.3fs; requests=%d cache_hits=%d worker_seconds=%.3f",
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

    def _path(self, key, method):
        digest = hashlib.sha256(json.dumps((1, *key, method)).encode()).hexdigest()
        return self.cache_dir / (digest + ".json")

    def _cached(self, key):
        repository, group, artifact, version = key
        module = ModuleId(group=group, artifact=artifact, version=version)
        for method in ("last_modified", "central_timestamp"):
            try:
                fact = PublicationFact.model_validate_json(
                    self._path(key, method).read_bytes()
                )
                suffix = _artifact_suffix(module)
                _public_url(fact.source_url, repository, suffix)
                fresh = (
                    timedelta(0) <= self.now() - fact.checked_at < timedelta(hours=24)
                )
                if (
                    fact.repository != repository
                    or fact.module != module
                    or fact.method != method
                    or fact.timestamp > self.now()
                    or not fresh
                ):
                    continue
                with self.lock:
                    self.cache_hits += 1
                return fact
            except OSError, ValueError, ValidationError, PublicationError:
                continue
        return None

    def submit(self, repository, module):
        key = self._key(repository, module)
        with self.lock:
            prior = self.inflight.get(key)
            if prior is not None:
                if not prior.done():
                    return prior
                value = prior.result()
                if not isinstance(value, PublicationFact) or (
                    timedelta(0) <= self.now() - value.checked_at < timedelta(hours=24)
                ):
                    return prior
            future = self.pool.submit(self._fetch, key, module)
            self.inflight[key] = future
            return future

    def prefetch(self, requests):
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
                raise PublicationError("publication timestamp lacks timezone")
            return "last_modified", timestamp
        if repository != "central":
            raise PublicationError("publication timestamp missing")
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
            raise PublicationError("Central timestamp unavailable")
        return "central_timestamp", _parse_central_timestamp(result[0], module)

    def _fetch(self, key, module):
        started = time.monotonic()
        try:
            if cached := self._cached(key):
                return cached
            repository = key[0]
            suffix = _artifact_suffix(module)
            url = _ROOTS[repository] + "/" + suffix
            response = self.transport(url, repository, suffix, self._count)
            if response is None:
                return None
            body, headers, final_url = response
            _public_url(final_url, repository, suffix)
            if len(body) > _MAX_BYTES:
                raise PublicationError("POM exceeds size limit")
            implementation = _pom_identity(body, module)
            headers = {k.lower(): v for k, v in headers.items()}
            method, timestamp = self._publication_timestamp(repository, module, headers)
            timestamp = timestamp.astimezone(UTC)
            if timestamp > self.now():
                raise PublicationError("future publication timestamp")
            fact = PublicationFact(
                repository=repository,
                module=module,
                source_url=final_url,
                method=method,
                artifact_digest=hashlib.sha256(body).hexdigest(),
                timestamp=timestamp,
                checked_at=self.now(),
                implementation=implementation,
            )
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                path = self._path(key, method)
                atomic_write_text(path, fact.model_dump_json())
            except OSError:
                # Evidence was verified live; disk errors cannot supply evidence.
                pass
            return fact
        except (
            http.client.HTTPException,
            OSError,
            ValueError,
            OverflowError,
            KeyError,
            TypeError,
            ET.ParseError,
            urllib.error.URLError,
            PublicationError,
        ) as error:
            logging.getLogger(__name__).debug(
                "Publication lookup failed for %s:%s",
                module.coordinate,
                module.version,
                exc_info=True,
            )
            reason = (
                str(error)
                if isinstance(error, PublicationError)
                else "publication lookup failed"
            )
            return AgeBlock(reason=f"{module.coordinate}:{module.version}: {reason}")
        finally:
            with self.lock:
                self.seconds += time.monotonic() - started

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


def _artifact_suffix(module):
    """Return the exact Maven-layout POM path for *module*."""
    parts = (module.group, module.artifact, module.version)
    if any(
        not p or "/" in p or "\\" in p or "${" in p or p in (".", "..") for p in parts
    ):
        raise PublicationError("unsupported artifact identity")
    quote = functools.partial(urllib.parse.quote, safe="")
    return "/".join(
        [
            *(quote(p) for p in module.group.split(".")),
            quote(module.artifact),
            quote(module.version),
            quote(f"{module.artifact}-{module.version}.pom"),
        ]
    )


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
        selected = [f for f in facts if f.module == module]
        if not selected:
            return AgeBlock(
                reason=f"no trusted exact POM for {module.coordinate}:{module.version}"
            )
        if len({f.artifact_digest for f in selected}) != 1:
            return AgeBlock(
                reason=(
                    f"conflicting artifact content for "
                    f"{module.coordinate}:{module.version}"
                )
            )
    result = PublicationEvidence(facts=tuple(facts))
    context.results[request.model_dump_json()] = result
    return result


def evaluate_gradle_candidate_age(candidate, minimum_age_days, context, now):
    """Withhold only releases with a known date inside the waiting period."""
    if now.tzinfo is None or minimum_age_days < 0:
        raise ValueError("current UTC date and nonnegative minimum age required")
    if minimum_age_days == 0:
        return None
    requests = candidate.publication_requests
    context.prefetch(requests)
    for request in requests:
        result = lookup_gradle_publication(request, context)
        if isinstance(result, AgeBlock):
            continue
        if result.timestamp >= now - timedelta(days=minimum_age_days):
            return AgeBlock(
                reason=f"release younger than required {minimum_age_days} days"
            )
    return None


def _scan_publication_futures(update, resolution, context):
    requests = []
    if update.gradle_target is None:
        return requests
    for member in update.gradle_target.members:
        if member.kind == "plugin":
            module = ModuleId(
                group=member.coordinate,
                artifact=member.coordinate + ".gradle.plugin",
                version=update.latest_version,
            )
        else:
            parts = member.coordinate.split(":")
            if len(parts) != 2:
                continue
            module = ModuleId(
                group=parts[0], artifact=parts[1], version=update.latest_version
            )
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


def _assess_scan_publication(update, requests, cutoff):
    dates = []
    complete = (
        bool(requests)
        and update.gradle_target is not None
        and len(requests) == len(update.gradle_target.members)
    )
    for futures in requests:
        facts = [future.result() for future in futures]
        known = [fact for fact in facts if isinstance(fact, PublicationFact)]
        dates.extend(fact.timestamp for fact in known)
        if (
            any(isinstance(fact, AgeBlock) for fact in facts)
            or len({fact.artifact_digest for fact in known}) != 1
        ):
            complete = False
    if dates and max(dates) >= cutoff:
        return None
    published = max(dates) if complete else None
    return update.model_copy(update={"published_date": published})


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
    cutoff = context.now() - timedelta(days=min_age_days)
    pending = [
        (update, _scan_publication_futures(update, resolution, context))
        for update in updates
    ]
    assessed = (
        _assess_scan_publication(update, requests, cutoff)
        for update, requests in pending
    )
    return [update for update in assessed if update is not None]
