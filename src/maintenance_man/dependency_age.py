import dbm
import functools
import hashlib
import http.client
import json
import logging
import os
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
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


def filter_by_age(
    updates: list[UpdateFinding],
    manager: str,
    min_age_days: int,
    project_path: str | Path | None = None,
) -> list[UpdateFinding]:
    """Filter out updates where the target version is younger than min_age_days.

    Sets published_date on each update. Returns only updates that pass the age gate.
    If min_age_days is 0, returns all updates unmodified (no registry lookups).
    """
    if min_age_days == 0 or not updates:
        return list(updates)

    lookup_fn = _REGISTRY_LOOKUPS.get(manager)
    if lookup_fn is None:
        return list(updates)

    # bun info needs a cwd with a package.json
    if manager == "bun" and project_path:
        lookup_fn = functools.partial(lookup_fn, cwd=project_path)  # type: ignore

    cutoff = _utcnow() - timedelta(days=min_age_days)

    def _lookup_one(update: UpdateFinding) -> tuple[UpdateFinding, datetime | None]:
        try:
            return update, lookup_fn(update.pkg_name, update.latest_version)
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


def _get_npm_publish_date(
    pkg: str,
    version: str,
    *,
    cwd: str | Path | None = None,
) -> datetime | None:
    """Fetch publish date via ``bun info``."""
    try:
        completed = subprocess.run(
            ["bun", "info", f"{pkg}@{version}"],
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
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


def _get_pypi_publish_date(pkg: str, version: str) -> datetime | None:
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
        dt = dt.replace(tzinfo=timezone.utc)

    with _pypi_cache_lock:
        try:
            with dbm.open(cache_file, "c") as db:
                db[key] = dt.isoformat()
        except OSError:
            pass

    return dt


def _get_maven_publish_date(pkg: str, version: str) -> datetime | None:
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
    if docs := data.get("response", {}).get("docs", []):
        if ts_ms := docs[0].get("timestamp"):
            return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    return None


_REGISTRY_LOOKUPS = {
    "bun": _get_npm_publish_date,
    "uv": _get_pypi_publish_date,
    "mvn": _get_maven_publish_date,
}


def _utcnow() -> datetime:
    """Return current UTC time. Extracted for testability."""
    return datetime.now(timezone.utc)


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


class PublicationFailure(Exception):
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
        raise PublicationFailure("untrusted publication redirect")
    if suffix is not None and not parsed.path.endswith("/" + suffix):
        raise PublicationFailure("redirect changed exact artifact path")


def _publication_http(url, repository, suffix, count):
    """Fetch *url* under the 15-second/five-redirect/1 MiB trust bounds."""
    opener = urllib.request.build_opener(_NoRedirect())
    deadline = time.monotonic() + 15
    for redirects in range(6):
        if suffix is not None:
            _public_url(url, repository, suffix)
        elif urllib.parse.urlsplit(url).netloc != "search.maven.org":
            raise PublicationFailure("untrusted Central timestamp endpoint")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PublicationFailure("publication lookup timed out")
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
                    raise PublicationFailure(
                        "publication redirect limit or invalid redirect"
                    )
                url = urllib.parse.urljoin(url, location)
                _public_url(url, repository, suffix)
                continue
            error.close()
            raise PublicationFailure(f"publication HTTP {error.code}") from error
        with response:
            if response.status != 200:
                raise PublicationFailure(f"publication HTTP {response.status}")
            chunks = []
            size = 0
            while size <= _MAX_BYTES:
                if response.fp is None:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PublicationFailure("publication lookup timed out")
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
                raise PublicationFailure("publication response exceeds limit")
            return body, dict(response.headers.items()), url
    raise PublicationFailure("publication redirect limit")


def _pom_identity(body, module):
    """Validate literal POM coordinates, including group/version from a parent.

    Property expansion remains unsupported. Returns the plugin marker's exact
    implementation ``ModuleId`` when present.
    """
    # UTF-16/32 could hide the lexical declaration guard: unsupported encodings
    # fail closed before parsing. UTF-8 POMs are the supported trust-v1 format.
    text = body.decode("utf-8-sig")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise PublicationFailure("POM entity declarations are unsupported")
    root = ET.fromstring(text)
    if root.tag not in ("project", "{http://maven.apache.org/POM/4.0.0}project"):
        raise PublicationFailure("invalid POM root")
    ns = "{http://maven.apache.org/POM/4.0.0}" if root.tag.startswith("{") else ""

    def identity(node, *, inherit=False):
        values = []
        for field in ("groupId", "artifactId", "version"):
            matches = node.findall(ns + field)
            if not matches and inherit and field in {"groupId", "version"}:
                parents = node.findall(ns + "parent")
                if len(parents) == 1:
                    parent = identity(parents[0])
                    values.append(
                        parent.group if field == "groupId" else parent.version
                    )
                    continue
            value = (matches[0].text or "").strip() if len(matches) == 1 else ""
            if not value or "${" in value:
                raise PublicationFailure("unresolved or ambiguous POM identity")
            values.append(value)
        return ModuleId(group=values[0], artifact=values[1], version=values[2])

    if identity(root, inherit=True) != module:
        raise PublicationFailure("POM identity mismatch")
    implementation = None
    if module.artifact.endswith(".gradle.plugin"):
        dependencies = root.findall(ns + "dependencies/" + ns + "dependency")
        if len(dependencies) != 1:
            raise PublicationFailure("unsupported plugin marker mapping")
        implementation = identity(dependencies[0])
    return implementation


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
            except OSError, ValueError, ValidationError, PublicationFailure:
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
                raise PublicationFailure("POM exceeds size limit")
            implementation = _pom_identity(body, module)
            headers = {k.lower(): v for k, v in headers.items()}
            method = "last_modified"
            raw = headers.get("last-modified")
            if raw is not None:
                timestamp = parsedate_to_datetime(raw)
                if timestamp.tzinfo is None:
                    raise PublicationFailure("publication timestamp lacks timezone")
            elif repository == "central":
                method = "central_timestamp"
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
                    raise PublicationFailure("Central timestamp unavailable")
                data = json.loads(result[0])
                docs = data["response"]["docs"]
                if not isinstance(docs, list) or not docs:
                    raise PublicationFailure("Central timestamp missing")
                dates = []
                for doc in docs:
                    if (doc["g"], doc["a"], doc["v"]) != (
                        module.group,
                        module.artifact,
                        module.version,
                    ):
                        raise PublicationFailure("Central timestamp identity mismatch")
                    ms = doc["timestamp"]
                    if (
                        isinstance(ms, bool)
                        or not isinstance(ms, int)
                        or not 0 < ms <= _MAX_EPOCH_MS
                    ):
                        raise PublicationFailure("invalid Central timestamp")
                    dates.append(datetime.fromtimestamp(ms / 1000, timezone.utc))
                timestamp = max(dates)
            else:
                raise PublicationFailure("publication timestamp missing")
            timestamp = timestamp.astimezone(timezone.utc)
            if timestamp > self.now():
                raise PublicationFailure("future publication timestamp")
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
                temporary = path.with_suffix(
                    f".{os.getpid()}.{threading.get_ident()}.tmp"
                )
                temporary.write_text(fact.model_dump_json())
                temporary.replace(path)
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
            PublicationFailure,
        ) as error:
            logging.getLogger(__name__).debug(
                "Publication lookup failed for %s:%s",
                module.coordinate,
                module.version,
                exc_info=True,
            )
            reason = (
                str(error)
                if isinstance(error, PublicationFailure)
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
        raise PublicationFailure("unsupported artifact identity")
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
    pending = []
    for update in updates:
        requests = []
        if update.gradle_target is not None:
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
        pending.append((update, requests))
    result = []
    for update, requests in pending:
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
            continue
        published = max(dates) if complete else None
        result.append(update.model_copy(update={"published_date": published}))
    return result
