import dbm
import functools
import hashlib
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
from itertools import repeat
from pathlib import Path

from pydantic import ValidationError

from maintenance_man.models.gradle import (
    AgeBlock,
    ModuleId,
    PublicationEvidence,
    PublicationFact,
    PublicationRequest,
)
from maintenance_man.models.scan import (
    GradleBlock,
    GradleMember,
    GradleUpdateTarget,
    UpdateFinding,
)


def gradle_lookup_coordinate(member: GradleMember) -> str:
    """Return the Maven coordinate that carries *member*'s publication timestamp.

    Plugins are published as marker artifacts, not under their plugin id.
    """
    if member.kind == "plugin":
        return f"{member.coordinate}:{member.coordinate}.gradle.plugin"
    return member.coordinate


def check_gradle_update_age(
    target: GradleUpdateTarget, minimum_age_days: int
) -> GradleBlock | None:
    """Return an age block, or None when every member has sufficient evidence."""
    return evaluate_gradle_group_age(target, minimum_age_days)[0]


def evaluate_gradle_group_age(
    target: GradleUpdateTarget, minimum_age_days: int
) -> tuple[GradleBlock | None, datetime | None]:
    """Resolve publication evidence for every member changed by *target*.

    Returns ``(block, youngest_verified_date)``.  One missing, failed or
    too-recent lookup blocks the whole group: for Gradle, unknown release age is
    never treated as eligible, and ``minimum_age_days == 0`` removes only the
    waiting period, not the evidence requirement.
    """
    if not target.members:
        # target.display_name indexes members[0] when version_ref is unset, so
        # it cannot be used here without risking the same empty-list failure.
        name = target.version_ref or "inline target"
        return (
            GradleBlock(
                kind="age",
                reason=(
                    f"{name} {target.target_version} has no members to verify; "
                    f"rescan to refresh this target"
                ),
            ),
            None,
        )

    dated: list[tuple[str, datetime]] = []
    for member in target.members:
        coordinate = gradle_lookup_coordinate(member)
        try:
            published = _get_maven_publish_date(coordinate, target.target_version)
        except Exception as e:
            return (
                GradleBlock(
                    kind="age",
                    reason=(
                        f"publication lookup failed for {coordinate} "
                        f"{target.target_version}: {type(e).__name__}; "
                        f"release age cannot be verified"
                    ),
                ),
                None,
            )
        if published is None:
            return (
                GradleBlock(
                    kind="age",
                    reason=(
                        f"no Maven Central publication date for {coordinate} "
                        f"{target.target_version}; mm does not update on unknown "
                        f"release age"
                    ),
                ),
                None,
            )
        dated.append((coordinate, published))

    coordinate, youngest = max(dated, key=lambda item: item[1])
    now = _utcnow()
    cutoff = now - timedelta(days=minimum_age_days)
    if minimum_age_days > 0 and youngest >= cutoff:
        age_days = (now - youngest).days
        return (
            GradleBlock(
                kind="age",
                reason=(
                    f"{coordinate} {target.target_version} was published "
                    f"{age_days} day(s) ago; minimum is {minimum_age_days}"
                ),
            ),
            youngest,
        )
    return (None, youngest)


def evaluate_gradle_group_ages(
    targets: list[GradleUpdateTarget], minimum_age_days: int
) -> list[tuple[GradleBlock | None, datetime | None]]:
    """Evaluate independent groups concurrently, retaining their input order."""
    if not targets:
        return []
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        return list(
            pool.map(evaluate_gradle_group_age, targets, repeat(minimum_age_days))
        )
    finally:
        pool.shutdown(cancel_futures=True)


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
            raise PublicationFailure("publication timeout")
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
                    raise PublicationFailure("publication timeout")
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
    """Validate that *body* is an exact, self-contained POM for *module*.

    Returns the plugin marker's implementation ``ModuleId`` when present.
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

    def identity(node):
        values = []
        for field in ("groupId", "artifactId", "version"):
            matches = node.findall(ns + field)
            value = (matches[0].text or "").strip() if len(matches) == 1 else ""
            if not value or "${" in value:
                raise PublicationFailure("unresolved or inherited POM identity")
            values.append(value)
        return ModuleId(group=values[0], artifact=values[1], version=values[2])

    if identity(root) != module:
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
            OSError,
            ValueError,
            OverflowError,
            KeyError,
            TypeError,
            ET.ParseError,
            urllib.error.URLError,
            PublicationFailure,
        ) as error:
            return AgeBlock(
                reason=(
                    f"{module.coordinate}:{module.version}: "
                    f"{type(error).__name__}: {error}"
                )
            )
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
    """Return an ``AgeBlock`` unless every publication request is proven old enough.

    Reliable exact-artifact evidence is required even when ``minimum_age_days``
    is zero: an unresolved lookup withholds the candidate rather than passing it.
    """
    if now.tzinfo is None or minimum_age_days < 0:
        raise ValueError("current UTC date and nonnegative minimum age required")
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
