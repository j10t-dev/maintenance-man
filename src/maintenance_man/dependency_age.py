import dbm
import functools
import json
import os
import subprocess
import threading
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from maintenance_man.models.scan import UpdateFinding


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
        lookup_fn = functools.partial(lookup_fn, cwd=project_path)

    cutoff = _utcnow() - timedelta(days=min_age_days)

    def _lookup_one(update: UpdateFinding) -> tuple[UpdateFinding, datetime | None]:
        try:
            return update, lookup_fn(update.pkg_name, update.latest_version)
        except Exception:
            return update, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        lookups = list(pool.map(_lookup_one, updates))

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
