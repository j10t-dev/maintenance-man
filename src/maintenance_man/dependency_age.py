import json
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from maintenance_man.models.scan import UpdateFinding


def _utcnow() -> datetime:
    """Return current UTC time. Extracted for testability."""
    return datetime.now(timezone.utc)


def _fetch_json(url: str) -> dict:
    """Fetch JSON from a URL using stdlib urllib."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _get_npm_publish_date(pkg: str, version: str) -> datetime | None:
    """Fetch publish date from npm registry."""
    data = _fetch_json(f"https://registry.npmjs.org/{urllib.parse.quote(pkg, safe='@')}")
    time_entry = data.get("time", {}).get(version)
    if time_entry:
        return datetime.fromisoformat(time_entry.replace("Z", "+00:00"))
    return None


def _get_pypi_publish_date(pkg: str, version: str) -> datetime | None:
    """Fetch publish date from PyPI."""
    data = _fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg, safe='')}/json")
    release_files = data.get("releases", {}).get(version, [])
    if release_files:
        ts = release_files[0].get("upload_time_iso_8601")
        if ts:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
    return None


def _get_maven_publish_date(pkg: str, version: str) -> datetime | None:
    """Fetch publish date from Maven Central.

    pkg is in the format "groupId:artifactId".
    """
    group_id, artifact_id = pkg.split(":", 1)
    url = (
        f"https://search.maven.org/solrsearch/select?"
        f"q=g:{urllib.parse.quote(group_id, safe='')}+AND+a:{urllib.parse.quote(artifact_id, safe='')}+AND+v:{urllib.parse.quote(version, safe='')}"
        f"&rows=1&wt=json"
    )
    data = _fetch_json(url)
    docs = data.get("response", {}).get("docs", [])
    if docs:
        ts_ms = docs[0].get("timestamp")
        if ts_ms:
            return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    return None


_REGISTRY_LOOKUPS = {
    "bun": _get_npm_publish_date,
    "uv": _get_pypi_publish_date,
    "mvn": _get_maven_publish_date,
}


def filter_by_age(
    updates: list[UpdateFinding],
    manager: str,
    min_age_days: int,
) -> list[UpdateFinding]:
    """Filter out updates where the target version is younger than min_age_days.

    Sets published_date on each update. Returns only updates that pass the age gate.
    If min_age_days is 0, returns all updates unmodified (no registry lookups).
    """
    if min_age_days == 0 or not updates:
        return list(updates)

    lookup = _REGISTRY_LOOKUPS.get(manager)
    if lookup is None:
        return list(updates)

    cutoff = _utcnow() - timedelta(days=min_age_days)
    result: list[UpdateFinding] = []

    for update in updates:
        try:
            pub_date = lookup(update.pkg_name, update.latest_version)
        except Exception:
            # Fail open — if registry is down, keep the update
            result.append(update)
            continue

        if pub_date is not None:
            update = update.model_copy(update={"published_date": pub_date})
            if pub_date >= cutoff:
                # Too young — skip
                continue

        result.append(update)

    return result
