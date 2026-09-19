import io
import subprocess
import threading
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.message import Message
from threading import Event, Lock
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from maintenance_man.dependency_age import (
    PublicationFailure,
    PublicationLookupContext,
    _public_url,
    _publication_http,
    check_gradle_update_age,
    evaluate_gradle_candidate_age,
    evaluate_gradle_group_age,
    filter_by_age,
    gradle_lookup_coordinate,
    lookup_gradle_publication,
    publication_request,
    trusted_repository,
)
from maintenance_man.models.gradle import (
    AgeBlock,
    ModuleId,
    PublicationRequest,
    RepositoryDeclaration,
)
from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    SemverTier,
    UpdateFinding,
)
from tests.conftest import make_gradle_member, make_gradle_target

_PATCH_FETCH = "maintenance_man.dependency_age._fetch_json"
_PATCH_SUBRUN = "maintenance_man.dependency_age.subprocess.run"
_PATCH_NOW = "maintenance_man.dependency_age._utcnow"
_PATCH_CACHE_DIR = "maintenance_man.dependency_age._pypi_cache_dir"


def _bun_info_result(published_iso: str) -> subprocess.CompletedProcess[str]:
    """Build a fake ``bun info`` CompletedProcess with a Published line."""
    return subprocess.CompletedProcess(
        args=["bun", "info", "pkg@version"],
        returncode=0,
        stdout=f"pkg@version | MIT\nPublished: {published_iso}\n",
        stderr="",
    )


_FROZEN_NOW = datetime(2026, 1, 30, tzinfo=timezone.utc)


def _make_update(pkg: str, latest: str = "2.0.0") -> UpdateFinding:
    return UpdateFinding(
        pkg_name=pkg,
        installed_version="1.0.0",
        latest_version=latest,
        semver_tier=SemverTier.MINOR,
    )


class TestFilterByAge:
    def test_returns_all_when_min_age_is_zero(self):
        """Age gating disabled -- all updates pass through, no HTTP calls."""
        updates = [_make_update("lodash"), _make_update("express")]
        result = filter_by_age(updates, manager="bun", min_age_days=0)
        assert len(result) == 2
        assert all(u.published_date is None for u in result)

    def test_empty_updates_returns_empty(self):
        result = filter_by_age([], manager="bun", min_age_days=7)
        assert result == []

    def test_filters_young_npm_package(self):
        """Package published 2 days ago, min_age=7 -- filtered out."""
        updates = [_make_update("lodash", "4.17.21")]
        two_days_ago = "2026-01-28T00:00:00.000Z"

        with (
            patch(_PATCH_SUBRUN, return_value=_bun_info_result(two_days_ago)),
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            result = filter_by_age(updates, manager="bun", min_age_days=7)

        assert len(result) == 0

    def test_keeps_old_npm_package(self):
        """Package published 30 days ago, min_age=7 -- passes."""
        updates = [_make_update("lodash", "4.17.21")]
        thirty_days_ago = "2025-12-31T00:00:00.000Z"

        with (
            patch(_PATCH_SUBRUN, return_value=_bun_info_result(thirty_days_ago)),
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            result = filter_by_age(updates, manager="bun", min_age_days=7)

        assert len(result) == 1
        assert result[0].published_date is not None

    def test_keeps_update_on_registry_error(self):
        """If registry lookup fails, keep the update (fail open)."""
        updates = [_make_update("unknown-pkg")]

        with patch(_PATCH_SUBRUN, side_effect=Exception("network error")):
            result = filter_by_age(updates, manager="bun", min_age_days=7)

        assert len(result) == 1
        assert result[0].published_date is None

    def test_pypi_lookup(self, tmp_path):
        """Test PyPI registry lookup for uv packages (cache miss path)."""
        updates = [_make_update("requests", "2.31.0")]
        thirty_days_ago = "2025-12-31T00:00:00"

        pypi_data = {
            "urls": [{"upload_time_iso_8601": thirty_days_ago}],
        }

        with (
            patch(_PATCH_CACHE_DIR, return_value=tmp_path),
            patch(_PATCH_FETCH, return_value=pypi_data),
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            result = filter_by_age(updates, manager="uv", min_age_days=7)

        assert len(result) == 1
        assert result[0].published_date is not None

    def test_pypi_cache_hit(self, tmp_path):
        """Second lookup should hit the dbm cache — no additional HTTP call."""
        updates = [_make_update("requests", "2.31.0")]
        thirty_days_ago = "2025-12-31T00:00:00"

        pypi_data = {
            "urls": [{"upload_time_iso_8601": thirty_days_ago}],
        }

        with (
            patch(_PATCH_CACHE_DIR, return_value=tmp_path),
            patch(_PATCH_FETCH, return_value=pypi_data) as mock_fetch,
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            filter_by_age(updates, manager="uv", min_age_days=7)
            assert mock_fetch.call_count == 1

            result = filter_by_age(updates, manager="uv", min_age_days=7)
            assert mock_fetch.call_count == 1  # no additional call

        assert len(result) == 1
        assert result[0].published_date is not None

    def test_maven_central_lookup(self):
        """Test Maven Central registry lookup for mvn packages."""
        updates = [_make_update("org.slf4j:slf4j-api", "2.0.16")]
        thirty_days_ago_ms = int(
            datetime(2025, 12, 31, tzinfo=timezone.utc).timestamp() * 1000
        )

        maven_data = {"response": {"docs": [{"timestamp": thirty_days_ago_ms}]}}

        with (
            patch(_PATCH_FETCH, return_value=maven_data),
            patch(_PATCH_NOW, return_value=_FROZEN_NOW),
        ):
            result = filter_by_age(updates, manager="mvn", min_age_days=7)

        assert len(result) == 1
        assert result[0].published_date is not None


_OLD = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _dates(mapping, monkeypatch):
    """Substitute Maven Central lookup with a coordinate -> date|None|raise map."""

    def _lookup(pkg: str, version: str):
        outcome = mapping[pkg]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(
        "maintenance_man.dependency_age._get_maven_publish_date", _lookup
    )


@pytest.mark.parametrize(
    "kind, coordinate, expected",
    [
        ("library", "androidx.room:room-runtime", "androidx.room:room-runtime"),
        (
            "plugin",
            "com.google.devtools.ksp",
            "com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin",
        ),
    ],
)
def test_lookup_coordinate_uses_plugin_markers(kind, coordinate, expected):
    member = make_gradle_member(kind=kind, coordinate=coordinate)

    assert gradle_lookup_coordinate(member) == expected


class TestGradleGroupAge:
    def test_all_members_old_enough_is_eligible(self, monkeypatch):
        target = make_gradle_target()
        _dates(
            {
                "androidx.room:room-runtime": _OLD,
                "androidx.room:room-compiler": _OLD,
                "androidx.room:room-testing": _OLD + timedelta(days=1),
            },
            monkeypatch,
        )

        block, published = evaluate_gradle_group_age(target, 7)

        assert block is None
        assert published == _OLD + timedelta(days=1)

    @pytest.mark.parametrize(
        "third_outcome, reason_fragment",
        [
            (None, "no Maven Central publication date"),
            (RuntimeError("network down"), "publication lookup failed"),
        ],
    )
    def test_one_member_without_evidence_blocks_the_group(
        self, monkeypatch, third_outcome, reason_fragment
    ):
        target = make_gradle_target()
        _dates(
            {
                "androidx.room:room-runtime": _OLD,
                "androidx.room:room-compiler": _OLD,
                "androidx.room:room-testing": third_outcome,
            },
            monkeypatch,
        )

        block = check_gradle_update_age(target, 7)

        assert block is not None
        assert block.kind == "age"
        assert reason_fragment in block.reason
        assert "androidx.room:room-testing" in block.reason

    def test_too_recent_member_blocks_the_group(self, monkeypatch):
        now = datetime.now(timezone.utc)
        target = make_gradle_target()
        _dates(
            {
                "androidx.room:room-runtime": _OLD,
                "androidx.room:room-compiler": _OLD,
                "androidx.room:room-testing": now - timedelta(days=2),
            },
            monkeypatch,
        )

        block = check_gradle_update_age(target, 7)

        assert block is not None
        assert block.kind == "age"
        assert "2 day(s) ago" in block.reason
        assert "minimum is 7" in block.reason

    def test_member_published_exactly_at_cutoff_blocks_the_group(self, monkeypatch):
        """A publication exactly ``minimum_age_days`` old is not yet old enough.

        Matches ``filter_by_age``'s existing ``>=`` semantics: pinned so a
        future refactor to ``>`` fails the suite instead of passing silently.
        """
        fixed_now = datetime(2024, 2, 1, tzinfo=timezone.utc)
        monkeypatch.setattr("maintenance_man.dependency_age._utcnow", lambda: fixed_now)
        target = make_gradle_target()
        exactly_at_cutoff = fixed_now - timedelta(days=7)
        _dates(
            {
                "androidx.room:room-runtime": _OLD,
                "androidx.room:room-compiler": _OLD,
                "androidx.room:room-testing": exactly_at_cutoff,
            },
            monkeypatch,
        )

        block = check_gradle_update_age(target, 7)

        assert block is not None
        assert block.kind == "age"
        assert "androidx.room:room-testing" in block.reason
        assert "7 day(s) ago" in block.reason
        assert "minimum is 7" in block.reason

    def test_zero_waiting_period_allows_recent_but_not_unknown(self, monkeypatch):
        now = datetime.now(timezone.utc)
        target = make_gradle_target(
            members=[make_gradle_member(alias="room-runtime")], version_ref=None
        )
        _dates({"androidx.room:room-runtime": now - timedelta(hours=1)}, monkeypatch)

        assert check_gradle_update_age(target, 0) is None

        _dates({"androidx.room:room-runtime": None}, monkeypatch)
        block = check_gradle_update_age(target, 0)

        assert block is not None and block.kind == "age"

    def test_plugin_member_is_looked_up_by_marker_coordinate(self, monkeypatch):
        seen: list[str] = []

        def _lookup(pkg: str, version: str):
            seen.append(pkg)
            return _OLD

        monkeypatch.setattr(
            "maintenance_man.dependency_age._get_maven_publish_date", _lookup
        )
        target = GradleUpdateTarget(
            version_ref="ksp",
            members=[
                GradleMember(
                    kind="plugin",
                    alias="ksp",
                    coordinate="com.google.devtools.ksp",
                    installed_version="2.3.10",
                )
            ],
            target_version="2.3.12",
        )

        assert check_gradle_update_age(target, 7) is None
        assert seen == ["com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin"]

    def test_empty_member_list_blocks_instead_of_raising(self):
        """A target with no members (e.g. malformed historical scan JSON) must
        block for a rescan, not raise out of ``max()`` on an empty sequence.
        """
        target = GradleUpdateTarget(
            version_ref="room", members=[], target_version="2.8.5"
        )

        block, published = evaluate_gradle_group_age(target, 7)

        assert block is not None
        assert block.kind == "age"
        assert "no members" in block.reason
        assert published is None


def test_interrupted_age_batch_cancels_queued_lookups(monkeypatch):
    from maintenance_man import dependency_age as age

    started = Event()
    release = Event()
    lock = Lock()
    calls = []

    def lookup(pkg, version):
        with lock:
            calls.append(pkg)
            if len(calls) == 8:
                started.set()
        assert release.wait(10), "worker cleanup did not release active lookups"
        return _OLD

    class InterruptingPool(ThreadPoolExecutor):
        def map(self, *args, **kwargs):
            # Keep the real iterator alive; its own cancellation cannot mask
            # missing cleanup when interruption follows eager submission.
            self.held_iterator = super().map(*args, **kwargs)
            assert started.wait(10), "eight lookups did not start"
            raise KeyboardInterrupt

        def shutdown(self, wait=True, *, cancel_futures=False):
            # Process actual queue cancellation before releasing active calls.
            try:
                super().shutdown(wait=False, cancel_futures=cancel_futures)
            finally:
                release.set()
            if wait:
                super().shutdown(wait=True)

    monkeypatch.setattr(age, "ThreadPoolExecutor", InterruptingPool)
    monkeypatch.setattr(age, "_get_maven_publish_date", lookup)
    monkeypatch.setitem(age._REGISTRY_LOOKUPS, "mvn", lookup)
    with pytest.raises(KeyboardInterrupt):
        filter_by_age([_make_update(f"g:lib{i}") for i in range(40)], "mvn", 7)
    assert len(calls) == 8, "queued lookups ran after interruption"


_PUB_NOW = datetime(2026, 9, 18, tzinfo=timezone.utc)


def _pom(module, dependency=None):
    body = (
        "<project><groupId>"
        + module.group
        + "</groupId><artifactId>"
        + module.artifact
        + "</artifactId><version>"
        + module.version
        + "</version>"
    )
    if dependency:
        body += (
            "<dependencies><dependency><groupId>"
            + dependency.group
            + "</groupId><artifactId>"
            + dependency.artifact
            + "</artifactId><version>"
            + dependency.version
            + "</version></dependency></dependencies>"
        )
    return (body + "</project>").encode()


def _publication_fixture(
    tmp_path, *, repositories=("central",), responses=None, routing_supported=True
):
    module = ModuleId(group="org.example", artifact="lib", version="2.0")
    request = PublicationRequest(
        module=module, repositories=repositories, routing_supported=routing_supported
    )
    calls = []

    def transport(url, repository, suffix, count):
        count()
        calls.append(url)
        result = (responses or {}).get(
            repository,
            (_pom(module), {"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"}),
        )
        if isinstance(result, Exception):
            raise result
        if result is None:
            return None
        return (*result, url)

    context = PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW)
    return module, request, calls, context


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://repo1.maven.org/maven2/", "central"),
        ("https://maven.google.com/", "google"),
        ("https://plugins.gradle.org/m2", "portal"),
        ("http://repo.maven.apache.org/maven2", None),
        ("https://user:secret@repo.maven.apache.org/maven2", None),
        ("https://repo.maven.apache.org.evil/maven2", None),
        ("https://repo.maven.apache.org/maven2?token=secret", None),
    ],
)
def test_publication_root_trust(url, expected):
    assert trusted_repository(url) == expected


@pytest.mark.parametrize(
    "repository,url,allowed",
    [
        ("central", "https://repo1.maven.org/maven2/a/b/2/b-2.pom", True),
        ("google", "https://dl.google.com/dl/android/maven2/a/b/2/b-2.pom", True),
        ("portal", "https://plugins-artifacts.gradle.org/a/b/2/b-2.pom", True),
        ("portal", "https://repo.maven.apache.org/maven2/a/b/2/b-2.pom", True),
        ("google", "https://repo1.maven.org/maven2/a/b/2/b-2.pom", False),
        ("portal", "https://evil.test/a/b/2/b-2.pom", False),
        ("portal", "http://plugins-artifacts.gradle.org/a/b/2/b-2.pom", False),
        ("portal", "https://plugins-artifacts.gradle.org/a/b/3/b-3.pom", False),
    ],
)
def test_publication_redirect_trust(repository, url, allowed):
    if allowed:
        _public_url(url, repository, "a/b/2/b-2.pom")
    else:
        with pytest.raises(PublicationFailure):
            _public_url(url, repository, "a/b/2/b-2.pom")


@pytest.mark.parametrize(
    "urls,expect_supported",
    [
        ([], False),
        (["https://repo1.maven.org/maven2", "https://maven.google.com"], True),
        (["https://repo1.maven.org/maven2", "https://evil.test/maven2"], False),
        ([None], False),
    ],
    ids=["empty", "all-trusted", "one-untrusted-among-trusted", "native-url-none"],
)
def test_publication_request_withholds_on_any_untrusted_repository(
    urls, expect_supported
):
    """Any declared repository outside the trusted roots withholds routing
    support for the whole request, rather than silently dropping just that
    repository and proceeding with the rest.
    """
    module = ModuleId(group="org.example", artifact="lib", version="2.0")
    declarations = tuple(
        RepositoryDeclaration(project_path=":app", domain="library", url=url)
        for url in urls
    )

    request = publication_request(module, declarations)

    assert request.routing_supported is expect_supported


def test_publication_request_reports_trusted_repository_ids():
    """When every declared repository is trusted, the request carries the
    deduplicated trust-policy repository ids, not the raw declared URLs.
    """
    module = ModuleId(group="org.example", artifact="lib", version="2.0")
    declarations = (
        RepositoryDeclaration(
            project_path=":app", domain="library", url="https://repo1.maven.org/maven2"
        ),
        RepositoryDeclaration(
            project_path=":app", domain="library", url="https://maven.google.com"
        ),
    )

    request = publication_request(module, declarations)

    assert request.routing_supported is True
    assert request.repositories == ("central", "google")


@pytest.mark.parametrize(
    "routing_supported,repositories",
    [(False, ("central",)), (True, ())],
    ids=["routing_unsupported", "no_repositories"],
)
def test_publication_routing_withheld_before_any_transport_call(
    tmp_path, routing_supported, repositories
):
    """Unsupported routing and a missing repository list are the two
    independent halves of the same guard; either one must withhold before
    any network call is made, not merely produce a block afterward.
    """
    _, request, calls, context = _publication_fixture(
        tmp_path, repositories=repositories, routing_supported=routing_supported
    )
    with context:
        result = lookup_gradle_publication(request, context)
    assert isinstance(result, AgeBlock)
    assert result.reason == "unsupported or missing scoped repository routing"
    assert calls == []


@pytest.mark.parametrize(
    "routing_supported,repositories",
    [(False, ("central",)), (True, ())],
    ids=["routing_unsupported", "no_repositories"],
)
def test_publication_candidate_age_propagates_routing_withholding(
    tmp_path, routing_supported, repositories
):
    """The routing guard's block must reach the policy decision as an
    ``AgeBlock``, not be silently treated as a passing ``None``."""
    _, request, calls, context = _publication_fixture(
        tmp_path, repositories=repositories, routing_supported=routing_supported
    )
    candidate = SimpleNamespace(publication_requests=(request,))
    with context:
        result = evaluate_gradle_candidate_age(candidate, 0, context, _PUB_NOW)
    assert isinstance(result, AgeBlock)
    assert calls == []


@pytest.mark.parametrize(
    "date,days,blocked",
    [
        ("Tue, 01 Sep 2026 00:00:00 GMT", 7, False),
        ("Fri, 11 Sep 2026 00:00:00 GMT", 7, False),
        ("Thu, 17 Sep 2026 00:00:00 GMT", 0, False),
        ("Sat, 19 Sep 2026 00:00:00 GMT", 0, True),
        ("broken", 0, True),
        (None, 0, True),
    ],
)
def test_publication_policy(tmp_path, date, days, blocked):
    module = ModuleId(group="org.example", artifact="lib", version="2.0")
    headers = {} if date is None else {"Last-Modified": date}
    _, request, calls, context = _publication_fixture(
        tmp_path,
        repositories=("google",),
        responses={"google": (_pom(module), headers)},
    )
    with context:
        result = evaluate_gradle_candidate_age(
            SimpleNamespace(publication_requests=(request,)), days, context, _PUB_NOW
        )
    assert isinstance(result, AgeBlock) == blocked
    assert len(calls) == 1


@pytest.mark.parametrize(
    "second,blocked",
    [
        (None, False),
        (TimeoutError("timeout"), True),
        (PublicationFailure("HTTP 429"), True),
        (
            (b"<project/>", {"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"}),
            True,
        ),
    ],
)
def test_publication_absence_does_not_mask_errors(tmp_path, second, blocked):
    _, request, _, context = _publication_fixture(
        tmp_path, repositories=("central", "google"), responses={"google": second}
    )
    with context:
        assert (
            isinstance(lookup_gradle_publication(request, context), AgeBlock) == blocked
        )


def test_publication_cache_and_current_policy(tmp_path):
    _, request, calls, context = _publication_fixture(tmp_path)
    candidate = SimpleNamespace(publication_requests=(request, request))
    with context:
        assert evaluate_gradle_candidate_age(candidate, 7, context, _PUB_NOW) is None
        assert isinstance(
            evaluate_gradle_candidate_age(candidate, 30, context, _PUB_NOW), AgeBlock
        )
        assert len(calls) == context.requests == 1
    _, _, second_calls, second = _publication_fixture(tmp_path)
    with second:
        assert lookup_gradle_publication(request, second).timestamp == datetime(
            2026, 9, 1, tzinfo=timezone.utc
        )
        assert second_calls == []
        assert second.cache_hits == 1
    _, _, expired_calls, expired = _publication_fixture(tmp_path)
    expired.now = lambda: _PUB_NOW + timedelta(hours=24)
    with expired:
        lookup_gradle_publication(request, expired)
        assert len(expired_calls) == 1
    for path in tmp_path.glob("*.json"):
        path.write_text("{broken")
    _, _, corrupt_calls, corrupt = _publication_fixture(tmp_path)
    with corrupt:
        lookup_gradle_publication(request, corrupt)
        assert len(corrupt_calls) == 1


def test_publication_negative_results_retry_next_command(tmp_path):
    for _ in range(2):
        _, request, calls, context = _publication_fixture(
            tmp_path, responses={"central": None}
        )
        with context:
            assert isinstance(lookup_gradle_publication(request, context), AgeBlock)
            assert isinstance(lookup_gradle_publication(request, context), AgeBlock)
            assert len(calls) == 1
    assert not list(tmp_path.glob("*.json"))


def test_publication_youngest_and_content_conflict(tmp_path):
    module = ModuleId(group="org.example", artifact="lib", version="2.0")
    responses = {
        "google": (_pom(module), {"Last-Modified": "Thu, 17 Sep 2026 00:00:00 GMT"})
    }
    _, request, _, context = _publication_fixture(
        tmp_path / "same", repositories=("central", "google"), responses=responses
    )
    with context:
        assert lookup_gradle_publication(request, context).timestamp == datetime(
            2026, 9, 17, tzinfo=timezone.utc
        )
    responses["google"] = (_pom(module) + b"\n", responses["google"][1])
    _, request, _, context = _publication_fixture(
        tmp_path / "different",
        repositories=("central", "google"),
        responses=responses,
    )
    with context:
        assert (
            "conflicting artifact" in lookup_gradle_publication(request, context).reason
        )


def test_plugin_implementation_age_is_part_of_policy(tmp_path):
    marker = ModuleId(
        group="org.plugin", artifact="org.plugin.gradle.plugin", version="2.0"
    )
    implementation = ModuleId(group="org.impl", artifact="engine", version="9.1")
    request = PublicationRequest(
        module=marker,
        repositories=("portal",),
        marker_implementation=implementation,
        routing_supported=True,
    )
    calls = []

    def transport(url, repository, suffix, count):
        count()
        calls.append(url)
        is_marker = "gradle.plugin" in url
        return (
            _pom(marker, implementation) if is_marker else _pom(implementation),
            {
                "Last-Modified": (
                    "Tue, 01 Sep 2026 00:00:00 GMT"
                    if is_marker
                    else "Thu, 17 Sep 2026 00:00:00 GMT"
                )
            },
            url,
        )

    with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
        assert isinstance(
            evaluate_gradle_candidate_age(
                SimpleNamespace(publication_requests=(request,)), 7, context, _PUB_NOW
            ),
            AgeBlock,
        )
        assert len(calls) == 2
        assert any("/9.1/engine-9.1.pom" in url for url in calls)


@pytest.mark.parametrize(
    "body",
    [
        b'<!DOCTYPE project [<!ENTITY x SYSTEM "file:///etc/passwd">]><project/>',
        b"<project><groupId>${group}</groupId><artifactId>lib</artifactId>"
        b"<version>2.0</version></project>",
        b"<project><parent><groupId>org.example</groupId><version>2.0</version>"
        b"</parent><artifactId>lib</artifactId></project>",
        b"<project><groupId>other</groupId><artifactId>lib</artifactId>"
        b"<version>2.0</version></project>",
        b"x" * (1024 * 1024 + 1),
    ],
)
def test_publication_rejects_unproven_pom(tmp_path, body):
    _, request, _, context = _publication_fixture(
        tmp_path,
        responses={
            "central": (body, {"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"})
        },
    )
    with context:
        assert isinstance(lookup_gradle_publication(request, context), AgeBlock)


def test_publication_shared_pool_bounds_and_inflight_dedup(tmp_path):
    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = peak = calls = 0

    def transport(url, repository, suffix, count):
        nonlocal active, peak, calls
        count()
        with lock:
            active += 1
            calls += 1
            peak = max(peak, active)
            if active == 8:
                entered.set()
        assert release.wait(5)
        with lock:
            active -= 1
        return None

    with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
        modules = [
            ModuleId(group="org.example", artifact=f"lib{i}", version="2")
            for i in range(12)
        ]
        futures = [context.submit("central", module) for module in modules]
        assert context.submit("central", modules[0]) is futures[0]
        try:
            assert entered.wait(5)
            assert peak == 8
        finally:
            release.set()
        assert [future.result() for future in futures] == [None] * 12
        assert calls == context.requests == 12
        assert peak == 8


@pytest.mark.parametrize(
    "redirects,allowed,location,expected_calls",
    [
        (5, True, "https://repo1.maven.org/maven2/a/b/2/b-2.pom", 6),
        (6, False, "https://repo1.maven.org/maven2/a/b/2/b-2.pom", 6),
        # A single redirect to an untrusted host must be refused by the real
        # 3xx-handling wiring inside `_publication_http` (not merely by the
        # standalone `_public_url` predicate exercised in isolation above),
        # and must stop before any request reaches the untrusted host.
        (1, False, "https://evil.test/a/b/2/b-2.pom", 1),
    ],
)
def test_publication_transport_redirect_bound(
    monkeypatch, redirects, allowed, location, expected_calls
):
    from maintenance_man import dependency_age as age

    calls = []

    class Response:
        status = 200
        headers = {}
        fp = SimpleNamespace(
            raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=lambda _: None))
        )

        def __init__(self):
            self.body = io.BytesIO(b"<project/>")

        def read1(self, count):
            return self.body.read(count)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            assert 0 < timeout <= 15
            if len(calls) <= redirects:
                headers = Message()
                headers["Location"] = location
                raise urllib.error.HTTPError(
                    request.full_url, 302, "redirect", headers, None
                )
            return Response()

    monkeypatch.setattr(age.urllib.request, "build_opener", lambda *_: Opener())

    def operation():
        return _publication_http(
            "https://repo.maven.apache.org/maven2/a/b/2/b-2.pom",
            "central",
            "a/b/2/b-2.pom",
            lambda: None,
        )

    if allowed:
        assert operation()[0] == b"<project/>"
    else:
        with pytest.raises(PublicationFailure):
            operation()
    assert len(calls) == expected_calls


@pytest.mark.parametrize("transfer", ["content-length", "chunked"])
def test_publication_http_response_eof(monkeypatch, transfer):
    import http.client
    import socket

    from maintenance_man import dependency_age as age

    module = ModuleId(group="org.example", artifact="lib", version="2.0")
    body = _pom(module)
    if transfer == "content-length":
        wire_body = body
        transfer_header = f"Content-Length: {len(body)}\r\n".encode()
    else:
        split = len(body) // 2
        chunks = (body[:split], body[split:])
        wire_body = (
            b"".join(
                f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n" for chunk in chunks
            )
            + b"0\r\n\r\n"
        )
        transfer_header = b"Transfer-Encoding: chunked\r\n"
    receiver, sender = socket.socketpair()
    try:
        sender.sendall(
            b"HTTP/1.1 200 OK\r\n"
            + transfer_header
            + b"Last-Modified: Tue, 01 Sep 2026 00:00:00 GMT\r\n\r\n"
            + wire_body
        )
        sender.shutdown(socket.SHUT_WR)
        response = http.client.HTTPResponse(receiver)
        response.begin()
        calls = []

        class Opener:
            def open(self, request, timeout):
                calls.append(request.full_url)
                assert 0 < timeout <= 15
                return response

        monkeypatch.setattr(age.urllib.request, "build_opener", lambda *_: Opener())
        suffix = "org/example/lib/2.0/lib-2.0.pom"
        url = "https://repo.maven.apache.org/maven2/" + suffix
        actual, headers, final_url = _publication_http(
            url, "central", suffix, lambda: None
        )
        assert actual == body
        assert headers["Last-Modified"] == "Tue, 01 Sep 2026 00:00:00 GMT"
        assert final_url == url
        assert calls == [url]
        assert response.fp is None
    finally:
        receiver.close()
        sender.close()


def test_publication_http_response_oversized_body_is_refused(monkeypatch):
    """The streaming 1 MiB bound in the real read loop must refuse an
    oversized body over a live socket.

    ``test_publication_rejects_unproven_pom``'s oversized case goes through a
    fake transport and only exercises the post-hoc length check; this drives
    the actual ``response.read1`` loop and its deadline-bounded socket reads.
    """
    import http.client
    import socket
    import threading

    from maintenance_man import dependency_age as age

    oversized = b"x" * (age._MAX_BYTES + 1)
    transfer_header = f"Content-Length: {len(oversized)}\r\n".encode()
    receiver, sender = socket.socketpair()

    def produce():
        try:
            sender.sendall(
                b"HTTP/1.1 200 OK\r\n"
                + transfer_header
                + b"Last-Modified: Tue, 01 Sep 2026 00:00:00 GMT\r\n\r\n"
                + oversized
            )
            sender.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    producer = threading.Thread(target=produce, daemon=True)
    producer.start()
    try:
        response = http.client.HTTPResponse(receiver)
        response.begin()

        class Opener:
            def open(self, request, timeout):
                assert 0 < timeout <= 15
                return response

        monkeypatch.setattr(age.urllib.request, "build_opener", lambda *_: Opener())
        suffix = "org/example/lib/2.0/lib-2.0.pom"
        url = "https://repo.maven.apache.org/maven2/" + suffix
        with pytest.raises(PublicationFailure):
            _publication_http(url, "central", suffix, lambda: None)
    finally:
        producer.join(5)
        receiver.close()
        sender.close()


def test_publication_exact_central_timestamp(tmp_path):
    import json

    module = ModuleId(group="org.example", artifact="lib", version="2.0")
    timestamp = int(datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp() * 1000)
    calls = []

    def transport(url, repository, suffix, count):
        count()
        calls.append(url)
        body = (
            _pom(module)
            if suffix
            else json.dumps(
                {
                    "response": {
                        "docs": [
                            {
                                "g": "org.example",
                                "a": "lib",
                                "v": "2.0",
                                "timestamp": timestamp,
                            }
                        ]
                    }
                }
            ).encode()
        )
        return body, {}, url

    with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
        result = lookup_gradle_publication(
            PublicationRequest(
                module=module, repositories=("central",), routing_supported=True
            ),
            context,
        )
        assert result.facts[0].method == "central_timestamp"
        assert result.timestamp == datetime(2026, 9, 1, tzinfo=timezone.utc)
        assert len(calls) == 2


def test_publication_central_timestamp_overflow_withholds(tmp_path):
    """A Central timestamp too large to convert must withhold, not crash.

    ``datetime.fromtimestamp`` raises ``ValueError`` for moderately-too-large
    values but ``OverflowError`` for very large ones; only the magnitude
    bound (not the caught-exception belt-and-braces) prevents that escape.
    """
    import json

    module = ModuleId(group="org.example", artifact="lib", version="2.0")
    hostile_timestamp = 10**22

    def transport(url, repository, suffix, count):
        count()
        if suffix:
            return _pom(module), {}, url
        return (
            json.dumps(
                {
                    "response": {
                        "docs": [
                            {
                                "g": "org.example",
                                "a": "lib",
                                "v": "2.0",
                                "timestamp": hostile_timestamp,
                            }
                        ]
                    }
                }
            ).encode(),
            {},
            url,
        )

    with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
        result = lookup_gradle_publication(
            PublicationRequest(
                module=module, repositories=("central",), routing_supported=True
            ),
            context,
        )
    assert isinstance(result, AgeBlock)
    assert "invalid Central timestamp" in result.reason


@pytest.mark.parametrize("unknown", [None, TimeoutError("unavailable")])
def test_publication_prefetch_overlaps_candidate_groups(tmp_path, unknown):
    from threading import Barrier

    barrier = Barrier(2, timeout=10)
    modules = [
        ModuleId(group="org.example", artifact=f"lib{i}", version="2.0")
        for i in range(2)
    ]
    candidates = [
        SimpleNamespace(
            publication_requests=(
                PublicationRequest(
                    module=module, repositories=("google",), routing_supported=True
                ),
            )
        )
        for module in modules
    ]

    def transport(url, repository, suffix, count):
        count()
        barrier.wait()
        if "/lib1/" in url:
            if unknown is not None:
                raise unknown
            return None
        return _pom(modules[0]), {"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"}, url

    with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
        context.prefetch(
            request
            for candidate in candidates
            for request in candidate.publication_requests
        )
        blocks = [
            evaluate_gradle_candidate_age(candidate, 7, context, _PUB_NOW)
            for candidate in candidates
        ]
    assert blocks[0] is None
    assert isinstance(blocks[1], AgeBlock)


def test_publication_context_interrupt_cancels_queued_requests(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock

    from maintenance_man import dependency_age as age

    started, release, lock = Event(), Event(), Lock()
    calls = []

    class ReleasingPool(ThreadPoolExecutor):
        def shutdown(self, wait=True, *, cancel_futures=False):
            try:
                super().shutdown(wait=False, cancel_futures=cancel_futures)
            finally:
                release.set()
            if wait:
                super().shutdown(wait=True)

    def transport(url, repository, suffix, count):
        count()
        with lock:
            calls.append(url)
            if len(calls) == 8:
                started.set()
        assert release.wait(10), "context cleanup did not release active requests"
        return None

    monkeypatch.setattr(age, "ThreadPoolExecutor", ReleasingPool)
    requests = tuple(
        PublicationRequest(
            module=ModuleId(group="org.example", artifact=f"lib{i}", version="2.0"),
            repositories=("google",),
            routing_supported=True,
        )
        for i in range(40)
    )
    with pytest.raises(KeyboardInterrupt):
        with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
            context.prefetch(requests)
            assert started.wait(10), "eight requests did not start"
            raise KeyboardInterrupt
    assert len(calls) == 8, "queued publication requests ran after interruption"
