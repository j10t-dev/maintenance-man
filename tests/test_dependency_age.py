import io
import subprocess
import threading
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from email.message import Message
from threading import Event, Lock
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import patch

import pytest

from maintenance_man.dependency_age import (
    PublicationError,
    PublicationLookupContext,
    _public_url,
    _publication_http,
    evaluate_gradle_candidate_age,
    filter_by_age,
    get_maven_publish_date,
    get_npm_publish_date,
    get_pypi_publish_date,
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
    SemverTier,
    UpdateFinding,
)

_PATCH_FETCH = "maintenance_man.dependency_age._fetch_json"
_PATCH_SUBRUN = "maintenance_man.process.subprocess.run"
_PATCH_NOW = "maintenance_man.dependency_age._utcnow"
_PATCH_CACHE_DIR = "maintenance_man.dependency_age._pypi_cache_dir"


_FROZEN_NOW = datetime(2026, 1, 30, tzinfo=UTC)


def _make_update(pkg: str, latest: str = "2.0.0") -> UpdateFinding:
    return UpdateFinding(
        pkg_name=pkg,
        installed_version="1.0.0",
        latest_version=latest,
        semver_tier=SemverTier.MINOR,
    )


def _no_lookup(pkg, version):
    pytest.fail("no publication lookup expected")


class TestFilterByAge:
    def test_returns_all_without_lookups_when_min_age_is_zero(self):
        updates = [_make_update("lodash"), _make_update("express")]
        result = filter_by_age(updates, _no_lookup, min_age_days=0)
        assert result == updates
        assert all(u.published_date is None for u in result)

    def test_empty_updates_returns_empty(self):
        assert filter_by_age([], _no_lookup, min_age_days=7) == []

    @pytest.mark.parametrize(
        ("published", "kept"),
        [
            (datetime(2026, 1, 28, tzinfo=UTC), False),
            (datetime(2026, 1, 23, tzinfo=UTC), False),
            (datetime(2026, 1, 22, 23, 59, 59, tzinfo=UTC), True),
            (datetime(2025, 12, 31, tzinfo=UTC), True),
        ],
    )
    def test_withholds_versions_younger_than_the_minimum_age(self, published, kept):
        with patch(_PATCH_NOW, return_value=_FROZEN_NOW):
            result = filter_by_age(
                [_make_update("lodash")], lambda pkg, v: published, min_age_days=7
            )
        assert [u.published_date for u in result] == ([published] if kept else [])

    @pytest.mark.parametrize("outcome", [None, RuntimeError("network error")])
    def test_unknown_or_failed_lookup_keeps_the_update(self, outcome):
        def lookup(pkg, version):
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        result = filter_by_age([_make_update("pkg")], lookup, min_age_days=7)
        assert [u.published_date for u in result] == [None]

    def test_lookup_receives_package_and_target_version(self):
        seen = []

        def lookup(pkg, version):
            seen.append((pkg, version))

        filter_by_age([_make_update("lodash", "4.17.21")], lookup, min_age_days=7)
        assert seen == [("lodash", "4.17.21")]


def test_pypi_lookup_reads_upload_time_and_caches_it(tmp_path):
    pypi_data = {"urls": [{"upload_time_iso_8601": "2025-12-31T00:00:00"}]}
    expected = datetime(2025, 12, 31, tzinfo=UTC)
    with (
        patch(_PATCH_CACHE_DIR, return_value=tmp_path),
        patch(_PATCH_FETCH, return_value=pypi_data) as fetch,
    ):
        assert get_pypi_publish_date("requests", "2.31.0") == expected
        assert get_pypi_publish_date("requests", "2.31.0") == expected
    assert fetch.call_count == 1


def test_maven_central_lookup_reads_the_timestamp():
    published_ms = int(datetime(2025, 12, 31, tzinfo=UTC).timestamp() * 1000)
    maven_data = {"response": {"docs": [{"timestamp": published_ms}]}}
    with patch(_PATCH_FETCH, return_value=maven_data):
        assert get_maven_publish_date("org.slf4j:slf4j-api", "2.0.16") == datetime(
            2025, 12, 31, tzinfo=UTC
        )


def test_bun_info_runs_isolated_and_parses_any_exit_status(tmp_path, monkeypatch):
    monkeypatch.setenv("VIRTUAL_ENV", "/host/venv")
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(
            cmd, 1, "pkg@1.0.0 | MIT\nPublished: 2024-01-02T03:04:05Z\n", "warning"
        )

    monkeypatch.setattr(_PATCH_SUBRUN, run)
    assert get_npm_publish_date("pkg", "1.0.0", tmp_path) == datetime(
        2024, 1, 2, 3, 4, 5, tzinfo=UTC
    )
    ((cmd, kwargs),) = calls
    assert cmd == ["bun", "info", "pkg@1.0.0"]
    assert kwargs["cwd"] == tmp_path
    assert kwargs["timeout"] == 30
    assert "VIRTUAL_ENV" not in kwargs["env"]


@pytest.mark.parametrize(
    "raised",
    [
        subprocess.TimeoutExpired(["bun", "info"], 30),
        FileNotFoundError(2, "No such file or directory", "bun"),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    ],
)
def test_bun_info_execution_failure_is_an_unknown_date(tmp_path, monkeypatch, raised):
    def run(cmd, **kwargs):
        raise raised

    monkeypatch.setattr(_PATCH_SUBRUN, run)
    assert get_npm_publish_date("pkg", "1.0.0", tmp_path) is None


_OLD = datetime(2024, 1, 1, tzinfo=UTC)


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
    with pytest.raises(KeyboardInterrupt):
        filter_by_age([_make_update(f"g:lib{i}") for i in range(40)], lookup, 7)
    assert len(calls) == 8, "queued lookups ran after interruption"


_PUB_NOW = datetime(2026, 9, 18, tzinfo=UTC)


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
        with pytest.raises(PublicationError):
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
def test_publication_candidate_age_allows_unknown_routing(
    tmp_path, routing_supported, repositories
):
    """Unsupported routing leaves age unknown and does not veto updates."""
    _, request, calls, context = _publication_fixture(
        tmp_path, repositories=repositories, routing_supported=routing_supported
    )
    candidate = SimpleNamespace(publication_requests=(request,))
    with context:
        result = evaluate_gradle_candidate_age(candidate, 0, context, _PUB_NOW)
    assert result is None
    assert calls == []


@pytest.mark.parametrize(
    "date,days,blocked",
    [
        ("Tue, 01 Sep 2026 00:00:00 GMT", 7, False),
        ("Fri, 11 Sep 2026 00:00:00 GMT", 7, True),
        ("Thu, 17 Sep 2026 00:00:00 GMT", 0, False),
        ("Sat, 19 Sep 2026 00:00:00 GMT", 0, False),
        ("broken", 0, False),
        (None, 0, False),
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
    assert len(calls) == (1 if days else 0)


@pytest.mark.parametrize(
    "second,blocked",
    [
        (None, False),
        (TimeoutError("timeout"), True),
        (PublicationError("HTTP 429"), True),
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
            2026, 9, 1, tzinfo=UTC
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


def test_publication_failure_has_readable_reason_and_debug_details(tmp_path, caplog):
    def transport(url, repository, suffix, count):
        msg = "publication lookup timed out"
        raise PublicationError(msg)

    _, request, _, context = _publication_fixture(tmp_path)
    context.transport = transport
    with caplog.at_level("DEBUG", logger="maintenance_man.dependency_age"), context:
        result = lookup_gradle_publication(request, context)

    assert isinstance(result, AgeBlock)
    assert "org.example:lib:2.0" in result.reason
    assert "publication lookup timed out" in result.reason
    assert "PublicationError" not in result.reason
    assert "PublicationError" in caplog.text


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
            2026, 9, 17, tzinfo=UTC
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
        return

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
        headers: ClassVar[dict[str, str]] = {}
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
        with pytest.raises(PublicationError):
            operation()
    assert len(calls) == expected_calls


def test_publication_redirect_and_read_share_deadline(monkeypatch):
    from email.message import Message
    from types import SimpleNamespace
    from urllib.error import HTTPError

    from maintenance_man import dependency_age as age

    now = [100.0]
    timeouts = []
    closed = []
    url = "https://repo.maven.apache.org/maven2/a/b/2/b-2.pom"
    headers = Message()
    headers["Location"] = url
    redirect = HTTPError(url, 302, "redirect", headers, None)
    original_close = redirect.close

    def close_redirect():
        closed.append("redirect")
        original_close()

    monkeypatch.setattr(redirect, "close", close_redirect)

    class Response:
        status = 200
        fp = SimpleNamespace(
            raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=lambda _: None))
        )

        def read1(self, count):
            now[0] = 116.0
            return b"chunk"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            closed.append("response")

    class Opener:
        def open(self, request, timeout):
            timeouts.append(timeout)
            if len(timeouts) == 1:
                now[0] = 114.0
                raise redirect
            assert closed == ["redirect"]
            return Response()

    monkeypatch.setattr(age.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(age.urllib.request, "build_opener", lambda *_: Opener())
    with pytest.raises(PublicationError, match=r"^publication lookup timed out$"):
        age._publication_http(url, "central", "a/b/2/b-2.pom", lambda: None)
    assert timeouts == [15.0, 1.0]
    assert closed == ["redirect", "response"]


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
        assert response.isclosed()
    finally:
        receiver.close()
        sender.close()


@pytest.mark.parametrize(
    "extra_byte,accepted", [(False, True), (True, False)], ids=["limit", "over-limit"]
)
def test_publication_http_response_size_bound(monkeypatch, extra_byte, accepted):
    """The live read loop accepts 1 MiB and refuses one byte more.

    ``test_publication_rejects_unproven_pom``'s oversized case goes through a
    fake transport and only exercises the post-hoc length check; this drives
    the actual ``response.read1`` loop and its deadline-bounded socket reads.
    """
    import http.client
    import socket
    import threading

    from maintenance_man import dependency_age as age

    body = b"x" * (age._MAX_BYTES + extra_byte)
    transfer_header = f"Content-Length: {len(body)}\r\n".encode()
    receiver, sender = socket.socketpair()

    def produce():
        try:
            sender.sendall(
                b"HTTP/1.1 200 OK\r\n"
                + transfer_header
                + b"Last-Modified: Tue, 01 Sep 2026 00:00:00 GMT\r\n\r\n"
                + body
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
        if accepted:
            assert _publication_http(url, "central", suffix, lambda: None)[0] == body
        else:
            with pytest.raises(PublicationError):
                _publication_http(url, "central", suffix, lambda: None)
        assert response.isclosed()
    finally:
        producer.join(5)
        receiver.close()
        sender.close()


def test_publication_exact_central_timestamp(tmp_path):
    import json

    module = ModuleId(group="org.example", artifact="lib", version="2.0")
    timestamp = int(datetime(2026, 9, 1, tzinfo=UTC).timestamp() * 1000)
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
        assert result.timestamp == datetime(2026, 9, 1, tzinfo=UTC)
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
    assert blocks[1] is None


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
        return

    monkeypatch.setattr(age, "ThreadPoolExecutor", ReleasingPool)
    requests = tuple(
        PublicationRequest(
            module=ModuleId(group="org.example", artifact=f"lib{i}", version="2.0"),
            repositories=("google",),
            routing_supported=True,
        )
        for i in range(40)
    )
    with (
        pytest.raises(KeyboardInterrupt),
        PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context,
    ):
        context.prefetch(requests)
        assert started.wait(10), "eight requests did not start"
        raise KeyboardInterrupt
    assert len(calls) == 8, "queued publication requests ran after interruption"


@pytest.mark.parametrize("failure", ["truncated-chunk", "bad-status-line"])
def test_publication_malformed_http_withholds_candidate(
    tmp_path, monkeypatch, caplog, failure
):
    import http.client
    import socket

    from maintenance_man import dependency_age as age

    receiver, sender = socket.socketpair()
    if failure == "truncated-chunk":
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n<project>"
    else:
        wire = b"not an HTTP status line\r\n\r\n"
    sender.sendall(wire)
    sender.shutdown(socket.SHUT_WR)

    class Opener:
        def open(self, request, timeout):
            response = http.client.HTTPResponse(receiver)
            response.begin()
            return response

    monkeypatch.setattr(age.urllib.request, "build_opener", lambda *args: Opener())
    caplog.set_level("DEBUG", logger="maintenance_man.dependency_age")
    try:
        module = ModuleId(group="org.example", artifact="lib", version="2.0")
        with PublicationLookupContext(tmp_path) as context:
            result = lookup_gradle_publication(
                PublicationRequest(
                    module=module, repositories=("central",), routing_supported=True
                ),
                context,
            )
        assert isinstance(result, AgeBlock)
        assert "publication lookup failed" in result.reason
        assert (
            "IncompleteRead" if failure == "truncated-chunk" else "BadStatusLine"
        ) in caplog.text
        assert not list(tmp_path.glob("*.json"))
    finally:
        receiver.close()
        sender.close()


@pytest.mark.parametrize(
    "explicit", ["", "<groupId>org.example</groupId>", "<version>2.0</version>"]
)
def test_publication_accepts_literal_parent_identity(tmp_path, explicit):
    from maintenance_man.models.gradle import PublicationEvidence

    pom = (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<modelVersion>4.0.0</modelVersion><parent><groupId>org.example</groupId>"
        "<artifactId>parent</artifactId><version>2.0</version></parent>"
        f"<artifactId>lib</artifactId>{explicit}</project>"
    ).encode()
    _, request, _, context = _publication_fixture(
        tmp_path,
        responses={
            "central": (pom, {"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"})
        },
    )
    with context:
        result = lookup_gradle_publication(request, context)
    assert isinstance(result, PublicationEvidence)
    assert result.facts[0].module == ModuleId(
        group="org.example", artifact="lib", version="2.0"
    )


@pytest.mark.parametrize(
    "identity",
    [
        "<groupId>wrong.group</groupId>",
        "<version>${revision}</version>",
        "<version></version>",
        "<version>2.0</version><version>2.0</version>",
    ],
)
def test_publication_never_replaces_invalid_explicit_identity_with_parent(
    tmp_path, identity
):
    pom = (
        "<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId>"
        "<version>2.0</version></parent><artifactId>lib</artifactId>"
        f"{identity}</project>"
    ).encode()
    _, request, _, context = _publication_fixture(
        tmp_path,
        responses={
            "central": (pom, {"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"})
        },
    )
    with context:
        assert isinstance(lookup_gradle_publication(request, context), AgeBlock)


@pytest.mark.parametrize("minimum_age", [0, 7])
def test_unknown_gradle_publication_does_not_veto_update(tmp_path, minimum_age):
    _, request, calls, context = _publication_fixture(
        tmp_path, responses={"central": TimeoutError("unavailable")}
    )
    with context:
        assert (
            evaluate_gradle_candidate_age(
                SimpleNamespace(publication_requests=(request,)),
                minimum_age,
                context,
                _PUB_NOW,
            )
            is None
        )
    if minimum_age == 0:
        assert calls == []


def test_gradle_age_without_requests_is_unknown(tmp_path):
    with PublicationLookupContext(tmp_path) as context:
        assert (
            evaluate_gradle_candidate_age(
                SimpleNamespace(publication_requests=()), 7, context, _PUB_NOW
            )
            is None
        )


@pytest.mark.parametrize("kind", ["library", "plugin"])
@pytest.mark.parametrize(
    "date,kept",
    [
        ("Tue, 01 Sep 2026 00:00:00 GMT", True),
        ("Thu, 17 Sep 2026 00:00:00 GMT", False),
        (None, True),
    ],
)
def test_gradle_scan_age_filter_keeps_unknown_and_filters_known_young(
    tmp_path, kind, date, kept
):
    from maintenance_man import dependency_age as age
    from maintenance_man.models.scan import GradleMember, GradleUpdateTarget

    coordinate = "org.example:lib" if kind == "library" else "org.example.plugin"
    target = GradleUpdateTarget(
        version_ref="lib",
        target_version="2.0",
        members=[
            GradleMember(
                kind=kind, alias="lib", coordinate=coordinate, installed_version="1.0"
            )
        ],
    )
    row = _make_update("lib", "2.0").model_copy(update={"gradle_target": target})
    module = (
        ModuleId(group="org.example", artifact="lib", version="2.0")
        if kind == "library"
        else ModuleId(
            group=coordinate, artifact=coordinate + ".gradle.plugin", version="2.0"
        )
    )

    def transport(url, repository, suffix, count):
        if date is None:
            msg = "unavailable"
            raise TimeoutError(msg)
        body = _pom(module)
        if kind == "plugin":
            body = body.replace(
                b"</project>",
                b"<dependencies><dependency><groupId>g</groupId><artifactId>impl</artifactId><version>2</version></dependency></dependencies></project>",
            )
        return body, {"Last-Modified": date}, url

    from maintenance_man.models.config import ProjectConfig
    from maintenance_man.models.gradle import (
        CompleteResolution,
        RepositoryDeclaration,
        ResolutionReport,
    )

    project = ProjectConfig(
        path=tmp_path,
        package_manager="gradle",
        gradle_repository_routing="standard-public",
    )
    resolution = CompleteResolution(
        report=ResolutionReport(
            schema_version=1,
            root_project=":",
            producer_versions={"gradle": "9", "cyclonedx": "3", "report": "1"},
            catalogue_digest="catalogue",
            repositories=(
                RepositoryDeclaration(
                    domain=kind,
                    project_path=":",
                    url="https://repo.maven.apache.org/maven2",
                ),
            ),
            selected_scopes=(),
            scopes=(),
        )
    )
    with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
        result = age.filter_gradle_updates_by_age(
            [row], project, resolution, 7, context
        )
    assert bool(result) is kept
    if kept:
        assert result[0].blocked_reason is None
        assert (result[0].published_date is not None) is (date is not None)


@pytest.mark.parametrize(
    "case,kept,dated",
    [
        ("member-timeout", True, False),
        ("member-routing", True, False),
        ("young-member", False, False),
        ("repository-timeout", True, False),
        ("young-repository", False, False),
        ("all-old", True, True),
    ],
)
def test_gradle_group_age_requires_every_member_date(tmp_path, case, kept, dated):
    from maintenance_man.dependency_age import filter_gradle_updates_by_age

    member_specs = [("library", "one", "g:one")]
    repository_specs = [("library", "https://repo.maven.apache.org/maven2")]
    if "repository" in case:
        repository_specs.append(("library", "https://dl.google.com/dl/android/maven2"))
    else:
        member_specs.append(
            (
                "plugin" if case == "member-routing" else "library",
                "two",
                "g.two" if case == "member-routing" else "g:two",
            )
        )
    row, project, resolution = _scan_age_inputs(
        tmp_path,
        member_specs=member_specs,
        repository_specs=repository_specs,
    )

    def transport(url, repository, suffix, count):
        artifact = "two" if "/two/" in url else "one"
        if repository == "google" or (artifact == "two" and case != "all-old"):
            msg = "unavailable"
            raise TimeoutError(msg)
        date = (
            "Thu, 17 Sep 2026 00:00:00 GMT"
            if case.startswith("young")
            else "Tue, 01 Sep 2026 00:00:00 GMT"
        )
        return (
            _pom(ModuleId(group="g", artifact=artifact, version="2")),
            {"Last-Modified": date},
            url,
        )

    with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
        result = filter_gradle_updates_by_age([row], project, resolution, 7, context)
    assert bool(result) is kept
    if kept:
        assert (result[0].published_date is not None) is dated


def _scan_age_inputs(
    tmp_path,
    *,
    member_specs=(("library", "one", "g:one"),),
    repository_specs=(
        ("library", "https://repo.maven.apache.org/maven2"),
        ("library", "https://dl.google.com/dl/android/maven2"),
    ),
):
    from maintenance_man.models.config import ProjectConfig
    from maintenance_man.models.gradle import (
        CompleteResolution,
        RepositoryDeclaration,
        ResolutionReport,
    )
    from maintenance_man.models.scan import GradleMember, GradleUpdateTarget

    target = GradleUpdateTarget(
        version_ref="shared",
        target_version="2",
        members=[
            GradleMember(
                kind=kind,
                alias=alias,
                coordinate=coordinate,
                installed_version="1",
            )
            for kind, alias, coordinate in member_specs
        ],
    )
    update = _make_update("shared", "2").model_copy(update={"gradle_target": target})
    project = ProjectConfig(
        path=tmp_path,
        package_manager="gradle",
        gradle_repository_routing="standard-public",
    )
    resolution = CompleteResolution(
        report=ResolutionReport(
            schema_version=1,
            root_project=":",
            producer_versions={"gradle": "9", "cyclonedx": "3", "report": "1"},
            catalogue_digest="catalogue",
            repositories=tuple(
                RepositoryDeclaration(
                    project_path=":",
                    domain=domain,
                    url=url,
                )
                for domain, url in repository_specs
            ),
            selected_scopes=(),
            scopes=(),
        )
    )
    return update, project, resolution


def _publication_fact(module, repository, timestamp, digest="0" * 64):
    from maintenance_man.models.gradle import PublicationFact

    root = {
        "central": "https://repo.maven.apache.org/maven2",
        "google": "https://dl.google.com/dl/android/maven2",
    }[repository]
    path = "/".join(
        (
            module.group.replace(".", "/"),
            module.artifact,
            module.version,
            f"{module.artifact}-{module.version}.pom",
        )
    )
    return PublicationFact(
        repository=repository,
        module=module,
        source_url=f"{root}/{path}",
        method="last_modified",
        artifact_digest=digest,
        timestamp=timestamp,
        checked_at=_PUB_NOW,
    )


@pytest.mark.parametrize(
    "case,kept,expected_date",
    [
        ("unknown", True, None),
        ("absent-repository", True, datetime(2026, 9, 1, tzinfo=UTC)),
        ("old", True, datetime(2026, 9, 1, tzinfo=UTC)),
        ("young", False, None),
        ("equal-cutoff", False, None),
        ("conflicting-digest", True, None),
    ],
)
def test_gradle_group_age_assesses_known_facts(
    tmp_path, monkeypatch, case, kept, expected_date
):
    from maintenance_man.dependency_age import filter_gradle_updates_by_age

    update, project, resolution = _scan_age_inputs(tmp_path)
    module = ModuleId(group="g", artifact="one", version="2")
    old = datetime(2026, 9, 1, tzinfo=UTC)
    dates = {
        "young": datetime(2026, 9, 17, tzinfo=UTC),
        "equal-cutoff": datetime(2026, 9, 11, tzinfo=UTC),
    }
    values = {
        "unknown": (
            _publication_fact(module, "central", old),
            AgeBlock(reason="publication lookup failed"),
        ),
        "absent-repository": (_publication_fact(module, "central", old), None),
        "old": (
            _publication_fact(module, "central", old),
            _publication_fact(module, "google", old),
        ),
        "young": (_publication_fact(module, "central", dates["young"]), None),
        "equal-cutoff": (
            _publication_fact(module, "central", dates["equal-cutoff"]),
            None,
        ),
        "conflicting-digest": (
            _publication_fact(module, "central", old),
            _publication_fact(module, "google", old, "1" * 64),
        ),
    }[case]

    class Future:
        def __init__(self, value):
            self.value = value

        def result(self):
            return self.value

    context = PublicationLookupContext(tmp_path, now=lambda: _PUB_NOW)
    outcomes = iter(values)
    monkeypatch.setattr(context, "submit", lambda *_: Future(next(outcomes)))
    with context:
        result = filter_gradle_updates_by_age([update], project, resolution, 7, context)
    assert bool(result) is kept
    if kept:
        assert result[0].published_date == expected_date


def test_gradle_scan_submits_every_update_before_waiting(tmp_path, monkeypatch):
    from maintenance_man.dependency_age import filter_gradle_updates_by_age

    first, project, resolution = _scan_age_inputs(tmp_path)
    second, _, _ = _scan_age_inputs(
        tmp_path, member_specs=(("library", "two", "g:two"),)
    )
    expected_submissions = 4
    submitted = []

    class Future:
        def __init__(self, fact):
            self.fact = fact

        def result(self):
            assert len(submitted) == expected_submissions
            return self.fact

    def submit(repository, module):
        submitted.append((repository, module))
        return Future(
            _publication_fact(module, repository, datetime(2026, 9, 1, tzinfo=UTC))
        )

    context = PublicationLookupContext(tmp_path, now=lambda: _PUB_NOW)
    monkeypatch.setattr(context, "submit", submit)
    with context:
        result = filter_gradle_updates_by_age(
            [first, second], project, resolution, 7, context
        )
    assert [update.gradle_target for update in result] == [
        first.gradle_target,
        second.gradle_target,
    ]
