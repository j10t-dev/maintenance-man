import hashlib
import io
import json
import subprocess
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from email.message import Message
from threading import Event, Lock
from types import SimpleNamespace
from typing import ClassVar

import pytest

from maintenance_man.dependency_age import (
    _MAX_BYTES,
    PublicationError,
    PublicationLookupContext,
    _public_url,
    _publication_http,
    evaluate_gradle_candidate_age,
    filter_registry_updates_by_age,
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
from maintenance_man.models.publication import RegistryFact
from maintenance_man.models.scan import (
    SemverTier,
    UpdateFinding,
)

_PATCH_SUBRUN = "maintenance_man.process.subprocess.run"


def _make_update(pkg: str, latest: str = "2.0.0") -> UpdateFinding:
    return UpdateFinding(
        pkg_name=pkg,
        installed_version="1.0.0",
        latest_version=latest,
        semver_tier=SemverTier.MINOR,
    )


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
        RepositoryDeclaration(
            project_path=":lib",
            domain="library",
            url="https://repo.maven.apache.org/maven2",
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
        result = evaluate_gradle_candidate_age(candidate, 7, context, _PUB_NOW)
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
    expired.clock = lambda: _PUB_NOW + timedelta(hours=24)
    with expired:
        lookup_gradle_publication(request, expired)
        assert len(expired_calls) == 1
    for path in tmp_path.glob("*.json"):
        path.write_text("{broken")
    _, _, corrupt_calls, corrupt = _publication_fixture(tmp_path)
    with corrupt:
        lookup_gradle_publication(request, corrupt)
        assert len(corrupt_calls) == 1


def test_publication_context_logs_a_manager_neutral_label(tmp_path, caplog):
    with (
        caplog.at_level("INFO", logger="maintenance_man.dependency_age"),
        PublicationLookupContext(tmp_path, clock=lambda: _PUB_NOW),
    ):
        pass
    assert "Publication lookup " in caplog.text
    assert "Gradle publication" not in caplog.text


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

    coordinate = "org.example:lib" if kind == "library" else "org.example.plugin"
    row, project, resolution = _scan_age_inputs(
        tmp_path,
        member_specs=((kind, "lib", coordinate),),
        repository_specs=((kind, "https://repo.maven.apache.org/maven2"),),
    )
    module = (
        ModuleId(group="org.example", artifact="lib", version="2")
        if kind == "library"
        else ModuleId(
            group=coordinate, artifact=coordinate + ".gradle.plugin", version="2"
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

    context = PublicationLookupContext(tmp_path, clock=lambda: _PUB_NOW)
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

    context = PublicationLookupContext(tmp_path, clock=lambda: _PUB_NOW)
    monkeypatch.setattr(context, "submit", submit)
    with context:
        result = filter_gradle_updates_by_age(
            [first, second], project, resolution, 7, context
        )
    assert [update.gradle_target for update in result] == [
        first.gradle_target,
        second.gradle_target,
    ]


def _pypi_body(name="pkg", version="1.0", uploads=("2025-12-31T00:00:00Z",)):
    return json.dumps(
        {
            "info": {"name": name, "version": version},
            "urls": [{"upload_time_iso_8601": value} for value in uploads],
        }
    ).encode()


def _pypi_context(cache, response, clock=lambda: _PUB_NOW):
    calls = []

    def transport(url, root, suffix, count):
        count()
        calls.append((url, root, suffix))
        if isinstance(response, Exception):
            raise response
        if response is None:
            return None
        body, final_url = response if isinstance(response, tuple) else (response, url)
        return body, {}, final_url

    return PublicationLookupContext(cache, transport, clock), calls


def _no_transport(url, root, suffix, count):
    pytest.fail("no publication lookup expected")


@pytest.mark.parametrize("updates, days", [([], 7), ([_make_update("pkg")], 0)])
def test_registry_age_skips_lookups(tmp_path, updates, days):
    with PublicationLookupContext(tmp_path, _no_transport, lambda: _PUB_NOW) as context:
        result = filter_registry_updates_by_age(
            updates, "pypi", tmp_path, days, context
        )
    assert result == updates
    assert all(update.published_date is None for update in result)


@pytest.mark.parametrize(
    "upload, kept",
    [
        ("2026-09-17T00:00:00Z", False),
        ("2026-09-11T00:00:00Z", False),
        ("2026-09-10T23:59:59Z", True),
        ("2025-12-31T00:00:00Z", True),
    ],
)
def test_registry_age_withholds_young_releases(tmp_path, upload, kept):
    update = _make_update("pkg", "1.0")
    context, calls = _pypi_context(tmp_path, _pypi_body(uploads=(upload,)))
    with context:
        result = filter_registry_updates_by_age([update], "pypi", tmp_path, 7, context)
    assert calls[0][0] == "https://pypi.org/pypi/pkg/1.0/json"
    expected = datetime.fromisoformat(upload)
    assert [u.published_date for u in result] == ([expected] if kept else [])


@pytest.mark.parametrize("response", [None, PublicationError("publication HTTP 429")])
def test_registry_age_keeps_unknown_dates(tmp_path, response):
    context, _ = _pypi_context(tmp_path, response)
    with context:
        result = filter_registry_updates_by_age(
            [_make_update("pkg", "1.0")], "pypi", tmp_path, 7, context
        )
    assert [u.published_date for u in result] == [None]


def test_registry_age_propagates_unexpected_errors(tmp_path):
    context, _ = _pypi_context(tmp_path, RuntimeError("bug"))
    with context, pytest.raises(RuntimeError, match="bug"):
        filter_registry_updates_by_age(
            [_make_update("pkg", "1.0")], "pypi", tmp_path, 7, context
        )


def test_registry_age_keeps_input_order(tmp_path):
    uploads = {
        "a": "2025-01-01T00:00:00Z",
        "b": "2026-09-17T00:00:00Z",
        "c": "2025-02-01T00:00:00Z",
    }

    def transport(url, root, suffix, count):
        name = suffix.split("/")[1]
        return _pypi_body(name, "1.0", (uploads[name],)), {}, url

    updates = [_make_update(name, "1.0") for name in ("a", "b", "c")]
    with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
        result = filter_registry_updates_by_age(updates, "pypi", tmp_path, 7, context)
    assert [u.pkg_name for u in result] == ["a", "c"]


def test_mvn_age_uses_the_exact_central_pom_and_cache(tmp_path):
    update = _make_update("org.example:lib", "2.0")
    first_calls = []

    def transport(url, repository, suffix, count):
        first_calls.append((url, repository))
        module = ModuleId(group="org.example", artifact="lib", version="2.0")
        return _pom(module), {"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"}, url

    with PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context:
        result = filter_registry_updates_by_age(
            [update], "central", tmp_path, 7, context
        )
    assert first_calls == [
        (
            "https://repo.maven.apache.org/maven2/org/example/lib/2.0/lib-2.0.pom",
            "central",
        )
    ]
    assert [u.published_date for u in result] == [datetime(2026, 9, 1, tzinfo=UTC)]
    with PublicationLookupContext(tmp_path, _no_transport, lambda: _PUB_NOW) as again:
        cached = filter_registry_updates_by_age([update], "central", tmp_path, 7, again)
    assert [u.published_date for u in cached] == [datetime(2026, 9, 1, tzinfo=UTC)]


@pytest.mark.parametrize("name", ["lib", "a:b:c", ":lib", "org.example:"])
def test_mvn_age_skips_names_that_are_not_group_artifact(tmp_path, name):
    update = _make_update(name, "2.0")
    with PublicationLookupContext(tmp_path, _no_transport, lambda: _PUB_NOW) as context:
        result = filter_registry_updates_by_age(
            [update], "central", tmp_path, 7, context
        )
    assert [u.published_date for u in result] == [None]


def test_npm_registry_switch_is_seen_by_the_next_scan(tmp_path, monkeypatch):
    _fake_bun(
        monkeypatch,
        "Published: 2024-01-01T00:00:00Z\n",
        "Published: 2026-09-17T00:00:00Z\n",
    )
    update = _make_update("pkg", "1.0.0")
    kept = []
    for _ in range(2):
        with PublicationLookupContext(tmp_path, clock=lambda: _PUB_NOW) as context:
            kept.append(
                filter_registry_updates_by_age([update], "npm", tmp_path, 7, context)
            )
    assert [len(result) for result in kept] == [1, 0]


@pytest.mark.parametrize(
    "source, method, prefix",
    [("npm", "submit_registry", "pkg"), ("central", "submit", "org.example:lib")],
)
def test_registry_age_submits_every_update_before_waiting(
    tmp_path, monkeypatch, source, method, prefix
):
    expected = 12
    submitted = []

    class Future:
        def result(self):
            assert len(submitted) == expected

    def submit(*args):
        submitted.append(args)
        return Future()

    context = PublicationLookupContext(tmp_path, clock=lambda: _PUB_NOW)
    monkeypatch.setattr(context, method, submit)
    updates = [_make_update(f"{prefix}{i}", "1.0") for i in range(expected)]
    with context:
        result = filter_registry_updates_by_age(updates, source, tmp_path, 7, context)
    assert [u.pkg_name for u in result] == [u.pkg_name for u in updates]


def test_interrupted_registry_batch_cancels_queued_lookups(tmp_path, monkeypatch):
    from maintenance_man import dependency_age as age

    started, release, lock = Event(), Event(), Lock()
    calls, submissions = [], []

    class InterruptingPool(ThreadPoolExecutor):
        def submit(self, *args, **kwargs):
            submissions.append(args)
            if len(submissions) == 12:
                assert started.wait(10), "eight lookups did not start"
                raise KeyboardInterrupt
            return super().submit(*args, **kwargs)

        def shutdown(self, wait=True, *, cancel_futures=False):
            try:
                super().shutdown(wait=False, cancel_futures=cancel_futures)
            finally:
                release.set()
            if wait:
                super().shutdown(wait=True)

    def transport(url, root, suffix, count):
        # No count(): the scanning thread holds the context lock inside submit.
        with lock:
            calls.append(url)
            if len(calls) == 8:
                started.set()
        assert release.wait(10), "context cleanup did not release lookups"

    monkeypatch.setattr(age, "ThreadPoolExecutor", InterruptingPool)
    updates = [_make_update(f"pkg{i}", "1.0") for i in range(12)]
    with (
        pytest.raises(KeyboardInterrupt),
        PublicationLookupContext(tmp_path, transport, lambda: _PUB_NOW) as context,
    ):
        filter_registry_updates_by_age(updates, "pypi", tmp_path, 7, context)
    assert len(calls) == 8, "queued lookups ran after interruption"


def _registry_path(cache, registry, package, version):
    key = json.dumps(["registry", registry, package, version]).encode()
    return cache / (hashlib.sha256(key).hexdigest() + ".json")


def test_pypi_lookup_uses_exact_url_and_earliest_upload(tmp_path):
    body = _pypi_body(
        name="requests",
        version="2.31.0",
        uploads=("2025-12-31T10:00:00Z", "2025-12-30T08:00:00Z"),
    )
    context, calls = _pypi_context(tmp_path, body)
    with context:
        fact = context.submit_registry("pypi", "requests", "2.31.0", tmp_path).result()
    assert calls == [
        (
            "https://pypi.org/pypi/requests/2.31.0/json",
            "pypi",
            "pypi/requests/2.31.0/json",
        )
    ]
    assert fact == RegistryFact(
        registry="pypi",
        package="requests",
        version="2.31.0",
        timestamp=datetime(2025, 12, 30, 8, tzinfo=UTC),
        checked_at=_PUB_NOW,
    )
    assert _registry_path(tmp_path, "pypi", "requests", "2.31.0").is_file()


@pytest.mark.parametrize(
    "package, version, body, expected",
    [
        (
            "Typing_Extensions",
            "4.12.2",
            _pypi_body("typing-extensions", "4.12.2", ("2024-06-07T18:52:13Z",)),
            datetime(2024, 6, 7, 18, 52, 13, tzinfo=UTC),
        ),
        (
            "pkg",
            "1.0.0",
            _pypi_body("pkg", "1.0", ("2025-12-31T00:00:00",)),
            datetime(2025, 12, 31, tzinfo=UTC),
        ),
        (
            "pkg",
            "6.0.2.0",
            _pypi_body("pkg", "6.0.2", ("2025-12-31T00:00:00Z", None)),
            datetime(2025, 12, 31, tzinfo=UTC),
        ),
    ],
    ids=["normalised-name", "equivalent-version-naive-utc", "null-upload-skipped"],
)
def test_pypi_identity_accepts_equivalent_names_and_versions(
    tmp_path, package, version, body, expected
):
    context, _ = _pypi_context(tmp_path, body)
    with context:
        fact = context.submit_registry("pypi", package, version, tmp_path).result()
    assert fact.timestamp == expected


def test_pypi_absent_release_is_unknown(tmp_path):
    context, _ = _pypi_context(tmp_path, None)
    with context:
        assert context.submit_registry("pypi", "pkg", "1.0", tmp_path).result() is None


@pytest.mark.parametrize(
    "response, reason",
    [
        (_pypi_body("other"), "PyPI identity mismatch"),
        (_pypi_body(version="2.0"), "PyPI identity mismatch"),
        (_pypi_body(version="not a version"), "publication lookup failed"),
        (_pypi_body(uploads=()), "PyPI upload time missing"),
        (_pypi_body(uploads=("2026-09-19T00:00:00Z",)), "future publication timestamp"),
        (_pypi_body(uploads=(1,)), "invalid registry timestamp"),
        (_pypi_body(uploads=("soon",)), "publication lookup failed"),
        (b"<html>", "publication lookup failed"),
        (b"[]", "unexpected PyPI response shape"),
        (b'{"info": null, "urls": []}', "unexpected PyPI response shape"),
        (b'{"info": [], "urls": []}', "unexpected PyPI response shape"),
        (
            b'{"info": {"name": "pkg", "version": "1.0"}, "urls": {}}',
            "unexpected PyPI response shape",
        ),
        (
            b'{"info": {"name": "pkg", "version": "1.0"}, "urls": ["x"]}',
            "unexpected PyPI response shape",
        ),
        (
            b'{"info": {"name": 1, "version": "1.0"}, "urls": []}',
            "unexpected PyPI response shape",
        ),
        ("oversized", "PyPI response exceeds size limit"),
        (
            (_pypi_body(), "https://pypi.org/pypi/other/1.0/json"),
            "PyPI response URL changed",
        ),
        (PublicationError("publication HTTP 429"), "publication HTTP 429"),
    ],
)
def test_pypi_failures_are_contained(tmp_path, response, reason):
    if response == "oversized":
        response = b" " * (_MAX_BYTES + 1)
    context, _ = _pypi_context(tmp_path, response)
    with context:
        result = context.submit_registry("pypi", "pkg", "1.0", tmp_path).result()
    assert result == AgeBlock(reason=f"pkg:1.0: {reason}")
    assert not list(tmp_path.glob("*.json"))


@pytest.mark.parametrize(
    "location",
    ["https://pypi.org/pypi/pkg/1.0/json", "https://pypi.org/pypi/other/1.0/json"],
)
def test_pypi_transport_refuses_any_redirect(monkeypatch, location):
    from maintenance_man import dependency_age as age

    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            headers = Message()
            headers["Location"] = location
            raise urllib.error.HTTPError(
                request.full_url, 302, "redirect", headers, None
            )

    monkeypatch.setattr(age.urllib.request, "build_opener", lambda *_: Opener())
    with pytest.raises(PublicationError, match="invalid redirect"):
        _publication_http(
            "https://pypi.org/pypi/pkg/1.0/json",
            "pypi",
            "pypi/pkg/1.0/json",
            lambda: None,
        )
    assert calls == ["https://pypi.org/pypi/pkg/1.0/json"]


def test_pypi_transport_refuses_other_hosts_before_opening(monkeypatch):
    from maintenance_man import dependency_age as age

    def refuse(*args, **kwargs):
        pytest.fail("no request expected")

    monkeypatch.setattr(
        age.urllib.request,
        "build_opener",
        lambda *_: SimpleNamespace(open=refuse),
    )
    with pytest.raises(PublicationError, match="untrusted publication redirect"):
        _publication_http(
            "https://evil.test/pypi/pkg/1.0/json",
            "pypi",
            "pypi/pkg/1.0/json",
            lambda: None,
        )


def _seed(cache, **changes):
    fact = RegistryFact(
        registry="pypi",
        package="pkg",
        version="1.0",
        timestamp=datetime(2025, 12, 31, tzinfo=UTC),
        checked_at=_PUB_NOW,
    ).model_copy(update=changes)
    path = _registry_path(cache, "pypi", "pkg", "1.0")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(fact.model_dump_json())
    return path


@pytest.mark.parametrize(
    "changes, clock, expected_calls",
    [
        ({}, _PUB_NOW + timedelta(hours=23, minutes=59), 0),
        ({}, _PUB_NOW + timedelta(hours=24), 1),
        ({}, _PUB_NOW - timedelta(seconds=1), 1),
        ({"timestamp": _PUB_NOW + timedelta(hours=1)}, _PUB_NOW, 1),
        ({"package": "other"}, _PUB_NOW, 1),
        ({"registry": "npm"}, _PUB_NOW, 1),
    ],
    ids=[
        "fresh",
        "expired",
        "future-check",
        "future-date",
        "other-package",
        "other-registry",
    ],
)
def test_pypi_cache_freshness_and_identity(tmp_path, changes, clock, expected_calls):
    _seed(tmp_path, **changes)
    context, calls = _pypi_context(tmp_path, _pypi_body(), clock=lambda: clock)
    with context:
        result = context.submit_registry("pypi", "pkg", "1.0", tmp_path).result()
    assert len(calls) == expected_calls
    assert context.cache_hits == 1 - expected_calls
    assert isinstance(result, RegistryFact)


def test_pypi_corrupt_cache_goes_live(tmp_path):
    _seed(tmp_path).write_text("{broken")
    context, calls = _pypi_context(tmp_path, _pypi_body())
    with context:
        assert isinstance(
            context.submit_registry("pypi", "pkg", "1.0", tmp_path).result(),
            RegistryFact,
        )
    assert len(calls) == 1


def test_pypi_fact_is_shared_across_projects(tmp_path):
    cache = tmp_path / "cache"
    first, _ = _pypi_context(cache, _pypi_body())
    with first:
        first.submit_registry("pypi", "pkg", "1.0", tmp_path / "a").result()
    second, calls = _pypi_context(cache, _pypi_body())
    with second:
        fact = second.submit_registry("pypi", "pkg", "1.0", tmp_path / "b").result()
    assert calls == []
    assert fact.timestamp == datetime(2025, 12, 31, tzinfo=UTC)


def test_pypi_cache_write_failure_returns_live_fact(tmp_path):
    cache = tmp_path / "not-a-directory"
    cache.write_text("")
    context, _ = _pypi_context(cache, _pypi_body())
    with context:
        result = context.submit_registry("pypi", "pkg", "1.0", tmp_path).result()
    assert isinstance(result, RegistryFact)


def test_registry_and_maven_facts_share_a_directory(tmp_path):
    _, request, _, maven = _publication_fixture(tmp_path)
    pypi, _ = _pypi_context(tmp_path, _pypi_body())
    with maven:
        lookup_gradle_publication(request, maven)
    with pypi:
        pypi.submit_registry("pypi", "pkg", "1.0", tmp_path).result()
    assert len(list(tmp_path.glob("*.json"))) == 2
    _, _, maven_calls, maven_again = _publication_fixture(tmp_path)
    pypi_again, pypi_calls = _pypi_context(tmp_path, _pypi_body())
    with maven_again:
        lookup_gradle_publication(request, maven_again)
    with pypi_again:
        pypi_again.submit_registry("pypi", "pkg", "1.0", tmp_path).result()
    assert maven_calls == [] and pypi_calls == []


def test_duplicate_registry_lookups_share_one_request(tmp_path):
    context, calls = _pypi_context(tmp_path, _pypi_body())
    with context:
        first = context.submit_registry("pypi", "pkg", "1.0", tmp_path)
        second = context.submit_registry("pypi", "pkg", "1.0", tmp_path)
        assert first is second
        assert isinstance(first.result(), RegistryFact)
    assert len(calls) == 1


def _fake_bun(monkeypatch, *outputs):
    calls = []
    queue = list(outputs)

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        output = queue.pop(0)
        if isinstance(output, BaseException):
            raise output
        return subprocess.CompletedProcess(cmd, 1, output, "warning")

    monkeypatch.setattr(_PATCH_SUBRUN, run)
    return calls


def test_npm_lookup_runs_bun_info_in_the_project_without_disk_cache(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("VIRTUAL_ENV", "/host/venv")
    project, cache = tmp_path / "project", tmp_path / "cache"
    calls = _fake_bun(monkeypatch, "pkg@1.0.0 | MIT\nPublished: 2024-01-02T03:04:05Z\n")
    with PublicationLookupContext(cache, clock=lambda: _PUB_NOW) as context:
        fact = context.submit_registry("npm", "pkg", "1.0.0", project).result()
        assert context.requests == 1
    assert fact.timestamp == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
    ((cmd, kwargs),) = calls
    assert cmd == ["bun", "info", "pkg@1.0.0"]
    assert kwargs["cwd"] == project
    assert kwargs["timeout"] == 30
    assert "VIRTUAL_ENV" not in kwargs["env"]
    assert not cache.exists() or not list(cache.iterdir())


@pytest.mark.parametrize(
    "output, expected",
    [
        (
            "Published: 2024-01-02T03:04:05\n",
            datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC),
        ),
        ("pkg@1.0.0 | MIT\n", None),
        ("Published:\n", None),
        (
            subprocess.TimeoutExpired(["bun", "info"], 30),
            AgeBlock(reason="pkg:1.0.0: publication lookup failed"),
        ),
        (
            FileNotFoundError(2, "No such file or directory", "bun"),
            AgeBlock(reason="pkg:1.0.0: publication lookup failed"),
        ),
        (
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
            AgeBlock(reason="pkg:1.0.0: publication lookup failed"),
        ),
        (
            "Published: soon\n",
            AgeBlock(reason="pkg:1.0.0: publication lookup failed"),
        ),
    ],
)
def test_npm_dates_and_failures(tmp_path, monkeypatch, output, expected):
    _fake_bun(monkeypatch, output)
    with PublicationLookupContext(tmp_path, clock=lambda: _PUB_NOW) as context:
        result = context.submit_registry("npm", "pkg", "1.0.0", tmp_path).result()
    if isinstance(expected, datetime):
        assert result.timestamp == expected
    else:
        assert result == expected


def test_npm_ignores_a_planted_cache_file_and_reruns_each_context(
    tmp_path, monkeypatch
):
    planted = _registry_path(tmp_path, "npm", "pkg", "1.0.0")
    planted.write_text(
        RegistryFact(
            registry="npm",
            package="pkg",
            version="1.0.0",
            timestamp=datetime(2020, 1, 1, tzinfo=UTC),
            checked_at=_PUB_NOW,
        ).model_dump_json()
    )
    calls = _fake_bun(
        monkeypatch,
        "Published: 2024-01-01T00:00:00Z\n",
        "Published: 2026-09-17T00:00:00Z\n",
    )
    dates = []
    for _ in range(2):
        with PublicationLookupContext(tmp_path, clock=lambda: _PUB_NOW) as context:
            first = context.submit_registry("npm", "pkg", "1.0.0", tmp_path)
            again = context.submit_registry("npm", "pkg", "1.0.0", tmp_path)
            dates.append(first.result().timestamp)
            assert again is first
    assert len(calls) == 2
    assert dates == [
        datetime(2024, 1, 1, tzinfo=UTC),
        datetime(2026, 9, 17, tzinfo=UTC),
    ]


_V6_DEAD = ("2001:db8::1", 443, 0, 0)
_V6_SECOND = ("2001:db8::2", 443, 0, 0)
_V4_LIVE = ("192.0.2.1", 443)


def _address_infos():
    import socket

    return [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", _V6_DEAD),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", _V6_SECOND),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", _V4_LIVE),
    ]


def _fake_network(
    monkeypatch, now, *, refused=(), infos=None, no_ipv6=False, connect_cost=0.0
):
    """Fake resolver and sockets: IPv6 connects time out, IPv4 connects succeed."""
    import errno
    import socket

    from maintenance_man import dependency_age as age

    network = SimpleNamespace(attempts=[], closed=[])

    class FakeSocket:
        def __init__(self, family, kind, proto):
            if no_ipv6 and family == socket.AF_INET6:
                raise OSError(errno.EAFNOSUPPORT, "Address family not supported")
            self.timeouts = []
            self.address = ("", 0)

        def settimeout(self, value):
            self.timeouts.append(value)

        def connect(self, address):
            self.address = address
            network.attempts.append((address[0], self.timeouts[-1]))
            now[0] += connect_cost
            if address in refused:
                msg = "refused"
                raise ConnectionRefusedError(msg)
            if ":" in address[0]:
                msg = "timed out"
                raise TimeoutError(msg)

        def close(self):
            network.closed.append(self.address[0])

    resolved = _address_infos() if infos is None else infos
    monkeypatch.setattr(age.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(age.socket, "getaddrinfo", lambda *a, **k: resolved)
    monkeypatch.setattr(age.socket, "socket", FakeSocket)
    return network


@pytest.mark.parametrize(
    "deadline, attempt, final",
    [(115.0, 3.0, 12.0), (101.5, 1.5, 1.5)],
    ids=["attempt-cap", "remaining-deadline"],
)
def test_publication_connect_alternates_families_within_the_deadline(
    monkeypatch, deadline, attempt, final
):
    from maintenance_man import dependency_age as age

    network = _fake_network(monkeypatch, [100.0])
    sock = age._deadline_connect(deadline)(("pypi.org", 443), 12.0)
    assert network.attempts == [("2001:db8::1", attempt), ("192.0.2.1", attempt)]
    assert network.closed == ["2001:db8::1"]
    assert sock.timeouts[-1] == final


def test_publication_connect_stops_at_the_deadline(monkeypatch):
    from maintenance_man import dependency_age as age

    network = _fake_network(monkeypatch, [100.0])
    with pytest.raises(PublicationError, match="publication lookup timed out"):
        age._deadline_connect(100.0)(("pypi.org", 443), 12.0)
    assert network.attempts == []


def test_publication_connect_expiring_during_connect_closes_the_socket(monkeypatch):
    from maintenance_man import dependency_age as age

    infos = [row for row in _address_infos() if row[4] == _V4_LIVE]
    network = _fake_network(monkeypatch, [100.0], infos=infos, connect_cost=2.0)
    with pytest.raises(PublicationError, match="publication lookup timed out"):
        age._deadline_connect(101.0)(("pypi.org", 443), 12.0)
    assert network.closed == ["192.0.2.1"]


def test_publication_connect_skips_an_unsupported_family(monkeypatch):
    from maintenance_man import dependency_age as age

    network = _fake_network(monkeypatch, [100.0], no_ipv6=True)
    age._deadline_connect(115.0)(("pypi.org", 443), 12.0)
    assert network.attempts == [("192.0.2.1", 3.0)]


def test_publication_connect_reports_the_last_failure(monkeypatch):
    from maintenance_man import dependency_age as age

    network = _fake_network(monkeypatch, [100.0], refused=(_V4_LIVE, _V6_SECOND))
    with pytest.raises(ConnectionRefusedError):
        age._deadline_connect(115.0)(("pypi.org", 443), 12.0)
    assert [address for address, _ in network.attempts] == [
        "2001:db8::1",
        "192.0.2.1",
        "2001:db8::2",
    ]
    assert network.closed == ["2001:db8::1", "192.0.2.1", "2001:db8::2"]


def test_publication_connect_without_addresses_fails(monkeypatch):
    from maintenance_man import dependency_age as age

    _fake_network(monkeypatch, [100.0], infos=[])
    with pytest.raises(PublicationError, match=r"no address for pypi\.org"):
        age._deadline_connect(115.0)(("pypi.org", 443), 12.0)


def test_publication_https_handler_verifies_and_uses_its_deadline(monkeypatch):
    import ssl

    from maintenance_man import dependency_age as age

    now = [113.5]
    network = _fake_network(monkeypatch, now)
    handler = age._DeadlineHTTPSHandler(115.0)
    assert handler.context.verify_mode is ssl.CERT_REQUIRED
    assert handler.context.check_hostname is True
    connection = handler.connection("pypi.org", timeout=12.0)
    connection._create_connection(("pypi.org", 443), 12.0)
    assert network.attempts == [("2001:db8::1", 1.5), ("192.0.2.1", 1.5)]


def test_publication_transport_installs_the_deadline_handler(monkeypatch):
    from maintenance_man import dependency_age as age

    handlers = []

    def capture(*args):
        handlers.extend(args)
        return SimpleNamespace(open=lambda *a, **k: pytest.fail("no request"))

    monkeypatch.setattr(age.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(age.urllib.request, "build_opener", capture)
    with pytest.raises(PublicationError):
        _publication_http(
            "https://evil.test/pypi/pkg/1.0/json",
            "pypi",
            "pypi/pkg/1.0/json",
            lambda: None,
        )
    deadlines = [
        h.deadline for h in handlers if isinstance(h, age._DeadlineHTTPSHandler)
    ]
    assert deadlines == [115.0]
