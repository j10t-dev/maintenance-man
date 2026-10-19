import hashlib
import http.client
import io
import json
import re
import socket
import subprocess
import threading
import urllib.request
import urllib.response
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from http import HTTPStatus
from pathlib import Path
from threading import Barrier, Event, Lock
from typing import Any

import pytest
from pydantic import ValidationError

from maintenance_man import dependency_age as age
from maintenance_man.dependency_age import (
    PublicationError,
    PublicationLookupContext,
    RegistryFact,
    _public_url,
    _publication_http,
    evaluate_gradle_candidate_age,
    filter_registry_updates_by_age,
    lookup_gradle_publication,
    member_module,
    publication_request,
    trusted_repository,
)
from maintenance_man.models.gradle import (
    AgeBlock,
    ModuleId,
    PublicationEvidence,
    PublicationFact,
    PublicationRequest,
    RepositoryDeclaration,
)
from maintenance_man.models.scan import SemverTier
from maintenance_man.process import ProcessError
from tests.fakes import FakeCommands
from tests.support.clock import FakeClock
from tests.support.findings import make_gradle_member, make_update
from tests.support.gradle import make_gradle_candidate
from tests.support.process import completed
from tests.support.publication import pypi_body

_PUB_NOW = datetime(2026, 9, 18, tzinfo=UTC)
_LIB = ModuleId(group="org.example", artifact="lib", version="2.0")
_LIB_POM_URL = "https://repo.maven.apache.org/maven2/org/example/lib/2.0/lib-2.0.pom"
_GOOGLE_POM_URL = (
    "https://dl.google.com/dl/android/maven2/org/example/lib/2.0/lib-2.0.pom"
)
_SEPTEMBER_1 = {"Last-Modified": "Tue, 01 Sep 2026 00:00:00 GMT"}


def _wire_response(raw: bytes) -> http.client.HTTPResponse:
    receiver, sender = socket.socketpair()

    def send() -> None:
        with sender:
            try:
                sender.sendall(raw)
                sender.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threading.Thread(target=send, daemon=True).start()
    response = http.client.HTTPResponse(receiver)
    response.begin()
    return response


class _WireOpener:
    def __init__(self, wire: bytes) -> None:
        self.wire = wire

    def open(self, url, timeout):
        return _wire_response(self.wire)


def _pool():
    class Pool(ThreadPoolExecutor):
        started = Event()
        release = Event()

        def shutdown(self, wait=True, *, cancel_futures=False):
            try:
                super().shutdown(wait=False, cancel_futures=cancel_futures)
            finally:
                type(self).release.set()
            if wait:
                super().shutdown(wait=True)

    return Pool


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


def _parented_pom(identity):
    return (
        "<project><parent><groupId>org.example</groupId>"
        "<artifactId>parent</artifactId><version>2.0</version></parent>"
        f"<artifactId>lib</artifactId>{identity}</project>"
    ).encode()


def _publication_fixture(
    tmp_path, *, repositories=("central",), responses=None, routing_supported=True
):
    request = PublicationRequest(
        module=_LIB, repositories=repositories, routing_supported=routing_supported
    )
    calls = []

    def transport(url, repository, suffix):
        calls.append(url)
        result = (responses or {}).get(repository, (_pom(_LIB), _SEPTEMBER_1))
        if isinstance(result, Exception):
            raise result
        if result is None:
            return None
        return (*result, url)

    context = PublicationLookupContext(tmp_path, transport, FakeClock(_PUB_NOW))
    return request, calls, context


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://repo1.maven.org/maven2/", "central"),
        ("https://maven.google.com/", "google"),
        ("https://plugins.gradle.org/m2", "portal"),
        ("http://repo.maven.apache.org/maven2", None),
        ("https://user:secret@repo.maven.apache.org/maven2", None),
        ("https://repo.maven.apache.org.evil/maven2", None),
        ("https://repo.maven.apache.org/maven2?token=secret", None),
        (None, None),
    ],
)
def test_given_repository_url_when_trusted_then_policy_id_or_none(url, expected):
    assert trusted_repository(url) == expected


@pytest.mark.parametrize(
    ("urls", "supported", "repositories"),
    [
        pytest.param([], False, (), id="empty"),
        pytest.param(
            ["https://repo1.maven.org/maven2", "https://maven.google.com"],
            True,
            ("central", "google"),
            id="all-trusted",
        ),
        pytest.param(
            ["https://repo1.maven.org/maven2", "https://evil.test/maven2"],
            False,
            ("central",),
            id="one-untrusted",
        ),
        pytest.param([None], False, (), id="native-url-none"),
        pytest.param(
            [
                "https://repo1.maven.org/maven2",
                "https://maven.google.com",
                "https://repo.maven.apache.org/maven2",
            ],
            True,
            ("central", "google"),
            id="deduplicated",
        ),
    ],
)
def test_given_declared_repositories_when_request_built_then_routing_needs_all_trusted(
    urls, supported, repositories
):
    declarations = tuple(
        RepositoryDeclaration(project_path=":app", domain="library", url=url)
        for url in urls
    )

    request = publication_request(_LIB, declarations)

    assert (request.routing_supported, request.repositories) == (
        supported,
        repositories,
    )


@pytest.mark.parametrize(
    ("repository", "url", "allowed"),
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
def test_given_redirect_target_when_pinned_then_only_trusted_exact_path_passes(
    repository, url, allowed
):
    if allowed:
        _public_url(url, repository, "a/b/2/b-2.pom")
    else:
        with pytest.raises(PublicationError):
            _public_url(url, repository, "a/b/2/b-2.pom")


def test_given_two_requests_when_aged_then_youngest_timestamp_returned(tmp_path):
    other = ModuleId(group="org.example", artifact="lib2", version="2.0")
    requests = (
        PublicationRequest(
            module=_LIB, repositories=("central",), routing_supported=True
        ),
        PublicationRequest(
            module=other, repositories=("google",), routing_supported=True
        ),
    )
    responses = {
        "central": (_pom(_LIB), {"Last-Modified": "Sat, 05 Sep 2026 00:00:00 GMT"}),
        "google": (_pom(other), _SEPTEMBER_1),
    }

    def transport(url, repository, suffix):
        return (*responses[repository], url)

    with PublicationLookupContext(tmp_path, transport, FakeClock(_PUB_NOW)) as context:
        result = evaluate_gradle_candidate_age(
            make_gradle_candidate(publication_requests=requests), 0, context, _PUB_NOW
        )

    assert result == datetime(2026, 9, 5, tzinfo=UTC)


@pytest.mark.parametrize(
    ("repositories", "routing", "response", "days", "expected", "expected_calls"),
    [
        pytest.param(
            ("central",),
            False,
            _SEPTEMBER_1,
            0,
            AgeBlock(reason="unsupported or missing scoped repository routing"),
            [],
            id="routing-unsupported",
        ),
        pytest.param(
            (),
            True,
            _SEPTEMBER_1,
            0,
            AgeBlock(reason="unsupported or missing scoped repository routing"),
            [],
            id="no-repositories",
        ),
        pytest.param(
            None,
            True,
            _SEPTEMBER_1,
            7,
            AgeBlock(reason="candidate has no publication requests"),
            [],
            id="no-requests",
        ),
        pytest.param(
            ("google",),
            True,
            _SEPTEMBER_1,
            7,
            datetime(2026, 9, 1, tzinfo=UTC),
            [_GOOGLE_POM_URL],
            id="old",
        ),
        pytest.param(
            ("google",),
            True,
            {"Last-Modified": "Fri, 11 Sep 2026 00:00:00 GMT"},
            7,
            datetime(2026, 9, 11, tzinfo=UTC),
            [_GOOGLE_POM_URL],
            id="exactly-seven-days",
        ),
        pytest.param(
            ("google",),
            True,
            {"Last-Modified": "Fri, 11 Sep 2026 00:00:01 GMT"},
            7,
            AgeBlock(reason="publication younger than required 7 days"),
            [_GOOGLE_POM_URL],
            id="one-second-younger",
        ),
        pytest.param(
            ("google",),
            True,
            {"Last-Modified": "Thu, 17 Sep 2026 00:00:00 GMT"},
            0,
            datetime(2026, 9, 17, tzinfo=UTC),
            [_GOOGLE_POM_URL],
            id="zero-days-accepts-past",
        ),
        pytest.param(
            ("google",),
            True,
            {"Last-Modified": "Sat, 19 Sep 2026 00:00:00 GMT"},
            0,
            AgeBlock(reason="org.example:lib:2.0: future publication timestamp"),
            [_GOOGLE_POM_URL],
            id="future",
        ),
        pytest.param(
            ("google",),
            True,
            {"Last-Modified": "broken"},
            0,
            AgeBlock(reason="org.example:lib:2.0: publication lookup failed"),
            [_GOOGLE_POM_URL],
            id="header-broken",
        ),
        pytest.param(
            ("google",),
            True,
            {"Last-Modified": "Tue, 01 Sep 2026 00:00:00"},
            0,
            AgeBlock(
                reason="org.example:lib:2.0: publication timestamp lacks timezone"
            ),
            [_GOOGLE_POM_URL],
            id="header-without-timezone",
        ),
        pytest.param(
            ("central",),
            True,
            {},
            7,
            AgeBlock(reason="org.example:lib:2.0: publication timestamp missing"),
            [_LIB_POM_URL],
            id="header-missing",
        ),
        *(
            pytest.param(
                ("central",),
                True,
                TimeoutError("unavailable"),
                days,
                AgeBlock(reason="org.example:lib:2.0: publication lookup failed"),
                [_LIB_POM_URL],
                id=f"timeout-at-{days}-days",
            )
            for days in (0, 7)
        ),
    ],
)
def test_given_publication_response_when_gradle_age_evaluated_then_policy_decides(
    tmp_path, repositories, routing, response, days, expected, expected_calls
):
    responses = {repo: (_pom(_LIB), response) for repo in repositories or ()}
    if isinstance(response, Exception):
        responses = {"central": response}
    request, calls, context = _publication_fixture(
        tmp_path,
        repositories=repositories or (),
        responses=responses,
        routing_supported=routing,
    )
    candidate = make_gradle_candidate(
        publication_requests=() if repositories is None else (request,)
    )

    with context:
        result = evaluate_gradle_candidate_age(candidate, days, context, _PUB_NOW)

    assert result == expected
    assert calls == expected_calls


@pytest.mark.parametrize(
    ("google", "expected"),
    [
        pytest.param(None, datetime(2026, 9, 1, tzinfo=UTC), id="absence-ignored"),
        pytest.param(
            TimeoutError("timeout"),
            AgeBlock(reason="org.example:lib:2.0: publication lookup failed"),
            id="timeout",
        ),
        pytest.param(
            PublicationError("HTTP 429"),
            AgeBlock(reason="org.example:lib:2.0: HTTP 429"),
            id="rate-limited",
        ),
        pytest.param(
            (b"<project/>", _SEPTEMBER_1),
            AgeBlock(
                reason="org.example:lib:2.0: unresolved or ambiguous POM identity"
            ),
            id="mismatched-pom",
        ),
        pytest.param(
            (_pom(_LIB), {"Last-Modified": "Thu, 17 Sep 2026 00:00:00 GMT"}),
            datetime(2026, 9, 17, tzinfo=UTC),
            id="same-content-youngest-date",
        ),
        pytest.param(
            (_pom(_LIB) + b"\n", {"Last-Modified": "Thu, 17 Sep 2026 00:00:00 GMT"}),
            AgeBlock(reason="conflicting artifact content for org.example:lib:2.0"),
            id="different-content",
        ),
    ],
)
def test_given_two_repositories_when_looked_up_then_evidence_or_block(
    tmp_path, google, expected
):
    request, _, context = _publication_fixture(
        tmp_path, repositories=("central", "google"), responses={"google": google}
    )

    with context:
        result = lookup_gradle_publication(request, context)

    actual = result.timestamp if isinstance(result, PublicationEvidence) else result
    assert actual == expected


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

    def transport(url, repository, suffix):
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

    with PublicationLookupContext(tmp_path, transport, FakeClock(_PUB_NOW)) as context:
        result = evaluate_gradle_candidate_age(
            make_gradle_candidate(publication_requests=(request,)),
            7,
            context,
            _PUB_NOW,
        )

    assert result == AgeBlock(reason="publication younger than required 7 days")
    assert sorted(calls) == [
        "https://plugins.gradle.org/m2/org/impl/engine/9.1/engine-9.1.pom",
        "https://plugins.gradle.org/m2/org/plugin/org.plugin.gradle.plugin/2.0/"
        "org.plugin.gradle.plugin-2.0.pom",
    ]


_UNRESOLVED = AgeBlock(
    reason="org.example:lib:2.0: unresolved or ambiguous POM identity"
)
_MISMATCH = AgeBlock(reason="org.example:lib:2.0: POM identity mismatch")


def _namespaced_parented_pom(explicit):
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<modelVersion>4.0.0</modelVersion><parent><groupId>org.example</groupId>"
        "<artifactId>parent</artifactId><version>2.0</version></parent>"
        f"<artifactId>lib</artifactId>{explicit}</project>"
    ).encode()


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param(_pom(_LIB), _LIB, id="plain"),
        pytest.param(_namespaced_parented_pom(""), _LIB, id="parent-supplies-both"),
        pytest.param(
            _namespaced_parented_pom("<groupId>org.example</groupId>"),
            _LIB,
            id="explicit-group",
        ),
        pytest.param(
            _namespaced_parented_pom("<version>2.0</version>"),
            _LIB,
            id="explicit-version",
        ),
        pytest.param(
            b'<!DOCTYPE project [<!ENTITY x SYSTEM "file:///etc/passwd">]><project/>',
            AgeBlock(
                reason="org.example:lib:2.0: POM entity declarations are unsupported"
            ),
            id="entity-declaration",
        ),
        pytest.param(
            b"<project><groupId>${group}</groupId><artifactId>lib</artifactId>"
            b"<version>2.0</version></project>",
            _UNRESOLVED,
            id="property-group",
        ),
        pytest.param(
            b"<project><parent><groupId>org.example</groupId><version>2.0</version>"
            b"</parent><artifactId>lib</artifactId></project>",
            _UNRESOLVED,
            id="parent-without-artifact",
        ),
        pytest.param(
            b"<project><groupId>other</groupId><artifactId>lib</artifactId>"
            b"<version>2.0</version></project>",
            _MISMATCH,
            id="other-group",
        ),
        pytest.param(
            _parented_pom("<groupId>wrong.group</groupId>"),
            _MISMATCH,
            id="parent-wrong",
        ),
        pytest.param(
            _parented_pom("<version>${revision}</version>"),
            _UNRESOLVED,
            id="property-version",
        ),
        pytest.param(
            _parented_pom("<version></version>"), _UNRESOLVED, id="empty-version"
        ),
        pytest.param(
            _parented_pom("<version>2.0</version><version>2.0</version>"),
            _UNRESOLVED,
            id="repeated-version",
        ),
    ],
)
def test_given_pom_when_publication_looked_up_then_identity_is_proven_or_withheld(
    tmp_path, body, expected
):
    request, _, context = _publication_fixture(
        tmp_path, responses={"central": (body, _SEPTEMBER_1)}
    )

    with context:
        result = lookup_gradle_publication(request, context)

    actual = (
        result.facts[0].module if isinstance(result, PublicationEvidence) else result
    )
    assert actual == expected


class _RecordingBody(io.BytesIO):
    """A response body that appends the size of every read to *reads*."""

    def __init__(self, body: bytes, reads: list[int]) -> None:
        super().__init__(body)
        self.reads = reads

    def read(self, size: int | None = -1) -> bytes:
        data = super().read(size)
        self.reads.append(len(data))
        return data


class _ScriptedHttps(urllib.request.HTTPSHandler):
    """Answer each HTTPS request with the next scripted (status, headers, body) hop."""

    def __init__(self, hops: list[tuple[int, dict[str, str], bytes]]) -> None:
        super().__init__()
        self.hops = iter(hops)
        self.urls: list[str] = []
        self.timeouts: list[float | None] = []
        self.reads: list[int] = []

    def https_open(  # ty:ignore[invalid-method-override]
        self, req: urllib.request.Request
    ) -> urllib.response.addinfourl:
        self.urls.append(req.full_url)
        self.timeouts.append(req.timeout)
        status, headers, body = next(self.hops)
        message = http.client.HTTPMessage()
        for name, value in headers.items():
            message[name] = value
        response = urllib.response.addinfourl(
            _RecordingBody(body, self.reads), message, req.full_url, status
        )
        response.msg = HTTPStatus(status).phrase  # ty:ignore[unresolved-attribute]
        return response


_SUFFIX = "a/b/2/b-2.pom"
_START = f"https://repo.maven.apache.org/maven2/{_SUFFIX}"
_HOPS = [f"https://repo1.maven.org/maven2/m{n}/{_SUFFIX}" for n in range(1, 7)]
_PYPI = "https://pypi.org/pypi/pkg/1.0/json"
_MAX = 1024 * 1024


def _redirect(location: str) -> tuple[int, dict[str, str], bytes]:
    return 302, {"Location": location}, b""


def _scripted_opener(monkeypatch, hops) -> _ScriptedHttps:
    """Route the module's opener through a handler scripted with *hops*."""
    handler = _ScriptedHttps(hops)
    real_build_opener = urllib.request.build_opener
    monkeypatch.setattr(
        "maintenance_man.dependency_age.urllib.request.build_opener",
        lambda *handlers: real_build_opener(*handlers, handler),
    )
    return handler


@pytest.mark.parametrize(
    ("repository", "url", "suffix", "hops", "expected", "expected_urls"),
    [
        pytest.param(
            "central",
            _START,
            _SUFFIX,
            [
                *(_redirect(hop) for hop in _HOPS[:5]),
                (200, _SEPTEMBER_1, b"<project/>"),
            ],
            (b"<project/>", _SEPTEMBER_1, _HOPS[4]),
            [_START, *_HOPS[:5]],
            id="five-redirects-then-body",
        ),
        pytest.param(
            "central",
            _START,
            _SUFFIX,
            [*(_redirect(hop) for hop in _HOPS), (200, {}, b"<project/>")],
            "publication HTTP 302",
            [_START, *_HOPS[:5]],
            id="sixth-redirect-refused",
        ),
        pytest.param(
            "central",
            _START,
            _SUFFIX,
            [*(_redirect(_HOPS[n % 2]) for n in range(6)), (200, {}, b"<project/>")],
            "publication HTTP 302",
            [_START, _HOPS[0], _HOPS[1], _HOPS[0], _HOPS[1], _HOPS[0]],
            id="sixth-redirect-between-two-urls-refused",
        ),
        pytest.param(
            "central",
            _START,
            _SUFFIX,
            [_redirect(_HOPS[0]), _redirect(f"https://evil.test/{_SUFFIX}")],
            "untrusted publication redirect",
            [_START, _HOPS[0]],
            id="untrusted-host-after-trusted-hop",
        ),
        pytest.param(
            "pypi",
            _PYPI,
            "pypi/pkg/1.0/json",
            [_redirect(_PYPI)],
            "publication redirect limit or invalid redirect",
            [_PYPI],
            id="pypi-same-url",
        ),
        pytest.param(
            "pypi",
            _PYPI,
            "pypi/pkg/1.0/json",
            [_redirect("https://pypi.org/pypi/other/1.0/json")],
            "publication redirect limit or invalid redirect",
            [_PYPI],
            id="pypi-other-url",
        ),
        pytest.param(
            "central", _START, _SUFFIX, [(404, {}, b"")], None, [_START], id="404"
        ),
        pytest.param(
            "central",
            _START,
            _SUFFIX,
            [(500, {}, b"")],
            "publication HTTP 500",
            [_START],
            id="500",
        ),
        pytest.param(
            "central",
            _START,
            _SUFFIX,
            [(200, _SEPTEMBER_1, b"x" * _MAX)],
            (b"x" * _MAX, _SEPTEMBER_1, _START),
            [_START],
            id="body-at-limit",
        ),
        pytest.param(
            "central",
            _START,
            _SUFFIX,
            [(200, {}, b"x" * (_MAX + 1))],
            "publication response exceeds limit",
            [_START],
            id="body-over-limit",
        ),
    ],
)
def test_given_scripted_hops_when_fetched_then_trust_bounds_hold(
    monkeypatch, repository, url, suffix, hops, expected, expected_urls
):
    handler = _scripted_opener(monkeypatch, hops)

    if isinstance(expected, str):
        with pytest.raises(PublicationError, match=f"^{re.escape(expected)}$"):
            _publication_http(url, repository, suffix)
    else:
        assert _publication_http(url, repository, suffix) == expected
    assert handler.urls == expected_urls
    assert handler.timeouts == [3] * len(expected_urls)


def test_given_oversized_redirect_body_when_fetched_then_only_the_final_body_is_read(
    monkeypatch,
):
    handler = _scripted_opener(
        monkeypatch,
        [
            (302, {"Location": _HOPS[0]}, b"x" * (_MAX + 1)),
            (200, _SEPTEMBER_1, b"<project/>"),
        ],
    )

    result = _publication_http(_START, "central", _SUFFIX)

    assert result == (b"<project/>", _SEPTEMBER_1, _HOPS[0])
    assert handler.reads == [len(b"<project/>")]


def test_given_untrusted_host_when_fetched_then_nothing_is_opened(monkeypatch):
    monkeypatch.setattr(
        "maintenance_man.dependency_age.urllib.request.build_opener",
        lambda *_: pytest.fail("no request expected"),
    )

    with pytest.raises(PublicationError, match="untrusted publication redirect"):
        _publication_http(
            "https://evil.test/pypi/pkg/1.0/json", "pypi", "pypi/pkg/1.0/json"
        )


@pytest.mark.parametrize("failure", ["truncated-chunk", "bad-status-line"])
def test_publication_malformed_http_withholds_candidate(tmp_path, monkeypatch, failure):
    if failure == "truncated-chunk":
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n<project>"
    else:
        wire = b"not an HTTP status line\r\n\r\n"
    monkeypatch.setattr(
        age.urllib.request, "build_opener", lambda *args: _WireOpener(wire)
    )
    request = PublicationRequest(
        module=_LIB, repositories=("central",), routing_supported=True
    )

    with PublicationLookupContext(tmp_path) as context:
        result = lookup_gradle_publication(request, context)

    assert result == AgeBlock(reason="org.example:lib:2.0: publication lookup failed")
    assert not list(tmp_path.glob("*.json"))


_FACT: dict[str, Any] = {
    "registry": "pypi",
    "package": "requests",
    "version": "2.31.0",
    "timestamp": datetime(2025, 12, 31, 1, tzinfo=timezone(timedelta(hours=1))),
    "checked_at": datetime(2026, 1, 1, tzinfo=UTC),
}


def test_registry_fact_stores_utc():
    fact = RegistryFact(**_FACT)

    assert fact.timestamp == datetime(2025, 12, 31, tzinfo=UTC)
    assert fact.timestamp.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "change",
    [
        {"timestamp": datetime(2025, 12, 31)},
        {"checked_at": datetime(2026, 1, 1)},
        {"registry": "central"},
        {"source": "bun"},
    ],
)
def test_registry_fact_rejects_invalid_values(change):
    with pytest.raises(ValidationError):
        RegistryFact(**(_FACT | change))


def _digest_path(cache: Path, key: list[object]) -> Path:
    return cache / f"{hashlib.sha256(json.dumps(key).encode()).hexdigest()}.json"


def _pypi_context(cache, response, clock=None):
    calls = []

    def transport(url, root, suffix):
        calls.append((url, root, suffix))
        if isinstance(response, Exception):
            raise response
        if response is None:
            return None
        body, final_url = response if isinstance(response, tuple) else (response, url)
        return body, {}, final_url

    return PublicationLookupContext(
        cache, transport, clock or FakeClock(_PUB_NOW)
    ), calls


def _no_transport(url, root, suffix):
    pytest.fail("no publication lookup expected")


@dataclass(frozen=True)
class _CacheKind:
    body: bytes
    headers: dict[str, str]
    key: list[object]
    live: Callable[[PublicationLookupContext, Path], Any]
    seed: Callable[..., PublicationFact | RegistryFact]
    other_identity: dict[str, Any]


def _maven_fact(**changes):
    return PublicationFact(
        repository="central",
        module=_LIB,
        artifact_digest=hashlib.sha256(_pom(_LIB)).hexdigest(),
        timestamp=datetime(2026, 9, 1, tzinfo=UTC),
        checked_at=_PUB_NOW,
    ).model_copy(update=changes)


def _pypi_fact(**changes):
    return RegistryFact(
        registry="pypi",
        package="pkg",
        version="1.0",
        timestamp=datetime(2025, 12, 31, tzinfo=UTC),
        checked_at=_PUB_NOW,
    ).model_copy(update=changes)


_CACHE_KINDS = {
    "maven": _CacheKind(
        _pom(_LIB),
        _SEPTEMBER_1,
        [1, "central", "org.example", "lib", "2.0", "last_modified"],
        lambda context, project: context.submit("central", _LIB).result(),
        _maven_fact,
        {"module": ModuleId(group="org.example", artifact="lib", version="3.0")},
    ),
    "pypi": _CacheKind(
        pypi_body(),
        {},
        ["registry", "pypi", "pkg", "1.0"],
        lambda context, project: context.submit_registry(
            "pypi", "pkg", "1.0", project
        ).result(),
        _pypi_fact,
        {"package": "other"},
    ),
}


def _kind_context(
    kind: _CacheKind, cache: Path, calls: list[str], *, clock=None, absent=False
):
    def transport(url, repository, suffix):
        calls.append(url)
        return None if absent else (kind.body, kind.headers, url)

    return PublicationLookupContext(cache, transport, clock or FakeClock(_PUB_NOW))


@pytest.mark.parametrize("name", ["maven", "pypi"])
@pytest.mark.parametrize(
    ("state", "changes", "clock", "expected_calls"),
    [
        pytest.param(
            "seeded", {}, _PUB_NOW + timedelta(hours=23, minutes=59), 0, id="fresh"
        ),
        pytest.param(
            "seeded", {}, _PUB_NOW + timedelta(hours=24), 1, id="exactly-24-hours"
        ),
        pytest.param(
            "seeded", {}, _PUB_NOW - timedelta(seconds=1), 1, id="future-check"
        ),
        pytest.param(
            "seeded",
            {"timestamp": _PUB_NOW + timedelta(hours=1)},
            _PUB_NOW,
            1,
            id="future-timestamp",
        ),
        pytest.param("other-identity", {}, _PUB_NOW, 1, id="other-identity"),
        pytest.param("corrupt", {}, _PUB_NOW, 1, id="corrupt"),
    ],
)
def test_given_cached_fact_when_looked_up_then_only_a_fresh_matching_fact_is_reused(
    tmp_path, name, state, changes, clock, expected_calls
):
    kind = _CACHE_KINDS[name]
    cache = tmp_path / "cache"
    cache.mkdir()
    path = _digest_path(cache, kind.key)
    seeded = kind.seed(
        **(kind.other_identity if state == "other-identity" else changes)
    )
    path.write_text("{broken" if state == "corrupt" else seeded.model_dump_json())
    calls: list[str] = []

    with _kind_context(kind, cache, calls, clock=lambda: clock) as context:
        result = kind.live(context, tmp_path)

    assert len(calls) == expected_calls
    assert result.timestamp == kind.seed().timestamp


@pytest.mark.parametrize("name", ["maven", "pypi"])
def test_given_fact_cached_by_another_project_when_looked_up_then_it_is_reused(
    tmp_path, name
):
    kind = _CACHE_KINDS[name]
    cache = tmp_path / "cache"
    first_calls: list[str] = []
    second_calls: list[str] = []
    with _kind_context(kind, cache, first_calls) as first:
        kind.live(first, tmp_path / "a")

    with _kind_context(kind, cache, second_calls) as second:
        result = kind.live(second, tmp_path / "b")

    assert (len(first_calls), second_calls) == (1, [])
    assert result == kind.seed()


@pytest.mark.parametrize("name", ["maven", "pypi"])
def test_given_absent_release_when_looked_up_twice_then_nothing_is_cached(
    tmp_path, name
):
    kind = _CACHE_KINDS[name]
    cache = tmp_path / "cache"
    calls: list[str] = []

    for _ in range(2):
        with _kind_context(kind, cache, calls, absent=True) as context:
            assert kind.live(context, tmp_path) is None

    assert len(calls) == 2
    assert not cache.exists()


@pytest.mark.parametrize("name", ["maven", "pypi"])
def test_given_unwritable_cache_when_looked_up_then_live_fact_is_returned(
    tmp_path, name
):
    kind = _CACHE_KINDS[name]
    cache = tmp_path / "not-a-directory"
    cache.write_text("")

    with _kind_context(kind, cache, []) as context:
        result = kind.live(context, tmp_path)

    assert result == kind.seed()


@pytest.mark.parametrize("name", ["maven", "pypi", "npm"])
def test_given_duplicate_lookups_when_submitted_then_one_request_serves_both(
    tmp_path, monkeypatch, name
):
    calls: list[object] = []
    monkeypatch.setattr(
        "maintenance_man.dependency_age.run_captured",
        lambda cmd, cwd, **kwargs: (
            calls.append(cmd),
            completed(stdout="Published: 2024-01-02T03:04:05Z\n"),
        )[1],
    )

    def transport(url, repository, suffix):
        calls.append(url)
        if name == "maven":
            return _pom(_LIB), _SEPTEMBER_1, url
        return pypi_body(), {}, url

    submit = {
        "maven": lambda context: context.submit("central", _LIB),
        "pypi": lambda context: context.submit_registry("pypi", "pkg", "1.0", tmp_path),
        "npm": lambda context: context.submit_registry("npm", "pkg", "1.0", tmp_path),
    }[name]
    with PublicationLookupContext(tmp_path, transport, FakeClock(_PUB_NOW)) as context:
        first, second = submit(context), submit(context)
        fact = first.result()

    assert (first is second, len(calls), fact is not None) == (True, 1, True)


@pytest.mark.parametrize(
    ("source", "method", "prefix"),
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

    context = PublicationLookupContext(tmp_path, clock=FakeClock(_PUB_NOW))
    monkeypatch.setattr(context, method, submit)
    updates = [
        make_update(SemverTier.MINOR, pkg_name=f"{prefix}{i}", latest_version="1.0")
        for i in range(expected)
    ]

    with context:
        result = filter_registry_updates_by_age(updates, source, tmp_path, 7, context)

    assert [u.pkg_name for u in result] == [u.pkg_name for u in updates]


@pytest.mark.parametrize(
    ("unknown", "reason"),
    [
        (None, "no trusted exact POM for org.example:lib1:2.0"),
        (
            TimeoutError("unavailable"),
            "org.example:lib1:2.0: publication lookup failed",
        ),
    ],
)
def test_publication_prefetch_overlaps_candidate_groups(tmp_path, unknown, reason):
    barrier = Barrier(2, timeout=10)
    modules = [
        ModuleId(group="org.example", artifact=f"lib{i}", version="2.0")
        for i in range(2)
    ]
    candidates = [
        make_gradle_candidate(
            publication_requests=(
                PublicationRequest(
                    module=module, repositories=("google",), routing_supported=True
                ),
            )
        )
        for module in modules
    ]

    def transport(url, repository, suffix):
        barrier.wait()
        if "/lib1/" in url:
            if unknown is not None:
                raise unknown
            return None
        return _pom(modules[0]), _SEPTEMBER_1, url

    with PublicationLookupContext(tmp_path, transport, FakeClock(_PUB_NOW)) as context:
        context.prefetch(
            request
            for candidate in candidates
            for request in candidate.publication_requests
        )
        blocks = [
            evaluate_gradle_candidate_age(candidate, 7, context, _PUB_NOW)
            for candidate in candidates
        ]

    assert blocks == [datetime(2026, 9, 1, tzinfo=UTC), AgeBlock(reason=reason)]


def test_publication_context_interrupt_cancels_queued_requests(tmp_path, monkeypatch):
    pool = _pool()
    lock = Lock()
    calls = []

    def transport(url, repository, suffix):
        with lock:
            calls.append(url)
            if len(calls) == 8:
                pool.started.set()
        assert pool.release.wait(10), "context cleanup did not release active requests"

    monkeypatch.setattr(age, "ThreadPoolExecutor", pool)
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
        PublicationLookupContext(tmp_path, transport, FakeClock(_PUB_NOW)) as context,
    ):
        context.prefetch(requests)
        assert pool.started.wait(10), "eight requests did not start"
        raise KeyboardInterrupt

    assert len(calls) == 8, "queued publication requests ran after interruption"


_UNUSED = object()


def _update(name="pkg", version="1.0"):
    return make_update(SemverTier.MINOR, pkg_name=name, latest_version=version)


@pytest.mark.parametrize(
    ("count", "days", "response", "expected"),
    [
        pytest.param(0, 7, _UNUSED, [], id="no-updates"),
        pytest.param(1, 0, _UNUSED, [None], id="zero-days"),
        pytest.param(
            1, 7, pypi_body(uploads=("2026-09-17T00:00:00Z",)), [], id="young"
        ),
        pytest.param(
            1,
            7,
            pypi_body(uploads=("2026-09-11T00:00:00Z",)),
            [datetime(2026, 9, 11, tzinfo=UTC)],
            id="exactly-cutoff",
        ),
        pytest.param(
            1,
            7,
            pypi_body(uploads=("2026-09-10T23:59:59Z",)),
            [datetime(2026, 9, 10, 23, 59, 59, tzinfo=UTC)],
            id="one-second-older",
        ),
        pytest.param(1, 7, pypi_body(), [datetime(2025, 12, 31, tzinfo=UTC)], id="old"),
        pytest.param(1, 7, None, [None], id="unknown-release"),
        pytest.param(
            1, 7, PublicationError("publication HTTP 429"), [None], id="lookup-error"
        ),
    ],
)
def test_given_pypi_release_when_filtered_then_known_young_releases_are_dropped(
    tmp_path, count, days, response, expected
):
    context = (
        PublicationLookupContext(tmp_path, _no_transport, FakeClock(_PUB_NOW))
        if response is _UNUSED
        else _pypi_context(tmp_path, response)[0]
    )

    with context:
        result = filter_registry_updates_by_age(
            [_update()] * count, "pypi", tmp_path, days, context
        )

    assert [u.published_date for u in result] == expected


@pytest.mark.parametrize("name", ["lib", "a:b:c", ":lib", "org.example:"])
def test_given_mvn_name_without_group_artifact_when_filtered_then_it_is_kept_undated(
    tmp_path, name
):
    with PublicationLookupContext(
        tmp_path, _no_transport, FakeClock(_PUB_NOW)
    ) as context:
        result = filter_registry_updates_by_age(
            [_update(name, "2.0")], "central", tmp_path, 7, context
        )

    assert [u.published_date for u in result] == [None]


def test_given_three_updates_when_filtered_then_input_order_is_kept(tmp_path):
    uploads = {
        "a": "2025-01-01T00:00:00Z",
        "b": "2026-09-17T00:00:00Z",
        "c": "2025-02-01T00:00:00Z",
    }

    def transport(url, root, suffix):
        name = suffix.split("/")[1]
        return pypi_body(name, "1.0", (uploads[name],)), {}, url

    updates = [_update(name) for name in ("a", "b", "c")]
    with PublicationLookupContext(tmp_path, transport, FakeClock(_PUB_NOW)) as context:
        result = filter_registry_updates_by_age(updates, "pypi", tmp_path, 7, context)

    assert [u.pkg_name for u in result] == ["a", "c"]


def test_given_unexpected_error_when_filtered_then_it_propagates(tmp_path):
    context, _ = _pypi_context(tmp_path, RuntimeError("bug"))

    with context, pytest.raises(RuntimeError, match="bug"):
        filter_registry_updates_by_age([_update()], "pypi", tmp_path, 7, context)


def test_given_mvn_update_when_filtered_then_exact_central_pom_dates_it(tmp_path):
    calls = []

    def transport(url, repository, suffix):
        calls.append((url, repository))
        return _pom(_LIB), _SEPTEMBER_1, url

    with PublicationLookupContext(tmp_path, transport, FakeClock(_PUB_NOW)) as context:
        result = filter_registry_updates_by_age(
            [_update("org.example:lib", "2.0")], "central", tmp_path, 7, context
        )

    assert calls == [(_LIB_POM_URL, "central")]
    assert [u.published_date for u in result] == [datetime(2026, 9, 1, tzinfo=UTC)]


def test_given_pom_without_last_modified_when_mvn_filtered_then_kept_undated(
    tmp_path,
):
    _, calls, context = _publication_fixture(
        tmp_path, responses={"central": (_pom(_LIB), {})}
    )
    update = make_update(pkg_name="org.example:lib", latest_version="2.0")

    with context:
        kept = filter_registry_updates_by_age([update], "central", tmp_path, 7, context)

    assert [(row.pkg_name, row.published_date) for row in kept] == [
        ("org.example:lib", None)
    ]
    assert calls == [_LIB_POM_URL]


@pytest.mark.parametrize(
    ("coordinate", "kind", "expected"),
    [
        ("g:a", "library", ModuleId(group="g", artifact="a", version="1")),
        ("g:", "library", None),
        ("g:a:b", "library", None),
        (
            "p.id",
            "plugin",
            ModuleId(group="p.id", artifact="p.id.gradle.plugin", version="1"),
        ),
    ],
)
def test_given_gradle_member_when_resolved_then_only_valid_coordinates_map(
    coordinate, kind, expected
):
    member = make_gradle_member(kind=kind, coordinate=coordinate)

    result = member_module(member, "1")

    assert result == expected


def _pypi_run(tmp_path, response, package="pkg", version="1.0"):
    context, calls = _pypi_context(tmp_path / "cache", response)
    with context:
        result = context.submit_registry("pypi", package, version, tmp_path).result()
    return result, calls


@pytest.mark.parametrize(
    ("package", "version", "body", "expected"),
    [
        pytest.param(
            "requests",
            "2.31.0",
            json.dumps(
                {
                    "info": {"name": "requests", "version": "2.31.0", "Extra": 1},
                    "urls": [
                        {"upload_time_iso_8601": "2026-09-03T00:00:00Z", "Extra": 1},
                        {"upload_time_iso_8601": "2026-09-01T00:00:00Z"},
                    ],
                    "Extra": 1,
                }
            ).encode(),
            datetime(2026, 9, 1, tzinfo=UTC),
            id="earliest-upload",
        ),
        pytest.param(
            "Typing_Extensions",
            "4.12.2",
            pypi_body("typing-extensions", "4.12.2", ("2024-06-07T18:52:13Z",)),
            datetime(2024, 6, 7, 18, 52, 13, tzinfo=UTC),
            id="normalised-name",
        ),
        pytest.param(
            "pkg",
            "1.0.0",
            pypi_body("pkg", "1.0", ("2025-12-31T00:00:00",)),
            datetime(2025, 12, 31, tzinfo=UTC),
            id="equivalent-version-naive-utc",
        ),
        pytest.param(
            "pkg",
            "6.0.2.0",
            pypi_body("pkg", "6.0.2", ("2025-12-31T00:00:00Z", None)),
            datetime(2025, 12, 31, tzinfo=UTC),
            id="null-upload-skipped",
        ),
        pytest.param("pkg", "1.0", None, None, id="release-absent"),
    ],
)
def test_given_pypi_release_when_looked_up_then_exact_url_dates_the_fact(
    tmp_path, package, version, body, expected
):
    result, calls = _pypi_run(tmp_path, body, package, version)

    assert calls == [
        (
            f"https://pypi.org/pypi/{package}/{version}/json",
            "pypi",
            f"pypi/{package}/{version}/json",
        )
    ]
    assert (
        result.timestamp if isinstance(result, RegistryFact) else result
    ) == expected


@pytest.mark.parametrize(
    "response",
    [
        pypi_body("other"),
        pypi_body(version="2.0"),
        pypi_body(version="not a version"),
        pypi_body(uploads=()),
        pypi_body(uploads=(None, None)),
        pypi_body(uploads=("2026-09-19T00:00:00Z",)),
        pypi_body(uploads=(1,)),
        pypi_body(uploads=("soon",)),
        b"<html>",
        b"[]",
        b'{"info": null, "urls": []}',
        b'{"info": [], "urls": []}',
        b'{"info": {"name": "pkg", "version": "1.0"}, "urls": {}}',
        b'{"info": {"name": "pkg", "version": "1.0"}, "urls": ["x"]}',
        b'{"info": {"name": 1, "version": "1.0"}, "urls": []}',
        (pypi_body(), "https://pypi.org/pypi/other/1.0/json"),
        PublicationError("publication HTTP 429"),
    ],
    ids=[
        "other-name",
        "other-version",
        "invalid-version",
        "no-uploads",
        "null-uploads",
        "future-upload",
        "numeric-upload",
        "unparsable-upload",
        "html",
        "list",
        "null-info",
        "list-info",
        "dict-urls",
        "string-url-row",
        "numeric-name",
        "redirected-url",
        "http-429",
    ],
)
def test_given_unusable_pypi_response_when_looked_up_then_it_is_blocked_and_uncached(
    tmp_path, response
):
    result, _ = _pypi_run(tmp_path, response)

    assert isinstance(result, AgeBlock)
    assert not (tmp_path / "cache").exists()


def _fake_bun(monkeypatch, cwd: Path, *outputs) -> FakeCommands:
    commands = FakeCommands()
    for output in outputs:
        if isinstance(output, BaseException):
            result = ProcessError(f"Could not run bun info in {cwd}: {output}")
            result.__cause__ = output
        else:
            result = completed(returncode=1, stdout=output, stderr="warning")
        commands.add(("bun", "info", "pkg@1.0.0"), cwd=cwd, result=result)
    monkeypatch.setattr("maintenance_man.dependency_age.run_captured", commands)
    return commands


_NPM_FAILED = AgeBlock(reason="pkg:1.0.0: publication lookup failed")


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        pytest.param(
            "pkg@1.0.0 | MIT\nPublished: 2024-01-02T03:04:05Z\n",
            RegistryFact(
                registry="npm",
                package="pkg",
                version="1.0.0",
                timestamp=datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC),
                checked_at=_PUB_NOW,
            ),
            id="published",
        ),
        pytest.param(
            "Published: 2024-01-02T03:04:05\n",
            RegistryFact(
                registry="npm",
                package="pkg",
                version="1.0.0",
                timestamp=datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC),
                checked_at=_PUB_NOW,
            ),
            id="naive-utc",
        ),
        pytest.param("pkg@1.0.0 | MIT\n", None, id="no-published-line"),
        pytest.param("Published:\n", None, id="empty-published"),
        pytest.param(
            subprocess.TimeoutExpired(["bun", "info"], 30), _NPM_FAILED, id="timeout"
        ),
        pytest.param(
            FileNotFoundError(2, "No such file or directory", "bun"),
            _NPM_FAILED,
            id="missing-bun",
        ),
        pytest.param(
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
            _NPM_FAILED,
            id="undecodable",
        ),
        pytest.param("Published: soon\n", _NPM_FAILED, id="unparsable"),
    ],
)
def test_given_bun_info_when_looked_up_then_it_runs_in_the_project_and_is_never_cached(
    tmp_path, monkeypatch, output, expected
):
    project, cache = tmp_path / "project", tmp_path / "cache"
    commands = _fake_bun(monkeypatch, project, output)

    with PublicationLookupContext(cache, clock=FakeClock(_PUB_NOW)) as context:
        result = context.submit_registry("npm", "pkg", "1.0.0", project).result()

    assert result == expected
    assert commands.calls == [
        (
            ("bun", "info", "pkg@1.0.0"),
            project,
            {"timeout": 30, "label": "bun info", "ok_codes": None},
        )
    ]
    assert not cache.exists()


def test_given_two_npm_contexts_when_filtered_then_each_context_runs_once(
    tmp_path, monkeypatch
):
    planted = _digest_path(tmp_path, ["registry", "npm", "pkg", "1.0.0"])
    planted.write_text(
        RegistryFact(
            registry="npm",
            package="pkg",
            version="1.0.0",
            timestamp=datetime(2020, 1, 1, tzinfo=UTC),
            checked_at=_PUB_NOW,
        ).model_dump_json()
    )
    commands = _fake_bun(
        monkeypatch,
        tmp_path,
        "Published: 2024-01-01T00:00:00Z\n",
        "Published: 2026-09-17T00:00:00Z\n",
    )
    update = make_update(SemverTier.MINOR, pkg_name="pkg", latest_version="1.0.0")
    kept = []

    for _ in range(2):
        with PublicationLookupContext(tmp_path, clock=FakeClock(_PUB_NOW)) as context:
            first = context.submit_registry("npm", "pkg", "1.0.0", tmp_path)
            assert context.submit_registry("npm", "pkg", "1.0.0", tmp_path) is first
            kept.append(
                filter_registry_updates_by_age([update], "npm", tmp_path, 7, context)
            )

    assert len(commands.calls) == 2
    assert [[item.published_date for item in result] for result in kept] == [
        [datetime(2024, 1, 1, tzinfo=UTC)],
        [],
    ]
