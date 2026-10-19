import email.message
import io
from urllib.error import HTTPError, URLError

import pytest

from maintenance_man.deployer import HealthCheckResult, check_health

_UP = b'{"is_up": true}'


def _http_error(code: int, msg: str) -> HTTPError:
    return HTTPError(url="", code=code, msg=msg, hdrs=email.message.Message(), fp=None)


@pytest.mark.parametrize(
    ("outcomes", "expected", "attempts"),
    [
        pytest.param([_UP], HealthCheckResult(True, None), 1, id="up"),
        pytest.param(
            [b'{"is_up": false, "last_error": "x"}'],
            HealthCheckResult(False, None),
            1,
            id="down",
        ),
        pytest.param(
            [_http_error(404, "Not Found")],
            HealthCheckResult(False, "Service 'lifts' not found in healthchecker"),
            1,
            id="unknown-service",
        ),
        pytest.param(
            [URLError("Connection refused")] * 3,
            HealthCheckResult(False, "Could not reach healthchecker after 3 attempts"),
            3,
            id="unreachable-exhausts-retries",
        ),
        pytest.param(
            [URLError("Connection refused"), _UP],
            HealthCheckResult(True, None),
            2,
            id="unreachable-then-up",
        ),
        pytest.param(
            [_http_error(503, "Service Unavailable"), _UP],
            HealthCheckResult(True, None),
            2,
            id="server-error-then-up",
        ),
        pytest.param(
            [_http_error(503, "Service Unavailable")] * 3,
            HealthCheckResult(False, "HTTP 503: Service Unavailable"),
            3,
            id="server-error-exhausts-retries",
        ),
        pytest.param(
            [_http_error(403, "Forbidden")],
            HealthCheckResult(False, "HTTP 403: Forbidden"),
            1,
            id="client-error-is-not-retried",
        ),
        pytest.param(
            [b"<html>502 Bad Gateway</html>"],
            HealthCheckResult(False, "Healthchecker returned non-JSON response"),
            1,
            id="non-json-body",
        ),
    ],
)
def test_given_healthchecker_responses_when_checked_then_result_and_attempts_match(
    outcomes: list[bytes | Exception],
    expected: HealthCheckResult,
    attempts: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remaining = iter(outcomes)
    calls: list[tuple[str, int]] = []

    def urlopen(url: str, timeout: int) -> io.BytesIO:
        calls.append((url, timeout))
        outcome = next(remaining)
        if isinstance(outcome, Exception):
            raise outcome
        return io.BytesIO(outcome)

    monkeypatch.setattr("maintenance_man.deployer.urllib.request.urlopen", urlopen)

    result = check_health("http://pihost:8080", "lifts", max_retries=3, initial_delay=0)

    assert result == expected
    assert calls == [("http://pihost:8080/api/status/lifts", 10)] * attempts
