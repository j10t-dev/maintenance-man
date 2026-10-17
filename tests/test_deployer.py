from unittest.mock import MagicMock, patch

from maintenance_man.deployer import check_health


class TestCheckHealth:
    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_healthy_service(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"name": "lifts", "is_up": true}'
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check_health("http://pihost:8080", "lifts")

        assert result.is_up is True
        assert result.error is None
        mock_urlopen.assert_called_once_with(
            "http://pihost:8080/api/status/lifts", timeout=10
        )

    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_unhealthy_service(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = (
            b'{"name": "lifts", "is_up": false, "last_error": "connection refused"}'
        )
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check_health("http://pihost:8080", "lifts")

        assert result.is_up is False
        assert result.error is None

    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_service_not_found(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            url="http://pihost:8080/api/status/unknown",
            code=404,
            msg="Not Found",
            hdrs=None,  # ty:ignore[invalid-argument-type]
            fp=None,
        )

        result = check_health("http://pihost:8080", "unknown")

        assert result.is_up is False
        assert result.error is not None
        assert "not found" in result.error.lower()

    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_connection_error_retries(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")

        result = check_health(
            "http://pihost:8080",
            "lifts",
            max_retries=3,
            initial_delay=0,
        )

        assert result.is_up is False
        assert result.error is not None
        assert mock_urlopen.call_count == 3

    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_retries_then_succeeds(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import URLError

        mock_response = MagicMock()
        mock_response.read.return_value = b'{"name": "lifts", "is_up": true}'
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [
            URLError("Connection refused"),
            mock_response,
        ]

        result = check_health(
            "http://pihost:8080",
            "lifts",
            max_retries=3,
            initial_delay=0,
        )

        assert result.is_up is True
        assert mock_urlopen.call_count == 2

    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_5xx_retries_then_succeeds(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import HTTPError

        mock_response = MagicMock()
        mock_response.read.return_value = b'{"name": "lifts", "is_up": true}'
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [
            HTTPError(
                url="",
                code=503,
                msg="Service Unavailable",
                hdrs=None,  # ty:ignore[invalid-argument-type]
                fp=None,
            ),
            mock_response,
        ]

        result = check_health(
            "http://pihost:8080",
            "lifts",
            max_retries=3,
            initial_delay=0,
        )

        assert result.is_up is True
        assert mock_urlopen.call_count == 2

    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_5xx_exhausts_retries(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            url="",
            code=502,
            msg="Bad Gateway",
            hdrs=None,  # ty:ignore[invalid-argument-type]
            fp=None,
        )

        result = check_health(
            "http://pihost:8080",
            "lifts",
            max_retries=3,
            initial_delay=0,
        )

        assert result.is_up is False
        assert result.error is not None
        assert "502" in result.error
        assert mock_urlopen.call_count == 3

    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_4xx_does_not_retry(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            url="",
            code=403,
            msg="Forbidden",
            hdrs=None,  # ty:ignore[invalid-argument-type]
            fp=None,
        )

        result = check_health(
            "http://pihost:8080",
            "lifts",
            max_retries=3,
            initial_delay=0,
        )

        assert result.is_up is False
        assert result.error is not None
        assert "403" in result.error
        assert mock_urlopen.call_count == 1

    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_non_json_response(self, mock_urlopen: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = b"<html>502 Bad Gateway</html>"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        result = check_health("http://pihost:8080", "lifts")

        assert result.is_up is False
        assert result.error is not None
        assert "non-JSON" in result.error
