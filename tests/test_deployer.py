import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from maintenance_man.deployer import (
    BuildError,
    DeployError,
    check_health,
    run_build,
    run_deploy,
)


class TestRunBuild:
    @patch("maintenance_man.deployer.subprocess.run")
    def test_successful_build(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        run_build("myproject", "scripts/build.sh", tmp_path)
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["cwd"] == tmp_path
        assert call_kwargs["shell"] is True
        assert call_kwargs["executable"] == "/bin/bash"
        assert call_kwargs["timeout"] == 600

    @patch("maintenance_man.deployer.subprocess.run")
    def test_failed_build_raises(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
        with pytest.raises(BuildError, match="myproject"):
            run_build("myproject", "scripts/build.sh", tmp_path)

    @patch("maintenance_man.deployer.subprocess.run")
    def test_build_strips_virtual_env(
        self,
        mock_run: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("VIRTUAL_ENV", "/some/venv")
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        run_build("myproject", "scripts/build.sh", tmp_path)
        env = mock_run.call_args.kwargs["env"]
        assert "VIRTUAL_ENV" not in env

    @patch("maintenance_man.deployer.subprocess.run")
    def test_build_scrubs_venv_from_path(
        self,
        mock_run: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        venv_dir = "/some/venv"
        monkeypatch.setenv("VIRTUAL_ENV", venv_dir)
        monkeypatch.setenv("PATH", f"{venv_dir}/bin:/usr/bin:/bin")
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        run_build("myproject", "scripts/build.sh", tmp_path)
        env = mock_run.call_args.kwargs["env"]
        assert f"{venv_dir}/bin" not in env["PATH"].split(":")
        assert "/usr/bin" in env["PATH"].split(":")

    @patch(
        "maintenance_man.deployer.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="scripts/build.sh", timeout=600),
    )
    def test_build_timeout_raises(self, mock_run: MagicMock, tmp_path: Path) -> None:
        with pytest.raises(BuildError, match="timed out"):
            run_build("myproject", "scripts/build.sh", tmp_path)


class TestRunDeploy:
    @patch("maintenance_man.deployer.subprocess.run")
    def test_successful_deploy(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        run_deploy("myproject", "scripts/deploy.sh", tmp_path)
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["shell"] is True
        assert call_kwargs["executable"] == "/bin/bash"

    @patch("maintenance_man.deployer.subprocess.run")
    def test_failed_deploy_raises(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
        with pytest.raises(DeployError, match="myproject"):
            run_deploy("myproject", "scripts/deploy.sh", tmp_path)

    @patch(
        "maintenance_man.deployer.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="scripts/deploy.sh", timeout=600),
    )
    def test_deploy_timeout_raises(self, mock_run: MagicMock, tmp_path: Path) -> None:
        with pytest.raises(DeployError, match="timed out"):
            run_deploy("myproject", "scripts/deploy.sh", tmp_path)


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
        mock_urlopen.assert_called_once()

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
            hdrs=None,
            fp=None,
        )

        result = check_health("http://pihost:8080", "unknown")

        assert result.is_up is False
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
            HTTPError(url="", code=503, msg="Service Unavailable", hdrs=None, fp=None),
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
            hdrs=None,
            fp=None,
        )

        result = check_health(
            "http://pihost:8080",
            "lifts",
            max_retries=3,
            initial_delay=0,
        )

        assert result.is_up is False
        assert "502" in result.error
        assert mock_urlopen.call_count == 3

    @patch("maintenance_man.deployer.urllib.request.urlopen")
    def test_4xx_does_not_retry(self, mock_urlopen: MagicMock) -> None:
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            url="",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=None,
        )

        result = check_health(
            "http://pihost:8080",
            "lifts",
            max_retries=3,
            initial_delay=0,
        )

        assert result.is_up is False
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
        assert "non-JSON" in result.error
