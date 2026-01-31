import pytest

from maintenance_man.cli import app


class TestHelp:
    def test_help_exits_zero(self):
        with pytest.raises(SystemExit) as exc_info:
            app(["--help"])
        assert exc_info.value.code == 0

    def test_help_contains_description(self, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit):
            app(["--help"])
        assert "maintenance" in capsys.readouterr().out.lower()


class TestVersion:
    def test_version_exits_zero(self):
        with pytest.raises(SystemExit) as exc_info:
            app(["--version"])
        assert exc_info.value.code == 0

    def test_version_prints_version(self, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit):
            app(["--version"])
        assert "0.1.0" in capsys.readouterr().out



class TestDeployStub:
    def test_deploy_requires_project(self):
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy"])
        assert exc_info.value.code != 0

    def test_deploy_stub_with_project(self, capsys: pytest.CaptureFixture[str]):
        with pytest.raises(SystemExit) as exc_info:
            app(["deploy", "feetfax"])
        assert exc_info.value.code == 1
        assert "not implemented" in capsys.readouterr().out.lower()
