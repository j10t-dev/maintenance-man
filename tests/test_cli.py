from typer.testing import CliRunner

from maintenance_man.cli import app

runner = CliRunner()


def test_help_exits_zero():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0


def test_help_contains_description():
    result = runner.invoke(app, ["--help"])
    assert "maintenance" in result.output.lower()


def test_version_exits_zero():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0


def test_version_prints_version():
    result = runner.invoke(app, ["--version"])
    assert "0.1.0" in result.output


def test_scan_stub_no_args():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 1
    assert "not implemented" in result.output.lower()


def test_scan_stub_with_project():
    result = runner.invoke(app, ["scan", "feetfax"])
    assert result.exit_code == 1
    assert "not implemented" in result.output.lower()


def test_update_requires_project():
    result = runner.invoke(app, ["update"])
    assert result.exit_code != 0


def test_update_stub_with_project():
    result = runner.invoke(app, ["update", "feetfax"])
    assert result.exit_code == 1
    assert "not implemented" in result.output.lower()


def test_deploy_requires_project():
    result = runner.invoke(app, ["deploy"])
    assert result.exit_code != 0


def test_deploy_stub_with_project():
    result = runner.invoke(app, ["deploy", "feetfax"])
    assert result.exit_code == 1
    assert "not implemented" in result.output.lower()
