from pathlib import Path

import pytest


@pytest.fixture()
def mm_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect MM_HOME to a temp directory."""
    home = tmp_path / ".mm"
    monkeypatch.setattr("maintenance_man.config.MM_HOME", home)
    return home
