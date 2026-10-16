from io import StringIO

import pytest
from rich.console import Console

from maintenance_man import cli
from maintenance_man.models import events
from maintenance_man.models.events import (
    FindingFailed,
    FindingPassed,
    FindingStarted,
    FindingStepFailed,
    FindingStepKind,
)


@pytest.fixture()
def output(monkeypatch):
    buffer = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=buffer, width=220, color_system=None)
    )
    return buffer


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    "event, expected",
    [
        (
            FindingStarted("vuln", "pkg[a]", "1.0", "1.1", "CVE-1"),
            "  VULN pkg[a] 1.0 -> 1.1 (CVE-1)",
        ),
        (
            FindingStarted("update", "pkg", "1.0", "2.0", "major"),
            "  UPDATE pkg 1.0 -> 2.0 (major)",
        ),
        (events.TestCommandStarted("uv run pytest"), "  $ uv run pytest"),
        (
            FindingStepFailed(FindingStepKind.PACKAGE_COMMAND, "boom"),
            "  FAIL Package manager command failed: boom",
        ),
        (FindingStepFailed(FindingStepKind.TEST, "unit failed"), "  FAIL unit failed"),
        (FindingPassed("pkg", False), "  PASS pkg"),
        (FindingPassed("pkg", True), "  PASS pkg (already applied)"),
        (FindingFailed("pkg", "unit"), "  FAIL pkg — unit failed"),
    ],
)
def test_given_progress_event_when_rendered_in_both_modes_then_expected_text_is_printed(
    output, batch, event, expected
):
    cli._Renderer(batch=batch)(event)
    assert output.getvalue().strip("\n") == expected
