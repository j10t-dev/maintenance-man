import json
import re
from pathlib import Path

import pytest

from maintenance_man import bun_dependencies
from maintenance_man.bun_dependencies import (
    BunDependencyError,
    registry_declared_bun_names,
    resolved_bun_versions,
)
from tests.fakes import FakeCommands
from tests.support.process import completed


@pytest.mark.parametrize(
    ("manifest", "declared"),
    [
        ({"dependencies": {"zod": "^3.0.0"}}, True),
        ({"devDependencies": {"zod": "3.0.0"}}, True),
        (
            {
                "dependencies": {"zod": "^3.0.0"},
                "devDependencies": {"zod": "file:../zod"},
            },
            False,
        ),
        (
            {
                "dependencies": {"zod": "^3.0.0"},
                "devDependencies": {"zod": "^3.0.0"},
            },
            False,
        ),
        (
            {
                "dependencies": {"zod": "^3.0.0"},
                "peerDependencies": {"zod": "^3.0.0"},
            },
            False,
        ),
        (
            {
                "dependencies": {"zod": "^3.0.0"},
                "optionalDependencies": {"zod": "^3.0.0"},
            },
            False,
        ),
        ({"dependencies": {"zod": "^3.0.0"}, "overrides": {"zod": "3.0.1"}}, False),
        ({"dependencies": {"zod": "^3.0.0"}, "resolutions": {"zod": "3.0.1"}}, False),
        ({"peerDependencies": {"zod": "^3.0.0"}}, False),
        ({"dependencies": {"zod": "file:../zod"}}, False),
        ({"dependencies": {"zod": "npm:other@1.0.0"}}, False),
        ({"dependencies": {"zod": "github/user/zod"}}, False),
        ({"dependencies": {"zod": 3}}, False),
        ({"dependencies": {"other": "1.0.0"}}, False),
        ({}, False),
    ],
)
def test_given_manifest_when_declared_names_read_then_registry_declaration_decides(
    tmp_path: Path, manifest, declared
):
    (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert ("zod" in registry_declared_bun_names(tmp_path)) is declared


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(None, id="missing"),
        pytest.param(b"{not json", id="invalid-json"),
        pytest.param(b"\xff\xfe{", id="invalid-utf8"),
        pytest.param(b"[]", id="array"),
        pytest.param(b'{"dependencies": []}', id="table-not-object"),
    ],
)
def test_given_unreadable_manifest_when_declared_names_read_then_error_raised(
    tmp_path: Path, content
):
    if content is not None:
        (tmp_path / "package.json").write_bytes(content)

    with pytest.raises(BunDependencyError, match="Failed to read"):
        registry_declared_bun_names(tmp_path)


def _bun_pm_ls(
    monkeypatch: pytest.MonkeyPatch, project_path: Path, result
) -> FakeCommands:
    commands = FakeCommands()
    commands.add(("bun", "pm", "ls"), cwd=project_path, result=result)
    monkeypatch.setattr(bun_dependencies, "run_captured", commands)
    return commands


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (
            "/tmp/probe node_modules (1 installed)\n└── is-number@6.0.0\n",
            {"is-number": "6.0.0"},
        ),
        (
            "/tmp/probe node_modules (2 installed)\n"
            "├── @types/node@22.1.0\n└── is-number@6.0.0\n",
            {"@types/node": "22.1.0", "is-number": "6.0.0"},
        ),
        ("", {}),
    ],
)
def test_given_bun_pm_ls_output_when_resolved_then_direct_versions_returned(
    tmp_path: Path, monkeypatch, stdout, expected
):
    _bun_pm_ls(monkeypatch, tmp_path, completed(stdout=stdout))

    assert resolved_bun_versions(tmp_path) == expected


@pytest.mark.parametrize(
    ("stdout", "message"),
    [
        (
            "/tmp/probe node_modules\n    nested@1.0.0\n",
            "bun pm ls: unrecognised line: '    nested@1.0.0'",
        ),
        ("header\n└── is-number\n", "bun pm ls: unrecognised line"),
        ("header\n└──  a@1.0.0\n", "bun pm ls: unrecognised line"),
        ("header\n├── a@1.0.0\n└── a@2.0.0\n", "bun pm ls: a is listed twice"),
    ],
)
def test_given_malformed_bun_pm_ls_output_when_resolved_then_error_raised(
    tmp_path: Path, monkeypatch, stdout, message
):
    _bun_pm_ls(monkeypatch, tmp_path, completed(stdout=stdout))

    with pytest.raises(BunDependencyError, match=f"^{re.escape(message)}"):
        resolved_bun_versions(tmp_path)


def test_given_failing_bun_pm_ls_when_resolved_then_its_error_propagates(
    tmp_path: Path, monkeypatch
):
    commands = _bun_pm_ls(monkeypatch, tmp_path, BunDependencyError("bun pm ls failed"))

    with pytest.raises(BunDependencyError, match=r"^bun pm ls failed$"):
        resolved_bun_versions(tmp_path)

    assert commands.calls == [
        (
            ("bun", "pm", "ls"),
            tmp_path,
            {"timeout": 120, "label": "bun pm ls", "error": BunDependencyError},
        )
    ]
