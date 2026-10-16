"""Structural guardrails: lint, import contracts and private imports."""

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
PACKAGE = "maintenance_man"
PACKAGE_DIR = REPO_ROOT / "src" / PACKAGE


def package_sources() -> dict[str, tuple[str, str]]:
    sources: dict[str, tuple[str, str]] = {}
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        parts = path.relative_to(PACKAGE_DIR).with_suffix("").parts
        if parts[-1] == "__init__":
            parts = parts[:-1]
        sources[".".join(parts)] = (
            path.relative_to(REPO_ROOT).as_posix(),
            path.read_text(encoding="utf-8"),
        )
    return sources


def run_tool(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    executable = Path(sys.executable).parent / name
    assert executable.is_file(), f"{executable} not found; run uv sync"
    return subprocess.run(
        [executable, *args],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def test_ruff_clean() -> None:
    result = run_tool(
        "ruff", "check", "--no-cache", "--no-fix", "--config", str(PYPROJECT)
    )
    assert result.returncode == 0, result.stdout


def test_import_contracts() -> None:
    result = run_tool("lint-imports", "--config", str(PYPROJECT), "--no-cache")
    assert result.returncode == 0, result.stdout


def test_only_cli_prints_prompts_or_exits() -> None:
    violations: list[str] = []
    for module, (path, source) in package_sources().items():
        if module == "cli":
            continue
        for node in ast.walk(ast.parse(source, filename=path)):
            match node:
                case ast.Call(func=ast.Name(id="print" | "input" as name)):
                    violations.append(f"{path}:{node.lineno} calls {name}")
                case ast.Call(
                    func=ast.Attribute(value=ast.Name(id="sys"), attr="exit")
                ):
                    violations.append(f"{path}:{node.lineno} calls sys.exit")
                case ast.Raise(
                    exc=ast.Name(id="SystemExit")
                    | ast.Call(func=ast.Name(id="SystemExit"))
                ):
                    violations.append(f"{path}:{node.lineno} raises SystemExit")
    assert violations == []


def test_given_sources_when_scanned_then_no_private_imports_between_modules() -> None:
    violations = [
        violation
        for module, (path, source) in package_sources().items()
        for violation in _private_import_violations(module, path, source)
    ]
    assert violations == []


def _private_import_violations(
    importing_module: str, path: str, source: str
) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(ast.parse(source, filename=path)):
        match node:
            case ast.Import(names=names):
                violations.extend(
                    f"{path}:{node.lineno} imports {alias.name}"
                    for alias in names
                    if _is_package_module(alias.name)
                    and any(_is_private(part) for part in alias.name.split(".")[1:])
                )
            case ast.ImportFrom(names=names):
                module = _absolute_import_module(node, importing_module, path)
                if not _is_package_module(module):
                    continue
                private_module = any(
                    _is_private(part) for part in module.split(".")[1:]
                )
                for alias in names:
                    if private_module or _is_private(alias.name):
                        imported = f"{module}.{alias.name}"
                        violations.append(f"{path}:{node.lineno} imports {imported}")
    return violations


def _is_package_module(module: str) -> bool:
    return module == PACKAGE or module.startswith(f"{PACKAGE}.")


def _is_private(name: str) -> bool:
    return name.startswith("_") and not name.startswith("__")


def _absolute_import_module(
    node: ast.ImportFrom, importing_module: str, path: str
) -> str:
    if node.level == 0:
        return node.module or ""

    package_parts = importing_module.split(".") if importing_module else []
    if not path.endswith("/__init__.py") and package_parts:
        package_parts.pop()
    for _ in range(node.level - 1):
        if package_parts:
            package_parts.pop()
    suffix = node.module.split(".") if node.module else []
    return ".".join([PACKAGE, *package_parts, *suffix])


@pytest.mark.parametrize(
    "source, expected",
    [
        (
            "from maintenance_man.vcs import _run\n",
            ["src/maintenance_man/probe.py:1 imports maintenance_man.vcs._run"],
        ),
        ("from maintenance_man.vcs import run\n", []),
        (
            "import maintenance_man._private\n",
            ["src/maintenance_man/probe.py:1 imports maintenance_man._private"],
        ),
        (
            "from ._x import y\n",
            ["src/maintenance_man/probe.py:1 imports maintenance_man._x.y"],
        ),
        ("from pathlib import _X\n", []),
        (
            "from maintenance_man import _private\n",
            ["src/maintenance_man/probe.py:1 imports maintenance_man._private"],
        ),
    ],
)
def test_given_import_when_scanned_then_private_imports_are_reported(
    source: str, expected: list[str]
) -> None:
    violations = _private_import_violations(
        "probe", "src/maintenance_man/probe.py", source
    )
    assert violations == expected
