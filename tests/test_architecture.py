"""Structural guardrails: lint, import contracts and private-name access."""

import ast
import subprocess
import sys
import tomllib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
PACKAGE = "maintenance_man"
PACKAGE_DIR = REPO_ROOT / "src" / PACKAGE

PrivateAccess = tuple[str, str, str]  # (importing_module, owning_module, name)


@dataclass(frozen=True)
class PrivateAccessSite:
    access: PrivateAccess
    path: str  # repository-relative source path
    line: int


# Each entry names the consolidation design that removes it.
ALLOWED_PRIVATE_ACCESS: frozenset[PrivateAccess] = frozenset(
    {
        ("gradle_resolution", "gradle", "_validate_inventory"),  # D
        ("gradle_updates", "vcs", "_run"),  # C
        ("gradle_workflow", "scanner", "_run_gradle_scan"),  # D
        ("gradle_workflow", "scanner", "_run_trivy_secret_scan"),  # D
        ("gradle_workflow", "gradle_updates", "_gradle_evidence_workspace"),  # C
    }
)

type _Function = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
type _Comprehension = ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp

_NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
# A name bound to something other than a project module.
_SHADOWED = None


def _is_private(name: str) -> bool:
    return name.startswith("_") and not name.startswith("__")


def _join(package: str, name: str) -> str:
    return f"{package}.{name}" if package else name


def _parent(module: str) -> str | None:
    if not module:
        return None
    return module.rpartition(".")[0]


def _parameters(args: ast.arguments) -> list[ast.arg]:
    optional = [arg for arg in (args.vararg, args.kwarg) if arg is not None]
    return [*args.posonlyargs, *args.args, *args.kwonlyargs, *optional]


def _enclosing_parts(node: _Function) -> list[ast.expr]:
    """Expressions of a function evaluated in the enclosing scope."""
    args = node.args
    defaults = [*args.defaults, *(d for d in args.kw_defaults if d is not None)]
    if isinstance(node, ast.Lambda):
        return defaults
    annotations = [a.annotation for a in _parameters(args) if a.annotation]
    returns = [node.returns] if node.returns is not None else []
    return [*node.decorator_list, *defaults, *annotations, *returns]


def _body(node: _Function) -> list[ast.AST]:
    return [node.body] if isinstance(node, ast.Lambda) else list(node.body)


def _relative(absolute: str) -> str | None:
    """Map an absolute import name to its package-relative module name."""
    if absolute == PACKAGE:
        return ""
    if absolute.startswith(PACKAGE + "."):
        return absolute.removeprefix(PACKAGE + ".")
    return None


class _Scanner:
    def __init__(self, module: str, path: str, modules: frozenset[str]) -> None:
        self.module = module
        self.path = path
        self.modules = modules
        self.package = module if path.endswith("__init__.py") else _parent(module)
        self.sites: list[PrivateAccessSite] = []

    def import_base(self, node: ast.ImportFrom) -> str | None:
        """Resolve the module named by a ``from`` import, or None if external."""
        if node.level == 0:
            return _relative(node.module or "")
        base = self.package
        for _ in range(node.level - 1):
            base = _parent(base) if base is not None else None
        if base is None:
            return None
        return _join(base, node.module) if node.module else base

    def module_or_shadowed(self, target: str | None) -> str | None:
        return target if target in self.modules else _SHADOWED

    def bindings(self, node: ast.AST) -> Iterator[tuple[str, str | None]]:
        """Yield (name, bound project module or _SHADOWED) for one node."""
        match node:
            case ast.Import():
                for alias in node.names:
                    if alias.asname is None:
                        top = alias.name.partition(".")[0]
                        yield top, ("" if top == PACKAGE else _SHADOWED)
                    else:
                        yield (
                            alias.asname,
                            self.module_or_shadowed(_relative(alias.name)),
                        )
            case ast.ImportFrom():
                base = self.import_base(node)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    target = None if base is None else _join(base, alias.name)
                    yield alias.asname or alias.name, self.module_or_shadowed(target)
            case ast.Name(ctx=ast.Store() | ast.Del()):
                yield node.id, _SHADOWED
            case ast.arg():
                yield node.arg, _SHADOWED
            case ast.ExceptHandler(name=str() as name):
                yield name, _SHADOWED
            case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.ClassDef():
                yield node.name, _SHADOWED
            case ast.MatchAs(name=str() as name) | ast.MatchStar(name=str() as name):
                yield name, _SHADOWED
            case ast.MatchMapping(rest=str() as name):
                yield name, _SHADOWED

    def scope_env(
        self, scope: ast.Module | _Function, parent: Mapping[str, str | None]
    ) -> dict[str, str | None]:
        """Resolve names bound directly in *scope*, over the enclosing env."""
        bound: dict[str, set[str | None]] = {}
        stack: list[ast.AST] = (
            list(scope.body)
            if isinstance(scope, ast.Module)
            else [*_parameters(scope.args), *_body(scope)]
        )
        while stack:
            node = stack.pop()
            for name, target in self.bindings(node):
                bound.setdefault(name, set()).add(target)
            if isinstance(node, ast.comprehension):
                # The target binds in the comprehension's own scope; a walrus
                # in iter or ifs still binds here.
                stack.extend([node.iter, *node.ifs])
            elif not isinstance(node, _NESTED_SCOPES):
                stack.extend(ast.iter_child_nodes(node))
        local = {
            name: next(iter(targets)) if len(targets) == 1 else _SHADOWED
            for name, targets in bound.items()
        }
        return {**parent, **local}

    def resolve(self, node: ast.expr, env: Mapping[str, str | None]) -> str | None:
        """Return the project module an expression names, if any."""
        match node:
            case ast.Name(id=name):
                return env.get(name)
            case ast.Attribute(value=value, attr=attr):
                base = self.resolve(value, env)
                if base is not None and _join(base, attr) in self.modules:
                    return _join(base, attr)
        return None

    def report(self, owner: str, name: str, line: int) -> None:
        if owner != self.module and _is_private(name):
            self.sites.append(
                PrivateAccessSite((self.module, owner, name), self.path, line)
            )

    def visit_function(self, node: _Function, env: Mapping[str, str | None]) -> None:
        for part in _enclosing_parts(node):
            self.visit(part, env)
        inner = self.scope_env(node, env)
        for part in _body(node):
            self.visit(part, inner)

    def visit_comprehension(
        self, node: _Comprehension, env: Mapping[str, str | None]
    ) -> None:
        first = node.generators[0]
        self.visit(first.iter, env)
        targets = {
            name.id
            for generator in node.generators
            for name in ast.walk(generator.target)
            if isinstance(name, ast.Name)
        }
        inner = {**env, **dict.fromkeys(targets, _SHADOWED)}
        for generator in node.generators:
            if generator is not first:
                self.visit(generator.iter, inner)
            for condition in generator.ifs:
                self.visit(condition, inner)
        elements = (
            [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
        )
        for element in elements:
            self.visit(element, inner)

    def visit(self, node: ast.AST, env: Mapping[str, str | None]) -> None:
        match node:
            case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.Lambda():
                self.visit_function(node, env)
                return
            case ast.ListComp() | ast.SetComp() | ast.DictComp() | ast.GeneratorExp():
                self.visit_comprehension(node, env)
                return
            case ast.ImportFrom():
                base = self.import_base(node)
                if base is not None and base in self.modules:
                    for alias in node.names:
                        self.report(base, alias.name, node.lineno)
            case ast.Attribute(value=value, attr=attr):
                owner = self.resolve(value, env)
                if owner is not None:
                    self.report(owner, attr, node.lineno)
        for child in ast.iter_child_nodes(node):
            self.visit(child, env)


def find_private_accesses(
    sources: Mapping[str, tuple[str, str]],
) -> list[PrivateAccessSite]:
    """sources maps package-relative dotted module name -> (path, source text)."""
    modules = frozenset(sources)
    sites: list[PrivateAccessSite] = []
    for module, (path, text) in sorted(sources.items()):
        scanner = _Scanner(module, path, modules)
        tree = ast.parse(text, filename=path)
        scanner.visit(tree, scanner.scope_env(tree, {}))
        sites.extend(scanner.sites)
    return sites


def unallowed_sites(
    sites: list[PrivateAccessSite], allowed: frozenset[PrivateAccess]
) -> list[PrivateAccessSite]:
    return [site for site in sites if site.access not in allowed]


def stale_allowlist_entries(
    sites: list[PrivateAccessSite], allowed: frozenset[PrivateAccess]
) -> set[PrivateAccess]:
    return set(allowed) - {site.access for site in sites}


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
    # Not resolved: resolving follows the interpreter symlink out of .venv/bin.
    executable = Path(sys.executable).parent / name
    assert executable.is_file(), f"{executable} not found; run uv sync"
    return subprocess.run(
        [executable, *args],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def test_ruff_clean() -> None:
    result = run_tool("ruff", "check", "--no-cache", "--no-fix")
    assert result.returncode == 0, result.stdout


def test_import_contracts() -> None:
    result = run_tool("lint-imports", "--config", str(PYPROJECT), "--no-cache")
    assert result.returncode == 0, result.stdout


def test_models_contract_covers_all_modules() -> None:
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    contracts = config["tool"]["importlinter"]["contracts"]
    (models,) = [c for c in contracts if c.get("id") == "models-pure"]
    forbidden = set(models["forbidden_modules"])
    expected = {
        f"{PACKAGE}.{path.stem}"
        for path in PACKAGE_DIR.glob("*.py")
        if path.stem != "__init__"
    } | {
        f"{PACKAGE}.{path.name}"
        for path in PACKAGE_DIR.iterdir()
        if (path / "__init__.py").is_file() and path.name != "models"
    }
    assert {m for m in forbidden if m.startswith(f"{PACKAGE}.")} == expected
    assert {"rich", "cyclopts"} <= forbidden


def _site_lines(sites: list[PrivateAccessSite]) -> str:
    return "\n".join(
        f"{s.path}:{s.line} {s.access[0]} -> {s.access[1]}.{s.access[2]}" for s in sites
    )


def test_no_new_private_access() -> None:
    sites = unallowed_sites(
        find_private_accesses(package_sources()), ALLOWED_PRIVATE_ACCESS
    )
    assert sites == [], _site_lines(sites)


def test_no_stale_private_allowlist() -> None:
    stale = stale_allowlist_entries(
        find_private_accesses(package_sources()), ALLOWED_PRIVATE_ACCESS
    )
    assert stale == set(), "\n".join(
        f"stale allowlist entry, delete it: {entry}" for entry in sorted(stale)
    )


# -- scanner self-tests ------------------------------------------------------

_OWNERS = {
    "": ("src/maintenance_man/__init__.py", ""),
    "vcs": ("src/maintenance_man/vcs.py", ""),
    "gradle": ("src/maintenance_man/gradle.py", ""),
    "config": ("src/maintenance_man/config.py", ""),
    "models": ("src/maintenance_man/models/__init__.py", ""),
    "models.scan": ("src/maintenance_man/models/scan.py", ""),
}


def _accesses(module: str, path: str, text: str) -> set[PrivateAccess]:
    sources = {**_OWNERS, module: (path, text)}
    return {
        site.access
        for site in find_private_accesses(sources)
        if site.access[0] == module
    }


_TOP = "src/maintenance_man/probe.py"


@pytest.mark.parametrize(
    "module, path, text, expected",
    [
        pytest.param(
            "probe",
            _TOP,
            "from maintenance_man.vcs import _run\n",
            {("probe", "vcs", "_run")},
            id="absolute-from-import",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\nv._run()\n",
            {("probe", "vcs", "_run")},
            id="absolute-module-alias",
        ),
        pytest.param(
            "probe",
            _TOP,
            "from .vcs import _run\n",
            {("probe", "vcs", "_run")},
            id="relative-from-import",
        ),
        pytest.param(
            "probe",
            _TOP,
            "from . import vcs as v\nv._run()\n",
            {("probe", "vcs", "_run")},
            id="relative-module-alias",
        ),
        pytest.param(
            "models.probe",
            "src/maintenance_man/models/probe.py",
            "from ..gradle import _x\n",
            {("models.probe", "gradle", "_x")},
            id="parent-relative-in-subpackage",
        ),
        pytest.param(
            "probe",
            _TOP,
            "def f():\n    import maintenance_man.vcs as v\n    v._run()\n",
            {("probe", "vcs", "_run")},
            id="function-local-alias",
        ),
        pytest.param(
            "probe",
            _TOP,
            "from maintenance_man import vcs\nvcs._run()\n",
            {("probe", "vcs", "_run")},
            id="from-package-import-module",
        ),
        pytest.param(
            "probe",
            _TOP,
            "from maintenance_man.models import scan\nscan._x\n",
            {("probe", "models.scan", "_x")},
            id="from-subpackage-import-module",
        ),
        pytest.param(
            "probe",
            _TOP,
            "def f():\n    from maintenance_man.vcs import _run\n",
            {("probe", "vcs", "_run")},
            id="function-local-from-import",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs\nmaintenance_man.vcs._run()\n",
            {("probe", "vcs", "_run")},
            id="dotted-chain",
        ),
        pytest.param(
            "models",
            "src/maintenance_man/models/__init__.py",
            "from .scan import _x\n",
            {("models", "models.scan", "_x")},
            id="relative-in-package-init",
        ),
        pytest.param(
            "probe",
            _TOP,
            "from maintenance_man import __version__\n",
            set(),
            id="dunder-exempt",
        ),
        pytest.param(
            "probe",
            _TOP,
            "from maintenance_man import config as _config\n_config.MM_HOME\n",
            set(),
            id="private-alias-of-public-module",
        ),
        pytest.param(
            "vcs",
            "src/maintenance_man/vcs.py",
            "import maintenance_man.vcs as v\n"
            "from maintenance_man.vcs import _run\n"
            "v._run()\n",
            set(),
            id="own-private-names",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\ndef f(v):\n    return v._run()\n",
            set(),
            id="parameter-shadows-module-alias",
        ),
        pytest.param(
            "probe",
            _TOP,
            "def f():\n    import maintenance_man.vcs as v\n"
            "def g():\n    return v._run()\n",
            set(),
            id="alias-not-visible-in-other-function",
        ),
        pytest.param(
            "probe",
            _TOP,
            "def f():\n    import maintenance_man.vcs as v\n"
            "    def g():\n        return v._run()\n",
            {("probe", "vcs", "_run")},
            id="nested-function-sees-enclosing-alias",
        ),
        pytest.param(
            "probe",
            _TOP,
            "from ...outside import _x\n",
            set(),
            id="relative-import-above-package-root",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\ndef f(v=v._run):\n    return v\n",
            {("probe", "vcs", "_run")},
            id="default-uses-enclosing-scope",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\n@v._deco\ndef f(v):\n    return v\n",
            {("probe", "vcs", "_deco")},
            id="decorator-uses-enclosing-scope",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\ndef f(v: v._T) -> v._R:\n    return v\n",
            {("probe", "vcs", "_T"), ("probe", "vcs", "_R")},
            id="annotations-use-enclosing-scope",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\ng = lambda v=v._run: v\n",
            {("probe", "vcs", "_run")},
            id="lambda-default-uses-enclosing-scope",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\n"
            "def f(items):\n    [v for v in items]\n    return v._run()\n",
            {("probe", "vcs", "_run")},
            id="comprehension-target-does-not-shadow-function",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\nitems = [v._run for v in range(3)]\n",
            set(),
            id="comprehension-target-shadows-inside",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\nitems = [v for v in v._items]\n",
            {("probe", "vcs", "_items")},
            id="first-iterator-uses-enclosing-scope",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\n"
            "def f(items):\n    [(v := i) for i in items]\n    return v._run()\n",
            set(),
            id="comprehension-walrus-binds-in-function",
        ),
    ],
)
def test_private_access_scanner(module, path, text, expected):
    assert _accesses(module, path, text) == expected


def test_stale_allowlist_entry_is_reported():
    sites = find_private_accesses(
        {**_OWNERS, "probe": (_TOP, "from maintenance_man.vcs import _run\n")}
    )
    allowed = frozenset({("probe", "vcs", "_run"), ("probe", "gradle", "_gone")})
    assert stale_allowlist_entries(sites, allowed) == {("probe", "gradle", "_gone")}
    assert unallowed_sites(sites, allowed) == []
