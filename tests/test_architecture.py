"""Structural guardrails: lint, import contracts and private-name access."""

import ast
import os
import subprocess
import sys
import tomllib
from collections.abc import Iterable, Iterator, Mapping
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
        ("gradle_workflow", "scanner", "_run_gradle_scan"),  # D
        ("gradle_workflow", "scanner", "_run_trivy_secret_scan"),  # D
    }
)

type _Def = ast.FunctionDef | ast.AsyncFunctionDef
type _Function = _Def | ast.Lambda
type _Scope = ast.Module | _Function
type _Comprehension = ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp
# Maps each name to the project modules it may be bound to.
type _Env = Mapping[str, frozenset[str]]

_NOT_A_MODULE: frozenset[str] = frozenset()


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


def _decorators(node: _Function) -> list[ast.expr]:
    return [] if isinstance(node, ast.Lambda) else list(node.decorator_list)


def _defaults(args: ast.arguments) -> list[ast.expr]:
    return [*args.defaults, *(d for d in args.kw_defaults if d is not None)]


def _annotations(node: _Def) -> list[ast.expr]:
    annotations = [a.annotation for a in _parameters(node.args) if a.annotation]
    returns = [node.returns] if node.returns is not None else []
    return [*annotations, *returns]


def _body(node: _Scope) -> list[ast.AST]:
    return [node.body] if isinstance(node, ast.Lambda) else list(node.body)


def _local_nodes(scope: _Scope) -> Iterator[ast.AST]:
    """Yield the nodes whose bindings land in *scope*."""
    stack: list[ast.AST] = _body(scope)
    if not isinstance(scope, ast.Module):
        stack.extend(_parameters(scope.args))
    while stack:
        node = stack.pop()
        yield node
        match node:
            case ast.comprehension():
                # The target binds in the comprehension's own scope; a walrus
                # in iter or ifs still binds here.
                stack.extend([node.iter, *node.ifs])
            case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.Lambda():
                # Decorators and defaults run here, so a walrus in them binds here.
                stack.extend([*_decorators(node), *_defaults(node.args)])
            case ast.ClassDef():
                stack.extend([*node.decorator_list, *node.bases, *node.keywords])
            case _:
                stack.extend(ast.iter_child_nodes(node))


def _declarations(function: _Function) -> tuple[set[str], set[str]]:
    """Return the names *function* declares global and nonlocal."""
    declared_global: set[str] = set()
    declared_nonlocal: set[str] = set()
    for node in _local_nodes(function):
        match node:
            case ast.Global(names=names):
                declared_global.update(names)
            case ast.Nonlocal(names=names):
                declared_nonlocal.update(names)
    return declared_global, declared_nonlocal


def _child_functions(scope: _Scope) -> Iterator[_Def]:
    """Yield the functions defined in *scope*'s body, including in class bodies."""
    stack = _body(scope)
    while stack:
        node = stack.pop()
        match node:
            case ast.FunctionDef() | ast.AsyncFunctionDef():
                yield node
            case ast.Lambda():
                pass  # a lambda cannot declare global or nonlocal
            case _:
                stack.extend(ast.iter_child_nodes(node))


def _merge(
    into: dict[str, frozenset[str]], pairs: Iterable[tuple[str, frozenset[str]]]
) -> None:
    for name, targets in pairs:
        into[name] = into.get(name, _NOT_A_MODULE) | targets


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
        self.module_env: _Env = {}
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

    def targets(self, module: str | None) -> frozenset[str]:
        return frozenset({module}) if module in self.modules else _NOT_A_MODULE

    def bindings(self, node: ast.AST) -> Iterator[tuple[str, frozenset[str]]]:
        """Yield (name, project modules it binds) for one node."""
        match node:
            case ast.Import():
                for alias in node.names:
                    if alias.asname is None:
                        top = alias.name.partition(".")[0]
                        yield top, self.targets("" if top == PACKAGE else None)
                    else:
                        yield alias.asname, self.targets(_relative(alias.name))
            case ast.ImportFrom():
                base = self.import_base(node)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    target = None if base is None else _join(base, alias.name)
                    yield alias.asname or alias.name, self.targets(target)
            case ast.Name(ctx=ast.Store() | ast.Del()):
                yield node.id, _NOT_A_MODULE
            case ast.arg():
                yield node.arg, _NOT_A_MODULE
            case ast.ExceptHandler(name=str() as name):
                yield name, _NOT_A_MODULE
            case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.ClassDef():
                yield node.name, _NOT_A_MODULE
            case ast.MatchAs(name=str() as name) | ast.MatchStar(name=str() as name):
                yield name, _NOT_A_MODULE
            case ast.MatchMapping(rest=str() as name):
                yield name, _NOT_A_MODULE

    def bound_names(self, scope: _Scope) -> dict[str, frozenset[str]]:
        """Union every binding made in *scope*, ignoring global and nonlocal."""
        bound: dict[str, frozenset[str]] = {}
        for node in _local_nodes(scope):
            _merge(bound, self.bindings(node))
        return bound

    def escaping(
        self, function: _Def
    ) -> tuple[dict[str, frozenset[str]], dict[str, frozenset[str]]]:
        """Bindings in *function* or its nested functions that land outside it.

        Returns those made through ``global`` and those made through
        ``nonlocal`` that no function up to *function* binds locally.
        """
        bound = self.bound_names(function)
        declared_global, declared_nonlocal = _declarations(function)
        local = bound.keys() - declared_global - declared_nonlocal
        to_module = {n: bound[n] for n in declared_global & bound.keys()}
        to_enclosing = {n: bound[n] for n in declared_nonlocal & bound.keys()}
        for child in _child_functions(function):
            child_module, child_enclosing = self.escaping(child)
            _merge(to_module, child_module.items())
            _merge(
                to_enclosing,
                ((n, t) for n, t in child_enclosing.items() if n not in local),
            )
        return to_module, to_enclosing

    def scope_env(self, scope: _Scope, parent: _Env) -> dict[str, frozenset[str]]:
        """Resolve names bound in *scope*, over the enclosing env."""
        bound = self.bound_names(scope)
        if isinstance(scope, ast.Module):
            for child in _child_functions(scope):
                _merge(bound, self.escaping(child)[0].items())
            return {**parent, **bound}
        declared_global, declared_nonlocal = _declarations(scope)
        local = bound.keys() - declared_global - declared_nonlocal
        for child in _child_functions(scope):
            _, to_enclosing = self.escaping(child)
            _merge(bound, ((n, t) for n, t in to_enclosing.items() if n in local))
        env = {**parent, **{n: bound[n] for n in local}}
        for name in declared_global:
            env[name] = self.module_env.get(name, _NOT_A_MODULE)
        return env

    def resolve(self, node: ast.expr, env: _Env) -> frozenset[str]:
        """Return the project modules an expression may name."""
        match node:
            case ast.Name(id=name):
                return env.get(name, _NOT_A_MODULE)
            case ast.Attribute(value=value, attr=attr):
                return frozenset(
                    module
                    for base in self.resolve(value, env)
                    if (module := _join(base, attr)) in self.modules
                )
        return _NOT_A_MODULE

    def report(self, owner: str, name: str, line: int) -> None:
        if owner != self.module and _is_private(name):
            self.sites.append(
                PrivateAccessSite((self.module, owner, name), self.path, line)
            )

    def scan(self, tree: ast.Module) -> None:
        self.module_env = self.scope_env(tree, {})
        self.visit(tree, self.module_env)

    def type_param_env(
        self, node: _Def | ast.ClassDef | ast.TypeAlias, env: _Env
    ) -> _Env:
        """Visit PEP 695 type parameters; return their annotation scope's env."""
        if not node.type_params:
            return env
        names = [
            param.name
            for param in node.type_params
            if isinstance(param, ast.TypeVar | ast.ParamSpec | ast.TypeVarTuple)
        ]
        inner = {**env, **dict.fromkeys(names, _NOT_A_MODULE)}
        for param in node.type_params:
            self.visit(param, inner)
        return inner

    def visit_function(self, node: _Function, env: _Env) -> None:
        for part in [*_decorators(node), *_defaults(node.args)]:
            self.visit(part, env)
        if not isinstance(node, ast.Lambda):
            env = self.type_param_env(node, env)
            for part in _annotations(node):
                self.visit(part, env)
        inner = self.scope_env(node, env)
        for part in _body(node):
            self.visit(part, inner)

    def visit_class(self, node: ast.ClassDef, env: _Env) -> None:
        for part in node.decorator_list:
            self.visit(part, env)
        inner = self.type_param_env(node, env)
        for part in [*node.bases, *node.keywords, *node.body]:
            self.visit(part, inner)

    def visit_comprehension(self, node: _Comprehension, env: _Env) -> None:
        first = node.generators[0]
        self.visit(first.iter, env)
        targets = {
            name.id
            for generator in node.generators
            for name in ast.walk(generator.target)
            if isinstance(name, ast.Name)
        }
        inner = {**env, **dict.fromkeys(targets, _NOT_A_MODULE)}
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

    def visit_import(self, node: ast.Import) -> None:
        """Report private modules named along each imported dotted path."""
        for alias in node.names:
            parts = (_relative(alias.name) or "").split(".")
            for index, name in enumerate(parts):
                owner = ".".join(parts[:index])
                if owner in self.modules:
                    self.report(owner, name, alias.lineno)

    def visit(self, node: ast.AST, env: _Env) -> None:
        match node:
            case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.Lambda():
                self.visit_function(node, env)
                return
            case ast.ClassDef():
                self.visit_class(node, env)
                return
            case ast.TypeAlias():
                self.visit(node.value, self.type_param_env(node, env))
                return
            case ast.ListComp() | ast.SetComp() | ast.DictComp() | ast.GeneratorExp():
                self.visit_comprehension(node, env)
                return
            case ast.Import():
                self.visit_import(node)
            case ast.ImportFrom():
                base = self.import_base(node)
                if base is not None and base in self.modules:
                    for alias in node.names:
                        self.report(base, alias.name, alias.lineno)
            case ast.Attribute(value=value, attr=attr):
                for owner in sorted(self.resolve(value, env)):
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
        scanner.scan(ast.parse(text, filename=path))
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
        # Import this checkout's package, not whatever the venv's install points at.
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
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


def test_package_directories_are_regular_packages() -> None:
    # grimp leaves namespace packages out of the graph, so no contract sees them.
    namespace = sorted(
        {
            path.parent.relative_to(REPO_ROOT).as_posix()
            for path in PACKAGE_DIR.rglob("*.py")
            if not (path.parent / "__init__.py").is_file()
        }
    )
    assert namespace == [], f"add __init__.py to: {namespace}"


def test_only_cli_prints_prompts_or_exits() -> None:
    violations: list[str] = []
    for module, (path, text) in package_sources().items():
        if module == "cli":
            continue
        for node in ast.walk(ast.parse(text, filename=path)):
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
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\n"
            "def f():\n    def g(x=(v := 1)):\n        return x\n    return v._run()\n",
            set(),
            id="walrus-in-nested-default-binds-in-function",
        ),
        pytest.param(
            "probe",
            _TOP,
            "try:\n    import maintenance_man.vcs as v\n"
            "except ImportError:\n    v = None\nv._run()\n",
            {("probe", "vcs", "_run")},
            id="alias-with-import-fallback",
        ),
        pytest.param(
            "probe",
            _TOP,
            "def f():\n    global v\n    import maintenance_man.vcs as v\nv._run()\n",
            {("probe", "vcs", "_run")},
            id="global-binds-in-module",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\n"
            "def f(v):\n    def g():\n        global v\n        return v._run()\n",
            {("probe", "vcs", "_run")},
            id="global-reads-module-binding",
        ),
        pytest.param(
            "probe",
            _TOP,
            "def f():\n    v = None\n"
            "    def g():\n        nonlocal v\n"
            "        import maintenance_man.vcs as v\n"
            "    return v._run()\n",
            {("probe", "vcs", "_run")},
            id="nonlocal-binds-in-enclosing-function",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\n"
            "def f[v](x: v._T) -> v._R:\n    return v._x\n",
            set(),
            id="function-type-param-shadows-alias",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\n"
            "def f[T: v._B = v._D](x: T):\n    return x\n",
            {("probe", "vcs", "_B"), ("probe", "vcs", "_D")},
            id="type-param-bound-uses-enclosing-scope",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\n"
            "class C[v](v._Base):\n    x = v._x\n"
            "class D[T: v._B]:\n    pass\n",
            {("probe", "vcs", "_B")},
            id="class-type-params",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs as v\ntype A[v] = v._T\ntype B = v._U\n",
            {("probe", "vcs", "_U")},
            id="type-alias-params",
        ),
        pytest.param(
            "probe",
            _TOP,
            "import maintenance_man.vcs._impl\nimport maintenance_man._util as u\n",
            {("probe", "vcs", "_impl"), ("probe", "", "_util")},
            id="plain-import-of-private-module",
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


def test_private_access_site_is_the_alias_line():
    text = "from maintenance_man.vcs import (\n    run,\n    _run,\n)\n"
    sites = find_private_accesses({**_OWNERS, "probe": (_TOP, text)})
    assert [site.line for site in sites] == [3]
