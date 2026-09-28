"""Shared in-memory repository adapter used by repository contract tests."""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Literal

from maintenance_man.github import CodeHostError
from maintenance_man.models.scan import WORKFLOW_BOOKMARKS
from maintenance_man.vcs import (
    ExpectedRevisions,
    RevisionError,
    RevisionFile,
    WorkingCopyState,
    _temporary_workspace,
)
from maintenance_man.vcs_workflow import VcsServices


@dataclass(frozen=True, slots=True)
class FakeCall:
    path: Path
    method: str
    arguments: tuple[tuple[str, object], ...]


@dataclass(frozen=True, slots=True)
class _HostFailure:
    method: str
    ordinal: int
    error: CodeHostError
    registered_after: int


@dataclass(slots=True)
class _HostData:
    prs: list[tuple[str, Literal["open", "merged", "closed"], str]] = field(
        default_factory=list
    )
    failures: list[_HostFailure] = field(default_factory=list)
    ordinals: dict[str, int] = field(default_factory=dict)
    attempts: list[FakeCall] = field(default_factory=list)
    effects: list[FakeCall] = field(default_factory=list)


class FakeCodeHost:
    def __init__(self, path: Path, *, _data: _HostData | None = None):
        self.path = path.resolve()
        self._data = _data or _HostData()

    @property
    def attempts(self) -> list[FakeCall]:
        return self._data.attempts

    @property
    def effects(self) -> list[FakeCall]:
        return self._data.effects

    def seed_pr(
        self,
        *,
        bookmark: str,
        state: Literal["open", "merged", "closed"],
        message: str = "PR #1",
    ) -> None:
        self._data.prs.append((bookmark, state, message))

    def fail(
        self,
        method: str,
        *,
        ordinal: int = 1,
        error: CodeHostError,
    ) -> None:
        self._data.failures.append(
            _HostFailure(
                method,
                ordinal,
                error,
                self._data.ordinals.get(method, 0),
            )
        )

    def _begin(self, method: str, **arguments: object) -> None:
        self._data.attempts.append(
            FakeCall(self.path, method, tuple(arguments.items()))
        )
        ordinal = self._data.ordinals.get(method, 0) + 1
        self._data.ordinals[method] = ordinal
        for failure in self._data.failures:
            if (
                failure.method == method
                and ordinal == failure.registered_after + failure.ordinal
            ):
                raise failure.error

    def pr_bookmarks(self, *, state: Literal["merged", "closed"]) -> frozenset[str]:
        self._begin("pr_bookmarks", state=state)
        return frozenset(
            bookmark
            for bookmark, observed_state, _message in self._data.prs
            if observed_state == state
        )

    def create_pr(self, *, bookmark: str) -> str:
        self._begin("create_pr", bookmark=bookmark)
        for existing, state, message in reversed(self._data.prs):
            if existing == bookmark and state == "open":
                return (
                    message
                    if message != "PR #1"
                    else f"PR already exists for {bookmark}"
                )
        self._data.prs.append((bookmark, "open", "PR #1"))
        self._data.effects.append(
            FakeCall(self.path, "create_pr", (("bookmark", bookmark),))
        )
        return "PR #1"


@dataclass(frozen=True, slots=True)
class _Commit:
    commit_id: str
    change_id: str
    parent: str | None
    files: tuple[tuple[str, bytes], ...]
    description: str
    tree_id: str


@dataclass(frozen=True, slots=True)
class _Workspace:
    name: str
    path: Path
    current: str


@dataclass(slots=True)
class _Origin:
    graph: dict[str, _Commit] = field(default_factory=dict)
    bookmarks: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(slots=True)
class _RepositoryData:
    graph: dict[str, _Commit]
    bookmarks: dict[str, tuple[str, ...]]
    tracking: dict[str, tuple[str, ...]]
    workspaces: dict[str, _Workspace]
    declared_files: set[str]
    origin_key: str
    tracks_main: bool = True


@dataclass(frozen=True, slots=True)
class _Failure:
    method: str
    ordinal: int
    error: RevisionError
    path: Path | None
    registered_after: int


@dataclass(frozen=True, slots=True)
class _Hook:
    method: str
    ordinal: int
    phase: Literal["before", "postcheck"]
    action: Callable[[], None]
    path: Path | None
    registered_after: int


def _tree_id(files: tuple[tuple[str, bytes], ...]) -> str:
    digest = hashlib.sha256()
    for name, content in files:
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _commit(
    *, change_id: str, parent: str | None, files: dict[str, bytes], description: str
) -> _Commit:
    frozen_files = tuple(sorted(files.items()))
    tree = _tree_id(frozen_files)
    digest = hashlib.sha256()
    digest.update(change_id.encode())
    digest.update((parent or "root").encode())
    digest.update(tree.encode())
    digest.update(description.encode())
    return _Commit(
        digest.hexdigest(), change_id, parent, frozen_files, description, tree
    )


class FakeJjState:
    """Repository graph and boundary controls shared by path-bound fake views."""

    _owners: ClassVar[dict[Path, FakeJjState]] = {}

    def __init__(self) -> None:
        self._repositories: dict[Path, _RepositoryData] = {}
        self._bindings: dict[Path, tuple[Path, str]] = {}
        self._origins: dict[str, _Origin] = {}
        self._sequence = 0
        self._failures: list[_Failure] = []
        self._hooks: list[_Hook] = []
        self._ordinals: dict[tuple[str, Path], int] = {}
        self._hook_ordinals: dict[tuple[str, str, Path], int] = {}
        self.attempts: list[FakeCall] = []
        self.effects: list[FakeCall] = []
        self._hosts: dict[Path, _HostData] = {}

    def _identity(self, label: str) -> str:
        self._sequence += 1
        return hashlib.sha256(f"{label}:{self._sequence}".encode()).hexdigest()

    def seed_repository(
        self, path: Path, *, files: dict[str, str], description: str = "baseline"
    ) -> FakeJj:
        root = path.resolve()
        if root in self._repositories:
            raise AssertionError(f"repository already seeded: {root}")
        root.mkdir(parents=True, exist_ok=True)
        encoded = {name: value.encode() for name, value in files.items()}
        baseline = _commit(
            change_id=self._identity("change"),
            parent=None,
            files=encoded,
            description=description,
        )
        child = _commit(
            change_id=self._identity("change"),
            parent=baseline.commit_id,
            files=encoded,
            description="",
        )
        origin_key = f"origin:{root}"
        self._origins[origin_key] = _Origin(
            graph={baseline.commit_id: baseline},
            bookmarks={"main": (baseline.commit_id,)},
        )
        data = _RepositoryData(
            graph={baseline.commit_id: baseline, child.commit_id: child},
            bookmarks={"main": (baseline.commit_id,)},
            tracking={"main": (baseline.commit_id,)},
            workspaces={"default": _Workspace("default", root, child.commit_id)},
            declared_files=set(files),
            origin_key=origin_key,
        )
        self._repositories[root] = data
        self._hosts[root] = _HostData()
        self._bind(root, root, "default")
        self._project(data, data.workspaces["default"])
        return FakeJj(root)

    def _bind(self, path: Path, root: Path, workspace: str) -> None:
        resolved = path.resolve()
        self._bindings[resolved] = (root, workspace)
        self._owners[resolved] = self

    def repository(self, path: Path) -> FakeJj:
        resolved = path.resolve()
        if resolved not in self._bindings:
            raise AssertionError(f"unknown fake repository path: {resolved}")
        return FakeJj(resolved)

    def code_host(self, path: Path) -> FakeCodeHost:
        resolved = path.resolve()
        try:
            root, _workspace = self._bindings[resolved]
            data = self._hosts[root]
        except KeyError as exc:
            raise AssertionError(f"unknown fake repository path: {resolved}") from exc
        return FakeCodeHost(resolved, _data=data)

    def services(self) -> VcsServices:
        return VcsServices(repository=self.repository, code_host=self.code_host)

    def register_files(self, path: Path, *filenames: str) -> None:
        data, _ = self._view(path)
        data.declared_files.update(filenames)

    def attach_origin(
        self, path: Path, *, origin: str, track_main: bool = False
    ) -> None:
        data, _ = self._view(path)
        self._origins.setdefault(origin, _Origin())
        data.origin_key = origin
        data.tracks_main = track_main

    def seed_peer(self, path: Path, *, source: Path, track_main: bool = True) -> FakeJj:
        source_data, _ = self._view(source)
        origin = self._origins[source_data.origin_key]
        main = self._single(origin.bookmarks.get("main", ()), "main@origin")
        root = path.resolve()
        root.mkdir(parents=True, exist_ok=True)
        graph = dict(origin.graph)
        base = graph[main]
        child = _commit(
            change_id=self._identity("change"),
            parent=main,
            files=dict(base.files),
            description="",
        )
        graph[child.commit_id] = child
        data = _RepositoryData(
            graph=graph,
            bookmarks={"main": (main,)},
            tracking={"main": (main,)},
            workspaces={"default": _Workspace("default", root, child.commit_id)},
            declared_files={name for name, _ in base.files},
            origin_key=source_data.origin_key,
            tracks_main=track_main,
        )
        self._repositories[root] = data
        self._bind(root, root, "default")
        self._project(data, data.workspaces["default"])
        return FakeJj(root)

    def track_main(self, path: Path, *, enabled: bool) -> None:
        data, _ = self._view(path)
        data.tracks_main = enabled

    def seed_commit(
        self,
        path: Path,
        *,
        parent: str,
        files: dict[str, str],
        description: str,
    ) -> str:
        data, _ = self._view(path)
        if parent not in data.graph:
            raise AssertionError(f"unknown parent: {parent}")
        record = _commit(
            change_id=self._identity("change"),
            parent=parent,
            files={name: value.encode() for name, value in files.items()},
            description=description,
        )
        data.graph[record.commit_id] = record
        self._origins[data.origin_key].graph[record.commit_id] = record
        return record.commit_id

    def seed_bookmark(
        self, path: Path, *, bookmark: str, targets: tuple[str, ...]
    ) -> None:
        data, _ = self._view(path)
        self._validate_targets(data, targets)
        if targets:
            data.bookmarks[bookmark] = tuple(dict.fromkeys(targets))
        else:
            data.bookmarks.pop(bookmark, None)

    def seed_working_copy(
        self,
        path: Path,
        *,
        parent: str,
        files: dict[str, str],
        description: str = "",
    ) -> str:
        data, workspace = self._view(path)
        record = _commit(
            change_id=self._identity("change"),
            parent=parent,
            files={name: value.encode() for name, value in files.items()},
            description=description,
        )
        data.graph[record.commit_id] = record
        self._replace_workspace(data, workspace, current=record.commit_id)
        data.declared_files.update(files)
        self._project(data, self._workspace(data, workspace.name))
        return record.change_id

    def seed_remote(
        self, path: Path, *, bookmark: str, targets: tuple[str, ...]
    ) -> None:
        data, _ = self._view(path)
        self._validate_targets(data, targets)
        origin = self._origins[data.origin_key]
        origin.graph.update(data.graph)
        if targets:
            origin.bookmarks[bookmark] = tuple(dict.fromkeys(targets))
        else:
            origin.bookmarks.pop(bookmark, None)

    def remote_bookmark_targets(self, path: Path, *, bookmark: str) -> tuple[str, ...]:
        """Inspect an actual-origin bookmark for workflow outcome assertions."""
        data, _ = self._view(path)
        return self._origins[data.origin_key].bookmarks.get(bookmark, ())

    def seed_tracking(
        self, path: Path, *, bookmark: str, targets: tuple[str, ...]
    ) -> None:
        data, _ = self._view(path)
        self._validate_targets(data, targets)
        if targets:
            data.tracking[bookmark] = tuple(dict.fromkeys(targets))
        else:
            data.tracking.pop(bookmark, None)

    def fail(
        self,
        method: str,
        *,
        ordinal: int = 1,
        error: RevisionError,
        path: Path | None = None,
    ) -> None:
        resolved = path.resolve() if path else None
        self._failures.append(
            _Failure(
                method,
                ordinal,
                error,
                resolved,
                self._matching_call_ordinal(method, resolved),
            )
        )

    def hook(
        self,
        method: str,
        *,
        ordinal: int = 1,
        phase: Literal["before", "postcheck"],
        action: Callable[[], None],
        path: Path | None = None,
    ) -> None:
        resolved = path.resolve() if path else None
        self._hooks.append(
            _Hook(
                method,
                ordinal,
                phase,
                action,
                resolved,
                self._matching_hook_ordinal(method, phase, resolved),
            )
        )

    def clear_calls(self) -> None:
        self.attempts.clear()
        self.effects.clear()
        self._ordinals.clear()
        self._hook_ordinals.clear()
        self._failures = [
            _Failure(item.method, item.ordinal, item.error, item.path, 0)
            for item in self._failures
        ]
        self._hooks = [
            _Hook(
                item.method,
                item.ordinal,
                item.phase,
                item.action,
                item.path,
                0,
            )
            for item in self._hooks
        ]
        for host in self._hosts.values():
            host.attempts.clear()
            host.effects.clear()
            host.ordinals.clear()
            host.failures = [
                _HostFailure(item.method, item.ordinal, item.error, 0)
                for item in host.failures
            ]

    def _matching_call_ordinal(self, method: str, path: Path | None) -> int:
        return sum(
            ordinal
            for (counted_method, counted_path), ordinal in self._ordinals.items()
            if counted_method == method and (path is None or counted_path == path)
        )

    def _matching_hook_ordinal(self, method: str, phase: str, path: Path | None) -> int:
        return sum(
            ordinal
            for (
                counted_method,
                counted_phase,
                counted_path,
            ), ordinal in self._hook_ordinals.items()
            if counted_method == method
            and counted_phase == phase
            and (path is None or counted_path == path)
        )

    def _view(self, path: Path) -> tuple[_RepositoryData, _Workspace]:
        resolved = path.resolve()
        try:
            root, name = self._bindings[resolved]
            data = self._repositories[root]
            return data, self._workspace(data, name)
        except KeyError as exc:
            raise AssertionError(f"unknown fake repository path: {resolved}") from exc

    @staticmethod
    def _workspace(data: _RepositoryData, name: str) -> _Workspace:
        try:
            return data.workspaces[name]
        except KeyError as exc:
            raise RevisionError(f"Unknown workspace: {name}") from exc

    @staticmethod
    def _replace_workspace(
        data: _RepositoryData, workspace: _Workspace, *, current: str
    ) -> None:
        data.workspaces[workspace.name] = _Workspace(
            workspace.name, workspace.path, current
        )

    @staticmethod
    def _single(targets: tuple[str, ...], revision: str) -> str:
        if len(targets) != 1:
            raise RevisionError(
                f"{revision} must resolve to exactly one commit, got {len(targets)}"
            )
        return targets[0]

    @staticmethod
    def _validate_targets(data: _RepositoryData, targets: tuple[str, ...]) -> None:
        unknown = set(targets) - data.graph.keys()
        if unknown:
            raise AssertionError(f"unknown fake commit targets: {sorted(unknown)}")

    def _project(self, data: _RepositoryData, workspace: _Workspace) -> None:
        files = dict(data.graph[workspace.current].files)
        workspace.path.mkdir(parents=True, exist_ok=True)
        for name in data.declared_files:
            target = workspace.path / name
            if name in files:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(files[name])
            elif target.exists() or target.is_symlink():
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink()

    def _snapshot(self, path: Path) -> _Commit:
        data, workspace = self._view(path)
        current = data.graph[workspace.current]
        files: dict[str, bytes] = {}
        for name in data.declared_files:
            target = workspace.path / name
            if target.is_file() and not target.is_symlink():
                files[name] = target.read_bytes()
        record = _commit(
            change_id=current.change_id,
            parent=current.parent,
            files=files,
            description=current.description,
        )
        data.graph[record.commit_id] = record
        self._replace_workspace(data, workspace, current=record.commit_id)
        return record

    def _is_ancestor(
        self, data: _RepositoryData, ancestor: str, descendant: str
    ) -> bool:
        cursor: str | None = descendant
        while cursor is not None:
            if cursor == ancestor:
                return True
            cursor = data.graph[cursor].parent
        return False

    def _begin(self, bound_path: Path, method: str, **arguments: object) -> None:
        resolved = bound_path.resolve()
        self.attempts.append(FakeCall(resolved, method, tuple(arguments.items())))
        key = (method, resolved)
        ordinal = self._ordinals.get(key, 0) + 1
        self._ordinals[key] = ordinal
        for failure in self._failures:
            if (
                failure.method == method
                and (failure.path is None or failure.path == resolved)
                and self._matching_call_ordinal(method, failure.path)
                == failure.registered_after + failure.ordinal
            ):
                raise failure.error
        self._run_hooks(resolved, method, "before")

    def _run_hooks(
        self, bound_path: Path, method: str, phase: Literal["before", "postcheck"]
    ) -> None:
        key = (method, phase, bound_path)
        ordinal = self._hook_ordinals.get(key, 0) + 1
        self._hook_ordinals[key] = ordinal
        for hook in tuple(self._hooks):
            if (
                hook.method == method
                and hook.phase == phase
                and (hook.path is None or hook.path == bound_path)
                and self._matching_hook_ordinal(method, phase, hook.path)
                == hook.registered_after + hook.ordinal
            ):
                hook.action()

    def _effect(self, bound_path: Path, method: str, **arguments: object) -> None:
        self.effects.append(
            FakeCall(bound_path.resolve(), method, tuple(arguments.items()))
        )


class FakeJj:
    """Path-bound Repository implementation backed by FakeJjState."""

    def __init__(self, path: Path):
        resolved = path.resolve()
        try:
            self._state = FakeJjState._owners[resolved]
        except KeyError as exc:
            raise AssertionError(f"unknown fake repository path: {resolved}") from exc
        self._path = resolved
        self._state._view(resolved)

    @property
    def path(self) -> Path:
        return self._path

    def _data(self) -> tuple[_RepositoryData, _Workspace]:
        return self._state._view(self.path)

    def bookmark_exists(self, *, bookmark: str) -> bool:
        self._state._begin(self.path, "bookmark_exists", bookmark=bookmark)
        data, _ = self._data()
        return bool(data.bookmarks.get(bookmark, ()))

    def local_bookmarks(self) -> frozenset[str]:
        self._state._begin(self.path, "local_bookmarks")
        data, _ = self._data()
        return frozenset(name for name, targets in data.bookmarks.items() if targets)

    def bookmark_conflicted(self, *, bookmark: str) -> bool:
        self._state._begin(self.path, "bookmark_conflicted", bookmark=bookmark)
        data, _ = self._data()
        targets = data.bookmarks.get(bookmark, ())
        if not targets:
            raise RevisionError(f"Cannot inspect bookmark conflict for {bookmark}")
        return len(targets) > 1

    def resolve_revision(self, *, revision: str, read_only: bool = False) -> str:
        self._state._begin(
            self.path, "resolve_revision", revision=revision, read_only=read_only
        )
        data, workspace = self._data()
        current = (
            workspace.current
            if read_only
            else self._state._snapshot(self.path).commit_id
        )
        if revision == "@":
            return current
        if revision == "@-":
            parent = data.graph[current].parent
            if parent is None:
                raise RevisionError("@- must resolve to exactly one commit, got 0")
            return parent
        if revision == "main@origin":
            return self._state._single(data.tracking.get("main", ()), revision)
        if revision in data.graph:
            return revision
        return self._state._single(data.bookmarks.get(revision, ()), revision)

    def revision_file(self, *, revision: str, filename: str) -> RevisionFile:
        self._state._begin(
            self.path, "revision_file", revision=revision, filename=filename
        )
        commit_id = self.resolve_revision(revision=revision, read_only=True)
        data, _ = self._data()
        return RevisionFile(
            commit_id=commit_id,
            is_regular=filename in dict(data.graph[commit_id].files),
        )

    def tree_id(self, *, revision: str = "@") -> str:
        self._state._begin(self.path, "tree_id", revision=revision)
        commit_id = self.resolve_revision(revision=revision)
        data, _ = self._data()
        return data.graph[commit_id].tree_id

    def same_revision(self, *, left: str, right: str) -> bool:
        self._state._begin(self.path, "same_revision", left=left, right=right)
        return self.resolve_revision(revision=left) == self.resolve_revision(
            revision=right
        )

    def is_ancestor(self, *, ancestor: str, descendant: str) -> bool:
        self._state._begin(
            self.path, "is_ancestor", ancestor=ancestor, descendant=descendant
        )
        left = self.resolve_revision(revision=ancestor)
        right = self.resolve_revision(revision=descendant)
        data, _ = self._data()
        return self._state._is_ancestor(data, left, right)

    def revision_bookmarks(self, *, revision: str) -> tuple[str, ...]:
        self._state._begin(self.path, "revision_bookmarks", revision=revision)
        commit_id = self.resolve_revision(revision=revision)
        data, _ = self._data()
        return tuple(
            sorted(
                name for name, targets in data.bookmarks.items() if commit_id in targets
            )
        )

    def change_id(self, *, revision: str = "@") -> str:
        self._state._begin(self.path, "change_id", revision=revision)
        commit_id = self.resolve_revision(revision=revision)
        data, _ = self._data()
        return data.graph[commit_id].change_id

    def working_copy_state(self) -> WorkingCopyState:
        self._state._begin(self.path, "working_copy_state")
        current = self._state._snapshot(self.path)
        data, _ = self._data()
        parent_files = (
            dict(data.graph[current.parent].files) if current.parent is not None else {}
        )
        bookmarks = tuple(
            sorted(
                name
                for name, targets in data.bookmarks.items()
                if targets == (current.commit_id,)
            )
        )
        return WorkingCopyState(
            has_changes=dict(current.files) != parent_files,
            description=current.description,
            bookmarks=bookmarks,
        )

    def has_changes(self) -> bool:
        self._state._begin(self.path, "has_changes")
        current = self._state._snapshot(self.path)
        data, _ = self._data()
        parent = dict(data.graph[current.parent].files) if current.parent else {}
        return dict(current.files) != parent

    def changed_paths(self, *, revision: str = "@") -> frozenset[str]:
        self._state._begin(self.path, "changed_paths", revision=revision)
        commit_id = self.resolve_revision(revision=revision)
        data, _ = self._data()
        record = data.graph[commit_id]
        parent = dict(data.graph[record.parent].files) if record.parent else {}
        current = dict(record.files)
        return frozenset(
            name
            for name in parent.keys() | current.keys()
            if parent.get(name) != current.get(name)
        )

    def create_bookmark(self, *, bookmark: str, revision: str) -> None:
        self._state._begin(
            self.path, "create_bookmark", bookmark=bookmark, revision=revision
        )
        data, _ = self._data()
        if data.bookmarks.get(bookmark):
            raise RevisionError(f"Bookmark already exists: {bookmark}")
        target = self.resolve_revision(revision=revision)
        data.bookmarks[bookmark] = (target,)
        self._state._effect(
            self.path, "create_bookmark", bookmark=bookmark, revision=revision
        )

    def set_bookmark(self, *, bookmark: str, revision: str) -> None:
        self._state._begin(
            self.path, "set_bookmark", bookmark=bookmark, revision=revision
        )
        target = self.resolve_revision(revision=revision)
        data, _ = self._data()
        data.bookmarks[bookmark] = (target,)
        self._state._effect(
            self.path, "set_bookmark", bookmark=bookmark, revision=revision
        )

    def delete_bookmark(self, *, bookmark: str) -> None:
        self._state._begin(self.path, "delete_bookmark", bookmark=bookmark)
        data, _ = self._data()
        if not data.bookmarks.pop(bookmark, None):
            raise RevisionError(f"Bookmark does not exist: {bookmark}")
        self._state._effect(self.path, "delete_bookmark", bookmark=bookmark)

    def new_change(self, *, revision: str) -> None:
        self._state._begin(self.path, "new_change", revision=revision)
        self._state._snapshot(self.path)
        target = self.resolve_revision(revision=revision)
        data, workspace = self._data()
        base = data.graph[target]
        record = _commit(
            change_id=self._state._identity("change"),
            parent=target,
            files=dict(base.files),
            description="",
        )
        data.graph[record.commit_id] = record
        self._state._replace_workspace(data, workspace, current=record.commit_id)
        self._state._project(data, self._state._workspace(data, workspace.name))
        self._state._effect(self.path, "new_change", revision=revision)

    def commit(self, *, message: str) -> None:
        self._state._begin(self.path, "commit", message=message)
        current = self._state._snapshot(self.path)
        data, workspace = self._data()
        finished = _commit(
            change_id=current.change_id,
            parent=current.parent,
            files=dict(current.files),
            description=message,
        )
        child = _commit(
            change_id=self._state._identity("change"),
            parent=finished.commit_id,
            files=dict(finished.files),
            description="",
        )
        data.graph[finished.commit_id] = finished
        data.graph[child.commit_id] = child
        self._state._replace_workspace(data, workspace, current=child.commit_id)
        self._state._project(data, self._state._workspace(data, workspace.name))
        self._state._effect(self.path, "commit", message=message)

    def describe(self, *, message: str) -> None:
        current = self._state._snapshot(self.path)
        data, workspace = self._data()
        described = _commit(
            change_id=current.change_id,
            parent=current.parent,
            files=dict(current.files),
            description=message,
        )
        data.graph[described.commit_id] = described
        self._state._replace_workspace(data, workspace, current=described.commit_id)

    def discard(self) -> None:
        self._state._begin(self.path, "discard")
        current = self._state._snapshot(self.path)
        if current.parent is None:
            raise RevisionError("Working copy has no parent")
        data, workspace = self._data()
        parent = data.graph[current.parent]
        restored = _commit(
            change_id=current.change_id,
            parent=current.parent,
            files=dict(parent.files),
            description=current.description,
        )
        data.graph[restored.commit_id] = restored
        self._state._replace_workspace(data, workspace, current=restored.commit_id)
        self._state._project(data, self._state._workspace(data, workspace.name))
        self._state._effect(self.path, "discard")

    def rebase_working_copy(self, *, revision: str) -> None:
        self._state._begin(self.path, "rebase_working_copy", revision=revision)
        current = self._state._snapshot(self.path)
        target = self.resolve_revision(revision=revision)
        data, workspace = self._data()
        old_parent = dict(data.graph[current.parent].files) if current.parent else {}
        current_files = dict(current.files)
        rebased_files = dict(data.graph[target].files)
        for name in old_parent.keys() | current_files.keys():
            if old_parent.get(name) == current_files.get(name):
                continue
            if name in current_files:
                rebased_files[name] = current_files[name]
            else:
                rebased_files.pop(name, None)
        rebased = _commit(
            change_id=current.change_id,
            parent=target,
            files=rebased_files,
            description=current.description,
        )
        data.graph[rebased.commit_id] = rebased
        self._state._replace_workspace(data, workspace, current=rebased.commit_id)
        self._state._project(data, self._state._workspace(data, workspace.name))
        self._state._effect(self.path, "rebase_working_copy", revision=revision)

    def _guard(self, bookmark: str, expected: ExpectedRevisions) -> None:
        if bookmark not in tuple(WORKFLOW_BOOKMARKS.values()):
            raise RevisionError("Unexpected managed Gradle bookmark")
        data, _ = self._data()
        if data.bookmarks.get("main", ()) != (expected.base,) or data.bookmarks.get(
            bookmark, ()
        ) != (expected.tip,):
            raise RevisionError("Guarded revisions changed")
        if not self._state._is_ancestor(data, expected.base, expected.tip):
            raise RevisionError("Guarded tip is not descended from its base")

    def promote_bookmark_to_main(
        self, *, bookmark: str, expected: ExpectedRevisions | None = None
    ) -> None:
        method = "promote_bookmark_to_main"
        self._state._begin(self.path, method, bookmark=bookmark, expected=expected)
        data, _ = self._data()
        if expected is None:
            target = self.resolve_revision(revision=bookmark)
        else:
            self._guard(bookmark, expected)
            target = expected.tip
        data.bookmarks["main"] = (target,)
        self._state._effect(self.path, method, bookmark=bookmark, expected=expected)
        self._state._run_hooks(self.path, method, "postcheck")
        if expected is not None and (
            data.bookmarks.get("main") != (expected.tip,)
            or data.bookmarks.get(bookmark) != (expected.tip,)
        ):
            raise RevisionError("Local revisions changed during promotion")

    def reset_verified_bookmark(
        self, *, bookmark: str, expected: ExpectedRevisions
    ) -> None:
        method = "reset_verified_bookmark"
        self._state._begin(self.path, method, bookmark=bookmark, expected=expected)
        self._guard(bookmark, expected)
        data, _ = self._data()
        data.bookmarks[bookmark] = (expected.base,)
        self._state._effect(self.path, method, bookmark=bookmark, expected=expected)
        self._state._run_hooks(self.path, method, "postcheck")
        if data.bookmarks.get(bookmark) != (expected.base,):
            raise RevisionError("Local revisions changed during reset")

    def fetch(self, *, main_only: bool = False) -> None:
        self._state._begin(self.path, "fetch", main_only=main_only)
        data, _ = self._data()
        origin = self._state._origins[data.origin_key]
        data.graph.update(origin.graph)
        names = {"main"} if main_only else set(origin.bookmarks)
        for name in names:
            remote = origin.bookmarks.get(name, ())
            old = data.tracking.get(name, ())
            local = data.bookmarks.get(name, ())
            data.tracking[name] = remote
            if name != "main" or not data.tracks_main:
                continue
            if local == old:
                data.bookmarks[name] = remote
            elif local == remote:
                pass
            elif len(local) == len(remote) == 1:
                left, right = local[0], remote[0]
                if self._state._is_ancestor(data, left, right):
                    data.bookmarks[name] = remote
                elif not self._state._is_ancestor(data, right, left):
                    data.bookmarks[name] = tuple(dict.fromkeys((*local, *remote)))
            else:
                data.bookmarks[name] = tuple(dict.fromkeys((*local, *remote)))
        self._state._effect(self.path, "fetch", main_only=main_only)

    def push_bookmark(
        self, *, bookmark: str, expected: ExpectedRevisions | None = None
    ) -> None:
        method = "push_bookmark"
        self._state._begin(self.path, method, bookmark=bookmark, expected=expected)
        data, _ = self._data()
        origin = self._state._origins[data.origin_key]
        if (
            bookmark == "main"
            and not data.tracks_main
            and origin.bookmarks.get(bookmark)
        ):
            raise RevisionError("Non-tracking remote bookmark main@origin exists")
        if expected is not None:
            self._guard(bookmark, expected)
            target = expected.tip
        else:
            target = self.resolve_revision(revision=bookmark)
        origin.graph.update(data.graph)
        origin.bookmarks[bookmark] = (target,)
        data.tracking[bookmark] = (target,)
        if bookmark == "main":
            data.tracks_main = True
        self._state._effect(self.path, method, bookmark=bookmark, expected=expected)
        self._state._run_hooks(self.path, method, "postcheck")
        if expected is not None and (
            data.bookmarks.get("main") != (expected.base,)
            or data.bookmarks.get(bookmark) != (expected.tip,)
        ):
            raise RevisionError("Local revisions changed during submission")

    def workspace_names(self) -> frozenset[str]:
        self._state._begin(self.path, "workspace_names")
        data, _ = self._data()
        return frozenset(data.workspaces)

    def add_workspace(self, *, name: str, path: Path, revision: str) -> None:
        self._state._begin(
            self.path, "add_workspace", name=name, path=path, revision=revision
        )
        data, _ = self._data()
        if name in data.workspaces or path.resolve() in self._state._bindings:
            raise RevisionError(f"Workspace already exists: {name}")
        target = self.resolve_revision(revision=revision)
        workspace = _Workspace(name, path.resolve(), target)
        data.workspaces[name] = workspace
        root, _ = self._state._bindings[self.path]
        self._state._bind(workspace.path, root, name)
        self._state._project(data, workspace)
        self._state._effect(
            self.path, "add_workspace", name=name, path=path, revision=revision
        )

    def forget_workspace(self, *, name: str) -> None:
        self._state._begin(self.path, "forget_workspace", name=name)
        data, _ = self._data()
        try:
            workspace = data.workspaces.pop(name)
        except KeyError as exc:
            raise RevisionError(f"Unknown workspace: {name}") from exc
        self._state._bindings.pop(workspace.path, None)
        self._state._owners.pop(workspace.path, None)
        self._state._effect(self.path, "forget_workspace", name=name)

    def temporary_workspace(self, *, revision: str):
        return _temporary_workspace(self, revision=revision, bind=FakeJj)
