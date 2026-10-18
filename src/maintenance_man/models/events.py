from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from maintenance_man.models.scan import ScanResult, UpdateResult

type Status = Literal["passed", "failed", "blocked", "skipped", "unchanged"]


class Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class SkipReason(StrEnum):
    PATH_MISSING = "path_missing"
    NO_SCAN_RESULTS = "no_scan_results"
    NOTHING_TO_DO = "nothing_to_do"
    FLOW_CONFLICT = "flow_conflict"
    NOT_DEPLOYABLE = "not_deployable"
    UNCHANGED = "unchanged"
    BLOCKED = "blocked"


class DeployStep(StrEnum):
    BUILD = "build"
    DEPLOY = "deploy"


class FindingStepKind(StrEnum):
    PREPARE = "prepare"
    PACKAGE_COMMAND = "package_command"
    TEST = "test"
    INSPECT = "inspect"
    COMMIT = "commit"
    BOOKMARK = "bookmark"
    DISCARD = "discard"


@dataclass(frozen=True, slots=True)
class Event:
    """Something a service reports while it works; the CLI renders each kind."""


@dataclass(frozen=True, slots=True)
class ProjectStarted(Event):
    project: str


@dataclass(frozen=True, slots=True)
class ProjectSkipped(Event):
    project: str
    reason: SkipReason
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class OperationFailed(Event):
    operation: str
    """The step that failed, in the reader's words, such as 'workspace cleanup'."""

    project: str
    error: str


@dataclass(frozen=True, slots=True)
class PromotionFailed(Event):
    project: str
    error: str


@dataclass(frozen=True, slots=True)
class ScanReported(Event):
    result: ScanResult
    elapsed_s: float | None = None


@dataclass(frozen=True, slots=True)
class MissingTestConfig(Event):
    project: str


@dataclass(frozen=True, slots=True)
class ProcessingStarted(Event):
    vulns: int
    updates: int


@dataclass(frozen=True, slots=True)
class FindingsProcessed(Event):
    results: tuple[UpdateResult, ...]
    blocked: int


@dataclass(frozen=True, slots=True)
class Promoted(Event):
    """A workflow bookmark has been promoted to local main."""


@dataclass(frozen=True, slots=True)
class ResolvePaused(Event):
    project: str


@dataclass(frozen=True, slots=True)
class FindingsBlocked(Event):
    findings: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class BlockersStillFailing(Event):
    phase: str
    pkgs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SyncCompleted(Event):
    project: str
    action: str


@dataclass(frozen=True, slots=True)
class DeployStepSucceeded(Event):
    project: str
    step: DeployStep


@dataclass(frozen=True, slots=True)
class DeployStepFailed(Event):
    project: str
    step: DeployStep
    error: str


@dataclass(frozen=True, slots=True)
class HealthChecked(Event):
    project: str
    is_up: bool
    error: str | None


@dataclass(frozen=True, slots=True)
class HealthcheckUnconfigured(Event):
    pass


@dataclass(frozen=True, slots=True)
class FindingStarted(Event):
    """An update attempt has started for this package and version pair."""

    pkg: str
    installed: str
    target: str


@dataclass(frozen=True, slots=True)
class TestCommandStarted(Event):
    command: str


@dataclass(frozen=True, slots=True)
class FindingStepFailed(Event):
    step: FindingStepKind
    error: str


@dataclass(frozen=True, slots=True)
class FindingPassed(Event):
    pkg: str
    already_applied: bool
    installed: str
    target: str


@dataclass(frozen=True, slots=True)
class FindingFailed(Event):
    pkg: str
    phase: str
    installed: str
    target: str


type Emit = Callable[[Event], None]
