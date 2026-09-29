from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from maintenance_man.models.scan import ScanResult


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


class Operation(StrEnum):
    UPDATE_SETUP = "update_setup"
    PROMOTE = "promote"
    REFRESH = "refresh"
    WORKSPACE_CLEANUP = "workspace_cleanup"
    BOOKMARK_CLEANUP = "bookmark_cleanup"
    RESOLVE_SETUP = "resolve_setup"
    SUBMIT = "submit"
    REMOTE_SYNC = "remote_sync"
    SCAN = "scan"
    SYNC = "sync"


class DeployStep(StrEnum):
    BUILD = "build"
    DEPLOY = "deploy"
    HEALTH = "health"


@dataclass(frozen=True, slots=True)
class ProjectStarted:
    project: str


@dataclass(frozen=True, slots=True)
class ProjectSkipped:
    project: str
    reason: SkipReason
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class OperationFailed:
    operation: Operation
    project: str
    error: str


@dataclass(frozen=True, slots=True)
class ScanReported:
    result: ScanResult
    elapsed_s: float | None = None


@dataclass(frozen=True, slots=True)
class SyncCompleted:
    project: str
    action: str


@dataclass(frozen=True, slots=True)
class DeployStepStarted:
    project: str
    step: DeployStep


@dataclass(frozen=True, slots=True)
class DeployStepSucceeded:
    project: str
    step: DeployStep


@dataclass(frozen=True, slots=True)
class DeployStepFailed:
    project: str
    step: DeployStep
    error: str


@dataclass(frozen=True, slots=True)
class HealthChecked:
    project: str
    is_up: bool
    error: str | None


@dataclass(frozen=True, slots=True)
class HealthcheckUnconfigured:
    pass


type Event = (
    ProjectStarted
    | ProjectSkipped
    | OperationFailed
    | ScanReported
    | SyncCompleted
    | DeployStepStarted
    | DeployStepSucceeded
    | DeployStepFailed
    | HealthChecked
    | HealthcheckUnconfigured
)
type Emit = Callable[[Event], None]
