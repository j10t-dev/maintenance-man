from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    ERROR = 1
    VULNS_FOUND = 2
    UPDATES_FOUND = 3
    UPDATE_FAILED = 4
    TEST_FAILED = 5
    BUILD_FAILED = 6
    DEPLOY_FAILED = 7
    SYNC_FAILED = 8


class UpdateSetupError(Exception):
    """An update workspace could not be prepared safely."""
