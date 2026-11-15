import re
from collections.abc import Sequence
from typing import NamedTuple

from packaging.version import InvalidVersion, Version

from maintenance_man.models.config import PackageManager


def select_package_fixes(
    installed: str, listed_fixes: Sequence[str | None], manager: PackageManager
) -> list[str | None]:
    """The fix each advisory of one package installed at *installed* is saved with.

    Entries follow *listed_fixes*. An advisory's own fix is the lowest listed
    version comparable with and above *installed*; the target is the highest own
    fix. An entry is the target when the advisory has an own fix and the target
    is known to fix it, else None.
    """
    own = [_own_fix(installed, listed, manager) for listed in listed_fixes]
    target = _highest([fix for fix in own if fix is not None], manager)
    return [
        target
        if fix is not None
        and target is not None
        and is_known_fixed(target, listed, manager)
        else None
        for fix, listed in zip(own, listed_fixes, strict=True)
    ]


def is_known_fixed(version: str, listed: str | None, manager: PackageManager) -> bool:
    """Whether *version* equals a version in *listed*, or *listed* names at least
    one version and *version* is comparable with and at or above each."""
    tokens = _tokens(listed)
    orders = [_compare(version, token, manager) for token in tokens]
    if version in tokens or 0 in orders:
        return True
    return bool(orders) and all(order is not None and order >= 0 for order in orders)


def _tokens(listed: str | None) -> list[str]:
    if listed is None:
        return []
    return [token.strip() for token in listed.split(",") if token.strip()]


def _own_fix(installed: str, listed: str | None, manager: PackageManager) -> str | None:
    lowest: str | None = None
    for token in _tokens(listed):
        if _compare(token, installed, manager) != 1:
            continue
        if lowest is None or _compare(token, lowest, manager) == -1:
            lowest = token
    return lowest


def _highest(versions: list[str], manager: PackageManager) -> str | None:
    highest: str | None = None
    for version in versions:
        if highest is None or _compare(version, highest, manager) == 1:
            highest = version
    return highest


def _compare(left: str, right: str, manager: PackageManager) -> int | None:
    if manager == "uv":
        return _compare_pep440(left, right)
    return _compare_numeric(left, right)


def _compare_pep440(left: str, right: str) -> int | None:
    try:
        left_version, right_version = Version(left), Version(right)
    except InvalidVersion:
        return None
    return (left_version > right_version) - (left_version < right_version)


def _compare_numeric(left: str, right: str) -> int | None:
    left_parts, right_parts = _numeric_parts(left), _numeric_parts(right)
    if left_parts is None or right_parts is None:
        return None
    if left_parts.qualifier != right_parts.qualifier:
        return None
    left_numbers, right_numbers = left_parts.numbers, right_parts.numbers
    return (left_numbers > right_numbers) - (left_numbers < right_numbers)


def _numeric_parts(version: str) -> _NumericParts | None:
    match = _NUMERIC_PREFIX_RE.match(version)
    if match is None:
        return None
    numbers = [int(part) for part in match.group().split(".")]
    while numbers and numbers[-1] == 0:
        numbers.pop()
    return _NumericParts(tuple(numbers), version[match.end() :])


class _NumericParts(NamedTuple):
    """The leading dotted integers without trailing zeros, and the rest."""

    numbers: tuple[int, ...]
    qualifier: str


_NUMERIC_PREFIX_RE = re.compile(r"\d+(?:\.\d+)*")
