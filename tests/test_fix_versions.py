import pytest

from maintenance_man.fix_versions import is_known_fixed, select_package_fixes

_URLLIB3_LISTS = [
    "1.24.2",
    "2.0.7, 1.26.18",
    "1.26.19, 2.2.2",
    "2.8.0",
    "1.24.3",
    "1.25.9",
    "2.0.6, 1.26.17",
    "2.5.0",
    "2.6.0",
    "2.6.3",
    "2.7.0",
]


@pytest.mark.parametrize(
    ("manager", "installed", "listed", "expected"),
    [
        pytest.param("mvn", "2.13.0", ["2.13.4.2"], ["2.13.4.2"], id="single-fix"),
        pytest.param(
            "mvn", "2.13.0", ["2.12.7.1, 2.13.4.2"], ["2.13.4.2"], id="between"
        ),
        pytest.param("mvn", "2.14.0", ["2.12.7.1, 2.13.4.2"], [None], id="above-all"),
        pytest.param(
            "mvn", "2.12.0", ["2.12.7.1, 2.13.4.2"], ["2.12.7.1"], id="below-all"
        ),
        pytest.param("bun", "1.0.1", ["1.0.1"], [None], id="fix-equals-installed"),
        pytest.param(
            "mvn", "31.1-jre", ["32.0.0-android"], [None], id="qualifier-differs"
        ),
        pytest.param(
            "mvn",
            "4.1.94.Final",
            ["4.1.100.Final"],
            ["4.1.100.Final"],
            id="qualifier-matches",
        ),
        pytest.param(
            "mvn",
            "31.1-jre",
            ["32.0.0-android, 32.0.0-jre"],
            ["32.0.0-jre"],
            id="mixed-qualifiers",
        ),
        pytest.param("bun", "1.0", ["1.0.0"], [None], id="trailing-zero-equal"),
        pytest.param("bun", "1.0", ["1.0.1"], ["1.0.1"], id="trailing-zero-above"),
        pytest.param(
            "bun", "v1.0.0", ["1.0.1"], [None], id="installed-has-no-leading-integer"
        ),
        pytest.param(
            "bun", "1.0.0", ["latest"], [None], id="fix-has-no-leading-integer"
        ),
        pytest.param(
            "mvn", "1.0.0", ["", None], [None, None], id="empty-and-absent-lists"
        ),
        pytest.param("mvn", "1.0.0", [], [], id="no-advisories"),
        pytest.param(
            "mvn",
            "2.13.0",
            ["2.13.2.1", "2.13.4.2"],
            ["2.13.4.2", "2.13.4.2"],
            id="target-fixes-both",
        ),
        pytest.param(
            "mvn",
            "2.12.3",
            ["2.12.7.1, 2.13.4.2", "2.13.1"],
            [None, "2.13.1"],
            id="target-leaves-one-open",
        ),
        pytest.param(
            "mvn",
            "2.14.0",
            ["2.13.4.2", "2.15.0"],
            [None, "2.15.0"],
            id="one-without-own-fix",
        ),
        pytest.param(
            "uv", "1.24.1", _URLLIB3_LISTS, ["2.8.0"] * 11, id="urllib3-pep440"
        ),
        pytest.param("uv", "1.0.0", ["2.0.0rc1"], ["2.0.0rc1"], id="uv-pre-release"),
        pytest.param(
            "uv",
            "1.0",
            ["not-a-version, 1.5"],
            ["1.5"],
            id="uv-unparseable-token-beside-own-fix",
        ),
        pytest.param(
            "uv",
            "1.0",
            ["not-a-version, 1.5", "2.0"],
            [None, "2.0"],
            id="uv-unparseable-token-blocks-target",
        ),
        pytest.param("uv", "abc", ["1.0"], [None], id="uv-unparseable-installed"),
        pytest.param("uv", "1.0", ["1.0.post1"], ["1.0.post1"], id="uv-post-release"),
        pytest.param(
            "bun",
            "1.0",
            ["1.0.post1"],
            [None],
            id="bun-post-release-is-a-qualifier",
        ),
    ],
)
def test_given_fix_lists_when_package_fixes_selected_then_one_target_or_none(
    manager, installed, listed, expected
):
    assert select_package_fixes(installed, listed, manager) == expected


@pytest.mark.parametrize(
    ("version", "listed", "manager", "expected"),
    [
        pytest.param("2.0.0", "2.0.0", "gradle", True, id="equals-listed"),
        pytest.param("1.0", "1.0.0", "gradle", True, id="equal-ignoring-trailing-zero"),
        pytest.param("2.1.0", "1.0.3, 2.0.0", "gradle", True, id="above-every-listed"),
        pytest.param("1.5.0", "1.0.3, 2.0.0", "gradle", False, id="between-two-listed"),
        pytest.param("1.2.9", "1.2.3, 1.3.1", "mvn", False, id="reintroduced-range"),
        pytest.param(
            "32.0.0-jre",
            "32.0.0-android, 32.0.0-jre",
            "gradle",
            True,
            id="mixed-list-equal-entry",
        ),
        pytest.param(
            "33.0.0-jre",
            "32.0.0-android, 32.0.0-jre",
            "gradle",
            False,
            id="mixed-list-above",
        ),
        pytest.param(
            "2.0.0", "not-a-version, 1.0.0", "uv", False, id="incomparable-entry"
        ),
        pytest.param("2.0.0", "", "mvn", False, id="empty-list"),
        pytest.param("2.0.0", None, "mvn", False, id="no-list"),
        pytest.param("1.0.5", "2.0.0", "gradle", False, id="below-fix"),
        pytest.param(
            "latest", "latest", "bun", True, id="identical-unorderable-string"
        ),
    ],
)
def test_given_fix_list_when_version_checked_then_known_fixed_only_with_evidence(
    version, listed, manager, expected
):
    assert is_known_fixed(version, listed, manager) is expected
