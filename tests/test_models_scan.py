import pytest
from pydantic import ValidationError

from maintenance_man.models.scan import (
    Failed,
    GradleBlock,
    GradleMember,
    GradleUpdateTarget,
    Ready,
    ScanResult,
    SecretFinding,
    SemverTier,
    Severity,
    VulnFinding,
    Workflow,
    highest_fix_version,
    sort_vulns_by_severity,
)
from maintenance_man.outdated import classify_semver
from tests.support.findings import (
    make_gradle_target,
    make_scan_result,
    make_update,
    make_vuln,
)


@pytest.mark.parametrize(
    ("installed", "latest", "expected"),
    [
        ("1.2.3", "1.2.4", SemverTier.PATCH),
        ("1.2.3", "1.3.0", SemverTier.MINOR),
        ("1.2.3", "2.0.0", SemverTier.MAJOR),
        ("1.2.3", "2.1.0", SemverTier.MAJOR),
        ("1.2.3", "1.2.3", SemverTier.UNKNOWN),
        ("abc", "def", SemverTier.UNKNOWN),
        ("1.2", "1.3", SemverTier.MINOR),
        ("1.2.3.4", "1.2.4.0", SemverTier.PATCH),
    ],
)
def test_given_versions_when_classified_then_semver_tier_is_returned(
    installed, latest, expected
):
    assert classify_semver(installed, latest) == expected


@pytest.mark.parametrize(
    ("vulns", "expected"),
    [
        (
            [
                make_vuln(vuln_id="a", pkg_name="a", severity=Severity.UNKNOWN),
                make_vuln(vuln_id="b", pkg_name="b", severity=Severity.LOW),
                make_vuln(vuln_id="c", pkg_name="c", severity=Severity.CRITICAL),
                make_vuln(vuln_id="d", pkg_name="d", severity=Severity.HIGH),
                make_vuln(vuln_id="e", pkg_name="e", severity=Severity.MEDIUM),
            ],
            ["c", "d", "e", "b", "a"],
        ),
        (
            [
                make_vuln(vuln_id="CVE-LOW", fixed_version="2.31.0"),
                make_vuln(vuln_id="CVE-HIGH", fixed_version="2.32.4"),
                make_vuln(vuln_id="CVE-MID", fixed_version="2.32.0"),
            ],
            ["CVE-HIGH", "CVE-MID", "CVE-LOW"],
        ),
        (
            [
                make_vuln(vuln_id="flask-high", pkg_name="flask"),
                make_vuln(
                    vuln_id="requests-crit",
                    pkg_name="requests",
                    severity=Severity.CRITICAL,
                ),
                make_vuln(
                    vuln_id="requests-med",
                    pkg_name="requests",
                    severity=Severity.MEDIUM,
                ),
            ],
            ["requests-crit", "requests-med", "flask-high"],
        ),
        ([make_vuln(vuln_id="only")], ["only"]),
        ([], []),
    ],
    ids=["severity-order", "fix-version-descending", "package-groups", "one", "empty"],
)
def test_given_vulnerabilities_when_sorted_then_severity_groups_then_fix_descending(
    vulns, expected
):
    assert [v.vuln_id for v in sort_vulns_by_severity(vulns)] == expected


@pytest.mark.parametrize(
    "versions, expected",
    [
        (["2.0.0", "10.0.0", "1.5"], "10.0.0"),
        (["1.0", "bad", "2.0"], "2.0"),
        (["bad-first", "bad-last"], "bad-first"),
        ([None, "bad"], "bad"),
        ([None], ""),
        (["2.31.0", "2.32.4", "2.32.0"], "2.32.4"),
        (["1.0.1"], "1.0.1"),
        (["not-a-version", "2.0.0"], "2.0.0"),
        (["2.0.0", "not-a-version"], "2.0.0"),
    ],
)
def test_highest_fix_version(versions, expected):
    vulns = [make_vuln(fixed_version=v) for v in versions]
    assert highest_fix_version(vulns) == expected


def test_findings_lists_vulnerabilities_then_updates():
    vuln = make_vuln(pkg_name="v")
    update = make_update(pkg_name="u")
    result = make_scan_result(vulns=[vuln], updates=[update])
    assert result.findings == (vuln, update)


@pytest.mark.parametrize(
    ("vulns", "secrets", "updates", "expected"),
    [
        ([], [], [], (False, False)),
        ([make_vuln()], [], [], (True, True)),
        ([make_vuln(fixed_version=None)], [], [], (True, False)),
        ([], [], [make_update()], (True, False)),
        (
            [],
            [
                SecretFinding(
                    file="a.env", rule_id="key", title="Key", severity=Severity.HIGH
                )
            ],
            [],
            (True, False),
        ),
    ],
    ids=["clean", "fixed-vulnerability", "no-fix-vulnerability", "update", "secret"],
)
def test_given_findings_when_summarised_then_scan_flags_match(
    vulns, secrets, updates, expected
):
    result = make_scan_result(vulns=vulns, updates=updates).model_copy(
        update={"secrets": secrets}
    )

    assert (result.has_findings, result.has_actionable_vulns) == expected


@pytest.mark.parametrize(
    ("target", "group_key", "display_name"),
    [
        pytest.param(
            GradleUpdateTarget(
                version_ref="room",
                members=[
                    GradleMember(
                        kind="library",
                        alias="room-runtime",
                        coordinate="androidx.room:room-runtime",
                        installed_version="2.8.4",
                    ),
                    GradleMember(
                        kind="plugin",
                        alias="ksp",
                        coordinate="com.google.devtools.ksp",
                        installed_version="2.3.10",
                    ),
                ],
                target_version="2.8.5",
            ),
            "ref:room",
            "room",
            id="ref",
        ),
        pytest.param(
            GradleUpdateTarget(
                members=[
                    GradleMember(
                        kind="library",
                        alias="gson",
                        coordinate="com.google.code.gson:gson",
                        installed_version="2.11.0",
                    )
                ],
                target_version="2.12.0",
            ),
            "library:gson",
            "com.google.code.gson:gson",
            id="inline",
        ),
    ],
)
def test_given_saved_gradle_target_when_reloaded_then_group_key_and_display_name_match(
    target, group_key, display_name
):
    update = make_update(gradle_target=target)
    result = make_scan_result(vulns=[], updates=[update])

    reloaded = ScanResult.model_validate_json(result.model_dump_json())

    assert reloaded.updates[0].gradle_target == target
    assert (target.group_key, target.display_name) == (group_key, display_name)


@pytest.mark.parametrize(
    ("fixed_version", "gradle_target", "expected"),
    [
        ("1.0.1", None, "1.0.1"),
        (None, make_gradle_target(), "2.8.5"),
    ],
)
def test_given_vulnerability_when_target_version_read_then_fix_or_saved_target_is_used(
    fixed_version, gradle_target, expected
):
    finding = make_vuln(fixed_version=fixed_version, gradle_target=gradle_target)

    assert finding.target_version == expected


def test_given_vulnerability_without_fix_or_target_when_read_then_error():
    with pytest.raises(ValueError, match="No fixed version available"):
        _ = make_vuln(fixed_version=None).target_version


@pytest.mark.parametrize(
    ("state", "payload"),
    [
        pytest.param(None, None, id="pending"),
        pytest.param(
            Ready(flow=Workflow.UPDATE),
            {"lifecycle": "ready", "flow": "update"},
            id="ready",
        ),
        pytest.param(
            Failed(flow=Workflow.RESOLVE, phase="unit"),
            {"lifecycle": "failed", "flow": "resolve", "phase": "unit"},
            id="failed",
        ),
        pytest.param(
            GradleBlock(kind="stale", reason="catalogue changed"),
            {"lifecycle": "blocked", "kind": "stale", "reason": "catalogue changed"},
            id="blocked",
        ),
    ],
)
def test_given_lifecycle_state_when_saved_then_it_round_trips(state, payload):
    finding = make_vuln(state=state)

    dumped = finding.model_dump(mode="json")

    assert dumped["state"] == payload
    assert VulnFinding.model_validate(dumped) == finding


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        pytest.param(
            {
                "update_status": None,
                "failed_phase": None,
                "flow": None,
                "blocked_reason": None,
                "gradle_block_kind": None,
            },
            "update_status",
            id="old-fields",
        ),
        pytest.param(
            {"state": {"lifecycle": "ready"}}, "flow", id="ready-without-flow"
        ),
        pytest.param(
            {"state": {"lifecycle": "paused"}}, "lifecycle", id="unknown-lifecycle"
        ),
        pytest.param({"unexpected": 1}, "unexpected", id="unknown-field"),
    ],
)
def test_given_invalid_lifecycle_payload_when_validated_then_it_is_refused(
    overrides, message
):
    payload = make_vuln().model_dump(mode="json") | overrides

    with pytest.raises(ValidationError, match=message):
        VulnFinding.model_validate(payload)


def test_given_unknown_top_level_key_when_scan_validated_then_it_is_refused():
    payload = make_scan_result().model_dump(mode="json") | {"unexpected": 1}

    with pytest.raises(ValidationError, match="unexpected"):
        ScanResult.model_validate(payload)
