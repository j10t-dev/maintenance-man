from datetime import UTC, datetime

import pytest

from maintenance_man.models.scan import (
    GradleMember,
    GradleUpdateTarget,
    ScanResult,
    SecretFinding,
    SemverTier,
    Severity,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
    Workflow,
    highest_fix_version,
    sort_vulns_by_severity,
)
from maintenance_man.outdated import classify_semver
from maintenance_man.storage import load_scan_results, save_scan_results
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
        ([], [], [], (False, False, False)),
        ([make_vuln()], [], [], (True, True, False)),
        ([make_vuln(fixed_version=None)], [], [], (True, False, False)),
        ([], [], [make_update()], (True, False, True)),
        (
            [],
            [
                SecretFinding(
                    file="a.env", rule_id="key", title="Key", severity=Severity.HIGH
                )
            ],
            [],
            (True, False, False),
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

    assert (
        result.has_findings,
        result.has_actionable_vulns,
        result.has_updates,
    ) == expected


@pytest.mark.parametrize("flow", [Workflow.UPDATE, Workflow.RESOLVE])
def test_scan_result_round_trips_ready_flow(mm_home, flow: Workflow):
    result = ScanResult(
        project="project-ready",
        scanned_at=datetime(2026, 1, 30, tzinfo=UTC),
        trivy_target="/tmp/project-ready",
        vulnerabilities=[
            VulnFinding(
                vuln_id="CVE-2026-00001",
                pkg_name="requests",
                installed_version="2.31.0",
                fixed_version="2.32.4",
                severity=Severity.HIGH,
                title="t",
                description="d",
                status="fixed",
                update_status=UpdateStatus.READY,
                flow=flow,
            )
        ],
        updates=[
            UpdateFinding(
                pkg_name="react",
                installed_version="18.2.0",
                latest_version="19.0.0",
                semver_tier=SemverTier.MAJOR,
                update_status=UpdateStatus.READY,
                flow=flow,
            )
        ],
    )

    save_scan_results("project-ready", result)

    assert load_scan_results("project-ready") == result


def test_historical_results_without_gradle_fields_still_load():
    payload = {
        "project": "legacy",
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "trivy_target": "/tmp/legacy",
        "vulnerabilities": [
            {
                "vuln_id": "CVE-2024-0001",
                "pkg_name": "some-pkg",
                "installed_version": "1.0.0",
                "fixed_version": "1.0.1",
                "severity": "HIGH",
                "title": "t",
                "description": "d",
                "status": "fixed",
            }
        ],
        "updates": [
            {
                "pkg_name": "pkg-a",
                "installed_version": "1.0.0",
                "latest_version": "1.0.1",
                "semver_tier": "patch",
            }
        ],
    }

    result = ScanResult.model_validate(payload)

    assert result.vulnerabilities[0].gradle_target is None
    assert result.vulnerabilities[0].blocked_reason is None
    assert result.vulnerabilities[0].gradle_block_kind is None
    assert result.vulnerabilities[0].actionable is True
    assert result.updates[0].gradle_target is None


def test_gradle_target_round_trips_through_scan_result_json():
    target = GradleUpdateTarget(
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
    )
    update = make_update(
        gradle_target=target,
        blocked_reason="no publication date",
        gradle_block_kind="age",
    )
    result = make_scan_result(vulns=[], updates=[update])

    reloaded = ScanResult.model_validate_json(result.model_dump_json())

    assert reloaded.updates[0].gradle_target == target
    assert (reloaded_target := reloaded.updates[0].gradle_target) is not None
    assert reloaded_target.group_key == "ref:room"
    assert reloaded_target.display_name == "room"
    assert reloaded.updates[0].blocked_reason == "no publication date"
    assert reloaded.updates[0].gradle_block_kind == "age"


def test_inline_target_display_name_is_its_coordinate():
    target = GradleUpdateTarget(
        members=[
            GradleMember(
                kind="library",
                alias="gson",
                coordinate="com.google.code.gson:gson",
                installed_version="2.11.0",
            )
        ],
        target_version="2.12.0",
    )

    assert target.group_key == "library:gson"
    assert target.display_name == "com.google.code.gson:gson"


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


def test_old_scan_does_not_require_gradle_resolution():
    from maintenance_man.models.scan import ScanResult

    result = ScanResult.model_validate(
        {
            "project": "demo",
            "scanned_at": "2030-01-01T00:00:00Z",
            "trivy_target": "/tmp/demo",
        }
    )
    assert result.gradle_resolution is None
