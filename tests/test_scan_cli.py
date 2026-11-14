import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from maintenance_man import cli, scanner
from maintenance_man.cli import ExitCode
from maintenance_man.gradle import GradleError
from maintenance_man.models.scan import (
    GradleBlock,
    ScanResult,
    SecretFinding,
    Severity,
    UpdateFinding,
    VulnFinding,
)
from tests.support.cli import run_mm, terminal_stdout
from tests.support.findings import (
    make_gradle_member,
    make_gradle_target,
    make_scan_result,
    make_update,
    make_vuln,
)
from tests.support.process import missing_tool
from tests.support.projects import write_config

_SECRET = SecretFinding(
    file="secrets.env",
    rule_id="generic-api-key",
    title="API Key",
    severity=Severity.HIGH,
)
_ADVISORY = {"fixed_version": None, "status": "affected"}


def _scan(
    vulns: list[VulnFinding] | None = None,
    updates: list[UpdateFinding] | None = None,
    secrets: list[SecretFinding] | None = None,
) -> ScanResult:
    return make_scan_result(vulns=vulns or [], updates=updates or [], secrets=secrets)


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        pytest.param(
            _scan(vulns=[make_vuln()]),
            ["vuln\tsome-pkg\t1.0.0\t1.0.1\tHIGH\tCVE-2024-0001\t-\tfixed\t-"],
            id="vulnerability",
        ),
        pytest.param(
            _scan(vulns=[make_vuln(**_ADVISORY)]),
            [
                "advisory\tsome-pkg\t1.0.0\t-\tHIGH\tCVE-2024-0001\t-\taffected\t-",
            ],
            id="advisory",
        ),
        pytest.param(
            _scan(
                vulns=[
                    make_vuln(
                        state=GradleBlock(
                            kind="mapping", reason="Cannot identify catalogue entry"
                        )
                    ),
                    make_vuln(
                        pkg_name="unfixed-pkg",
                        vuln_id="CVE-2024-0002",
                        state=GradleBlock(kind="mapping", reason="No published fix"),
                        **_ADVISORY,
                    ),
                ]
            ),
            [
                "vuln\tsome-pkg\t1.0.0\t1.0.1\tHIGH\tCVE-2024-0001\t-\tblocked\t"
                "Cannot identify catalogue entry",
                "advisory\tunfixed-pkg\t1.0.0\t-\tHIGH\tCVE-2024-0002\t-\tblocked\t"
                "No published fix",
            ],
            id="blocked-vulnerability-and-advisory",
        ),
        pytest.param(
            _scan(secrets=[_SECRET]),
            ["secret\tsecrets.env\t-\t-\tHIGH\tgeneric-api-key\t-\tfound\tAPI Key"],
            id="secret",
        ),
        pytest.param(
            _scan(
                updates=[
                    make_update(
                        pkg_name="ksp",
                        installed_version="2.3.10",
                        latest_version="2.3.12",
                        state=GradleBlock(kind="age", reason="no publication date"),
                    ),
                    make_update(),
                ]
            ),
            [
                "update\tksp\t2.3.10\t2.3.12\tpatch\t-\t-\tblocked\t"
                "no publication date",
                "update\tpkg-a\t1.0.0\t1.0.1\tpatch\t-\t-\tavailable\t-",
            ],
            id="blocked-and-available-updates",
        ),
        pytest.param(
            _scan(
                vulns=[
                    make_vuln(
                        vuln_id=vuln_id,
                        pkg_name="requests",
                        installed_version="2.25.0",
                        fixed_version=fixed,
                    )
                    for vuln_id, fixed in (("CVE-OLD", "2.31.0"), ("CVE-NEW", "2.32.4"))
                ]
            ),
            [
                "vuln\trequests\t2.25.0\t2.32.4\tHIGH\tCVE-NEW\t-\tfixed\tselected fix",
                "vuln\trequests\t2.25.0\t2.31.0\tHIGH\tCVE-OLD\t-\tfixed\t-",
            ],
            id="selected-fix-marks-the-highest-version",
        ),
        pytest.param(
            _scan(
                vulns=[
                    make_vuln(
                        vuln_id="CVE-LOW", pkg_name="low-pkg", severity=Severity.LOW
                    ),
                    make_vuln(
                        vuln_id="CVE-CRIT",
                        pkg_name="crit-pkg",
                        severity=Severity.CRITICAL,
                    ),
                    make_vuln(vuln_id="CVE-HIGH", pkg_name="high-pkg"),
                ]
            ),
            [
                "vuln\tcrit-pkg\t1.0.0\t1.0.1\tCRITICAL\tCVE-CRIT\t-\tfixed\t-",
                "vuln\thigh-pkg\t1.0.0\t1.0.1\tHIGH\tCVE-HIGH\t-\tfixed\t-",
                "vuln\tlow-pkg\t1.0.0\t1.0.1\tLOW\tCVE-LOW\t-\tfixed\t-",
            ],
            id="severity-order",
        ),
        pytest.param(
            _scan(
                vulns=[
                    make_vuln(
                        pkg_name="org.example:shared",
                        installed_version=version,
                        severity=Severity.UNKNOWN,
                        **_ADVISORY,
                    )
                    for version in ("1.0", "2.0")
                ]
            ),
            [
                "advisory\torg.example:shared\t1.0\t-\tUNKNOWN\tCVE-2024-0001\t-\t"
                "affected\t-",
                "advisory\torg.example:shared\t2.0\t-\tUNKNOWN\tCVE-2024-0001\t-\t"
                "affected\t-",
            ],
            id="gradle-installed-versions-stay-separate",
        ),
        pytest.param(
            _scan(vulns=[make_vuln(pkg_name="a[b]", vuln_id="CVE-[x]")]),
            ["vuln\ta[b]\t1.0.0\t1.0.1\tHIGH\tCVE-[x]\t-\tfixed\t-"],
            id="brackets-stay-literal",
        ),
    ],
)
def test_given_scan_result_when_piped_then_each_finding_is_one_whole_record(
    capsys: pytest.CaptureFixture[str], result: ScanResult, expected: list[str]
) -> None:
    cli._print_scan_result(result)

    assert capsys.readouterr().out.splitlines() == [
        f"vulnerable\t{record}" for record in expected
    ]


_MIXED_SCAN = _scan(
    vulns=[
        make_vuln(
            state=GradleBlock(kind="mapping", reason="Cannot identify catalogue entry")
        ),
        make_vuln(
            pkg_name="unfixed-pkg",
            vuln_id="CVE-2024-0002",
            state=GradleBlock(kind="mapping", reason="No published fix"),
            **_ADVISORY,
        ),
    ],
    updates=[
        make_update(
            pkg_name="org.x:[lib]",
            installed_version="unknown",
            latest_version="2.0",
            state=GradleBlock(kind="mapping", reason="cannot render [catalogue]"),
        ),
        make_update(),
    ],
)


def _unwrap_footer(lines: list[str]) -> list[str]:
    """Join a footer that the terminal wrapped, so wrap position is not pinned."""
    start = next(
        (i for i, line in enumerate(lines) if line.startswith("hidden:")), None
    )
    if start is None:
        return lines
    return [*lines[:start], " ".join(" ".join(lines[start:]).split())]


@pytest.mark.parametrize(
    ("width", "result", "expected"),
    [
        pytest.param(
            220,
            _MIXED_SCAN,
            [
                "vulnerable · 4 findings",
                "  kind       severity  versions       package / detail",
                "  ! blocked  high      1.0.0 → 1.0.1  some-pkg · CVE-2024-0001 · "
                "Cannot identify catalogue entry",
                "  ! blocked  high      no fix         unfixed-pkg · CVE-2024-0002 · "
                "No published fix",
                "  ! blocked  patch     unknown → 2.0  org.x:[lib] · "
                "cannot render [catalogue]",
                "  ~ update   patch     1.0.0 → 1.0.1  pkg-a",
            ],
            id="wide-shows-every-column-and-the-full-reason",
        ),
        pytest.param(
            80,
            _MIXED_SCAN,
            [
                "vulnerable · 4 findings",
                "  kind       severity  versions       package / detail",
                "  ! blocked  high      1.0.0 → 1.0.1  some-pkg · CVE-2024-0001 · "
                "Cannot identif…",
                "  ! blocked  high      no fix         unfixed-pkg · CVE-2024-0002 · "
                "No publishe…",
                "  ! blocked  patch     unknown → 2.0  org.x:[lib] · "
                "cannot render [catalogue]",
                "  ~ update   patch     1.0.0 → 1.0.1  pkg-a",
            ],
            id="eighty-columns-ends-long-detail-in-an-ellipsis",
        ),
        pytest.param(
            40,
            _MIXED_SCAN,
            [
                "vulnerable · 4 findings",
                "  kind       package / detail",
                "  ! blocked  some-pkg · CVE-2024-0001 ·…",
                "  ! blocked  unfixed-pkg · CVE-2024-000…",
                "  ! blocked  org.x:[lib] · cannot rende…",
                "  ~ update   pkg-a",
                "hidden: severity, versions · pipe for full records",
            ],
            id="narrow-hides-severity-and-versions-but-keeps-kind",
        ),
        pytest.param(
            120,
            _scan(
                vulns=[
                    make_vuln(
                        vuln_id="CVE-A",
                        pkg_name="org.example:shared",
                        installed_version="1.0",
                        severity=Severity.LOW,
                        **_ADVISORY,
                    ),
                    make_vuln(
                        vuln_id="CVE-B",
                        pkg_name="org.example:shared",
                        installed_version="1.0",
                        fixed_version="1.1",
                    ),
                ]
            ),
            [
                "vulnerable · 2 findings",
                "  kind        severity  versions   package / detail",
                "  ! vuln      high      1.0 → 1.1  org.example:shared · CVE-B",
                "  ! advisory  low       no fix     org.example:shared · CVE-A",
            ],
            id="fixed-vulnerability-and-advisory-kinds",
        ),
    ],
)
def test_given_scan_result_when_rendered_on_terminal_then_columns_follow_the_width(
    monkeypatch: pytest.MonkeyPatch,
    width: int,
    result: ScanResult,
    expected: list[str],
) -> None:
    stream = terminal_stdout(monkeypatch, width)

    cli._print_scan_result(result)

    assert _unwrap_footer(stream.getvalue().splitlines()) == expected


def test_numbered_findings_print_bracketed_values_literally(
    capsys: pytest.CaptureFixture[str],
) -> None:
    vuln = make_vuln(pkg_name="a[b]", vuln_id="CVE-[x]")
    update = make_update(pkg_name="u[p]")

    cli._print_numbered_findings([vuln], [update])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "a[b]" in captured.err
    assert "CVE-[x]" in captured.err
    assert "u[p]" in captured.err


def test_numbered_findings_name_the_gradle_target_that_owns_each_row(
    capsys: pytest.CaptureFixture[str],
) -> None:
    ksp = make_gradle_target(
        version_ref="ksp",
        members=[
            make_gradle_member(
                kind="plugin",
                alias="ksp",
                coordinate="com.google.devtools.ksp",
                installed_version="2.3.10",
            )
        ],
        target_version="2.3.12",
    )
    advisory = make_vuln(
        vuln_id="CVE-1",
        pkg_name="androidx.room:room-runtime",
        installed_version="2.8.4",
        fixed_version="2.8.5",
    )

    cli._print_numbered_findings(
        [
            advisory.model_copy(update={"gradle_target": make_gradle_target()}),
            advisory.model_copy(update={"gradle_target": ksp}),
        ],
        [make_update(pkg_name="room", gradle_target=make_gradle_target())],
    )

    unwrapped = " ".join(capsys.readouterr().err.split())
    rows = re.split(r" (?=\d+ [!~] )", unwrapped)
    assert rows == [
        "1 ! vuln high · CVE-1 2.8.4 → 2.8.5 androidx.room:room-runtime"
        " via room 2.8.4 → 2.8.5",
        "2 ! vuln high · CVE-1 2.8.4 → 2.8.5 androidx.room:room-runtime"
        " via ksp 2.3.10 → 2.3.12",
        "3 ~ update patch 1.0.0 → 1.0.1 room",
    ]


@pytest.fixture(autouse=True)
def _mock_trivy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent all CLI tests from calling real Trivy."""

    def _fake_scan(
        name: str,
        project_config: object,
        min_version_age_days: int = 7,
        **kwargs: object,
    ) -> ScanResult:
        match name:
            case "vulnerable":
                result = make_scan_result(updates=[])
            case "outdated":
                result = make_scan_result(vulns=[])
            case "deployable":
                result = make_scan_result()
            case _:
                result = make_scan_result(vulns=[], updates=[])
        result.project = name
        return result

    monkeypatch.setattr("maintenance_man.services.scan.scan_project", _fake_scan)


def _two_project_config(mm_home, tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    mm_home.mkdir(parents=True, exist_ok=True)
    write_config(
        mm_home,
        f'[projects.first]\npath = "{first}"\npackage_manager = "bun"\n'
        f'[projects.second]\npath = "{second}"\npackage_manager = "uv"\n'
        "scan_secrets = false\n",
    )
    results = mm_home / "scan-results"
    results.mkdir(exist_ok=True)
    (results / "first.json").write_bytes(b"previous first result")
    return results


def test_given_two_clean_projects_when_batch_scanned_then_one_notice_names_both(
    mm_home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _two_project_config(mm_home, tmp_path)
    monkeypatch.setattr(
        "maintenance_man.services.scan.scan_project",
        lambda name, project, days: ScanResult(
            project=name,
            package_manager=project.package_manager,
            scanned_at=datetime(2026, 1, 15, 12, tzinfo=UTC),
        ),
    )

    assert run_mm("scan") == ExitCode.OK

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines()[-1].startswith(
        "2 projects have no findings: first, second · scanned in "
    )


def test_batch_scan_without_trivy_scans_uv_and_exits_error(
    mm_home, tmp_path, monkeypatch
):
    results = _two_project_config(mm_home, tmp_path)
    (results / "first.json").unlink()
    monkeypatch.setattr(
        "maintenance_man.services.scan.scan_project", scanner.scan_project
    )
    monkeypatch.setattr("maintenance_man.scanner.require_tool", missing_tool("trivy"))
    monkeypatch.setattr("maintenance_man.scanner._run_uv_audit", lambda path: [])
    for name, (_, source) in scanner._OUTDATED.items():
        monkeypatch.setitem(scanner._OUTDATED, name, (lambda project: [], source))
    assert run_mm("scan") == ExitCode.ERROR
    assert not (results / "first.json").exists()
    assert (results / "second.json").is_file()


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (("scan", "vulnerable"), 2),
        (("scan", "clean"), 0),
        (("scan",), 2),
        (("scan", "outdated"), 3),
        (("scan", "deployable"), 2),
    ],
)
def test_given_saved_project_when_scanned_then_exit_code_reflects_findings(
    mm_home_with_projects: Path, argv: tuple[str, ...], expected: int
) -> None:
    assert run_mm(*argv) == expected


def test_gradle_scan_failure_in_all_project_scan_exits_error_after_others(
    mm_home_with_gradle, monkeypatch, capsys
):
    scanned: list[str] = []

    def _scan(name, proj_config, *, minimum_age_days, emit):
        scanned.append(name)
        if proj_config.package_manager == "gradle":
            msg = "boom"
            raise GradleError(msg)
        return make_scan_result(vulns=[], updates=[])

    monkeypatch.setattr("maintenance_man.services.scan.scan_one", _scan)

    assert run_mm("scan") == ExitCode.ERROR
    assert "clean" in scanned or len(scanned) > 1
    assert "boom" in capsys.readouterr().err


@pytest.mark.parametrize("scope", [("sample",), ()], ids=["single", "batch"])
@pytest.mark.parametrize("with_updates", [False, True])
@pytest.mark.parametrize("with_vulnerability", [False, True])
def test_scan_blocked_no_fix_vulnerability_exit(
    mm_home,
    tmp_path,
    monkeypatch,
    scope,
    with_updates,
    with_vulnerability,
):
    mm_home.mkdir(parents=True, exist_ok=True)
    write_config(
        mm_home,
        f'[projects.sample]\npath = "{tmp_path}"\npackage_manager = "bun"\n',
    )
    result = make_scan_result(
        vulns=[
            VulnFinding(
                vuln_id="CVE-no-fix",
                pkg_name="unmapped",
                installed_version="1",
                fixed_version=None,
                severity=Severity.HIGH,
                title="No fix",
                description="No published fix",
                status="affected",
                state=GradleBlock(kind="mapping", reason="no fixed version"),
            )
        ]
        if with_vulnerability
        else [],
        updates=[
            make_update(state=GradleBlock(kind="age", reason="no publication date"))
        ]
        if with_updates
        else [],
    )
    assert not result.has_actionable_vulns
    monkeypatch.setattr(
        "maintenance_man.services.scan.scan_project", lambda *args, **kwargs: result
    )
    expected = 3 if with_updates else 0
    assert run_mm("scan", *scope) == expected
