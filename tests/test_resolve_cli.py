from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maintenance_man.cli import _ordered_resolve_candidates, app
from maintenance_man.models.scan import (
    MaintenanceFlow,
    ScanResult,
    SemverTier,
    Severity,
    UpdateFinding,
    UpdateStatus,
    VulnFinding,
)
from maintenance_man.updater import UpdateResult

pytestmark = pytest.mark.usefixtures("mock_resolve_cli_deps")

RESOLVE_BRANCH = "mm/resolve-dependencies"


class TestResolveCandidateSelection:
    def test_ordered_resolve_candidates_excludes_other_flows(self):
        scan_result = ScanResult(
            project="vulnerable",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="tests/fixtures/vulnerable-project",
            vulnerabilities=[
                VulnFinding(
                    vuln_id="CVE-2024-1000",
                    pkg_name="pkg-a",
                    installed_version="1.0.0",
                    fixed_version="1.0.1",
                    severity=Severity.HIGH,
                    title="Test vuln",
                    description="desc",
                    status="fixed",
                ),
                VulnFinding(
                    vuln_id="CVE-2024-1001",
                    pkg_name="pkg-b",
                    installed_version="1.0.0",
                    fixed_version="1.0.2",
                    severity=Severity.MEDIUM,
                    title="Test vuln",
                    description="desc",
                    status="fixed",
                    update_status=UpdateStatus.FAILED,
                    flow=MaintenanceFlow.RESOLVE,
                ),
            ],
            updates=[
                UpdateFinding(
                    pkg_name="pkg-c",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    semver_tier=SemverTier.PATCH,
                    update_status=UpdateStatus.FAILED,
                    flow=MaintenanceFlow.UPDATE,
                ),
                UpdateFinding(
                    pkg_name="pkg-d",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    semver_tier=SemverTier.PATCH,
                    update_status=UpdateStatus.READY,
                    flow=MaintenanceFlow.RESOLVE,
                ),
                UpdateFinding(
                    pkg_name="pkg-e",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    semver_tier=SemverTier.PATCH,
                ),
            ],
        )

        candidates = _ordered_resolve_candidates(scan_result)

        assert {f.pkg_name for f in candidates} == {"pkg-a", "pkg-b", "pkg-e"}


class TestResolveCommand:
    def test_resolve_aborts_on_update_owned_in_progress_findings(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result = ScanResult(
            project="vulnerable",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="tests/fixtures/vulnerable-project",
            vulnerabilities=[
                VulnFinding(
                    vuln_id="CVE-2024-9999",
                    pkg_name="some-pkg",
                    installed_version="1.0.0",
                    fixed_version="1.0.1",
                    severity=Severity.HIGH,
                    title="Test vuln",
                    description="desc",
                    status="fixed",
                    update_status=UpdateStatus.FAILED,
                    flow="update",
                )
            ],
        )
        mock_process = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        mock_process.assert_not_called()

    def test_resolve_aborts_when_in_progress_findings_lack_flow(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        scan_result = ScanResult(
            project="vulnerable",
            scanned_at=datetime.now(tz=timezone.utc),
            trivy_target="tests/fixtures/vulnerable-project",
            vulnerabilities=[
                VulnFinding(
                    vuln_id="CVE-2024-9998",
                    pkg_name="some-pkg",
                    installed_version="1.0.0",
                    fixed_version="1.0.1",
                    severity=Severity.HIGH,
                    title="Test vuln",
                    description="desc",
                    status="fixed",
                    update_status=UpdateStatus.READY,
                )
            ],
        )
        mock_process = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        mock_process.assert_not_called()

    def test_no_failed_findings_exits_0(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        make_failed_resolve_scan_result,
    ):
        scan_result = make_failed_resolve_scan_result()
        for finding in [*scan_result.vulnerabilities, *scan_result.updates]:
            finding.update_status = UpdateStatus.COMPLETED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert "Nothing to resolve." in capsys.readouterr().out

    def test_no_failed_findings_does_not_require_graphite(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        make_failed_resolve_scan_result,
    ):
        from maintenance_man.vcs import GraphiteNotFoundError

        scan_result = make_failed_resolve_scan_result()
        for finding in [*scan_result.vulnerabilities, *scan_result.updates]:
            finding.update_status = UpdateStatus.COMPLETED
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr(
            "maintenance_man.cli.check_graphite_available",
            MagicMock(side_effect=GraphiteNotFoundError("missing gt")),
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert "Nothing to resolve." in capsys.readouterr().out

    def test_missing_graphite_aborts_before_dirty_tree_prompt(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        from maintenance_man.vcs import GraphiteNotFoundError, RepoDirtyError

        mock_check_repo_clean = MagicMock(side_effect=RepoDirtyError("dirty"))
        mock_confirm = MagicMock(return_value=True)
        mock_reset = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.check_graphite_available",
            MagicMock(side_effect=GraphiteNotFoundError("missing gt")),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            mock_check_repo_clean,
        )
        monkeypatch.setattr("maintenance_man.cli.Confirm.ask", mock_confirm)
        monkeypatch.setattr("maintenance_man.cli.reset_to_main", mock_reset)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 1
        assert "missing gt" in capsys.readouterr().out
        mock_check_repo_clean.assert_not_called()
        mock_confirm.assert_not_called()
        mock_reset.assert_not_called()

    def test_resolve_requires_project_arg(
        self,
        capsys: pytest.CaptureFixture[str],
    ):
        with pytest.raises(SystemExit) as exc_info:
            app(["resolve"])

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert 'Command "resolve" parameter "--project" requires an argument.' in (
            captured.out + captured.err
        )

    def test_resolve_processes_only_failed(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_failed_resolve_scan_result,
        make_pass_side_effect,
    ):
        scan_result = make_failed_resolve_scan_result()
        mock_process = MagicMock(
            side_effect=make_pass_side_effect(flow="resolve")
        )
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        findings = mock_process.call_args.args[0]
        assert [f.pkg_name for f in findings] == ["some-pkg", "pkg-a"]

    def test_resolve_creates_single_resolve_branch(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_create = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.git_create_branch", mock_create)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert mock_create.call_args.args[0] == RESOLVE_BRANCH
        assert mock_create.call_args.args[1].name == "vulnerable-project"

    def test_resolve_stops_on_first_failure_and_preserves_changes(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ):
        mock_submit = MagicMock(return_value=(True, "submitted"))
        mock_delete = MagicMock(return_value=True)
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
            MagicMock(
                return_value=[
                    UpdateResult(
                        pkg_name="some-pkg",
                        kind="vuln",
                        passed=False,
                        failed_phase="unit",
                    )
                ]
            ),
        )
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)
        monkeypatch.setattr(
            "maintenance_man.cli.git_delete_branch", mock_delete, raising=False
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 4
        mock_submit.assert_not_called()
        mock_delete.assert_not_called()
        assert "mm resolve vulnerable --continue" in capsys.readouterr().out

    def test_resolve_submits_via_graphite(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_submit = MagicMock(return_value=(True, "submitted"))
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        mock_submit.assert_called_once()

    def test_resolve_submit_failure_preserves_branch_and_findings(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_failed_resolve_scan_result,
        make_pass_side_effect,
    ):
        scan_result = make_failed_resolve_scan_result()
        mock_remove = MagicMock()
        mock_save = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
            MagicMock(side_effect=make_pass_side_effect(flow="resolve")),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.submit_stack", MagicMock(return_value=(False, "nope"))
        )
        monkeypatch.setattr(
            "maintenance_man.cli.remove_completed_findings", mock_remove
        )
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", mock_save)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 4
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.READY
        assert scan_result.updates[0].update_status == UpdateStatus.READY
        assert scan_result.vulnerabilities[0].flow == "resolve"
        assert scan_result.updates[0].flow == "resolve"
        assert scan_result.vulnerabilities[1].update_status == UpdateStatus.COMPLETED
        assert scan_result.updates[1].update_status == UpdateStatus.COMPLETED
        mock_remove.assert_not_called()
        mock_save.assert_called_once()

    def test_resolve_marks_completed_on_submit(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_failed_resolve_scan_result,
        make_pass_side_effect,
    ):
        scan_result = make_failed_resolve_scan_result()
        mock_remove = MagicMock()
        mock_save = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr(
            "maintenance_man.cli.process_findings",
            MagicMock(side_effect=make_pass_side_effect(flow="resolve")),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.remove_completed_findings", mock_remove
        )
        monkeypatch.setattr("maintenance_man.cli.save_scan_results", mock_save)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.COMPLETED
        assert scan_result.updates[0].update_status == UpdateStatus.COMPLETED
        assert scan_result.vulnerabilities[0].flow is None
        assert scan_result.updates[0].flow is None
        mock_remove.assert_called_once_with(scan_result)
        mock_save.assert_called_once()

    def test_resolve_branch_collision_prompt_uses_replace_helper(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        mock_replace = MagicMock(return_value=True)
        monkeypatch.setattr("maintenance_man.cli.git_branch_exists", lambda b, p: True)
        monkeypatch.setattr("maintenance_man.cli.git_replace_branch", mock_replace)
        monkeypatch.setattr(
            "maintenance_man.cli.Prompt.ask", MagicMock(return_value="d")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable"])

        assert exc_info.value.code == 0
        mock_replace.assert_called_once()
        assert mock_replace.call_args.args[:2] == (RESOLVE_BRANCH, "main")


class TestResolveContinue:
    def test_resolve_continue_retests_current_finding(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_failed_resolve_scan_result,
        make_pass_side_effect,
    ):
        scan_result = make_failed_resolve_scan_result()
        mock_process = MagicMock(
            side_effect=make_pass_side_effect(flow="resolve")
        )
        mock_submit = MagicMock(return_value=(True, "submitted"))
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.COMPLETED
        remaining = mock_process.call_args.args[0]
        assert [f.pkg_name for f in remaining] == ["pkg-a"]
        mock_submit.assert_called_once()

    def test_resolve_continue_not_on_branch_errors(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr("maintenance_man.cli.get_current_branch", lambda p: "main")

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 1

    def test_resolve_continue_retries_apply_for_apply_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_failed_resolve_scan_result,
        make_pass_side_effect,
    ):
        scan_result = make_failed_resolve_scan_result()
        scan_result.vulnerabilities[0].failed_phase = "apply"

        mock_process = MagicMock(
            side_effect=make_pass_side_effect(flow="resolve")
        )
        mock_submit = MagicMock(return_value=(True, "submitted"))
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0
        assert [
            f.pkg_name for f in mock_process.call_args_list[0].args[0]
        ] == ["some-pkg"]
        assert [
            f.pkg_name for f in mock_process.call_args_list[1].args[0]
        ] == ["pkg-a"]
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.COMPLETED
        assert scan_result.vulnerabilities[0].failed_phase is None

    def test_resolve_continue_requires_committed_manual_fix(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_failed_resolve_scan_result,
    ):
        from maintenance_man.vcs import RepoDirtyError

        scan_result = make_failed_resolve_scan_result()
        scan_result.vulnerabilities[0].failed_phase = "unit"
        mock_check_repo_clean = MagicMock(side_effect=RepoDirtyError("dirty"))
        mock_process = MagicMock()
        mock_submit = MagicMock()
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr(
            "maintenance_man.cli.check_repo_clean",
            mock_check_repo_clean,
        )
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 1
        mock_check_repo_clean.assert_called_once()
        mock_process.assert_not_called()
        mock_submit.assert_not_called()

    def test_resolve_continue_retests_without_graphite_until_submit(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_failed_resolve_scan_result,
    ):
        from maintenance_man.vcs import GraphiteNotFoundError

        scan_result = make_failed_resolve_scan_result()
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr(
            "maintenance_man.cli.check_graphite_available",
            MagicMock(side_effect=GraphiteNotFoundError("missing gt")),
        )
        monkeypatch.setattr(
            "maintenance_man.cli.run_test_phases", lambda cfg, p: (False, "unit")
        )

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 4
        assert scan_result.vulnerabilities[0].update_status == UpdateStatus.FAILED
        assert scan_result.vulnerabilities[0].failed_phase == "unit"

    def test_resolve_continue_skips_apply_for_test_failure(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_failed_resolve_scan_result,
        make_pass_side_effect,
    ):
        """When a finding failed during tests (not apply), --continue must not
        call apply_update — the package change is already on disk."""
        scan_result = make_failed_resolve_scan_result()
        scan_result.vulnerabilities[0].failed_phase = "unit"

        mock_process = MagicMock(
            side_effect=make_pass_side_effect(flow="resolve")
        )
        mock_submit = MagicMock(return_value=(True, "submitted"))
        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.process_findings", mock_process)
        monkeypatch.setattr("maintenance_man.cli.submit_stack", mock_submit)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 0

    def test_resolve_continue_apply_ok_then_test_fail_updates_phase(
        self,
        mm_home_with_projects: Path,
        monkeypatch: pytest.MonkeyPatch,
        make_failed_resolve_scan_result,
    ):
        scan_result = make_failed_resolve_scan_result()
        scan_result.vulnerabilities[0].failed_phase = "apply"

        saved = {}

        def _process(findings, *_args, **_kwargs):
            finding = findings[0]
            finding.update_status = UpdateStatus.FAILED
            finding.failed_phase = "unit"
            finding.flow = "resolve"
            saved["scan_result"] = scan_result
            return [
                UpdateResult(
                    pkg_name=finding.pkg_name,
                    kind="vuln",
                    passed=False,
                    failed_phase="unit",
                )
            ]

        monkeypatch.setattr(
            "maintenance_man.cli.load_scan_results", lambda name, d: scan_result
        )
        monkeypatch.setattr("maintenance_man.cli.process_findings", _process)

        with pytest.raises(SystemExit) as exc_info:
            app(["resolve", "vulnerable", "--continue"])

        assert exc_info.value.code == 4
        assert scan_result.vulnerabilities[0].failed_phase == "unit"
        assert "scan_result" in saved
