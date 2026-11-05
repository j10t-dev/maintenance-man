"""Regressions for evidence that must distinguish real promotion from fixture setup."""

import json
from pathlib import Path

import pytest

from tests.support import verification
from tests.support.findings import make_scan_result


def test_given_unpromoted_main_when_checking_update_then_proof_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    project = tmp_path / "state" / "project"
    project.mkdir(parents=True)
    scan = tmp_path / "state" / "mm" / "scan-results"
    scan.mkdir(parents=True)
    (scan / "fixture.json").write_text(make_scan_result(updates=[]).model_dump_json())
    current_manifest = '[project]\ndependencies = ["mm-proof-dep==1.0.1"]\n'
    (project / "pyproject.toml").write_text(current_manifest)
    (evidence / "before.json").write_text(json.dumps({"main": "initial"}))
    (evidence / "updated.json").write_text(
        json.dumps(
            {
                "main": "fixture-repair-requirement",
                "manifest": current_manifest,
                "main_manifest": '[project]\ndependencies = ["mm-proof-dep==1.0.0"]\n',
            }
        )
    )
    (evidence / "test-runs.jsonl").write_text('{"version": "1.0.1"}\n')
    monkeypatch.setattr(verification, "_revision", lambda *_: "initial")
    monkeypatch.setattr(verification, "_command", lambda *_, **__: "")

    with pytest.raises(AssertionError, match="Committed main"):
        verification._assert_updated(tmp_path)


@pytest.mark.parametrize("existing", ["before.json", "verdict.json"])
def test_given_consumed_run_when_driving_again_then_evidence_is_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: str
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    record = evidence / existing
    record.write_text('{"original": true}\n')

    def unexpected_action(*_args: object) -> None:
        pytest.fail("A consumed run must refuse before Doctor or Cleanup")

    monkeypatch.setattr(verification, "_doctor", unexpected_action)
    monkeypatch.setattr(verification, "_cleanup", unexpected_action)
    with pytest.raises(ValueError, match="already attempted"):
        verification._drive(tmp_path, "recovery")
    assert record.read_text() == '{"original": true}\n'
    assert list(evidence.iterdir()) == [record]
