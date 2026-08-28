from __future__ import annotations

import json

import pytest

from mac_audit_agent.anti_ransomware.cli import main
from mac_audit_agent.anti_ransomware.simulation_suite import (
    SIMULATION_CATALOG,
    export_simulation_report,
    run_simulation_suite,
)


def test_all_attack_scenarios_and_negative_controls_pass_without_host_actions() -> None:
    report = run_simulation_suite()

    assert len(SIMULATION_CATALOG) == 28
    assert report["scenario_count"] == 28
    assert report["attack_scenario_count"] == 24
    assert report["negative_control_count"] == 4
    assert report["caught_count"] == 24
    assert report["missed_count"] == 0
    assert report["control_passed_count"] == 4
    assert report["unexpected_escalation_count"] == 0
    assert report["passed_count"] == 28
    assert report["all_passed"] is True
    assert set(report["safety"].values()) == {False}
    assert report["external_malware_hash_or_yara_claim"] is False
    for result in report["results"]:
        observed = {item["signal_id"] for item in result["observed_signals"]}
        assert result["passed"] is True
        if result["expected_outcome"] == "CAUGHT":
            assert result["result"] == "CAUGHT"
            assert result["actual_score"] >= result["expected_minimum_score"]
        else:
            assert result["result"] == "CONTROL_PASS"
            assert result["actual_score"] <= result["expected_maximum_score"]
        assert set(result["required_signal_ids"]) <= observed
        assert result["missing_required_signals"] == []
        assert result["containment_performed"] is False


def test_selected_scenario_and_unknown_id_handling() -> None:
    report = run_simulation_suite({"AR-SIM-04"})
    assert report["scenario_count"] == 1
    assert report["results"][0]["simulation_id"] == "AR-SIM-04"
    assert {item["signal_id"] for item in report["results"][0]["observed_signals"]} >= {
        "protected_canary_modified", "high_entropy_transition",
    }
    with pytest.raises(ValueError, match="Unknown ransomware simulation IDs"):
        run_simulation_suite({"AR-SIM-99"})


def test_approved_maintenance_reduces_but_does_not_erase_correlated_signal() -> None:
    result = run_simulation_suite({"AR-SIM-15"})["results"][0]
    snapshot = next(item for item in result["observed_signals"] if item["signal_id"] == "snapshot_deletion_attempt")
    assert snapshot["weight"] == 20
    assert "approved maintenance lowers" in snapshot["rationale"]
    assert result["result"] == "CAUGHT"


def test_simulation_evidence_export_is_private(tmp_path) -> None:
    destination = export_simulation_report(run_simulation_suite(), tmp_path / "suite.json")
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["scenario_count"] == 28
    assert destination.stat().st_mode & 0o077 == 0


def test_cli_definition_suite_profile(capsys) -> None:
    assert main(["simulate", "--safe", "--no-file-destruction", "--profile", "definition-suite", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["all_passed"] is True
    assert payload["safety"]["filesystem_writes"] is False


@pytest.mark.parametrize("simulation_id", [f"AR-SIM-{number:02d}" for number in range(17, 25)])
def test_added_attack_demos_are_independently_caught(simulation_id: str) -> None:
    result = run_simulation_suite({simulation_id})["results"][0]
    assert result["result"] == "CAUGHT"
    assert result["passed"] is True


@pytest.mark.parametrize("simulation_id", [f"AR-CTRL-{number:02d}" for number in range(1, 5)])
def test_negative_controls_do_not_escalate(simulation_id: str) -> None:
    result = run_simulation_suite({simulation_id})["results"][0]
    assert result["result"] == "CONTROL_PASS"
    assert result["passed"] is True
