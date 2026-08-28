from __future__ import annotations

import json
import sqlite3

import pytest

from mac_audit_agent.continuous_security_assurance import ContinuousSecurityAssuranceEngine, SecurityAssuranceRepository
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json


def healthy_evidence() -> dict:
    return {
        "identity_accounts_authorized": True, "authentication_anomalies": 0, "ssh_identity_changes": 0,
        "unapproved_applications": 0, "unsigned_applications": 0, "modified_trusted_applications": 0, "known_vulnerabilities": 0,
        "firewall_enabled": True, "filevault_enabled": True, "sip_enabled": True,
        "gatekeeper_enabled": True, "privacy_controls_compliant": True,
        "suspicious_persistence": 0, "ransomware_indicators": 0, "suspicious_network_activity": 0,
        "backup_healthy": True, "evidence_collection_ready": True, "response_workflow_ready": True,
        "evidence_references": {"firewall_enabled": ["event:firewall-1"]},
    }


def evaluate(engine: ContinuousSecurityAssuranceEngine, evidence: dict, timestamp: str, previous=None):
    return engine.evaluate(evidence, device_id="device-1", hostname="mac.test", timestamp=timestamp, previous=previous)


def test_complete_healthy_evidence_has_explainable_full_posture() -> None:
    snapshot, changes = evaluate(ContinuousSecurityAssuranceEngine(), healthy_evidence(), "2026-07-17T10:00:00Z")
    assert snapshot.security_score == 100
    assert snapshot.evidence_coverage_percent == 100
    assert snapshot.trust_decision == "VERIFIED TRUST"
    assert snapshot.integrity_hash and len(snapshot.integrity_hash) == 64
    assert any("weighted domain scores" in line for line in snapshot.score_explanation)
    assert changes == []


def test_missing_evidence_is_unknown_not_healthy_or_regression() -> None:
    engine = ContinuousSecurityAssuranceEngine()
    baseline, _ = evaluate(engine, healthy_evidence(), "2026-07-17T10:00:00Z")
    current, changes = evaluate(engine, {}, "2026-07-17T10:01:00Z", baseline)
    assert current.security_score == 0
    assert current.evidence_coverage_percent == 0
    assert current.trust_decision == "INSUFFICIENT EVIDENCE"
    assert changes == []


def test_security_control_regression_preserves_evidence_and_score_reason() -> None:
    engine = ContinuousSecurityAssuranceEngine()
    baseline, _ = evaluate(engine, healthy_evidence(), "2026-07-17T10:00:00Z")
    current_evidence = healthy_evidence()
    current_evidence["firewall_enabled"] = {"value": False, "evidence_reference": ["event:firewall-disabled"]}
    current, changes = evaluate(engine, current_evidence, "2026-07-17T10:01:00Z", baseline)
    regression = next(item for item in changes if item.affected_component == "Firewall enabled")
    assert regression.change_type == "regression"
    assert regression.risk_score_change < 0
    assert regression.evidence_reference == ("event:firewall-disabled",)
    assert "T1562.004" in regression.mitre_mapping
    assert current.security_score < baseline.security_score


def test_improvement_is_not_emitted_as_security_alert() -> None:
    engine = ContinuousSecurityAssuranceEngine()
    weak = healthy_evidence(); weak["known_vulnerabilities"] = 2
    baseline, _ = evaluate(engine, weak, "2026-07-17T10:00:00Z")
    _, changes = evaluate(engine, healthy_evidence(), "2026-07-17T10:01:00Z", baseline)
    improvement = next(item for item in changes if item.affected_component == "Applicable known vulnerabilities")
    assert improvement.change_type == "improvement"
    assert improvement.risk_score_change > 0
    assert engine.alert_payloads(changes) == []


def test_cross_module_pattern_is_correlated_and_qualified() -> None:
    engine = ContinuousSecurityAssuranceEngine()
    baseline, _ = evaluate(engine, healthy_evidence(), "2026-07-17T10:00:00Z")
    attacked = healthy_evidence()
    attacked.update({
        "unsigned_applications": {"value": 1, "evidence_reference": ["app:hash-1"]},
        "suspicious_persistence": {"value": 1, "evidence_reference": ["plist:agent-1"]},
        "suspicious_network_activity": {"value": 1, "evidence_reference": ["connection:1"]},
    })
    snapshot, changes = evaluate(engine, attacked, "2026-07-17T10:01:00Z", baseline)
    correlated = next(item for item in changes if item.change_type == "correlated_regression")
    assert correlated.severity == "critical"
    assert len(correlated.correlated_change_ids) == 3
    assert "not proof of compromise" in correlated.description
    dashboard = engine.dashboard(snapshot, changes, [baseline])
    assert dashboard["security_regressions"]
    assert dashboard["risk_trend"][0]["score"] == 100


def test_repository_persists_history_and_changes_atomically(tmp_path) -> None:
    engine = ContinuousSecurityAssuranceEngine()
    baseline, _ = evaluate(engine, healthy_evidence(), "2026-07-17T10:00:00Z")
    degraded = healthy_evidence(); degraded["filevault_enabled"] = False
    current, changes = evaluate(engine, degraded, "2026-07-17T10:01:00Z", baseline)
    repository = SecurityAssuranceRepository(tmp_path / "audit.sqlite3")
    repository.save(baseline, [])
    repository.save(current, changes)
    assert repository.latest("device-1").snapshot_id == current.snapshot_id
    assert len(repository.history("device-1")) == 2
    assert repository.changes()[0]["affected_component"] == "FileVault enabled"
    with pytest.raises(sqlite3.IntegrityError):
        repository.save(current, changes)
    assert len(repository.history("device-1")) == 2
    repository.close()


def test_application_hash_change_is_a_critical_software_regression() -> None:
    engine = ContinuousSecurityAssuranceEngine()
    baseline, _ = evaluate(engine, healthy_evidence(), "2026-07-17T10:00:00Z")
    changed = healthy_evidence()
    changed["modified_trusted_applications"] = {"value": 1, "evidence_reference": ["hash:old", "hash:new"]}
    _, changes = evaluate(engine, changed, "2026-07-17T10:01:00Z", baseline)
    event = next(item for item in changes if item.affected_component == "Modified trusted applications")
    assert event.severity == "critical"
    assert event.evidence_reference == ("hash:old", "hash:new")


def test_approved_application_inventory_change_is_not_a_regression() -> None:
    engine = ContinuousSecurityAssuranceEngine()
    baseline, _ = evaluate(engine, healthy_evidence(), "2026-07-17T10:00:00Z")
    approved_install = healthy_evidence()
    approved_install["unapproved_applications"] = 0
    _, changes = evaluate(engine, approved_install, "2026-07-17T10:01:00Z", baseline)
    assert not any(item.affected_component == "Unapproved applications" for item in changes)


def test_unapproved_application_installation_is_detected() -> None:
    engine = ContinuousSecurityAssuranceEngine()
    baseline, _ = evaluate(engine, healthy_evidence(), "2026-07-17T10:00:00Z")
    installed = healthy_evidence()
    installed["unapproved_applications"] = {"value": 1, "evidence_reference": ["inventory:app-1"]}
    _, changes = evaluate(engine, installed, "2026-07-17T10:01:00Z", baseline)
    change = next(item for item in changes if item.affected_component == "Unapproved applications")
    assert change.change_type == "regression"
    assert change.evidence_reference == ("inventory:app-1",)


def test_repository_detects_snapshot_payload_tampering(tmp_path) -> None:
    engine = ContinuousSecurityAssuranceEngine()
    snapshot, _ = evaluate(engine, healthy_evidence(), "2026-07-17T10:00:00Z")
    repository = SecurityAssuranceRepository(tmp_path / "tamper.sqlite3")
    repository.save(snapshot, [])
    payload = repository.conn.execute("SELECT payload_json FROM security_posture_history").fetchone()[0]
    repository.conn.execute("UPDATE security_posture_history SET payload_json=?", (payload.replace('"security_score":100', '"security_score":1'),))
    repository.conn.commit()
    with pytest.raises(ValueError, match="integrity verification failed"):
        repository.latest("device-1")
    repository.close()


def test_scan_reports_expose_continuous_assurance_without_claiming_certification(tmp_path) -> None:
    engine = ContinuousSecurityAssuranceEngine()
    snapshot, changes = evaluate(engine, healthy_evidence(), "2026-07-17T10:00:00Z")
    assurance = {"snapshot": snapshot.to_dict(), "changes": [item.to_dict() for item in changes]}
    scan = ScanResult("scan-csae", snapshot.timestamp, "mac.test", "analyst", collected_artifacts={"continuous_security_assurance": assurance})
    json_path = export_scan_result_json(scan, tmp_path / "csae.json")
    html_path = export_scan_result_html(scan, tmp_path / "csae.html")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["continuous_security_assurance"]["snapshot"]["security_score"] == 100
    assert payload["report_summary"]["continuous_security_assurance"]["snapshot"]["trust_decision"] == "VERIFIED TRUST"
    html = html_path.read_text(encoding="utf-8")
    assert "Continuous Security Assurance" in html
    assert "not certification" in html
