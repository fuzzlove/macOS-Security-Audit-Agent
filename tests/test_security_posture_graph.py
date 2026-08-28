from __future__ import annotations

import json

import pytest

from mac_audit_agent.security_posture_graph import SecurityPostureGraphEngine, SecurityPostureGraphRepository
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json


def entity(entity_type: str, entity_id: str, **attributes):
    return {"entity_type": entity_type, "entity_id": entity_id, "name": entity_id, "attributes": attributes}


def event(event_id: str, timestamp: str, source: str, event_type: str, severity: str, entities: list[dict], mitre: list[str], evidence_ref: str):
    return {"event_id": event_id, "timestamp": timestamp, "source_module": source, "event_type": event_type, "severity": severity, "entities": entities, "mitre_mapping": mitre, "evidence_reference": [evidence_ref]}


def correlated_events() -> list[dict]:
    device = entity("device", "device-1", trust_state="conditional")
    application = entity("application", "com.example.unknown", signature="unsigned", trust_score=35)
    process = entity("process", "pid-4242", path="/private/tmp/tool", signature="unsigned")
    return [
        event("app-1", "2026-07-17T10:00:00Z", "supply_chain_security", "application_installed", "medium", [device, application], ["T1195"], "inventory:app-1"),
        event("persist-1", "2026-07-17T10:07:00Z", "persistence_hunting", "launchagent_created", "high", [device, application, process], ["T1543.001"], "plist:agent-1"),
        event("network-1", "2026-07-17T10:12:00Z", "network_monitor", "outbound_connection", "high", [device, process, entity("network_endpoint", "203.0.113.7:443", reputation="unknown")], ["T1105"], "connection:event-1"),
        event("identity-1", "2026-07-17T10:15:00Z", "identity_attack", "keychain_access", "critical", [device, process, entity("user", "analyst", privileges="standard")], ["T1555.001"], "identity:event-1"),
    ]


def test_application_persistence_network_and_identity_form_qualified_path() -> None:
    graph = SecurityPostureGraphEngine().build(correlated_events(), context={"security_score": 88})
    assert graph.risk_paths
    path = max(graph.risk_paths, key=lambda item: len(item.event_ids))
    assert path.event_ids == ("app-1", "persist-1", "network-1", "identity-1")
    assert path.confidence == "high" and path.risk_level == "critical"
    assert {"T1195", "T1543.001", "T1105", "T1555.001"}.issubset(path.mitre_mapping)
    assert "not proof of compromise" in graph.qualification
    assert graph.posture_score_after < graph.posture_score_before
    assert SecurityPostureGraphEngine.verify_integrity(graph)


def test_temporal_edges_explain_shared_identity_and_delta() -> None:
    graph = SecurityPostureGraphEngine().build(correlated_events())
    temporal = [item for item in graph.relationships if item.relationship_type == "precedes"]
    assert temporal
    assert any("420 seconds apart" in item.explanation for item in temporal)
    assert all(item.observed is False and item.evidence_reference for item in temporal)


def test_unrelated_events_do_not_create_false_attack_path() -> None:
    first = event("one", "2026-07-17T10:00:00Z", "persistence_hunting", "launchagent_created", "high", [entity("application", "app.one")], ["T1543.001"], "evidence:1")
    second = event("two", "2026-07-17T10:01:00Z", "network_monitor", "outbound_connection", "high", [entity("process", "pid-2")], ["T1105"], "evidence:2")
    third = event("three", "2026-07-17T10:02:00Z", "identity_attack", "keychain_access", "critical", [entity("user", "user-3")], ["T1555.001"], "evidence:3")
    graph = SecurityPostureGraphEngine().build([first, second, third], context={"security_score": 70})
    assert graph.risk_paths == ()
    assert graph.posture_score_after == 70
    assert "did not change" in graph.score_explanation[0]


def test_events_outside_temporal_window_do_not_form_path() -> None:
    events = correlated_events()
    events[1]["timestamp"] = "2026-07-17T12:00:00Z"
    events[2]["timestamp"] = "2026-07-17T14:00:00Z"
    events[3]["timestamp"] = "2026-07-17T16:00:00Z"
    assert SecurityPostureGraphEngine(temporal_window_seconds=1800).build(events).risk_paths == ()


def test_missing_timestamp_source_or_evidence_is_rejected_not_inferred() -> None:
    good = correlated_events()[0]
    bad = [dict(good, event_id="no-evidence", evidence_reference=[]), dict(good, event_id="no-source", source_module=""), dict(good, event_id="no-time", timestamp="invalid")]
    graph = SecurityPostureGraphEngine().build(bad)
    assert graph.events == () and graph.evidence_graph.nodes == []


def test_vulnerability_relationship_requires_explicit_evidence() -> None:
    vulnerability = event("vuln-1", "2026-07-17T11:00:00Z", "vulnerability_management", "critical_kev_detected", "critical", [entity("device", "device-1"), entity("vulnerability", "CVE-2026-0001", kev=True)], [], "advisory:kev-1")
    vulnerability["relationships"] = [{"source_entity": "device:device-1", "target_entity": "vulnerability:CVE-2026-0001", "relationship_type": "affected_by", "confidence": "high", "evidence_reference": ["advisory:kev-1"], "explanation": "Exact product and version matched an applicable advisory."}]
    graph = SecurityPostureGraphEngine().build([vulnerability])
    relation = next(item for item in graph.relationships if item.relationship_type == "affected_by")
    assert relation.observed is True and relation.confidence == "high"


def test_ransomware_event_correlates_only_through_shared_process() -> None:
    events = correlated_events()[:2]
    events.append(event("ransom-1", "2026-07-17T10:10:00Z", "ransomware_defense", "encryption_behavior", "critical", [entity("device", "device-1"), entity("process", "pid-4242")], ["T1486"], "ransomware:activity-1"))
    graph = SecurityPostureGraphEngine().build(events)
    assert any("T1486" in path.mitre_mapping for path in graph.risk_paths)


def test_sensitive_entity_attributes_are_not_collected() -> None:
    item = event("privacy-1", "2026-07-17T10:00:00Z", "identity_attack", "credential_metadata_access", "high", [entity("process", "pid-1", password="do-not-store", access_token="secret", path="/tmp/tool")], ["T1555"], "identity:metadata-1")
    graph = SecurityPostureGraphEngine().build([item])
    payload = json.dumps(graph.to_dict())
    assert "do-not-store" not in payload and '"access_token"' not in payload
    assert "/tmp/tool" in payload


def test_threat_intelligence_context_without_evidence_is_ignored() -> None:
    graph = SecurityPostureGraphEngine().build(correlated_events(), context={"security_score": 90, "threat_intelligence_match": True})
    assert any("ignored because it lacked evidence" in item for item in graph.score_explanation)


def test_hunting_queries_use_only_graph_evidence() -> None:
    engine = SecurityPostureGraphEngine(); graph = engine.build(correlated_events())
    related = engine.related_to(graph, "process:pid-4242")
    assert related["relationships"]
    before = engine.before_event(graph, "identity-1")
    assert [item["event_id"] for item in before] == ["app-1", "persist-1", "network-1"]
    assert len(engine.changed_recently(graph, since="2026-07-17T10:10:00Z")) == 2


def test_ai_and_incident_context_preserve_analyst_control() -> None:
    engine = SecurityPostureGraphEngine(); graph = engine.build(correlated_events())
    path = max(graph.risk_paths, key=lambda item: len(item.event_ids))
    ai = engine.analyst_context(graph, path.path_id); incident = engine.incident_context(graph, path.path_id)
    assert ai["observed_facts"] and "Do not claim compromise" in ai["guardrail"]
    assert incident["eligible"] and incident["authorization_required"] and not incident["automatic_action"]
    dashboard = engine.dashboard(graph)
    assert dashboard["attack_paths"] and dashboard["risk_relationships"] and dashboard["timeline"]
    assert dashboard["actions"] == ["investigate_node", "view_evidence", "expand_relationship", "generate_incident_report", "export_graph"]


def test_repository_preserves_graph_and_detects_tampering(tmp_path) -> None:
    graph = SecurityPostureGraphEngine().build(correlated_events())
    repository = SecurityPostureGraphRepository(tmp_path / "graph.sqlite3"); repository.save(graph)
    assert repository.latest_payload()["graph_id"] == graph.graph_id
    repository.conn.execute("UPDATE posture_graphs SET payload_json=replace(payload_json, 'critical', 'low')"); repository.conn.commit()
    with pytest.raises(ValueError, match="integrity verification failed"):
        repository.latest_payload()
    repository.close()


def test_reports_expose_risk_paths_and_qualification(tmp_path) -> None:
    graph = SecurityPostureGraphEngine().build(correlated_events(), context={"security_score": 88})
    scan = ScanResult("scan-graph", graph.generated_at, "mac.test", "analyst", collected_artifacts={"security_posture_graph": graph.to_dict()})
    json_path = export_scan_result_json(scan, tmp_path / "graph.json"); html_path = export_scan_result_html(scan, tmp_path / "graph.html")
    payload = json.loads(json_path.read_text(encoding="utf-8")); html = html_path.read_text(encoding="utf-8")
    assert payload["security_posture_graph"]["risk_paths"]
    assert payload["report_summary"]["security_posture_graph"]["posture_score_after"] < 88
    assert "Security Posture Graph" in html
    assert "not automatically labeled malicious" in html
