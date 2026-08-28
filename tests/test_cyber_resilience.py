import json,pytest
from mac_audit_agent.cyber_resilience import *
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html,export_scan_result_json

T1="2026-01-01T00:00:00Z";T2="2026-07-17T00:00:00Z"
def all_evidence(status="passed"):
 return {control.evidence_key:{"status":status,"evidence_reference":[f"evidence:{control.control_id}"]} for control in CONTROLS}

def test_full_evidenced_readiness_scores_100_and_explains_every_point():
 a=CyberResilienceEngine().assess(device_id="mac-1",evidence=all_evidence(),timestamp=T1)
 assert a.overall_score==100 and all(x==100 for x in a.category_scores.values()) and a.evidence_coverage_percent==100;assert all(r.score_credit==r.weight and r.framework_mapping for r in a.results);assert CyberResilienceEngine.verify_integrity(a)

def test_missing_evidence_gets_no_credit_and_is_visible_not_false_confidence():
 a=CyberResilienceEngine().assess(device_id="mac-1",evidence={},timestamp=T1)
 assert a.overall_score==0 and a.evidence_coverage_percent==0 and len(a.weaknesses)==len(CONTROLS);assert all(x.status=="not_measured" for x in a.results)

def test_failed_recovery_is_not_hidden_by_strong_detection():
 evidence=all_evidence()
 for control in CONTROLS:
  if control.category=="recovery":evidence[control.evidence_key]={"status":"failed","evidence_reference":[f"failure:{control.control_id}"]}
 a=CyberResilienceEngine().assess(device_id="mac-1",evidence=evidence,timestamp=T1)
 assert a.category_scores["detection"]==100 and a.category_scores["recovery"]==0 and a.overall_score==82;assert any("Restore procedure tested" in x for x in a.weaknesses)

def test_history_changes_document_control_score_delta():
 e=CyberResilienceEngine();before=e.assess(device_id="mac-1",evidence=all_evidence(),timestamp=T1);current=all_evidence();current["restore_testing"]={"status":"failed","evidence_reference":["restore:test-failed"]};after=e.assess(device_id="mac-1",evidence=current,timestamp=T2,previous=before)
 change=next(x for x in after.changes if x.control_id=="REC-TEST");assert change.score_change==-25 and "passed to failed" in change.reason;assert after.to_event()["calculation_version"]==CALCULATION_VERSION

def test_safe_simulation_adapter_requires_pass_and_simulation_label():
 e=CyberResilienceEngine();passed=e.evidence_from_modules(simulation={"results":[{"result":"PASS","simulation_mode":True,"evidence_path":"simulation:e1"}]});failed=e.evidence_from_modules(simulation={"results":[{"result":"PASS","simulation_mode":False,"evidence_path":"simulation:e2"}]})
 assert passed["simulation_detection"]["status"]=="passed" and failed["simulation_detection"]["status"]=="failed"
 assert "simulation_detection" not in e.evidence_from_modules(simulation={"results":["malformed"]})

def test_evidence_adapter_uses_stable_artifact_identifiers():
 out=CyberResilienceEngine().evidence_from_modules(evidence_collection={"case_id":"case-1","artifacts":[{"evidence_id":"ev-1","artifact_hash":"abc"}]});refs=out["evidence_collection"]["evidence_reference"]
 assert refs==("abc","case-1","ev-1")

def test_module_adapter_links_supply_attestation_exposure_control_and_regression_evidence():
 e=CyberResilienceEngine();out=e.evidence_from_modules(supply_graph={"graph":{"sbom_status":"cyclonedx_parsed","entities":[{}],"software_trust":[{"evidence_reference":["graph:1"]}]}},attestation={"assessment":{"results":[{"trust_state":"verified","evidence_reference":["attest:1"]}]}},exposure={"assessment":{"exposures":[{"status":"open","exploit_status":"known_exploited_in_wild","evidence_reference":["kev:1"]}]}},control_validation={"assessment":{"not_assessed_controls":0,"results":[{"evidence_reference":["control:1"]}]}},regression={"assessment":{"regressions":[{"evidence_reference":["regression:1"]}]}})
 assert out["sbom_coverage"]["status"]=="passed" and out["attestation_coverage"]["status"]=="passed" and out["kev_readiness"]["status"]=="failed" and out["drift_detection"]["status"]=="passed"

def test_dashboard_ai_and_trend_do_not_guarantee_outcomes():
 e=CyberResilienceEngine();a=e.assess(device_id="mac-1",evidence={},timestamp=T1);b=e.assess(device_id="mac-1",evidence=all_evidence(),timestamp=T2,previous=a);dashboard=e.dashboard(b,[a]);context=e.analyst_context(b)
 assert dashboard["historical_trend"]==[{"timestamp":T1,"score":0},{"timestamp":T2,"score":100}] and "does not guarantee" in context["guardrail"].lower()

def test_repository_detects_history_tamper(tmp_path):
 a=CyberResilienceEngine().assess(device_id="mac-1",evidence=all_evidence(),timestamp=T1);repo=CyberResilienceRepository(tmp_path/"r.db");repo.save(a);assert repo.history("mac-1")[0]["overall_score"]==100
 repo.conn.execute("UPDATE resilience_scores SET payload_json=replace(payload_json,'\"overall_score\":100','\"overall_score\":5')");repo.conn.commit()
 with pytest.raises(ValueError):repo.history("mac-1")
 repo.close()

def test_sensitive_input_is_not_retained():
 evidence=all_evidence();evidence["event_logging"]["access_token"]="secret";a=CyberResilienceEngine().assess(device_id="mac-1",evidence=evidence,timestamp=T1);assert "access_token" not in json.dumps(a.to_dict())

def test_invalid_arbitrary_weights_are_rejected():
 bad=(ResilienceControl("x","detection","Bad",1,"x",("NIST",),"fix"),)
 with pytest.raises(ValueError):CyberResilienceEngine(bad)

def test_reports_and_dashboard_show_categories_weaknesses_and_limits(tmp_path):
 assessment=CyberResilienceEngine().assess(device_id="mac-1",evidence=all_evidence(),timestamp=T1);artifact={"assessment":assessment.to_dict()};scan=ScanResult("s1",T1,"mac","analyst",collected_artifacts={"cyber_resilience_score":artifact});jp=export_scan_result_json(scan,tmp_path/"c.json");hp=export_scan_result_html(scan,tmp_path/"c.html");payload=json.loads(jp.read_text());html=hp.read_text()
 assert payload["cyber_resilience_score"]["assessment"]["category_scores"]["recovery"]==100 and payload["report_summary"]["cyber_resilience_score"]["assessment"]["calculation_version"]==CALCULATION_VERSION;assert "Cyber Resilience Score" in html and "does not guarantee incident outcomes" in html
 from PySide6.QtWidgets import QApplication
 from mac_audit_agent.ui.cyber_resilience_panel import CyberResiliencePanel
 app=QApplication.instance() or QApplication([]);panel=CyberResiliencePanel();panel.set_assessment(artifact);assert panel.table.rowCount()==8 and "100/100" in panel.summary.text();panel.close()
