import json,pytest
from mac_audit_agent.security_regression_detection import *
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html,export_scan_result_json

T1="2026-07-01T10:00:00Z";T2="2026-07-17T10:00:00Z"
def record(value,status,ref,**kw):return {"value":value,"status":status,"evidence_reference":[ref],**kw}
def snapshots(before,after,old_score=95,new_score=70):
 e=SecurityRegressionEngine();return e,e.snapshot(device_id="mac-1",security_state=before,security_score=old_score,timestamp=T1,baseline_id="trusted-1"),e.snapshot(device_id="mac-1",security_state=after,security_score=new_score,timestamp=T2,baseline_id="current-1")

def test_firewall_regression_tracks_actor_process_and_score_reason():
 before={"configuration":{"firewall":record(True,"enabled","fw:old")}};after={"configuration":{"firewall":record(False,"disabled","fw:new",changed_by="admin",responsible_process="System Settings",change_reason="test",source="security_controls")}}
 e,a,b=snapshots(before,after);r=e.compare(a,b).regressions[0]
 assert r.security_impact=="security_regression" and r.risk_score_change<0 and r.changed_by=="admin" and r.responsible_process=="System Settings";assert "category weight" in r.score_explanation[1]

def test_filevault_improvement_is_positive():
 e,a,b=snapshots({"configuration":{"filevault":record(False,"disabled","fv:old")}}, {"configuration":{"filevault":record(True,"enabled","fv:new")}},70,90);r=e.compare(a,b).regressions[0]
 assert r.security_impact=="security_improvement" and r.risk_score_change>0 and r.severity=="info"

def test_approved_application_update_can_be_neutral_without_hiding_change():
 old=record({"hash":"a","version":"1"},"verified","app:old");new=record({"hash":"b","version":"2"},"verified","app:new",authorized_change=True,approved_security_impact="neutral",changed_by="admin",change_reason="vendor update")
 e,a,b=snapshots({"software":{"app":old}},{"software":{"app":new}},95,95);r=e.compare(a,b).regressions[0]
 assert r.security_impact=="neutral_change" and r.risk_score_change==0 and r.authorized_change

def test_application_hash_and_signature_regression():
 old=record({"hash":"a","signature":"valid"},"verified","attest:old");new=record({"hash":"b","signature":"invalid"},"failed","attest:new",severity="critical",responsible_process="updater")
 e,a,b=snapshots({"software":{"app":old}},{"software":{"app":new}});r=e.compare(a,b).regressions[0]
 assert r.security_impact=="security_regression" and r.severity=="critical" and r.category=="software"

def test_new_administrator_and_ssh_access_regressions():
 before={"identity":{"alice":record("standard","approved","id:old")}};after={"identity":{"alice":record("administrator","unapproved","id:new",severity="high"),"ssh-key":record("fingerprint","unapproved","ssh:new",severity="critical")}}
 e,a,b=snapshots(before,after);rows=e.compare(a,b).regressions
 assert len(rows)==2 and all(x.security_impact=="security_regression" for x in rows)

def test_vulnerability_reintroduction_policy_failure_and_attack_path():
 before={"vulnerability":{"CVE-1":record("fixed","patched","cve:old")},"policy":{"firewall":record("pass","passed","policy:old")},"attack_path":{"path-1":record("closed","closed","path:old")}}
 after={"vulnerability":{"CVE-1":record("affected","vulnerable","cve:new",threat_intelligence_match=True)},"policy":{"firewall":record("fail","failed","policy:new",policy_violation=True)},"attack_path":{"path-1":record("reachable","open","path:new")}}
 e,a,b=snapshots(before,after);rows=e.compare(a,b).regressions
 assert {x.category for x in rows}=={"vulnerability","policy","attack_path"};assert next(x for x in rows if x.category=="policy").policy_violation

def test_missing_evidence_does_not_create_regression():
 e,a,b=snapshots({"configuration":{"firewall":record(True,"enabled","fw:old")}},{"configuration":{"firewall":{"value":False,"status":"disabled"}}});assert not e.compare(a,b).regressions

def test_trend_dashboard_ai_and_response_are_decision_support():
 e,a,b=snapshots({"configuration":{"sip":record(True,"enabled","sip:old")}},{"configuration":{"sip":record(False,"disabled","sip:new",severity="critical")}});assessment=e.compare(a,b);dashboard=e.dashboard(assessment);context=e.analyst_context(assessment);response=e.response_context(assessment.regressions[0])
 assert len(dashboard["security_trend"])==2 and dashboard["risk_increases"] and dashboard["trend_analysis"]["direction"]=="degrading";assert "Do not infer malicious" in context["guardrail"] and response["authorization_required"] and not response["automatic_action"]

def test_artifact_adapter_preserves_additional_state_and_marks_new_exposure():
 e=SecurityRegressionEngine();before=e.snapshot(device_id="mac-1",security_state={"configuration":{"firewall":record(True,"enabled","fw:1")}},security_score=95,timestamp=T1);current=e.snapshot_from_artifacts(device_id="mac-1",security_score=70,timestamp=T2,additional_state={"configuration":{"firewall":record(True,"enabled","fw:2")}},exposure={"assessment":{"exposures":[{"affected_component":"Example.app","cve_id":"CVE-1","severity":"critical","evidence_reference":["cve:1"]}]}});rows=e.compare(before,current).regressions
 assert any(x.category=="vulnerability" and x.security_impact=="security_regression" for x in rows);assert "configuration" in current.security_state and "software" not in current.security_state

def test_repository_detects_tampering(tmp_path):
 e,a,b=snapshots({"configuration":{"firewall":record(True,"enabled","fw:old")}},{"configuration":{"firewall":record(False,"disabled","fw:new")}});assessment=e.compare(a,b);repo=SecurityRegressionRepository(tmp_path/"r.db");repo.save(a,b,assessment);assert repo.latest("mac-1")["assessment_id"]==assessment.assessment_id
 repo.conn.execute("UPDATE regression_assessments SET payload_json=replace(payload_json,'\"current_score\":70','\"current_score\":99')");repo.conn.commit()
 with pytest.raises(ValueError):repo.latest("mac-1")
 repo.close()

def test_sensitive_fields_are_removed_from_snapshot():
 e=SecurityRegressionEngine();s=e.snapshot(device_id="mac-1",security_state={"identity":{"x":record("changed","failed","id:1",access_token="secret")}},security_score=50,timestamp=T1);assert "access_token" not in json.dumps(s.to_dict())

def test_reports_and_dashboard_show_attribution_and_qualification(tmp_path):
 before={"configuration":{"firewall":record(True,"enabled","fw:old")}};after={"configuration":{"firewall":record(False,"disabled","fw:new",changed_by="administrator",responsible_process="System Settings")}};e,a,b=snapshots(before,after);assessment=e.compare(a,b);artifact={"assessment":assessment.to_dict()};scan=ScanResult("s1",T2,"mac","analyst",collected_artifacts={"security_regression_detection":artifact});jp=export_scan_result_json(scan,tmp_path/"r.json");hp=export_scan_result_html(scan,tmp_path/"r.html");payload=json.loads(jp.read_text());html=hp.read_text()
 assert payload["security_regression_detection"]["assessment"]["regressions"] and payload["report_summary"]["security_regression_detection"]["assessment"]["previous_score"]==95;assert "Security Regression Detection" in html and "Changes are not assumed malicious" in html
 from PySide6.QtWidgets import QApplication
 from mac_audit_agent.ui.security_regression_panel import SecurityRegressionPanel
 app=QApplication.instance() or QApplication([]);panel=SecurityRegressionPanel();panel.set_assessment(artifact);assert panel.table.rowCount()==1 and "Regressions: 1" in panel.summary.text();panel.close()
