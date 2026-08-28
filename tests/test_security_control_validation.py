import json
import pytest
from mac_audit_agent.security_control_validation import *
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html,export_scan_result_json

TS="2026-07-17T10:00:00Z"
def ev(value,key): return {"value":value,"source":f"collector.{key}","collected_at":TS,"evidence_reference":[f"evidence:{key}"]}
def healthy(): return {"firewall_enabled":ev(True,"firewall"),"filevault_enabled":ev(True,"filevault"),"sip_enabled":ev(True,"sip"),"gatekeeper_enabled":ev(True,"gatekeeper"),"patch_status":ev("current","updates"),"unapproved_administrators":ev(0,"admins"),"remote_login_enabled":ev(False,"ssh"),"unexpected_sensitive_permissions":ev(0,"tcc"),"unapproved_applications":ev(0,"apps")}

def test_all_evidence_passes_without_claiming_certification():
 a=SecurityControlValidationEngine().assess(device_id="d1",profile_id="government",evidence=healthy(),timestamp=TS)
 assert a.compliance_score==100 and a.posture_status=="meets_profile_requirements" and a.passed_controls==9
 assert "not certification" in a.qualification and SecurityControlValidationEngine.verify_integrity(a)

@pytest.mark.parametrize("key,control",[("firewall_enabled","MSAA-MAC-FW-001"),("filevault_enabled","MSAA-MAC-FV-001"),("sip_enabled","MSAA-MAC-SIP-001"),("gatekeeper_enabled","MSAA-MAC-GK-001")])
def test_core_control_failures(key,control):
 data=healthy();data[key]=ev(False,key);a=SecurityControlValidationEngine().assess(device_id="d1",profile_id="government",evidence=data,timestamp=TS)
 r=next(x for x in a.results if x.control_id==control);assert r.result=="failed" and r.evidence_reference
 assert a.compliance_score<100 and a.posture_status=="non_compliant"

def test_user_privacy_and_application_controls():
 data=healthy();data["unapproved_administrators"]=ev(1,"admins");data["unexpected_sensitive_permissions"]=ev(2,"tcc");data["unapproved_applications"]=ev(1,"apps")
 a=SecurityControlValidationEngine().assess(device_id="d1",profile_id="enterprise",evidence=data,timestamp=TS)
 assert {x.control_id for x in a.results if x.result=="failed"}=={"MSAA-MAC-ADM-001","MSAA-MAC-TCC-001","MSAA-MAC-APP-001"}

def test_missing_stale_and_invalid_evidence_never_passes():
 data=healthy();data.pop("firewall_enabled");data["filevault_enabled"]={**ev(True,"fv"),"collected_at":"2026-07-01T00:00:00Z"};data["sip_enabled"]=ev("yes","sip")
 a=SecurityControlValidationEngine().assess(device_id="d1",profile_id="enterprise",evidence=data,timestamp=TS)
 assert a.not_assessed_controls==3 and a.posture_status=="insufficient_evidence" and a.compliance_score<100

def test_exception_is_time_bounded_and_receives_no_pass_credit():
 exc=ControlException("MSAA-MAC-SSH-001","Approved managed SSH","admin","2026-07-01T00:00:00Z","2026-08-01T00:00:00Z",("change:123",))
 data=healthy();data["remote_login_enabled"]=ev(True,"ssh")
 a=SecurityControlValidationEngine().assess(device_id="d1",profile_id="enterprise",evidence=data,exceptions=[exc],timestamp=TS)
 assert a.excepted_controls==1 and a.compliance_score==89 and a.posture_status=="qualified_with_exceptions"

def test_drift_detects_pass_to_fail_only():
 e=SecurityControlValidationEngine();before=e.assess(device_id="d1",profile_id="enterprise",evidence=healthy(),timestamp=TS)
 data=healthy();data["firewall_enabled"]=ev(False,"firewall");after=e.assess(device_id="d1",profile_id="enterprise",evidence=data,timestamp="2026-07-17T11:00:00Z",previous=before)
 assert after.security_regressions==("MSAA-MAC-FW-001",)

def test_profiles_override_severity_and_unknown_profile_fails():
 data=healthy();data["filevault_enabled"]=ev(False,"fv")
 a=SecurityControlValidationEngine().assess(device_id="d1",profile_id="government",evidence=data,timestamp=TS)
 assert next(x for x in a.results if x.control_id=="MSAA-MAC-FV-001").severity=="critical"
 with pytest.raises(ValueError):SecurityControlValidationEngine().assess(device_id="d1",profile_id="missing",evidence=data,timestamp=TS)

def test_remediation_is_guidance_only_and_ai_uses_evidence():
 data=healthy();data["firewall_enabled"]=ev(False,"fw");e=SecurityControlValidationEngine();a=e.assess(device_id="d1",profile_id="enterprise",evidence=data,timestamp=TS);r=next(x for x in a.results if x.control_id=="MSAA-MAC-FW-001")
 w=e.remediation_workflow(r);ctx=e.analyst_context(r);assert w["authorization_required"] and not w["automatic_execution"] and w["stages"]==["review","approve","apply_external_change","verify"]
 assert ctx["observed_facts"]["evidence_reference"] and "Do not claim compliance" in ctx["guardrail"]

def test_repository_integrity(tmp_path):
 a=SecurityControlValidationEngine().assess(device_id="d1",profile_id="enterprise",evidence=healthy(),timestamp=TS);r=ControlValidationRepository(tmp_path/"c.db");r.save(a);assert r.latest_payload("d1","enterprise")["compliance_score"]==100
 r.conn.execute("UPDATE control_assessments SET payload_json=replace(payload_json, '\"compliance_score\":100','\"compliance_score\":1')");r.conn.commit()
 with pytest.raises(ValueError):r.latest_payload("d1","enterprise")
 r.close()

def test_reports_and_dashboard_preserve_failed_not_assessed_distinction(tmp_path):
 data=healthy();data["firewall_enabled"]=ev(False,"fw");data.pop("filevault_enabled");a=SecurityControlValidationEngine().assess(device_id="d1",profile_id="enterprise",evidence=data,timestamp=TS);artifact={"assessment":a.to_dict()}
 scan=ScanResult("s1",TS,"mac","analyst",collected_artifacts={"security_control_validation":artifact});jp=export_scan_result_json(scan,tmp_path/"a.json");hp=export_scan_result_html(scan,tmp_path/"a.html");payload=json.loads(jp.read_text());html=hp.read_text()
 assert payload["security_control_validation"]["assessment"]["failed_controls"]==1 and payload["report_summary"]["security_control_validation"]["assessment"]["not_assessed_controls"]==1
 assert "Security Control Validation" in html and "receive no pass credit" in html
 from PySide6.QtWidgets import QApplication
 from mac_audit_agent.ui.security_control_validation_panel import SecurityControlValidationPanel
 app=QApplication.instance() or QApplication([]);panel=SecurityControlValidationPanel();panel.set_assessment(artifact);assert panel.table.rowCount()==9 and "Not assessed: 1" in panel.summary.text();panel.close()
