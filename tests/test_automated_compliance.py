from datetime import datetime,timedelta,timezone
from pathlib import Path
import pytest
from mac_audit_agent.automated_compliance import *
from mac_audit_agent.emergency_response import AuthorizationContext

def auth(admin=True):return AuthorizationContext("auditor","local_admin_auth",True,admin,(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat())
def controls():return [ControlDefinition("CIS-FW","CIS Apple macOS Benchmark","Firewall enabled",("firewall",),"high","Enable the approved firewall configuration.","Network Security"),ControlDefinition("NIST-AU","NIST SP 800-53 Rev. 5","Audit logging evidence",("audit",),"critical","Restore and validate audit logging.","Security Monitoring"),ControlDefinition("CSF-RC","NIST CSF 2.0","Recovery readiness",("backup",),"high","Verify protected backups and restoration testing.","Recovery")]
def test_evidence_scoring_exports_integrity_and_history(tmp_path:Path):
 s=ComplianceReportStore(tmp_path/"c.sqlite3");e=ComplianceAssessmentEngine(s,controls());r=e.assess({"firewall":{"status":"PASS","event_id":"1"},"audit":{"status":"FAIL","event_id":"2"}},auth())
 assert (r.passed_controls,r.failed_controls,r.needs_review_controls)==(1,1,1);assert "NEEDS_REVIEW earns no points" in r.score_explanation;assert e.verify(r)
 assert e.export_json(r,tmp_path/"r.json").is_file();assert e.export_html(r,tmp_path/"r.html").stat().st_mode&0o077==0;assert s.history()[0]["report_hash"]==r.report_hash
def test_history_comparison_and_schedule_authorization(tmp_path:Path):
 s=ComplianceReportStore(tmp_path/"c.sqlite3");e=ComplianceAssessmentEngine(s,controls());a=e.assess({"firewall":{"status":"FAIL"},"audit":{"status":"PASS"},"backup":{"status":"PASS"}},auth());b=e.assess({"firewall":{"status":"PASS"},"audit":{"status":"PASS"},"backup":{"status":"PASS"}},auth());assert "CIS-FW" in s.compare(a.report_id,b.report_id)["resolved"]
 assert s.schedule(auth(),"weekly","2026-08-01T00:00:00Z",["NIST CSF 2.0"],90)
 with pytest.raises(ComplianceReportError):s.schedule(auth(False),"daily","x",[],30)
def test_pdf_export_when_dependency_available(tmp_path:Path):
 pytest.importorskip("reportlab");e=ComplianceAssessmentEngine(ComplianceReportStore(tmp_path/"c.sqlite3"),controls());r=e.assess({"firewall":{"status":"PASS"},"audit":{"status":"PASS"},"backup":{"status":"PASS"}},auth());assert e.export_pdf(r,tmp_path/"r.pdf").read_bytes().startswith(b"%PDF")
