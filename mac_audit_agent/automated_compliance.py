"""Evidence-backed endpoint compliance reporting (not certification)."""
from __future__ import annotations

import hashlib, html, json, socket, sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from mac_audit_agent.emergency_response import AuthorizationContext
from mac_audit_agent.models import utc_now_iso


DISCLAIMER = "Assessment support only; this report is not certification, authorization, or a legal compliance determination."


class ComplianceReportError(RuntimeError): pass


@dataclass(frozen=True)
class ControlDefinition:
    control_id: str; framework: str; description: str; evidence_required: tuple[str, ...]
    severity: str; remediation: str; category: str = "Endpoint Security"


@dataclass
class ControlAssessment:
    control_id: str; framework: str; description: str; status: str; severity: str
    evidence: list[dict[str, Any]]; remediation: str; category: str; explanation: str
    def to_dict(self): return asdict(self)


@dataclass
class ComplianceReport:
    report_id: str; timestamp: str; hostname: str; frameworks: list[str]; assessment_type: str
    score: int; score_explanation: str; passed_controls: int; failed_controls: int
    needs_review_controls: int; critical_findings: int; evidence_reference: str
    generated_by: str; controls: list[ControlAssessment]; report_hash: str = ""
    disclaimer: str = DISCLAIMER
    def payload(self):
        value=asdict(self); value["controls"]=[c.to_dict() for c in self.controls]; return value


class ComplianceReportStore:
    def __init__(self,path:Path):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
        self.connection=sqlite3.connect(self.path); self.connection.row_factory=sqlite3.Row
        self.connection.executescript("""
        CREATE TABLE IF NOT EXISTS compliance_reports(report_id TEXT PRIMARY KEY,timestamp TEXT,hostname TEXT,framework_json TEXT,assessment_type TEXT,score INTEGER,passed_controls INTEGER,failed_controls INTEGER,critical_findings INTEGER,evidence_reference TEXT,generated_by TEXT,report_hash TEXT,payload_json TEXT);
        CREATE TABLE IF NOT EXISTS compliance_controls(report_id TEXT,control_id TEXT,framework TEXT,description TEXT,status TEXT,severity TEXT,evidence_json TEXT,remediation TEXT,PRIMARY KEY(report_id,control_id,framework));
        CREATE TABLE IF NOT EXISTS compliance_audit(audit_id TEXT PRIMARY KEY,timestamp TEXT,username TEXT,action TEXT,result TEXT,report_id TEXT);
        CREATE TABLE IF NOT EXISTS compliance_schedules(schedule_id TEXT PRIMARY KEY,frequency TEXT,next_run TEXT,framework_json TEXT,retention_days INTEGER,created_by TEXT,enabled INTEGER);
        """); self.connection.commit()
    def save(self,report:ComplianceReport):
        payload=json.dumps(report.payload(),sort_keys=True)
        self.connection.execute("INSERT INTO compliance_reports VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(report.report_id,report.timestamp,report.hostname,json.dumps(report.frameworks),report.assessment_type,report.score,report.passed_controls,report.failed_controls,report.critical_findings,report.evidence_reference,report.generated_by,report.report_hash,payload))
        for c in report.controls:self.connection.execute("INSERT INTO compliance_controls VALUES(?,?,?,?,?,?,?,?)",(report.report_id,c.control_id,c.framework,c.description,c.status,c.severity,json.dumps(c.evidence,sort_keys=True),c.remediation))
        self.connection.commit()
    def audit(self,auth:AuthorizationContext,action:str,result:str,report_id:str=""):
        self.connection.execute("INSERT INTO compliance_audit VALUES(?,?,?,?,?,?)",(f"ca-{uuid4().hex}",utc_now_iso(),auth.username or "unknown",action,result,report_id));self.connection.commit()
    def history(self,limit=50):return [dict(r) for r in self.connection.execute("SELECT * FROM compliance_reports ORDER BY timestamp DESC LIMIT ?",(limit,)).fetchall()]
    def compare(self,older:str,newer:str)->dict[str,Any]:
        rows={r["report_id"]:dict(r) for r in self.connection.execute("SELECT * FROM compliance_reports WHERE report_id IN (?,?)",(older,newer)).fetchall()}
        if set(rows)!={older,newer}:raise ComplianceReportError("Both historical reports are required.")
        old=json.loads(rows[older]["payload_json"]);new=json.loads(rows[newer]["payload_json"]); os={c["control_id"]:c["status"] for c in old["controls"]};ns={c["control_id"]:c["status"] for c in new["controls"]}
        return {"previous_score":old["score"],"current_score":new["score"],"change":new["score"]-old["score"],"resolved":[k for k in ns if os.get(k)=="FAILED" and ns[k]=="PASSED"],"regressions":[k for k in ns if os.get(k)=="PASSED" and ns[k]=="FAILED"],"new_controls":[k for k in ns if k not in os]}
    def schedule(self,auth:AuthorizationContext,frequency:str,next_run:str,frameworks:list[str],retention_days:int)->str:
        _authorize(auth); freq=frequency.lower()
        if freq not in {"daily","weekly","monthly"} or retention_days<1:raise ComplianceReportError("Invalid schedule or retention policy.")
        sid=f"schedule-{uuid4().hex}";self.connection.execute("INSERT INTO compliance_schedules VALUES(?,?,?,?,?,?,1)",(sid,freq,next_run,json.dumps(frameworks),retention_days,auth.username));self.audit(auth,"compliance_schedule_created","success");return sid


class ComplianceAssessmentEngine:
    def __init__(self,store:ComplianceReportStore,controls:list[ControlDefinition]):self.store,self.controls=store,controls
    def assess(self,evidence:dict[str,dict[str,Any]],auth:AuthorizationContext,*,assessment_type="endpoint_readiness")->ComplianceReport:
        _authorize(auth); assessed=[]
        for control in self.controls:
            records=[evidence[k] for k in control.evidence_required if k in evidence]
            missing=[k for k in control.evidence_required if k not in evidence]
            if missing:status,explanation="NEEDS_REVIEW","Missing required evidence: "+", ".join(missing)
            elif any(str(r.get("status","")).upper() in {"FAIL","FAILED","NON_COMPLIANT","DISABLED"} for r in records):status,explanation="FAILED","Contradictory or failed technical evidence was observed."
            elif records and all(str(r.get("status","")).upper() in {"PASS","PASSED","COMPLIANT","ENABLED"} for r in records):status,explanation="PASSED","All required technical evidence records reported a passing state."
            else:status,explanation="NEEDS_REVIEW","Evidence exists but does not support a definitive technical determination."
            assessed.append(ControlAssessment(control.control_id,control.framework,control.description,status,control.severity,records,control.remediation,control.category,explanation))
        passed=sum(c.status=="PASSED" for c in assessed);failed=sum(c.status=="FAILED" for c in assessed);review=sum(c.status=="NEEDS_REVIEW" for c in assessed)
        weights={"critical":10,"high":7,"medium":4,"low":2};maximum=sum(weights.get(c.severity.lower(),4) for c in assessed) or 1;earned=sum(weights.get(c.severity.lower(),4) for c in assessed if c.status=="PASSED")
        score=round(100*earned/maximum);explain=f"Weighted evidence score: earned={earned}, maximum={maximum}; NEEDS_REVIEW earns no points and is not treated as failure or pass."
        evidence_ref="sha256:"+hashlib.sha256(json.dumps(evidence,sort_keys=True,default=str).encode()).hexdigest(); frameworks=sorted({c.framework for c in assessed})
        report=ComplianceReport(f"compliance-{uuid4().hex}",utc_now_iso(),socket.gethostname(),frameworks,assessment_type,score,explain,passed,failed,review,sum(c.status=="FAILED" and c.severity.lower()=="critical" for c in assessed),evidence_ref,auth.username,assessed)
        canonical=json.dumps(report.payload(),sort_keys=True,separators=(",",":"),default=str).encode();report.report_hash=hashlib.sha256(canonical).hexdigest();self.store.save(report);self.store.audit(auth,"compliance_assessment_generated","success",report.report_id);return report
    def verify(self,report:ComplianceReport)->bool:
        expected=report.report_hash;report.report_hash="";actual=hashlib.sha256(json.dumps(report.payload(),sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest();report.report_hash=expected;return actual==expected
    def export_json(self,report:ComplianceReport,path:Path)->Path:return _secure_write(path,json.dumps(report.payload(),indent=2,sort_keys=True).encode())
    def export_html(self,report:ComplianceReport,path:Path)->Path:
        rows="".join(f"<tr><td>{html.escape(c.control_id)}</td><td>{html.escape(c.framework)}</td><td>{c.status}</td><td>{html.escape(c.explanation)}</td><td>{html.escape(c.remediation)}</td></tr>" for c in report.controls)
        body=f"<!doctype html><meta charset=utf-8><title>MSAA Compliance Report</title><h1>MSAA Automated Compliance Report</h1><p>{html.escape(DISCLAIMER)}</p><h2>Executive Summary</h2><p>Score {report.score}/100; passed {report.passed_controls}; failed {report.failed_controls}; needs review {report.needs_review_controls}.</p><p>{html.escape(report.score_explanation)}</p><table><tr><th>Control</th><th>Framework</th><th>Status</th><th>Evidence determination</th><th>Remediation</th></tr>{rows}</table><p>Report SHA-256: {report.report_hash}</p>"
        return _secure_write(path,body.encode())
    def export_pdf(self,report:ComplianceReport,path:Path)->Path:
        try:from reportlab.lib.pagesizes import letter;from reportlab.pdfgen.canvas import Canvas
        except ImportError as exc:raise ComplianceReportError("PDF export requires the optional reportlab dependency; HTML and JSON remain available.") from exc
        path.parent.mkdir(parents=True,exist_ok=True);canvas=Canvas(str(path),pagesize=letter);y=750
        for line in ["MSAA Automated Compliance Report",DISCLAIMER,f"Score: {report.score}/100",report.score_explanation,*[f"{c.control_id} | {c.framework} | {c.status} | {c.remediation}" for c in report.controls]]:
            if y<60:canvas.showPage();y=750
            canvas.drawString(50,y,line[:110]);y-=16
        canvas.save();path.chmod(0o600);return path


def _authorize(auth:AuthorizationContext):
    if not auth.valid():raise ComplianceReportError("Valid time-limited administrator authorization is required.")
def _secure_write(path:Path,data:bytes)->Path:
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o600);path.with_suffix(path.suffix+".sha256").write_text(hashlib.sha256(data).hexdigest()+"  "+path.name+"\n");return path


__all__=["ComplianceAssessmentEngine","ComplianceReportStore","ComplianceReportError","ControlDefinition","ControlAssessment","ComplianceReport","DISCLAIMER"]
