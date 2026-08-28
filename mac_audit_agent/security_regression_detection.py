"""Accountable, evidence-bound security regression analysis for MSAA."""
from __future__ import annotations
import hashlib,json,sqlite3
from dataclasses import asdict,dataclass
from datetime import datetime,timezone
from typing import Any,Iterable,Mapping
from uuid import uuid4

SENSITIVE=("password","secret","token","private_key","credential")
POSITIVE={"enabled","secure","validated","verified","passed","patched","compliant","approved","closed","resolved","signed"}
NEGATIVE={"disabled","insecure","concern","failed","modified","vulnerable","non_compliant","unapproved","open","unsigned","invalid","revoked"}
WEIGHTS={"configuration":20,"software":20,"identity":20,"persistence":18,"vulnerability":18,"policy":15,"attack_path":18,"network":12,"compliance":12}
def _canon(v):return json.dumps(v,sort_keys=True,separators=(",",":"),default=str)
def _hash(v):return hashlib.sha256(_canon(v).encode()).hexdigest()
def _now():return datetime.now(timezone.utc).isoformat()
def _refs(v):return tuple(sorted({str(x) for x in ([v] if isinstance(v,str) else (v or [])) if str(x).strip()}))

@dataclass(frozen=True)
class RegressionSnapshot:
 baseline_id:str;device_id:str;timestamp:str;security_score:int;security_state:dict[str,Any];evidence_reference:tuple[str,...];integrity_hash:str=""
 def to_dict(self):return asdict(self)
@dataclass(frozen=True)
class SecurityRegression:
 regression_id:str;event_id:str;timestamp:str;device_id:str;baseline_reference:str;category:str;affected_component:str;previous_state:Any;current_state:Any;change_source:str;changed_by:str;responsible_process:str;change_reason:str;authorized_change:bool;security_impact:str;severity:str;risk_score_change:int;score_explanation:tuple[str,...];policy_violation:bool;evidence_reference:tuple[str,...];recommended_action:str;resolution_status:str="open";analyst_status:str="new"
 def to_dict(self):return asdict(self)
 def to_event(self):return {"event_id":self.event_id,"timestamp":self.timestamp,"device_id":self.device_id,"baseline_reference":self.baseline_reference,"affected_component":self.affected_component,"previous_state":self.previous_state,"current_state":self.current_state,"change_source":self.change_source,"security_impact":self.security_impact,"risk_score_change":self.risk_score_change,"evidence_reference":list(self.evidence_reference),"analyst_status":self.analyst_status}
@dataclass(frozen=True)
class RegressionAssessment:
 assessment_id:str;timestamp:str;device_id:str;baseline_id:str;current_snapshot_id:str;previous_score:int;current_score:int;regressions:tuple[SecurityRegression,...];trend:tuple[dict[str,Any],...];integrity_hash:str="";qualification:str="Changes are classified from evidence and policy context; a regression does not by itself establish malicious intent or compromise."
 def to_dict(self):return {**asdict(self),"regressions":[x.to_dict() for x in self.regressions],"trend":list(self.trend)}

class SecurityRegressionEngine:
 def snapshot(self,*,device_id:str,security_state:Mapping[str,Any],security_score:int,timestamp:str|None=None,baseline_id:str|None=None)->RegressionSnapshot:
  ts=timestamp or _now();state=self._sanitize(dict(security_state));refs=tuple(sorted(self._all_refs(state)));base=RegressionSnapshot(baseline_id or f"regression-snapshot-{uuid4().hex}",device_id,ts,max(0,min(100,int(security_score))),state,refs);return RegressionSnapshot(base.baseline_id,base.device_id,base.timestamp,base.security_score,base.security_state,base.evidence_reference,_hash(base.to_dict()))
 def snapshot_from_artifacts(self,*,device_id:str,security_score:int,timestamp:str|None=None,continuous_assurance:Mapping[str,Any]|None=None,software_attestation:Mapping[str,Any]|None=None,identity:Mapping[str,Any]|None=None,exposure:Mapping[str,Any]|None=None,control_validation:Mapping[str,Any]|None=None,posture_graph:Mapping[str,Any]|None=None,additional_state:Mapping[str,Any]|None=None)->RegressionSnapshot:
  state=dict(additional_state or {});csa=(continuous_assurance or {}).get("snapshot",continuous_assurance or {});signals=csa.get("signals",[]) if isinstance(csa,Mapping) else []
  for signal in signals:
   if isinstance(signal,Mapping):state.setdefault(str(signal.get("domain","configuration")),{})[str(signal.get("key","unknown"))]={"value":signal.get("observed_value"),"status":signal.get("status"),"severity":signal.get("severity"),"evidence_reference":signal.get("evidence_reference",[]),"source":"continuous_security_assurance"}
  if software_attestation:
   att=software_attestation.get("assessment",software_attestation);state["software"]={x.get("application",{}).get("application_id",x.get("application",{}).get("name","unknown")):{"value":{"hash":x.get("hash_after"),"signature":x.get("application",{}).get("signature_status"),"version":x.get("application",{}).get("version"),"developer":x.get("application",{}).get("developer")},"status":x.get("trust_state"),"severity":"high" if x.get("trust_state")=="failed" else "medium","evidence_reference":x.get("evidence_reference",[]),"source":"software_attestation","responsible_process":x.get("application",{}).get("responsible_process","")} for x in att.get("results",[]) if isinstance(x,Mapping)}
  for name,payload in (("identity",identity),("vulnerability",exposure),("policy",control_validation),("attack_path",posture_graph)):
   if payload:state[name]=self._artifact_records(name,payload)
  return self.snapshot(device_id=device_id,security_state=state,security_score=security_score,timestamp=timestamp)
 def compare(self,baseline:RegressionSnapshot,current:RegressionSnapshot,*,history:Iterable[RegressionSnapshot]=())->RegressionAssessment:
  if baseline.device_id!=current.device_id:raise ValueError("Regression snapshots must belong to the same device.")
  if not self.verify_snapshot(baseline) or not self.verify_snapshot(current):raise ValueError("Regression snapshot integrity verification failed.")
  before=self._flatten(baseline.security_state);after=self._flatten(current.security_state);changes=[]
  for key in sorted(set(before)|set(after)):
   old=before.get(key);new=after.get(key)
   if _canon(self._value(old))==_canon(self._value(new)) and self._status(old)==self._status(new):continue
   current_refs=self._record_refs(new)
   if not current_refs:continue
   refs=tuple(sorted(set(self._record_refs(old))|set(current_refs)))
   category,component=key.split("/",1);impact=self._impact(old,new);authorized=bool(self._field(new,"authorized_change",False));policy_violation=bool(self._field(new,"policy_violation",False) or category=="policy" and self._status(new) in NEGATIVE)
   if authorized and impact=="security_regression" and not policy_violation and self._field(new,"approved_security_impact","")=="neutral":impact="neutral_change"
   severity=self._severity(category,new,impact);delta=self._risk_delta(category,severity,impact,new);explanation=self._explain(category,component,old,new,impact,authorized,policy_violation,delta)
   changes.append(SecurityRegression(f"regression-{uuid4().hex}",f"regression-event-{uuid4().hex}",current.timestamp,current.device_id,baseline.baseline_id,category,component,self._value(old),self._value(new),str(self._field(new,"source","unknown")),str(self._field(new,"changed_by","unknown")),str(self._field(new,"responsible_process","unknown")),str(self._field(new,"change_reason","not recorded")),authorized,impact,severity,delta,tuple(explanation),policy_violation,refs,self._recommend(category,component,impact)))
  points=sorted([*history,baseline,current],key=lambda x:x.timestamp);trend=tuple({"timestamp":x.timestamp,"security_score":x.security_score,"snapshot_id":x.baseline_id} for x in points)
  base=RegressionAssessment(f"regression-assessment-{uuid4().hex}",current.timestamp,current.device_id,baseline.baseline_id,current.baseline_id,baseline.security_score,current.security_score,tuple(changes),trend);return RegressionAssessment(base.assessment_id,base.timestamp,base.device_id,base.baseline_id,base.current_snapshot_id,base.previous_score,base.current_score,base.regressions,base.trend,_hash(base.to_dict()))
 def dashboard(self,a):
  rows=list(a.regressions);return {"category":"Security Regression Detection","security_trend":list(a.trend),"trend_analysis":self.trend_analysis(a),"baseline_comparison":{"previous_score":a.previous_score,"current_score":a.current_score,"delta":a.current_score-a.previous_score},"recent_changes":[x.to_dict() for x in rows],"risk_increases":[x.to_dict() for x in rows if x.security_impact=="security_regression"],"resolved_issues":[x.to_dict() for x in rows if x.security_impact=="security_improvement"],"actions":["compare_states","investigate_change","view_evidence","approve_exception","generate_report"]}
 def trend_analysis(self,a):
  points=list(a.trend);delta=(points[-1]["security_score"]-points[0]["security_score"]) if len(points)>1 else 0;direction="degrading" if delta<0 else "improving" if delta>0 else "stable";causes=sorted({x.affected_component for x in a.regressions if x.security_impact=="security_regression"});return {"direction":direction,"score_change":delta,"observation_count":len(points),"evidence_backed_causes":causes,"explanation":f"Security posture is {direction} across {len(points)} integrity-verified snapshots; score changed by {delta}."}
 def analyst_context(self,a):return {"observed_changes":[x.to_dict() for x in a.regressions],"score_change":a.current_score-a.previous_score,"confidence":"high" if all(x.evidence_reference for x in a.regressions) else "low","investigation_guidance":["Validate actor, process, authorization, and change record.","Review related software, identity, exposure, persistence, and attack-path evidence.","Remediate only through an approved workflow and verify the next snapshot."],"guardrail":"Do not infer malicious intent or compromise from regression evidence alone."}
 def response_context(self,r):return {"eligible":r.security_impact=="security_regression" and r.severity=="critical","automatic_action":False,"authorization_required":True,"evidence_reference":list(r.evidence_reference),"workflow":"collect_evidence_create_timeline_and_request_investigation"}
 @staticmethod
 def verify_snapshot(s):p=s.to_dict();expected=p.pop("integrity_hash","");p["integrity_hash"]="";return bool(expected) and _hash(p)==expected
 @staticmethod
 def verify_assessment(a):p=a.to_dict();expected=p.pop("integrity_hash","");p["integrity_hash"]="";return bool(expected) and _hash(p)==expected
 @staticmethod
 def _flatten(state):
  out={}
  for category,items in state.items():
   if isinstance(items,Mapping):
    for component,value in items.items():out[f"{category}/{component}"]=value
  return out
 @staticmethod
 def _value(record):return record.get("value") if isinstance(record,Mapping) and "value" in record else record
 @staticmethod
 def _field(record,key,default=None):return record.get(key,default) if isinstance(record,Mapping) else default
 @staticmethod
 def _status(record):
  if isinstance(record,Mapping) and record.get("status") is not None:return str(record.get("status")).lower()
  value=SecurityRegressionEngine._value(record)
  if isinstance(value,bool):return "enabled" if value else "disabled"
  return str(value).lower()
 @staticmethod
 def _impact(old,new):
  explicit=SecurityRegressionEngine._field(new,"security_effect","")
  if explicit in {"security_regression","security_improvement","neutral_change"}:return explicit
  a,b=SecurityRegressionEngine._status(old),SecurityRegressionEngine._status(new)
  if a in POSITIVE and b in NEGATIVE:return "security_regression"
  if a in NEGATIVE and b in POSITIVE:return "security_improvement"
  if old is None and b in NEGATIVE:return "security_regression"
  if new is None and a in NEGATIVE:return "security_improvement"
  return "neutral_change"
 @staticmethod
 def _severity(category,new,impact):
  if impact!="security_regression":return "info"
  supplied=str(SecurityRegressionEngine._field(new,"severity","")).lower()
  if supplied in {"low","medium","high","critical"}:return supplied
  return "critical" if any(x in str(new).lower() for x in ("filevault","sip","administrator","known_exploited")) else "high" if category in {"configuration","software","identity","vulnerability","attack_path","policy"} else "medium"
 @staticmethod
 def _risk_delta(category,severity,impact,new):
  if impact=="neutral_change":return 0
  base=WEIGHTS.get(category,10);mult={"info":.5,"low":.5,"medium":.75,"high":1,"critical":1.5}.get(severity,1);context=1.25 if SecurityRegressionEngine._field(new,"asset_importance","") in {"high","critical"} or SecurityRegressionEngine._field(new,"threat_intelligence_match",False) else 1;value=max(1,round(base*mult*context));return -value if impact=="security_regression" else value
 @staticmethod
 def _explain(category,component,old,new,impact,authorized,violation,delta):return [f"{category}/{component} changed from {_canon(SecurityRegressionEngine._value(old))} to {_canon(SecurityRegressionEngine._value(new))}.",f"Classification: {impact}; risk score change {delta}, derived from category weight {WEIGHTS.get(category,10)}, severity, asset importance, and threat-intelligence context.",f"Authorization recorded: {'yes' if authorized else 'no'}; policy violation: {'yes' if violation else 'no'}."]
 @staticmethod
 def _recommend(category,component,impact):return "Document the approved change and retain evidence." if impact=="neutral_change" else "Validate the improvement in the next integrity-bound snapshot." if impact=="security_improvement" else f"Investigate {component}, validate authorization and responsible process, preserve evidence, and restore the approved {category} state through change control."
 @staticmethod
 def _record_refs(record):return _refs(record.get("evidence_reference",[]) if isinstance(record,Mapping) else [])
 @staticmethod
 def _all_refs(value):
  refs=set()
  if isinstance(value,Mapping):
   refs.update(_refs(value.get("evidence_reference",[])))
   for item in value.values():refs.update(SecurityRegressionEngine._all_refs(item))
  elif isinstance(value,(list,tuple)):
   for item in value:refs.update(SecurityRegressionEngine._all_refs(item))
  return refs
 @staticmethod
 def _sanitize(value):
  if isinstance(value,Mapping):return {str(k):SecurityRegressionEngine._sanitize(v) for k,v in value.items() if not any(s in str(k).lower() for s in SENSITIVE)}
  if isinstance(value,list):return [SecurityRegressionEngine._sanitize(x) for x in value]
  return value
 @staticmethod
 def _artifact_records(name,payload):
  root=payload.get("assessment",payload) if isinstance(payload,Mapping) else {};items=root.get("results",root.get("exposures",root.get("risk_paths",root.get("events",[])))) if isinstance(root,Mapping) else []
  out={}
  for index,item in enumerate(items if isinstance(items,list) else []):
   if not isinstance(item,Mapping):continue
   component=str(item.get("control_id") or item.get("affected_component") or item.get("path_id") or item.get("event_id") or index);status=item.get("result") or item.get("status") or item.get("severity") or item.get("risk_level")
   if name=="vulnerability":status="vulnerable"
   elif name=="attack_path":status="open"
   elif name=="identity" and str(item.get("severity","")).lower() in {"high","critical"}:status="unapproved"
   out[component]={"value":dict(item),"status":status,"severity":item.get("severity",item.get("risk_level","medium")),"evidence_reference":item.get("evidence_reference",item.get("evidence",[])),"source":name}
  return out

class SecurityRegressionRepository:
 def __init__(self,database):
  self._owns=not isinstance(database,sqlite3.Connection);self.conn=sqlite3.connect(str(database)) if self._owns else database;self.conn.row_factory=sqlite3.Row;self.conn.executescript("CREATE TABLE IF NOT EXISTS regression_baselines(baseline_id TEXT PRIMARY KEY,device_id TEXT,timestamp TEXT,security_state TEXT,hash TEXT,payload_json TEXT);CREATE TABLE IF NOT EXISTS security_regressions(regression_id TEXT PRIMARY KEY,timestamp TEXT,device_id TEXT,category TEXT,previous_value TEXT,current_value TEXT,impact TEXT,severity TEXT,resolution_status TEXT,payload_json TEXT);CREATE TABLE IF NOT EXISTS regression_assessments(assessment_id TEXT PRIMARY KEY,timestamp TEXT,device_id TEXT,integrity_hash TEXT,payload_json TEXT);");self.conn.commit()
 def save(self,baseline,current,assessment):
  if not all(SecurityRegressionEngine.verify_snapshot(x) for x in (baseline,current)) or not SecurityRegressionEngine.verify_assessment(assessment):raise ValueError("Refusing to store invalid regression evidence.")
  with self.conn:
   for x in (baseline,current):self.conn.execute("INSERT OR REPLACE INTO regression_baselines VALUES(?,?,?,?,?,?)",(x.baseline_id,x.device_id,x.timestamp,_canon(x.security_state),x.integrity_hash,_canon(x.to_dict())))
   for r in assessment.regressions:self.conn.execute("INSERT INTO security_regressions VALUES(?,?,?,?,?,?,?,?,?,?)",(r.regression_id,r.timestamp,r.device_id,r.category,_canon(r.previous_state),_canon(r.current_state),r.security_impact,r.severity,r.resolution_status,_canon(r.to_dict())))
   self.conn.execute("INSERT INTO regression_assessments VALUES(?,?,?,?,?)",(assessment.assessment_id,assessment.timestamp,assessment.device_id,assessment.integrity_hash,_canon(assessment.to_dict())))
 def latest(self,device_id):
  row=self.conn.execute("SELECT payload_json FROM regression_assessments WHERE device_id=? ORDER BY timestamp DESC LIMIT 1",(device_id,)).fetchone()
  if not row:return None
  p=json.loads(row[0]);expected=p.get("integrity_hash","");q=dict(p);q["integrity_hash"]=""
  if _hash(q)!=expected:raise ValueError("Security regression assessment integrity verification failed.")
  return p
 def close(self):
  if self._owns:self.conn.close()

__all__=["RegressionAssessment","RegressionSnapshot","SecurityRegression","SecurityRegressionEngine","SecurityRegressionRepository"]
