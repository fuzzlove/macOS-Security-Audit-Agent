"""Evidence-backed cyber resilience preparedness scoring for MSAA."""
from __future__ import annotations
import hashlib,json,sqlite3
from dataclasses import asdict,dataclass
from datetime import datetime,timezone
from typing import Any,Iterable,Mapping
from uuid import uuid4

CALCULATION_VERSION="1.0"
CATEGORY_WEIGHTS={"detection":20,"response":18,"containment":12,"recovery":18,"identity":10,"supply_chain":10,"vulnerability":6,"configuration":6}
PASS={"pass","passed","ready","enabled","active","available","verified","healthy","compliant","complete"}
FAIL={"fail","failed","not_ready","disabled","inactive","unavailable","unhealthy","non_compliant","incomplete"}
SENSITIVE_KEYS={"password","password_value","secret","secret_value","token","access_token","private_key","credential","credential_value","authorization_header"}
def _canon(v):return json.dumps(v,sort_keys=True,separators=(",",":"),default=str)
def _hash(v):return hashlib.sha256(_canon(v).encode()).hexdigest()
def _now():return datetime.now(timezone.utc).isoformat()
def _refs(v):return tuple(sorted({str(x) for x in ([v] if isinstance(v,str) else (v or [])) if str(x).strip()}))

@dataclass(frozen=True)
class ResilienceControl:
 control_id:str;category:str;name:str;weight:int;evidence_key:str;framework_mapping:tuple[str,...];recommendation:str
@dataclass(frozen=True)
class ResilienceControlResult:
 control_id:str;category:str;name:str;status:str;score_credit:int;weight:int;evidence_reference:tuple[str,...];explanation:str;recommendation:str;framework_mapping:tuple[str,...]
 def to_dict(self):return asdict(self)
@dataclass(frozen=True)
class ResilienceChange:
 control_id:str;previous_status:str;current_status:str;score_change:int;reason:str;evidence_reference:tuple[str,...]
 def to_dict(self):return asdict(self)
@dataclass(frozen=True)
class CyberResilienceAssessment:
 score_id:str;event_id:str;timestamp:str;device_id:str;overall_score:int;category_scores:dict[str,int];results:tuple[ResilienceControlResult,...];evidence_sources:tuple[str,...];calculation_version:str;changes:tuple[ResilienceChange,...];weaknesses:tuple[str,...];recommendations:tuple[str,...];evidence_coverage_percent:int;integrity_hash:str="";qualification:str="This score measures evidenced preparedness, not guaranteed incident outcomes, compliance certification, or replacement for human incident response."
 def to_dict(self):return {**asdict(self),"results":[x.to_dict() for x in self.results],"changes":[x.to_dict() for x in self.changes]}
 def to_event(self):return {"event_id":self.event_id,"timestamp":self.timestamp,"device_id":self.device_id,"score":self.overall_score,"category_scores":self.category_scores,"evidence_sources":list(self.evidence_sources),"calculation_version":self.calculation_version,"changes":[x.to_dict() for x in self.changes]}

CONTROLS=(
 ResilienceControl("DET-LOG","detection","Event logging active",15,"event_logging",("NIST CSF DE.CM","NIST 800-61 Detection and Analysis","CISA CPG Security Logging"),"Restore durable event logging and verify searchable records."),
 ResilienceControl("DET-MON","detection","Process and endpoint monitoring active",15,"endpoint_monitoring",("NIST CSF DE.CM","NIST SI-4"),"Enable approved endpoint monitoring and validate telemetry coverage."),
 ResilienceControl("DET-PER","detection","Persistence detection active",15,"persistence_detection",("NIST CSF DE.CM","MITRE T1543"),"Validate persistence monitoring and alert delivery."),
 ResilienceControl("DET-RAN","detection","Ransomware behavior detection active",15,"ransomware_detection",("NIST CSF DE.CM","MITRE T1486"),"Validate ransomware behavioral monitoring safely."),
 ResilienceControl("DET-ID","detection","Identity attack detection active",15,"identity_detection",("NIST CSF DE.CM","NIST AC-2"),"Validate identity event monitoring and privacy controls."),
 ResilienceControl("DET-NET","detection","Network monitoring active",10,"network_monitoring",("NIST CSF DE.CM","NIST SI-4"),"Restore approved network telemetry."),
 ResilienceControl("DET-SIM","detection","Detection controls validated by safe simulation",15,"simulation_detection",("NIST CSF DE.CM","NIST 800-61 Preparation"),"Run an authorized, non-destructive validation assessment."),
 ResilienceControl("RSP-EVD","response","Evidence collection available",20,"evidence_collection",("NIST CSF RS.AN","NIST 800-61 Detection and Analysis"),"Repair evidence collection and integrity verification."),
 ResilienceControl("RSP-TIM","response","Incident timeline generation available",15,"timeline_generation",("NIST CSF RS.AN","NIST AU-6"),"Validate incident timeline generation from preserved events."),
 ResilienceControl("RSP-ALT","response","Alerts are actionable and evidence-linked",20,"alert_quality",("NIST CSF DE.AE","NIST 800-61 Detection and Analysis"),"Correct vague or evidence-free alert contracts."),
 ResilienceControl("RSP-CASE","response","Case management available",15,"case_management",("NIST CSF RS.MA","NIST 800-61 Preparation"),"Configure named, auditable incident case management."),
 ResilienceControl("RSP-WF","response","Incident workflow validated",15,"incident_workflow",("NIST CSF RS.MA","NIST 800-61 Containment"),"Exercise the authorized incident workflow."),
 ResilienceControl("RSP-EXP","response","Evidence export and integrity verification ready",15,"evidence_export",("NIST CSF RS.AN","NIST AU-9"),"Validate integrity-checked evidence export."),
 ResilienceControl("CON-ERM","containment","Emergency Response Mode ready",25,"emergency_response",("NIST CSF RS.MA","NIST 800-61 Containment"),"Validate emergency activation, authorization, and audit logging."),
 ResilienceControl("CON-NET","containment","Reversible network containment available",20,"network_containment",("NIST CSF RS.MI","NIST 800-61 Containment"),"Establish an approved reversible network containment workflow."),
 ResilienceControl("CON-PROC","containment","Process investigation and controlled response ready",20,"process_response",("NIST CSF RS.MI","NIST 800-61 Containment"),"Validate process identity, evidence capture, and authorization controls."),
 ResilienceControl("CON-ISO","containment","Isolation workflow preserves management access",15,"isolation_workflow",("NIST CSF RS.MI","CISA CPG Incident Response"),"Test reversible isolation without locking out responders."),
 ResilienceControl("CON-AUTH","containment","Administrator authorization enforced",20,"containment_authorization",("NIST CSF GV.RR","NIST AC-6"),"Require authenticated, time-limited, audited containment approval."),
 ResilienceControl("REC-BKP","recovery","Approved backup is healthy",25,"backup_health",("NIST CSF RC.RP","CISA CPG Data Backups"),"Validate protected backup availability without collecting backup contents."),
 ResilienceControl("REC-PROC","recovery","Documented recovery procedure available",20,"recovery_procedure",("NIST CSF RC.RP","NIST 800-61 Recovery"),"Document and approve endpoint recovery procedures."),
 ResilienceControl("REC-TEST","recovery","Restore procedure tested",25,"restore_testing",("NIST CSF RC.RP","CISA CPG Data Backups"),"Perform and document an authorized restore test."),
 ResilienceControl("REC-INT","recovery","System integrity can be revalidated",15,"integrity_validation",("NIST CSF RC.RP","NIST SI-7"),"Validate post-recovery integrity assessment."),
 ResilienceControl("REC-BASE","recovery","Trusted configuration baseline available",15,"configuration_baseline",("NIST CSF PR.PS","NIST CM-2"),"Create an integrity-protected recovery baseline."),
 ResilienceControl("ID-VIS","identity","Account and privilege visibility",25,"account_visibility",("NIST CSF PR.AA","CISA CPG Account Security"),"Restore account and privilege inventory visibility."),
 ResilienceControl("ID-AUTH","identity","Authentication monitoring active",25,"authentication_monitoring",("NIST CSF DE.CM","NIST AU-6"),"Validate authentication-event processing."),
 ResilienceControl("ID-SSH","identity","SSH identity changes monitored",20,"ssh_protection",("NIST CSF PR.AA","MITRE T1098"),"Validate SSH fingerprint and permission monitoring."),
 ResilienceControl("ID-PRIV","identity","Privileged accounts conform to policy",20,"privileged_account_health",("NIST CSF PR.AA","NIST AC-6"),"Review privileged accounts and approved change evidence."),
 ResilienceControl("ID-CRED","identity","Credential exposure monitoring active",10,"credential_exposure_monitoring",("NIST CSF DE.CM","MITRE T1555"),"Validate metadata-only credential access monitoring."),
 ResilienceControl("SC-PROV","supply_chain","Software provenance coverage",25,"software_provenance",("NIST CSF GV.SC","NIST SR-4"),"Improve signing, source, and developer provenance evidence."),
 ResilienceControl("SC-SBOM","supply_chain","SBOM coverage",20,"sbom_coverage",("NIST CSF GV.SC","NIST SSDF"),"Generate or obtain SPDX/CycloneDX SBOM evidence."),
 ResilienceControl("SC-DEP","supply_chain","Dependency visibility",20,"dependency_visibility",("NIST CSF ID.AM","NIST SA-10"),"Inventory application dependencies."),
 ResilienceControl("SC-ATT","supply_chain","Software attestation coverage",25,"attestation_coverage",("NIST SI-7","NIST SR-4"),"Establish approved identity and hash baselines."),
 ResilienceControl("SC-DEV","supply_chain","Developer and certificate identity visible",10,"developer_identity",("NIST SR-4","NIST SA-11"),"Collect Apple signing identity and certificate status."),
 ResilienceControl("VUL-PAT","vulnerability","Patch posture measured",25,"patch_status",("NIST CSF PR.PS","NIST SI-2"),"Validate applicable patch status."),
 ResilienceControl("VUL-KEV","vulnerability","No unresolved critical KEV exposure",30,"kev_readiness",("NIST CSF ID.RA","CISA KEV"),"Prioritize applicable KEV remediation through change control."),
 ResilienceControl("VUL-PRI","vulnerability","Risk-based remediation prioritization active",25,"risk_prioritization",("NIST CSF ID.RA","NIST RA-5"),"Prioritize by applicability, exploitation, asset, and exposure context."),
 ResilienceControl("VUL-REM","vulnerability","Remediation progress tracked",20,"remediation_tracking",("NIST CSF GV.OV","NIST SI-2"),"Track remediation ownership and verification."),
 ResilienceControl("CFG-CIS","configuration","Security control assessment current",30,"control_validation",("NIST CSF PR.PS","CIS Apple macOS"),"Run an evidence-backed control assessment."),
 ResilienceControl("CFG-BASE","configuration","Approved security baseline active",25,"security_baseline",("NIST CM-2","NIST CM-6"),"Approve and verify an appropriate baseline profile."),
 ResilienceControl("CFG-DRIFT","configuration","Configuration drift detection active",25,"drift_detection",("NIST CM-3","NIST CA-7"),"Enable integrity-bound regression detection."),
 ResilienceControl("CFG-POL","configuration","Policy violations tracked",20,"policy_tracking",("NIST CSF GV.PO","NIST AU-6"),"Track failed controls, exceptions, and remediation."),
)

class CyberResilienceEngine:
 def __init__(self,controls:Iterable[ResilienceControl]=CONTROLS):self.controls=tuple(controls);self._validate()
 def assess(self,*,device_id:str,evidence:Mapping[str,Any],timestamp:str|None=None,previous:CyberResilienceAssessment|None=None)->CyberResilienceAssessment:
  ts=timestamp or _now();clean=self._sanitize(dict(evidence));results=[]
  for control in self.controls:
   raw=clean.get(control.evidence_key);refs=_refs(raw.get("evidence_reference",[]) if isinstance(raw,Mapping) else []);value=raw.get("status",raw.get("value")) if isinstance(raw,Mapping) else raw;normalized=str(value).strip().lower() if value is not None else ""
   status="passed" if refs and (value is True or normalized in PASS) else "failed" if refs and (value is False or normalized in FAIL) else "not_measured"
   credit=control.weight if status=="passed" else 0;shown="not collected" if not refs else repr(value);explanation=f"{control.name}: {status}; observed {shown}; credit {credit}/{control.weight}."
   results.append(ResilienceControlResult(control.control_id,control.category,control.name,status,credit,control.weight,refs,explanation,control.recommendation,control.framework_mapping))
  category_scores={category:self._category_score(results,category) for category in CATEGORY_WEIGHTS};overall=round(sum(category_scores[x]*w for x,w in CATEGORY_WEIGHTS.items())/100);coverage=round(100*sum(x.weight for x in results if x.status!="not_measured")/sum(x.weight for x in results));changes=self._changes(previous,results) if previous else ();weak=tuple(x.explanation for x in results if x.status!="passed");recommendations=tuple(dict.fromkeys(x.recommendation for x in results if x.status!="passed"));sources=tuple(sorted({r for x in results for r in x.evidence_reference}));base=CyberResilienceAssessment(f"resilience-{uuid4().hex}",f"resilience-event-{uuid4().hex}",ts,device_id,overall,category_scores,tuple(results),sources,CALCULATION_VERSION,changes,weak,recommendations,coverage);return CyberResilienceAssessment(base.score_id,base.event_id,base.timestamp,base.device_id,base.overall_score,base.category_scores,base.results,base.evidence_sources,base.calculation_version,base.changes,base.weaknesses,base.recommendations,base.evidence_coverage_percent,_hash(base.to_dict()))
 def evidence_from_modules(self,*,continuous_assurance:Mapping[str,Any]|None=None,simulation:Mapping[str,Any]|None=None,evidence_collection:Mapping[str,Any]|None=None,emergency_response:Mapping[str,Any]|None=None,identity:Mapping[str,Any]|None=None,supply_graph:Mapping[str,Any]|None=None,attestation:Mapping[str,Any]|None=None,exposure:Mapping[str,Any]|None=None,control_validation:Mapping[str,Any]|None=None,regression:Mapping[str,Any]|None=None)->dict[str,Any]:
  out={};snapshot=(continuous_assurance or {}).get("snapshot",continuous_assurance or {});signals={x.get("key"):x for x in snapshot.get("signals",[]) if isinstance(x,Mapping)} if isinstance(snapshot,Mapping) else {}
  mapping={"event_logging":"evidence_collection_ready","endpoint_monitoring":"response_workflow_ready","persistence_detection":"suspicious_persistence","ransomware_detection":"ransomware_indicators","identity_detection":"identity_accounts_authorized","network_monitoring":"suspicious_network_activity","backup_health":"backup_healthy","integrity_validation":"evidence_collection_ready","configuration_baseline":"response_workflow_ready"}
  for target,key in mapping.items():
   signal=signals.get(key)
   if signal:out[target]={"status":"passed" if signal.get("status")=="validated" else "failed","evidence_reference":signal.get("evidence_reference",[])}
  sim=(simulation or {});results=sim.get("results",[]);sim_refs=[x.get("evidence_path") for x in results if isinstance(x,Mapping) and x.get("evidence_path")];out.update(self._simulation_evidence(results,sim_refs))
  if evidence_collection:
   refs=self._module_refs(evidence_collection);out.update({k:{"status":"passed","evidence_reference":refs} for k in ("evidence_collection","timeline_generation","case_management","evidence_export")})
  if emergency_response:
   refs=self._module_refs(emergency_response);out.update({k:{"status":"passed","evidence_reference":refs} for k in ("emergency_response","network_containment","process_response","isolation_workflow","containment_authorization","incident_workflow")})
  if identity:
   refs=self._module_refs(identity);out.update({k:{"status":"passed","evidence_reference":refs} for k in ("account_visibility","authentication_monitoring","ssh_protection","credential_exposure_monitoring")})
  graph=(supply_graph or {}).get("graph",supply_graph or {});graph_refs=[r for x in graph.get("software_trust",[]) if isinstance(x,Mapping) for r in x.get("evidence_reference",[])];
  if graph:out.update({"software_provenance":{"status":"passed","evidence_reference":graph_refs},"dependency_visibility":{"status":"passed" if graph.get("entities") else "failed","evidence_reference":graph_refs},"developer_identity":{"status":"passed","evidence_reference":graph_refs},"sbom_coverage":{"status":"passed" if str(graph.get("sbom_status","")).endswith("parsed") else "failed","evidence_reference":graph_refs}})
  att=(attestation or {}).get("assessment",attestation or {});att_refs=[r for x in att.get("results",[]) if isinstance(x,Mapping) for r in x.get("evidence_reference",[])]
  if att:out["attestation_coverage"]={"status":"passed" if att.get("results") and all(x.get("trust_state")!="review" for x in att.get("results",[])) else "failed","evidence_reference":att_refs}
  exp=(exposure or {}).get("assessment",exposure or {});exp_refs=[r for x in exp.get("exposures",[]) if isinstance(x,Mapping) for r in x.get("evidence_reference",[])]
  if exp:
   kev=any(x.get("exploit_status") in {"known_exploited","known_exploited_in_wild"} and x.get("status","open")!="resolved" for x in exp.get("exposures",[]) if isinstance(x,Mapping));out.update({"patch_status":{"status":"passed" if not exp.get("exposures") else "failed","evidence_reference":exp_refs},"kev_readiness":{"status":"failed" if kev else "passed","evidence_reference":exp_refs},"risk_prioritization":{"status":"passed","evidence_reference":exp_refs},"remediation_tracking":{"status":"passed" if all(x.get("status") for x in exp.get("exposures",[])) else "failed","evidence_reference":exp_refs}})
  val=(control_validation or {}).get("assessment",control_validation or {});val_refs=[r for x in val.get("results",[]) if isinstance(x,Mapping) for r in x.get("evidence_reference",[])]
  if val:out.update({"control_validation":{"status":"passed" if val.get("not_assessed_controls",1)==0 else "failed","evidence_reference":val_refs},"security_baseline":{"status":"passed","evidence_reference":val_refs},"policy_tracking":{"status":"passed","evidence_reference":val_refs}})
  reg=(regression or {}).get("assessment",regression or {});reg_refs=[r for x in reg.get("regressions",[]) if isinstance(x,Mapping) for r in x.get("evidence_reference",[])]
  if reg:out["drift_detection"]={"status":"passed","evidence_reference":reg_refs}
  return out
 def dashboard(self,a,history=()):return {"category":"Cyber Resilience Score","overall_resilience_score":a.overall_score,"category_scores":a.category_scores,"historical_trend":[{"timestamp":x.timestamp,"score":x.overall_score} for x in [*history,a]],"security_weaknesses":list(a.weaknesses),"improvement_recommendations":list(a.recommendations),"evidence_coverage_percent":a.evidence_coverage_percent,"actions":["view_details","compare_history","generate_report","run_validation"]}
 def analyst_context(self,a):return {"measured_controls":[x.to_dict() for x in a.results],"score_explanation":f"Overall {a.overall_score}/100 is the fixed weighted sum of category scores using calculation version {a.calculation_version}.","weaknesses":list(a.weaknesses),"recommendations":list(a.recommendations),"confidence":"high" if a.evidence_coverage_percent>=90 else "medium" if a.evidence_coverage_percent>=70 else "low","guardrail":"Preparedness evidence does not guarantee incident outcomes or replace security leadership and incident responders."}
 @staticmethod
 def verify_integrity(a):p=a.to_dict();expected=p.pop("integrity_hash","");p["integrity_hash"]="";return bool(expected) and _hash(p)==expected
 @staticmethod
 def _category_score(results,category):
  selected=[x for x in results if x.category==category];return round(100*sum(x.score_credit for x in selected)/sum(x.weight for x in selected))
 @staticmethod
 def _changes(previous,results):
  old={x.control_id:x for x in previous.results};out=[]
  for now in results:
   before=old.get(now.control_id)
   if before and before.status!=now.status:out.append(ResilienceChange(now.control_id,before.status,now.status,now.score_credit-before.score_credit,f"{now.name} changed from {before.status} to {now.status}.",tuple(sorted(set(before.evidence_reference)|set(now.evidence_reference)))))
  return tuple(out)
 @staticmethod
 def _simulation_evidence(results,refs):
  rows=[x for x in results if isinstance(x,Mapping)]
  if not rows:return {}
  passed=all(str(x.get("result","")).upper()=="PASS" and x.get("simulation_mode") is True for x in rows);return {"simulation_detection":{"status":"passed" if passed else "failed","evidence_reference":refs},"alert_quality":{"status":"passed" if passed else "failed","evidence_reference":refs}}
 @staticmethod
 def _module_refs(payload):
  refs=set(_refs(payload.get("evidence_reference",[])))
  for item in payload.get("artifacts",[]):
   if isinstance(item,Mapping):
    for key in ("evidence_id","artifact_hash","artifact_path"):
     if item.get(key):refs.add(str(item[key]))
  for key in ("evidence_id","evidence_bundle","evidence_sha256","case_id","incident_id"):
   if payload.get(key):refs.add(str(payload[key]))
  return tuple(sorted(refs))
 @staticmethod
 def _sanitize(value):
  if isinstance(value,Mapping):return {str(k):CyberResilienceEngine._sanitize(v) for k,v in value.items() if str(k).lower() not in SENSITIVE_KEYS}
  if isinstance(value,list):return [CyberResilienceEngine._sanitize(x) for x in value]
  return value
 def _validate(self):
  if sum(CATEGORY_WEIGHTS.values())!=100:raise ValueError("Resilience category weights must total 100.")
  ids=set()
  for x in self.controls:
   if x.control_id in ids or x.category not in CATEGORY_WEIGHTS or x.weight<=0 or not x.framework_mapping:raise ValueError(f"Invalid resilience control: {x.control_id}")
   ids.add(x.control_id)
  for category in CATEGORY_WEIGHTS:
   if sum(x.weight for x in self.controls if x.category==category)!=100:raise ValueError(f"Control weights for {category} must total 100.")

class CyberResilienceRepository:
 def __init__(self,database):
  self._owns=not isinstance(database,sqlite3.Connection);self.conn=sqlite3.connect(str(database)) if self._owns else database;self.conn.row_factory=sqlite3.Row;self.conn.executescript("CREATE TABLE IF NOT EXISTS resilience_scores(score_id TEXT PRIMARY KEY,device_id TEXT,timestamp TEXT,overall_score INTEGER,detection_score INTEGER,response_score INTEGER,containment_score INTEGER,recovery_score INTEGER,identity_score INTEGER,supply_chain_score INTEGER,vulnerability_score INTEGER,configuration_score INTEGER,calculation_version TEXT,integrity_hash TEXT,payload_json TEXT);");self.conn.commit()
 def save(self,a):
  if not CyberResilienceEngine.verify_integrity(a):raise ValueError("Refusing to store an invalid cyber resilience assessment.")
  c=a.category_scores;self.conn.execute("INSERT INTO resilience_scores VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(a.score_id,a.device_id,a.timestamp,a.overall_score,c["detection"],c["response"],c["containment"],c["recovery"],c["identity"],c["supply_chain"],c["vulnerability"],c["configuration"],a.calculation_version,a.integrity_hash,_canon(a.to_dict())));self.conn.commit()
 def history(self,device_id,limit=100):
  rows=self.conn.execute("SELECT payload_json FROM resilience_scores WHERE device_id=? ORDER BY timestamp DESC LIMIT ?",(device_id,max(1,min(1000,limit)))).fetchall();out=[]
  for row in rows:
   p=json.loads(row[0]);expected=p.get("integrity_hash","");q=dict(p);q["integrity_hash"]=""
   if _hash(q)!=expected:raise ValueError("Cyber resilience history integrity verification failed.")
   out.append(p)
  return out
 def close(self):
  if self._owns:self.conn.close()

__all__=["CALCULATION_VERSION","CATEGORY_WEIGHTS","CONTROLS","CyberResilienceAssessment","CyberResilienceEngine","CyberResilienceRepository","ResilienceChange","ResilienceControl","ResilienceControlResult"]
