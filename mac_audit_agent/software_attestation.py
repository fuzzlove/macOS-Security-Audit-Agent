"""Evidence-bound software attestation for MSAA; performs no software mutation."""
from __future__ import annotations
import hashlib,json,sqlite3
from dataclasses import asdict,dataclass
from datetime import datetime,timezone
from typing import Any,Iterable,Mapping
from uuid import uuid4

SENSITIVE=("password","secret","token","private_key","credential")
VALID_SIGNATURES={"valid","developer_id_valid","developer_id_notarized","apple_platform","mac_app_store"}
def _canon(v):return json.dumps(v,sort_keys=True,separators=(",",":"),default=str)
def _digest(v):return hashlib.sha256(_canon(v).encode()).hexdigest()
def _now():return datetime.now(timezone.utc).isoformat()

@dataclass(frozen=True)
class SoftwareIdentityRecord:
 application_id:str;name:str;bundle_identifier:str;version:str;build_number:str;developer:str;team_id:str;certificate_id:str;signature_status:str;sha256:str;bundle_hash:str;resource_hash:str;notarization_status:str;gatekeeper_status:str;installation_source:str;installation_date:str;first_seen:str;responsible_process:str;evidence_reference:tuple[str,...]
 def to_dict(self):return asdict(self)
@dataclass(frozen=True)
class TrustedSoftwareBaseline:
 baseline_id:str;profile:str;application_id:str;approved_versions:tuple[str,...];approved_hashes:tuple[str,...];approved_developers:tuple[str,...];approved_team_ids:tuple[str,...];approved_sources:tuple[str,...];require_valid_signature:bool=True;require_notarization:bool=False;require_sbom:bool=False;evidence_reference:tuple[str,...]=();approved_bundle_hashes:tuple[str,...]=();approved_resource_hashes:tuple[str,...]=()
 def to_dict(self):return asdict(self)
@dataclass(frozen=True)
class PolicyDecision:
 policy_id:str;result:str;reason:str;evidence_reference:tuple[str,...];administrator_approval_required:bool=False
 def to_dict(self):return asdict(self)
@dataclass(frozen=True)
class SoftwareAttestationResult:
 attestation_id:str;timestamp:str;device_id:str;application:SoftwareIdentityRecord;identity_status:str;integrity_status:str;provenance_status:str;behavior_status:str;exposure_status:str;trust_state:str;trust_score:int;risk_score:int;hash_before:str;hash_after:str;change_types:tuple[str,...];reasons:tuple[str,...];unknowns:tuple[str,...];evidence_reference:tuple[str,...];policy_results:tuple[PolicyDecision,...];analyst_status:str="open";qualification:str="Attestation reports observed trust evidence; it does not prove safety, maliciousness, or compromise."
 def to_dict(self):return {**asdict(self),"application":self.application.to_dict(),"policy_results":[x.to_dict() for x in self.policy_results]}
 def to_event(self):return {"event_id":self.attestation_id,"timestamp":self.timestamp,"device_id":self.device_id,"application":self.application.name,"version":self.application.version,"developer":self.application.developer,"signature_status":self.application.signature_status,"hash_before":self.hash_before,"hash_after":self.hash_after,"trust_state":self.trust_state,"risk_score":self.risk_score,"evidence_reference":list(self.evidence_reference),"analyst_status":self.analyst_status}
@dataclass(frozen=True)
class SoftwareAttestationAssessment:
 assessment_id:str;timestamp:str;profile:str;results:tuple[SoftwareAttestationResult,...];integrity_hash:str=""
 def to_dict(self):return {**asdict(self),"results":[x.to_dict() for x in self.results]}

class SoftwareAttestationEngine:
 def attest(self,software:Iterable[Mapping[str,Any]],baselines:Iterable[TrustedSoftwareBaseline|Mapping[str,Any]],*,device_id:str,profile:str="enterprise",trust_graph:Mapping[str,Any]|None=None,exposure_assessment:Mapping[str,Any]|None=None,posture_graph:Mapping[str,Any]|None=None,timestamp:str|None=None)->SoftwareAttestationAssessment:
  ts=timestamp or _now();baseline_by_id={self._baseline(x).application_id:self._baseline(x) for x in baselines};results=[]
  for raw in software:
   item=self._sanitize(dict(raw));identity=self._identity(item);refs=set(identity.evidence_reference)
   if not identity.application_id or not refs:continue
   baseline=baseline_by_id.get(identity.application_id);score=0;reasons=[];unknowns=[];changes=[];before="";identity_status="unknown";integrity_status="unknown";provenance_status="unknown"
   signature=identity.signature_status.lower()
   if signature in VALID_SIGNATURES:score+=25;identity_status="verified";reasons.append("Valid Apple signing evidence: +25")
   elif signature in {"invalid","revoked"}:identity_status="failed";changes.append("signature_failure");reasons.append("Signature validation failed: +0")
   elif signature in {"unsigned","ad_hoc"}:identity_status="review";reasons.append("Unsigned/ad-hoc identity requires review and is not automatically malicious: +5");score+=5
   else:unknowns.append("Signature state is unavailable.")
   if baseline:
    refs.update(baseline.evidence_reference);before=baseline.approved_hashes[0] if baseline.approved_hashes else ""
    if identity.sha256 and identity.sha256 in baseline.approved_hashes:score+=30;integrity_status="verified";reasons.append("Current SHA-256 matches the approved baseline: +30")
    elif identity.sha256 and baseline.approved_hashes:integrity_status="modified";changes.append("binary_hash_changed");reasons.append("Current SHA-256 differs from the approved baseline: +0")
    else:unknowns.append("A current and approved SHA-256 pair is not available.")
    if baseline.approved_bundle_hashes and identity.bundle_hash not in baseline.approved_bundle_hashes:integrity_status="modified";changes.append("bundle_hash_changed");reasons.append("Application bundle contents differ from the approved baseline.")
    if baseline.approved_resource_hashes and identity.resource_hash not in baseline.approved_resource_hashes:integrity_status="modified";changes.append("resource_hash_changed");reasons.append("Application resource contents differ from the approved baseline.")
    checks=[]
    if baseline.approved_developers:checks.append(identity.developer in baseline.approved_developers)
    if baseline.approved_team_ids:checks.append(identity.team_id in baseline.approved_team_ids)
    if baseline.approved_sources:checks.append(identity.installation_source in baseline.approved_sources)
    if checks and all(checks):score+=20;provenance_status="verified";reasons.append("Developer, team, and source match the approved provenance baseline: +20")
    elif checks:provenance_status="changed";changes.append("provenance_changed");reasons.append("Observed provenance differs from the approved baseline: +0")
    if baseline.approved_versions and identity.version not in baseline.approved_versions:changes.append("unexpected_version")
   else:unknowns.append("No approved baseline exists for this application.")
   notarized=identity.notarization_status.lower() in {"valid","notarized","accepted","true"};gatekeeper=identity.gatekeeper_status.lower() in {"accepted","pass","valid"}
   if notarized and gatekeeper:score+=10;reasons.append("Notarization and Gatekeeper assessments are accepted: +10")
   elif identity.notarization_status or identity.gatekeeper_status:unknowns.append("Notarization or Gatekeeper evidence is incomplete or not accepted.")
   behavior_status="expected";behavior_hits=self._matches(posture_graph or {},identity.application_id,identity.name)
   if behavior_hits:behavior_status="review";changes.append("behavioral_risk_context");reasons.append("Related posture-graph behavior lowers confidence; behavior alone does not prove maliciousness: +0");refs.update(self._refs_from(behavior_hits))
   else:score+=10;reasons.append("No related adverse behavior was supplied: +10")
   graph_hits=self._matches(trust_graph or {},identity.application_id,identity.name);exposure_hits=self._matches(exposure_assessment or {},identity.application_id,identity.name)
   adverse_graph=any(term in _canon(graph_hits).lower() for term in ("high_risk","vulnerability","matched_intelligence"));adverse_exposure=bool(exposure_hits) and any(term in _canon(exposure_hits).lower() for term in ("critical","high","kev","known_exploited"))
   if adverse_graph or adverse_exposure:exposure_status="elevated";changes.append("supply_chain_or_vulnerability_risk");reasons.append("Supply-chain or vulnerability context reduces trust without implying compromise: +0");refs.update(self._refs_from(graph_hits));refs.update(self._refs_from(exposure_hits))
   else:exposure_status="no_elevated_context";score+=5;reasons.append("No elevated supplied exposure context: +5")
   score=max(0,min(100,score));risk=100-score
   state="verified" if score>=90 and baseline and not changes and not unknowns else "failed" if integrity_status=="modified" or identity_status=="failed" else "review"
   policies=self._policies(identity,baseline,integrity_status,profile,item)
   if any(x.result=="blocked_pending_approval" for x in policies):state="failed"
   results.append(SoftwareAttestationResult(f"attest-{uuid4().hex}",ts,device_id,identity,identity_status,integrity_status,provenance_status,behavior_status,exposure_status,state,score,risk,before,identity.sha256,tuple(sorted(set(changes))),tuple(reasons),tuple(unknowns),tuple(sorted(refs)),policies))
  base=SoftwareAttestationAssessment(f"software-attestation-{uuid4().hex}",ts,profile,tuple(results));return SoftwareAttestationAssessment(base.assessment_id,base.timestamp,base.profile,base.results,_digest(base.to_dict()))
 def _policies(self,i,b,status,profile,item):
  refs=tuple(sorted(set(i.evidence_reference)|set(b.evidence_reference if b else ())));out=[]
  notarized=i.notarization_status.lower() in {"valid","notarized","accepted","true"}
  requirements=(("valid_signature",i.signature_status.lower() in VALID_SIGNATURES,bool(not b or b.require_valid_signature)),("approved_developer",bool(b and (not b.approved_developers or i.developer in b.approved_developers)),False),("verified_hash",status=="verified",bool(b)),("notarized",notarized,bool(b and b.require_notarization)),("sbom_available",bool(item.get("sbom_available")),bool(b and b.require_sbom)))
  for name,passed,required in requirements:
   result="approved" if passed else "blocked_pending_approval" if required else "review"
   out.append(PolicyDecision(f"{profile}.{name}",result,f"{name.replace('_',' ').title()} {'satisfied' if passed else 'requires review' }.",refs,result=="blocked_pending_approval"))
  return tuple(out)
 def dashboard(self,a):return {"category":"Software Attestation","profile":a.profile,"verified_applications":[x.to_dict() for x in a.results if x.trust_state=="verified"],"failed_attestations":[x.to_dict() for x in a.results if x.trust_state=="failed"],"changed_software":[x.to_dict() for x in a.results if x.change_types],"developer_identity":[{"application":x.application.name,"developer":x.application.developer,"team_id":x.application.team_id,"identity_status":x.identity_status} for x in a.results],"results":[x.to_dict() for x in a.results],"actions":["verify_software","view_evidence","compare_hashes","review_trust","generate_report"]}
 def analyst_context(self,r):return {"observed_facts":r.to_dict(),"evidence_used":list(r.evidence_reference),"confidence":"high" if not r.unknowns else "medium","uncertainty":list(r.unknowns),"investigation_steps":["Verify the change through the vendor's signed release channel.","Compare signature, Team ID, version, and SHA-256 history.","Review related dependency, vulnerability, process, persistence, and network evidence."],"guardrail":"Do not infer malware, compromise, or safe status beyond the collected evidence."}
 def evidence_request(self,r):return {"collection_requested":r.trust_state=="failed","automatic_collection":False,"authorization_required":True,"artifacts":["application_metadata","hash_history","signature_information","timeline","related_events"],"evidence_reference":list(r.evidence_reference)}
 @staticmethod
 def verify_integrity(a):p=a.to_dict();expected=p.pop("integrity_hash","");p["integrity_hash"]="";return bool(expected) and _digest(p)==expected
 @staticmethod
 def _identity(x):
  refs=SoftwareAttestationEngine._refs(x.get("evidence_reference",[]));aid=str(x.get("application_id") or x.get("bundle_identifier") or x.get("name") or "").strip()
  return SoftwareIdentityRecord(aid,str(x.get("name",aid)),str(x.get("bundle_identifier","")),str(x.get("version","")),str(x.get("build_number","")),str(x.get("developer","")),str(x.get("team_id","")),str(x.get("certificate_id","")),str(x.get("signature_status","unknown")),str(x.get("sha256","")),str(x.get("bundle_hash","")),str(x.get("resource_hash","")),str(x.get("notarization_status",x.get("notarized",""))),str(x.get("gatekeeper_status","")),str(x.get("installation_source",x.get("source",""))),str(x.get("installation_date","")),str(x.get("first_seen","")),str(x.get("responsible_process","")),refs)
 @staticmethod
 def _baseline(x):return x if isinstance(x,TrustedSoftwareBaseline) else TrustedSoftwareBaseline(str(x.get("baseline_id","")),str(x.get("profile","enterprise")),str(x.get("application_id","")),tuple(x.get("approved_versions",[])),tuple(x.get("approved_hashes",[])),tuple(x.get("approved_developers",[])),tuple(x.get("approved_team_ids",[])),tuple(x.get("approved_sources",[])),bool(x.get("require_valid_signature",True)),bool(x.get("require_notarization",False)),bool(x.get("require_sbom",False)),SoftwareAttestationEngine._refs(x.get("evidence_reference",[])),tuple(x.get("approved_bundle_hashes",[])),tuple(x.get("approved_resource_hashes",[])))
 @staticmethod
 def _matches(payload,*terms):
  if not payload:return []
  candidates=payload.get("exposures",payload.get("risk_paths",payload.get("relationships",payload.get("software_trust",[])))) if isinstance(payload,Mapping) else []
  return [x for x in candidates if any(t and t.lower() in _canon(x).lower() for t in terms)]
 @staticmethod
 def _refs_from(items):
  refs=[]
  for x in items:
   if isinstance(x,Mapping):refs.extend(x.get("evidence_reference",x.get("evidence",[])) or [])
  return refs
 @staticmethod
 def _refs(v):return tuple(sorted({str(x) for x in ([v] if isinstance(v,str) else (v or [])) if str(x).strip()}))
 @staticmethod
 def _sanitize(v):return {str(k):x for k,x in v.items() if not any(s in str(k).lower() for s in SENSITIVE)}

class SoftwareAttestationRepository:
 def __init__(self,database):
  self._owns=not isinstance(database,sqlite3.Connection);self.conn=sqlite3.connect(str(database)) if self._owns else database;self.conn.row_factory=sqlite3.Row;self.conn.executescript("CREATE TABLE IF NOT EXISTS software_attestations(attestation_id TEXT PRIMARY KEY,application_id TEXT,timestamp TEXT,identity_status TEXT,integrity_status TEXT,provenance_status TEXT,trust_score INTEGER,evidence TEXT,payload_json TEXT);CREATE TABLE IF NOT EXISTS software_history(history_id TEXT PRIMARY KEY,application TEXT,previous_state TEXT,current_state TEXT,change_type TEXT,timestamp TEXT,evidence TEXT);CREATE TABLE IF NOT EXISTS software_attestation_assessments(assessment_id TEXT PRIMARY KEY,timestamp TEXT,profile TEXT,integrity_hash TEXT,payload_json TEXT);");self.conn.commit()
 def save(self,a):
  if not SoftwareAttestationEngine.verify_integrity(a):raise ValueError("Refusing to store an invalid software attestation assessment.")
  with self.conn:
   for r in a.results:
    self.conn.execute("INSERT INTO software_attestations VALUES(?,?,?,?,?,?,?,?,?)",(r.attestation_id,r.application.application_id,r.timestamp,r.identity_status,r.integrity_status,r.provenance_status,r.trust_score,_canon(r.evidence_reference),_canon(r.to_dict())))
    for change in r.change_types:self.conn.execute("INSERT INTO software_history VALUES(?,?,?,?,?,?,?)",(f"history-{uuid4().hex}",r.application.name,r.hash_before,r.hash_after,change,r.timestamp,_canon(r.evidence_reference)))
   self.conn.execute("INSERT INTO software_attestation_assessments VALUES(?,?,?,?,?)",(a.assessment_id,a.timestamp,a.profile,a.integrity_hash,_canon(a.to_dict())))
 def latest(self):
  row=self.conn.execute("SELECT payload_json FROM software_attestation_assessments ORDER BY timestamp DESC LIMIT 1").fetchone()
  if not row:return None
  p=json.loads(row[0]);expected=p.get("integrity_hash","");q=dict(p);q["integrity_hash"]=""
  if _digest(q)!=expected:raise ValueError("Software attestation integrity verification failed.")
  return p
 def close(self):
  if self._owns:self.conn.close()

__all__=["PolicyDecision","SoftwareAttestationAssessment","SoftwareAttestationEngine","SoftwareAttestationRepository","SoftwareAttestationResult","SoftwareIdentityRecord","TrustedSoftwareBaseline"]
