"""Unifying supply-chain assessment over existing MSAA inventory engines."""
from __future__ import annotations
import hashlib,json,re,sqlite3
from dataclasses import asdict,dataclass,field
from pathlib import Path
from typing import Any
from uuid import uuid4
from mac_audit_agent.models import BackgroundMonitorEvent,utc_now_iso
from mac_audit_agent.not_signed.models import InstalledSoftwareItem,SoftwareTrustClassification
from mac_audit_agent.not_signed.risk_engine import score as provenance_score
from mac_audit_agent.anti_typosquatting.project_audit import scan_project

@dataclass
class SupplyChainFinding:
 event_id:str;timestamp:str;software_name:str="";package_name:str="";version:str="";source_registry:str="";developer:str="";signature_status:str="unknown";sha256:str="";dependency_information:dict[str,Any]=field(default_factory=dict);risk_score:int=0;severity:str="medium";mitre_mapping:list[str]=field(default_factory=list);cve_reference:list[str]=field(default_factory=list);description:str="";recommendation:str="";analyst_status:str="open";evidence:list[str]=field(default_factory=list)
 def to_dict(self):return asdict(self)
 def to_ai_finding(self):return {"finding_id":self.event_id,"title":self.description,"severity":self.severity,"confidence":"high" if self.risk_score>=80 else "medium","sha256":self.sha256,"signature_status":self.signature_status,"mitre_attack":self.mitre_mapping,"evidence":self.evidence,"recommended_action":self.recommendation}

class SupplyChainStore:
 def __init__(self,path:Path):
  self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True);self.connection=sqlite3.connect(self.path);self.connection.row_factory=sqlite3.Row
  self.connection.execute("CREATE TABLE IF NOT EXISTS supply_chain_events(event_id TEXT PRIMARY KEY,timestamp TEXT,software_name TEXT,package_name TEXT,version TEXT,source_registry TEXT,developer TEXT,signature_status TEXT,hash TEXT,dependency_information TEXT,risk_score INTEGER,severity TEXT,mitre_mapping TEXT,cve_reference TEXT,description TEXT,recommendation TEXT,analyst_status TEXT,evidence_json TEXT,payload_hash TEXT)");self.connection.commit()
 def record(self,f:SupplyChainFinding):
  p=f.to_dict();enc=json.dumps(p,sort_keys=True).encode();vals=[p[k] for k in ("event_id","timestamp","software_name","package_name","version","source_registry","developer","signature_status","sha256")]+[json.dumps(f.dependency_information,sort_keys=True),f.risk_score,f.severity,json.dumps(f.mitre_mapping),json.dumps(f.cve_reference),f.description,f.recommendation,f.analyst_status,json.dumps(f.evidence),hashlib.sha256(enc).hexdigest()];self.connection.execute("INSERT INTO supply_chain_events VALUES("+",".join("?" for _ in vals)+")",vals);self.connection.commit()
 def recent(self,limit=100):return [dict(x) for x in self.connection.execute("SELECT * FROM supply_chain_events ORDER BY timestamp DESC LIMIT ?",(limit,)).fetchall()]

class SupplyChainEngine:
 def __init__(self,store:SupplyChainStore,shared_event_store:Any|None=None):self.store,self.shared=store,shared_event_store
 def assess_application(self,item:InstalledSoftwareItem,sha256:str,previous_sha256:str="")->list[SupplyChainFinding]:
  classification=item.signing.classification;severity,reasons=provenance_score(classification,item.executable_path,item.running_processes,bool(item.persistence_items));findings=[]
  if classification in {SoftwareTrustClassification.UNSIGNED,SoftwareTrustClassification.AD_HOC,SoftwareTrustClassification.UNKNOWN,SoftwareTrustClassification.INVALID,SoftwareTrustClassification.REVOKED}:
   risk={"medium":45,"high":70,"critical":90}.get(severity,25);findings.append(self._save(SupplyChainFinding(f"supply-{uuid4().hex}",utc_now_iso(),item.display_name,version=item.version or "",developer=(item.signing.authorities[0] if item.signing.authorities else ""),signature_status=classification.value,sha256=sha256,risk_score=risk,severity=severity,mitre_mapping=["T1195"],description="Software provenance requires review",recommendation="Verify publisher, signature, notarization, origin, hash, and business purpose. Do not remove solely because software is unsigned.",evidence=list(reasons))))
  if previous_sha256 and sha256 and previous_sha256!=sha256:
   sev="critical" if classification in {SoftwareTrustClassification.DEVELOPER_ID_NOTARIZED,SoftwareTrustClassification.MAC_APP_STORE,SoftwareTrustClassification.APPLE_PLATFORM} else "high";findings.append(self._save(SupplyChainFinding(f"supply-{uuid4().hex}",utc_now_iso(),item.display_name,version=item.version or "",signature_status=classification.value,sha256=sha256,risk_score=90 if sev=="critical" else 75,severity=sev,mitre_mapping=["T1195"],description="Installed software hash changed from its approved baseline",recommendation="Preserve both hash records and validate the update through the signed vendor channel before trust or removal.",evidence=[f"previous_sha256={previous_sha256}",f"current_sha256={sha256}"])))
  return findings
 def inventory_project(self,root:Path,protected_assets=()):return scan_project(root,protected_assets)
 def match_advisories(self,packages:list[dict],advisories:list[dict])->list[SupplyChainFinding]:
  out=[]
  for p in packages:
   for a in advisories:
    if p.get("ecosystem")==a.get("ecosystem") and p.get("name")==a.get("name") and p.get("version")==a.get("version") and a.get("advisory_id"):
     out.append(self._save(SupplyChainFinding(f"supply-{uuid4().hex}",utc_now_iso(),package_name=str(p["name"]),version=str(p["version"]),source_registry=str(p.get("source","")),risk_score=80,severity="high",mitre_mapping=["T1195.001"],cve_reference=[str(a["advisory_id"])],description="Exact package and version matched a supplied security advisory",recommendation="Validate advisory applicability and upgrade through an approved, reproducible dependency workflow.",evidence=[f"source_category={a.get('source_category','local advisory dataset')}"])))
  return out
 def analyze_install_script(self,name:str,text:str,ecosystem:str)->SupplyChainFinding|None:
  bounded=text[:262144];signals=[]
  for pattern,label in ((r"https?://|\bcurl\b|\bwget\b","remote download"),(r"\bsecurity\s+(?:find|dump|export)|keychain|\.ssh/","credential-resource access"),(r"LaunchAgents|LaunchDaemons|launchctl","persistence modification"),(r"\bsudo\b|/etc/|/Library/","privileged/system modification")):
   if re.search(pattern,bounded,re.I):signals.append(label)
  if not signals:return None
  risk=min(100,45+15*len(signals));return self._save(SupplyChainFinding(f"supply-{uuid4().hex}",utc_now_iso(),package_name=name,source_registry=ecosystem,risk_score=risk,severity="critical" if risk>=85 else "high",mitre_mapping=["T1195.001","T1105"] if "remote download" in signals else ["T1195.001"],description="Package install script contains behavior requiring review",recommendation="Review the complete package provenance and script in an isolated environment; do not execute it on the endpoint.",evidence=signals))
 def report(self,path:Path)->Path:
  payload={"generated_at":utc_now_iso(),"findings":self.store.recent(),"disclaimer":"Evidence-based supply-chain review; findings are not automatic malicious verdicts."};data=json.dumps(payload,indent=2,sort_keys=True).encode();path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o600);path.with_suffix(path.suffix+".sha256").write_text(hashlib.sha256(data).hexdigest()+"  "+path.name+"\n");return path
 def _save(self,f):
  self.store.record(f)
  if self.shared:self.shared.record_background_monitor_event(BackgroundMonitorEvent(event_id=f.event_id,timestamp=f.timestamp,event_type="supply_chain_risk_detected",severity=f.severity,source="supply_chain_security",evidence="; ".join(f.evidence),confidence="high" if f.risk_score>=80 else "medium",recommendation=f.recommendation,metadata_json=json.dumps(f.to_dict(),sort_keys=True),related_file_hash=f.sha256),dedupe_window_seconds=0)
  return f
__all__=["SupplyChainEngine","SupplyChainFinding","SupplyChainStore"]
