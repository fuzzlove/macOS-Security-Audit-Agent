"""Evidence-bound software supply-chain trust graph for MSAA."""
from __future__ import annotations
import hashlib,json,sqlite3
from dataclasses import asdict,dataclass
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Iterable,Mapping
from uuid import uuid4

TYPES={"software","developer","certificate","build","package_source","dependency","vulnerability","threat_indicator"}
RELATIONS={"developed_by","signed_by","built_as","distributed_by","depends_on","affected_by","matched_intelligence","similar_to","updated_from"}
SENSITIVE=("password","secret","token","private_key","credential")
def _canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),default=str)
def _hash(x):return hashlib.sha256(_canon(x).encode()).hexdigest()
def _now():return datetime.now(timezone.utc).isoformat()

@dataclass(frozen=True)
class TrustEntity:
 entity_id:str;entity_type:str;name:str;version:str="";attributes:dict[str,Any]=None
 def to_dict(self):return {**asdict(self),"attributes":self.attributes or {}}
@dataclass(frozen=True)
class TrustRelationship:
 relationship_id:str;source:str;target:str;relationship_type:str;confidence:str;timestamp:str;evidence_reference:tuple[str,...];source_module:str;risk_impact:int;explanation:str
 def to_dict(self):return asdict(self)
@dataclass(frozen=True)
class SoftwareTrustResult:
 software_id:str;trust_score:int;trust_state:str;reasons:tuple[str,...];evidence_reference:tuple[str,...];unknowns:tuple[str,...]
 def to_dict(self):return asdict(self)
@dataclass(frozen=True)
class SupplyChainTrustGraph:
 graph_id:str;timestamp:str;entities:tuple[TrustEntity,...];relationships:tuple[TrustRelationship,...];software_trust:tuple[SoftwareTrustResult,...];sbom_status:str;risk_relationships:tuple[str,...];integrity_hash:str="";qualification:str="Trust scores and relationships are evidence-based decision support; they do not prove malicious intent or compromise."
 def to_dict(self):return {**asdict(self),"entities":[x.to_dict() for x in self.entities],"relationships":[x.to_dict() for x in self.relationships],"software_trust":[x.to_dict() for x in self.software_trust]}

class SupplyChainTrustGraphEngine:
 def build(self,software:Iterable[Mapping[str,Any]],*,sbom:Mapping[str,Any]|None=None,vulnerabilities:Iterable[Mapping[str,Any]]=(),typosquatting:Iterable[Mapping[str,Any]]=(),threat_intelligence:Iterable[Mapping[str,Any]]=(),update_history:Iterable[Mapping[str,Any]]=(),posture_graph:Mapping[str,Any]|None=None,timestamp:str|None=None)->SupplyChainTrustGraph:
  timestamp=timestamp or _now();entities={};rels=[];software_rows=[];sbom_components,sbom_edges,sbom_status=self._sbom(sbom or {},timestamp)
  for e in sbom_components:entities[e.entity_id]=e
  rels.extend(sbom_edges)
  for raw in software:
   item=self._sanitize(dict(raw));sid=str(item.get("software_id") or item.get("bundle_identifier") or item.get("name") or "").strip();refs=self._refs(item.get("evidence_reference",[]))
   if not sid or not refs:continue
   sn=f"software:{sid}";entities[sn]=TrustEntity(sn,"software",str(item.get("name",sid)),str(item.get("version","")),self._sanitize({k:v for k,v in item.items() if k not in {"evidence_reference"}}))
   developer=str(item.get("developer","")).strip();team=str(item.get("team_id","")).strip();signing=str(item.get("signature_status","unknown")).lower();cert=str(item.get("certificate_id","")).strip();score=50;reasons=[];unknowns=[]
   if signing in {"valid","developer_id_valid","developer_id_notarized","apple_platform","mac_app_store"}:score+=25;reasons.append("Valid signature evidence: +25")
   elif signing in {"invalid","revoked"}:score-=40;reasons.append(f"{signing.title()} signature evidence: -40")
   elif signing in {"unsigned","ad_hoc"}:score-=12;reasons.append("Unsigned/ad-hoc software requires review but is not automatically malicious: -12")
   else:unknowns.append("Signature state is unknown.")
   if item.get("notarized") is True:score+=8;reasons.append("Notarization verified: +8")
   if developer:
    did=f"developer:{team or developer}";developer_trust=90 if team and signing in {"valid","developer_id_valid","developer_id_notarized","apple_platform","mac_app_store"} else 55
    entities.setdefault(did,TrustEntity(did,"developer",developer,attributes={"team_id":team,"trust_score":developer_trust,"assessment_basis":"observed signing identity; reputation alone is insufficient"}));rels.append(self._rel(sn,did,"developed_by","high",timestamp,refs,"software_inventory",0,"Signing metadata identifies the developer."))
   else:score-=8;unknowns.append("Developer identity is unavailable.")
   if cert:
    cid=f"certificate:{cert}";entities.setdefault(cid,TrustEntity(cid,"certificate",cert,attributes={"valid":item.get("certificate_valid"),"expires":item.get("certificate_expires",""),"expired":item.get("certificate_expired"),"revoked":item.get("certificate_revoked")}));rels.append(self._rel(sn,cid,"signed_by","high",timestamp,refs,"signing_assessor",0,"Code-signing evidence identifies this certificate."))
    if item.get("certificate_valid") is False or item.get("certificate_expired") is True or item.get("certificate_revoked") is True:score-=25;reasons.append("Certificate validation, expiration, or revocation evidence failed: -25")
   else:unknowns.append("Certificate identity is unavailable.")
   source=str(item.get("package_source",item.get("source",""))).strip()
   if source:
    src=f"package_source:{source}";entities.setdefault(src,TrustEntity(src,"package_source",source,attributes={}));rels.append(self._rel(sn,src,"distributed_by","medium",timestamp,refs,"software_inventory",0,"Inventory records the installation source."));score+=5 if item.get("source_verified") else 0;reasons.append("Verified distribution source: +5") if item.get("source_verified") else unknowns.append("Distribution source is not verified.")
   build_identity=str(item.get("build_identity","")).strip()
   if build_identity:
    bid=f"build:{sid}:{build_identity}";entities.setdefault(bid,TrustEntity(bid,"build",build_identity,attributes={"software_id":sid}));rels.append(self._rel(sn,bid,"built_as","medium",timestamp,refs,"software_inventory",0,"Collected build metadata identifies this build."))
   software_rows.append((sid,sn,item,refs,score,reasons,unknowns))
  for sid,sn,item,refs,score,reasons,unknowns in software_rows:
   for dep in item.get("dependencies",[]):
    if not isinstance(dep,Mapping):continue
    name=str(dep.get("name","")).strip();version=str(dep.get("version",""));drefs=self._refs(dep.get("evidence_reference",refs))
    if not name or not drefs:continue
    did=f"dependency:{name}@{version}";entities.setdefault(did,TrustEntity(did,"dependency",name,version,self._sanitize(dict(dep))));rels.append(self._rel(sn,did,"depends_on","high",timestamp,drefs,"dependency_inventory",0,"The supplied dependency manifest links this component."))
   for e in sbom_edges:
    if e.source in {sn,f"software:{item.get('bundle_identifier','')}"}:pass
   matches=[v for v in vulnerabilities if str(v.get("component",v.get("name",""))).lower() in _canon(item).lower() and v.get("cve_id") and self._refs(v.get("evidence_reference",[]))]
   if matches:score-=min(35,15*len(matches));reasons.append(f"Exact supplied vulnerability correlations ({len(matches)}): -{min(35,15*len(matches))}")
   typo=[x for x in typosquatting if str(x.get("package_name","")).lower() in _canon(item).lower() and self._refs(x.get("evidence_reference",[]))]
   if typo:score-=15;reasons.append("Evidence-backed typosquatting similarity requires review: -15")
   intel=[x for x in threat_intelligence if self._valid_intel(x) and (str(x.get("indicator_value","")).lower() in {str(item.get("sha256","")).lower(),str(item.get("developer","")).lower(),str(item.get("certificate_id","")).lower()} or str(x.get("indicator_value","")).lower() in _canon(item).lower())]
   if intel:score-=25;reasons.append("Sourced threat-intelligence association: -25")
   changes=[x for x in update_history if str(x.get("software_id",""))==sid and self._refs(x.get("evidence_reference",[])) and (x.get("previous_certificate")!=x.get("current_certificate") or x.get("previous_source")!=x.get("current_source"))]
   if changes:score-=20;reasons.append("Signing identity or update source changed: -20")
   graph_paths=[x for x in (posture_graph or {}).get("risk_paths",[]) if sid.lower() in _canon(x).lower()]
   if graph_paths:score-=10;reasons.append("Potential Security Posture Graph path: -10")
   score=max(0,min(100,score));state="trusted" if score>=85 and not unknowns else "review" if score>=35 else "high_risk"
   # append independently to avoid mutating provenance inputs
   entities[sn].attributes["calculated_trust_score"]=score
   item["_trust_result"]=(score,state,tuple(reasons),tuple(unknowns),refs)
  trust=[]
  for sid,sn,item,refs,_score,_reasons,_unknowns in software_rows:
   score,state,reasons,unknowns,refs=item["_trust_result"];trust.append(SoftwareTrustResult(sid,score,state,reasons,refs,unknowns))
  # add explicit vulnerability/intelligence/update relationships
  self._correlations(entities,rels,vulnerabilities,threat_intelligence,typosquatting,update_history,timestamp)
  risk=tuple(x.relationship_id for x in rels if x.risk_impact<0);base=SupplyChainTrustGraph(f"supply-trust-{uuid4().hex}",timestamp,tuple(sorted(entities.values(),key=lambda x:x.entity_id)),tuple(rels),tuple(trust),sbom_status,risk);digest=_hash(base.to_dict())
  return SupplyChainTrustGraph(**{**base.to_dict(),"entities":base.entities,"relationships":base.relationships,"software_trust":base.software_trust,"risk_relationships":risk,"integrity_hash":digest})
 def _sbom(self,sbom,timestamp):
  if not sbom:return [],[],"not_provided"
  entities=[];rels=[];fmt=str(sbom.get("bomFormat",sbom.get("spdxVersion",""))).lower()
  if "cyclonedx" in fmt:
   for c in sbom.get("components",[]):
    ref=str(c.get("bom-ref",c.get("name","")));name=str(c.get("name",""));evidence=self._refs(c.get("evidence_reference",sbom.get("evidence_reference",[])))
    if ref and name and evidence:entities.append(TrustEntity(f"dependency:{ref}","dependency",name,str(c.get("version","")),self._sanitize(dict(c))))
   for d in sbom.get("dependencies",[]):
    for target in d.get("dependsOn",[]):
     if f"dependency:{d.get('ref')}" in {x.entity_id for x in entities} and f"dependency:{target}" in {x.entity_id for x in entities}:rels.append(self._rel(f"dependency:{d.get('ref')}",f"dependency:{target}","depends_on","high",timestamp,self._refs(sbom.get("evidence_reference",[])),"cyclonedx_sbom",0,"CycloneDX dependency relationship."))
   return entities,rels,"cyclonedx_parsed"
  if "spdx" in fmt:
   for p in sbom.get("packages",[]):
    pid=str(p.get("SPDXID",p.get("name","")));name=str(p.get("name",""));refs=self._refs(p.get("evidence_reference",sbom.get("evidence_reference",[])))
    if pid and name and refs:entities.append(TrustEntity(f"dependency:{pid}","dependency",name,str(p.get("versionInfo","")),self._sanitize(dict(p))))
   ids={x.entity_id for x in entities}
   for r in sbom.get("relationships",[]):
    source=f"dependency:{r.get('spdxElementId')}";target=f"dependency:{r.get('relatedSpdxElement')}"
    if r.get("relationshipType")=="DEPENDS_ON" and source in ids and target in ids:rels.append(self._rel(source,target,"depends_on","high",timestamp,self._refs(sbom.get("evidence_reference",[])),"spdx_sbom",0,"SPDX dependency relationship."))
   return entities,rels,"spdx_parsed"
  return [],[],"unsupported_format"
 def _correlations(self,entities,rels,vulns,intel,typos,updates,timestamp):
  for v in vulns:
   refs=self._refs(v.get("evidence_reference",[]));cve=str(v.get("cve_id",""));component=str(v.get("component",v.get("name",""))).lower()
   if not refs or not cve:continue
   vid=f"vulnerability:{cve}";entities.setdefault(vid,TrustEntity(vid,"vulnerability",cve,attributes=self._sanitize(dict(v))))
   for eid,e in list(entities.items()):
    if e.entity_type=="dependency" and component and component==e.name.lower():rels.append(self._rel(eid,vid,"affected_by","high",timestamp,refs,"vulnerability_management",-15,"Exact component identity matched supplied vulnerability evidence."))
  for x in intel:
   if not self._valid_intel(x):continue
   iid=f"threat_indicator:{x.get('indicator_type')}:{x.get('indicator_value')}";entities.setdefault(iid,TrustEntity(iid,"threat_indicator",str(x.get("indicator_value")),attributes=self._sanitize(dict(x))))
   indicator=str(x.get("indicator_value","")).lower();kind=str(x.get("indicator_type","")).lower();refs=self._refs([x.get("reference")])
   for eid,e in list(entities.items()):
    attrs=e.attributes or {};matched=(kind in {"hash","sha256"} and str(attrs.get("sha256","")).lower()==indicator) or (kind in {"developer","team_id"} and (e.name.lower()==indicator or str(attrs.get("team_id","")).lower()==indicator)) or (kind in {"certificate","certificate_id"} and e.entity_type=="certificate" and e.name.lower()==indicator) or (kind in {"package","software"} and e.name.lower()==indicator) or (kind in {"cve","vulnerability"} and e.entity_type=="vulnerability" and e.name.lower()==indicator)
    if matched:rels.append(self._rel(eid,iid,"matched_intelligence",str(x.get("confidence")),timestamp,refs,"threat_intelligence",-25,"The observed indicator exactly matches a sourced intelligence record; this is not proof of compromise."))
  for x in typos:
   refs=self._refs(x.get("evidence_reference",[]));a=str(x.get("package_name",""));b=str(x.get("target_package",""))
   if refs and a and b:
    entities.setdefault(f"dependency:{a}",TrustEntity(f"dependency:{a}","dependency",a,attributes={"reference_only":True,"source_module":"supply_chain_security"}))
    entities.setdefault(f"dependency:{b}",TrustEntity(f"dependency:{b}","dependency",b,attributes={"reference_only":True,"source_module":"supply_chain_security"}))
   source=next((eid for eid,e in entities.items() if e.entity_type=="dependency" and e.name.lower()==a.lower()),"");target=next((eid for eid,e in entities.items() if e.entity_type=="dependency" and e.name.lower()==b.lower()),"")
   if refs and source and target:rels.append(self._rel(source,target,"similar_to",str(x.get("confidence","medium")),timestamp,refs,"supply_chain_security",-15,"Package-name similarity requires analyst review; it does not establish maliciousness."))
  for x in updates:
   refs=self._refs(x.get("evidence_reference",[]));sid=str(x.get("software_id","")).strip();sn=f"software:{sid}"
   if not refs or sn not in entities or (x.get("previous_certificate")==x.get("current_certificate") and x.get("previous_source")==x.get("current_source")):continue
   lineage=_hash({k:x.get(k) for k in ("previous_certificate","current_certificate","previous_source","current_source")})[:16];bid=f"build:{sid}:update:{lineage}"
   entities.setdefault(bid,TrustEntity(bid,"build",f"Update lineage for {sid}",attributes=self._sanitize(dict(x))));rels.append(self._rel(sn,bid,"updated_from","high",timestamp,refs,"update_monitor",-20,"Observed update source or signing identity changed and requires review."))
 def dashboard(self,g):return {"category":"Supply Chain Trust Graph","software_trust":[x.to_dict() for x in g.software_trust],"developer_identity":[x.to_dict() for x in g.entities if x.entity_type in {"developer","certificate"}],"dependencies":[x.to_dict() for x in g.entities if x.entity_type=="dependency"],"sbom_status":g.sbom_status,"vulnerabilities":[x.to_dict() for x in g.entities if x.entity_type=="vulnerability"],"risk_relationships":[x.to_dict() for x in g.relationships if x.risk_impact<0],"actions":["investigate_software","view_dependency_tree","verify_signature","export_sbom","generate_report"]}
 def analyst_context(self,g,software_id):
  r=next((x for x in g.software_trust if x.software_id==software_id),None);return {"observed_facts":r.to_dict() if r else {},"confidence":"high" if r and not r.unknowns else "medium" if r else "none","unknowns":list(r.unknowns) if r else ["Software is not present in the graph."],"guardrail":"Do not infer malicious intent, compromise, or provenance relationships not represented by evidence."}
 def incident_context(self,g,software_id):
  r=next((x for x in g.software_trust if x.software_id==software_id),None);eligible=bool(r and r.trust_state=="high_risk");return {"eligible":eligible,"authorization_required":True,"automatic_removal":False,"evidence_reference":list(r.evidence_reference) if r else [],"recommended_action":"preserve_software_dependency_certificate_and_timeline_evidence" if eligible else "continue_review"}
 @staticmethod
 def verify_integrity(g):p=g.to_dict();expected=p.pop("integrity_hash","");p["integrity_hash"]="";return bool(expected) and _hash(p)==expected
 @staticmethod
 def _rel(a,b,t,c,ts,refs,source,impact,why):return TrustRelationship("trust-rel-"+hashlib.sha256(f"{a}|{t}|{b}|{ts}".encode()).hexdigest()[:24],a,b,t,c if c in {"low","medium","high"} else "medium",ts,refs,source,impact,why)
 @staticmethod
 def _refs(v):
  if isinstance(v,str):v=[v]
  return tuple(sorted({str(x) for x in (v or []) if str(x).strip()}))
 @staticmethod
 def _sanitize(v):return {str(k):x for k,x in v.items() if not any(s in str(k).lower() for s in SENSITIVE)}
 @staticmethod
 def _valid_intel(x):
  if not (x.get("indicator_type") and x.get("indicator_value") and x.get("source") and x.get("timestamp") and x.get("confidence") in {"low","medium","high"} and x.get("reference")):return False
  try:datetime.fromisoformat(str(x["timestamp"]).replace("Z","+00:00"))
  except (TypeError,ValueError):return False
  return True

class SupplyChainTrustRepository:
 def __init__(self,database):
  self._owns=not isinstance(database,sqlite3.Connection);self.conn=sqlite3.connect(str(database)) if self._owns else database;self.conn.row_factory=sqlite3.Row;self.conn.executescript("CREATE TABLE IF NOT EXISTS trust_software(software_id TEXT PRIMARY KEY,name TEXT,version TEXT,developer TEXT,signature TEXT,hash TEXT,payload_json TEXT);CREATE TABLE IF NOT EXISTS trust_developers(developer_id TEXT PRIMARY KEY,identity TEXT,certificate TEXT,trust_score INTEGER,payload_json TEXT);CREATE TABLE IF NOT EXISTS trust_dependencies(dependency_id TEXT PRIMARY KEY,name TEXT,version TEXT,source TEXT,payload_json TEXT);CREATE TABLE IF NOT EXISTS trust_relationships(relationship_id TEXT PRIMARY KEY,source TEXT,target TEXT,relationship_type TEXT,confidence TEXT,timestamp TEXT,payload_json TEXT);CREATE TABLE IF NOT EXISTS supply_trust_graphs(graph_id TEXT PRIMARY KEY,timestamp TEXT,integrity_hash TEXT,payload_json TEXT);");self.conn.commit()
 def save(self,g):
  if not SupplyChainTrustGraphEngine.verify_integrity(g):raise ValueError("Invalid supply-chain trust graph")
  with self.conn:
   for e in g.entities:
    if e.entity_type=="software":self.conn.execute("INSERT OR REPLACE INTO trust_software VALUES(?,?,?,?,?,?,?)",(e.entity_id,e.name,e.version,str(e.attributes.get("developer","")),str(e.attributes.get("signature_status","")),str(e.attributes.get("sha256","")),_canon(e.to_dict())))
    elif e.entity_type=="developer":self.conn.execute("INSERT OR REPLACE INTO trust_developers VALUES(?,?,?,?,?)",(e.entity_id,e.name,"",int(e.attributes.get("trust_score",0)),_canon(e.to_dict())))
    elif e.entity_type=="dependency":self.conn.execute("INSERT OR REPLACE INTO trust_dependencies VALUES(?,?,?,?,?)",(e.entity_id,e.name,e.version,str(e.attributes.get("source","")),_canon(e.to_dict())))
   for r in g.relationships:self.conn.execute("INSERT OR REPLACE INTO trust_relationships VALUES(?,?,?,?,?,?,?)",(r.relationship_id,r.source,r.target,r.relationship_type,r.confidence,r.timestamp,_canon(r.to_dict())))
   self.conn.execute("INSERT INTO supply_trust_graphs VALUES(?,?,?,?)",(g.graph_id,g.timestamp,g.integrity_hash,_canon(g.to_dict())))
 def latest(self):
  row=self.conn.execute("SELECT payload_json FROM supply_trust_graphs ORDER BY timestamp DESC LIMIT 1").fetchone()
  if not row:return None
  p=json.loads(row[0]);expected=p.get("integrity_hash","");q=dict(p);q["integrity_hash"]=""
  if _hash(q)!=expected:raise ValueError("Supply-chain trust graph integrity verification failed")
  return p
 def close(self):
  if self._owns:self.conn.close()
__all__=["SupplyChainTrustGraphEngine","SupplyChainTrustGraph","SupplyChainTrustRepository","TrustEntity","TrustRelationship","SoftwareTrustResult"]
