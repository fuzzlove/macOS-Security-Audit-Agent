"""General DFIR case repository with hashed artifacts and chained custody."""
from __future__ import annotations
import hashlib,json,os,platform,socket,sqlite3,tempfile,zipfile
from dataclasses import asdict,dataclass
from pathlib import Path
from typing import Any,Callable
from uuid import uuid4
from mac_audit_agent.models import utc_now_iso

FORBIDDEN=("password","token","secret","private_key","key_material","credential_value","cookie_value")
class EvidenceError(RuntimeError):pass
@dataclass
class EvidenceCase:
 case_id:str;created_at:str;analyst:str;description:str;severity:str;status:str="ACTIVE";related_alerts:list[str]=None;integrity_status:str="NOT_COLLECTED"
 def __post_init__(self):self.related_alerts=list(self.related_alerts or [])
 def to_dict(self):return asdict(self)
@dataclass
class EvidenceArtifact:
 case_id:str;evidence_id:str;timestamp:str;collector_version:str;artifact_name:str;artifact_path:str;artifact_hash:str;hash_algorithm:str;size:int;creation_timestamp:str;collection_method:str;collected_by:str;integrity_status:str="VERIFIED";chain_of_custody_status:str="CURRENT"
 def to_dict(self):return asdict(self)

class EvidenceRepository:
 def __init__(self,root:Path,db_path:Path,collector_version="MSAA"):
  self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True,mode=0o700);self.root.chmod(0o700)
  if self.root.is_symlink():raise EvidenceError("Evidence repository may not be a symlink.")
  self.collector_version=collector_version;self.db=sqlite3.connect(db_path);self.db.row_factory=sqlite3.Row
  self.db.executescript("""CREATE TABLE IF NOT EXISTS evidence_cases(case_id TEXT PRIMARY KEY,created_at TEXT,analyst TEXT,description TEXT,severity TEXT,status TEXT,related_alerts_json TEXT,integrity_status TEXT);CREATE TABLE IF NOT EXISTS evidence_artifacts(case_id TEXT,evidence_id TEXT PRIMARY KEY,timestamp TEXT,collector_version TEXT,artifact_name TEXT,artifact_path TEXT,artifact_hash TEXT,hash_algorithm TEXT,size INTEGER,creation_timestamp TEXT,collection_method TEXT,collected_by TEXT,integrity_status TEXT,chain_of_custody_status TEXT);CREATE TABLE IF NOT EXISTS evidence_custody(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE,evidence_id TEXT,timestamp TEXT,user TEXT,action TEXT,reason TEXT,system_identity TEXT,previous_hash TEXT,entry_hash TEXT);""");self.db.commit()
 def create_case(self,analyst:str,description:str,severity:str,related_alerts=None)->EvidenceCase:
  if not analyst.strip() or not description.strip():raise EvidenceError("Named analyst and case description are required.")
  case=EvidenceCase(f"MSAA-IR-{utc_now_iso()[:4]}-{uuid4().hex[:8].upper()}",utc_now_iso(),analyst,description,severity.upper(),related_alerts=related_alerts or [])
  base=self.root/case.case_id
  for name in ("evidence","manifest","reports","logs"):p=base/name;p.mkdir(parents=True,mode=0o700);p.chmod(0o700)
  self.db.execute("INSERT INTO evidence_cases VALUES(?,?,?,?,?,?,?,?)",(case.case_id,case.created_at,case.analyst,case.description,case.severity,case.status,json.dumps(case.related_alerts),case.integrity_status));self.db.commit();self._custody(case.case_id,case.created_at,analyst,"CREATED","Case created");return case
 def collect_snapshot(self,case_id:str,user:str,collectors:dict[str,Callable[[],Any]])->dict[str,Any]:
  self._case(case_id);artifacts=[];errors={}
  for name,collector in sorted(collectors.items()):
   safe="".join(c if c.isalnum() or c in "-_" else "_" for c in name) or "collector"
   try:data=collector();self._reject_secrets(data);artifacts.append(self.add_json(case_id,f"{safe}.json",data,user,"READ_ONLY_COLLECTOR"))
   except Exception as exc:errors[name]={"error_type":type(exc).__name__,"message":str(exc)};self._custody(case_id,utc_now_iso(),user,"COLLECTION_FAILED",f"{name}: {type(exc).__name__}: {exc}")
  manifest=self.generate_manifest(case_id,user,collection_status="PARTIAL" if errors else "COMPLETE",collector_errors=errors)
  self.db.execute("UPDATE evidence_cases SET integrity_status=? WHERE case_id=?",("PARTIAL" if errors else "VERIFIED",case_id));self.db.commit();return {"case_id":case_id,"artifacts":[a.to_dict() for a in artifacts],"errors":errors,"manifest":str(manifest)}
 def add_json(self,case_id:str,name:str,payload:Any,user:str,method:str)->EvidenceArtifact:
  self._case(case_id);self._reject_secrets(payload);destination=self.root/case_id/"evidence"/Path(name).name;encoded=json.dumps(payload,sort_keys=True,indent=2,default=str).encode();self._atomic(destination,encoded)
  st=destination.stat();artifact=EvidenceArtifact(case_id,f"evidence-{uuid4().hex}",utc_now_iso(),self.collector_version,destination.name,str(destination),hashlib.sha256(encoded).hexdigest(),"SHA-256",len(encoded),utc_now_iso(),method,user)
  self.db.execute("INSERT INTO evidence_artifacts VALUES("+",".join("?" for _ in artifact.to_dict())+")",tuple(artifact.to_dict().values()));self.db.commit();self._custody(artifact.evidence_id,artifact.timestamp,user,"COLLECTED",f"case={case_id}; method={method}");return artifact
 def verify(self,evidence_id:str,user:str,reason="Integrity verification")->str:
  row=self.db.execute("SELECT * FROM evidence_artifacts WHERE evidence_id=?",(evidence_id,)).fetchone()
  if not row:raise EvidenceError("Evidence record not found.")
  path=Path(row["artifact_path"]);status="MATCH" if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==row["artifact_hash"] else "MODIFIED"
  self.db.execute("UPDATE evidence_artifacts SET integrity_status=? WHERE evidence_id=?",(status,evidence_id));self.db.commit();self._custody(evidence_id,utc_now_iso(),user,"VERIFIED",f"{reason}: {status}");return status
 def verify_case(self,case_id:str,user:str)->dict[str,str]:
  return {r["evidence_id"]:self.verify(r["evidence_id"],user) for r in self.db.execute("SELECT evidence_id FROM evidence_artifacts WHERE case_id=?",(case_id,)).fetchall()}
 def generate_manifest(self,case_id:str,user:str,**metadata)->Path:
  case=dict(self._case(case_id));rows=[dict(r) for r in self.db.execute("SELECT * FROM evidence_artifacts WHERE case_id=? ORDER BY timestamp,evidence_id",(case_id,)).fetchall()];payload={"schema_version":"1.0","case":case,"collection_time":utc_now_iso(),"collector_version":self.collector_version,"host":{"hostname":socket.gethostname(),"platform":platform.platform()},"files":rows,"integrity_status":"VERIFIED" if all(r["integrity_status"] in {"VERIFIED","MATCH"} for r in rows) else "REVIEW_REQUIRED",**metadata};path=self.root/case_id/"manifest"/"evidence_manifest.json";self._atomic(path,json.dumps(payload,indent=2,sort_keys=True).encode());self._custody(case_id,utc_now_iso(),user,"MANIFEST_CREATED",str(path));return path
 def timeline(self,case_id:str)->list[dict[str,Any]]:
  ids=[case_id]+[r[0] for r in self.db.execute("SELECT evidence_id FROM evidence_artifacts WHERE case_id=?",(case_id,)).fetchall()];q="SELECT * FROM evidence_custody WHERE evidence_id IN ("+",".join("?" for _ in ids)+") ORDER BY sequence";return [dict(r) for r in self.db.execute(q,ids).fetchall()]
 def verify_custody_chain(self)->bool:
  previous=""
  for row in self.db.execute("SELECT * FROM evidence_custody ORDER BY sequence").fetchall():
   value={k:row[k] for k in ("event_id","evidence_id","timestamp","user","action","reason","system_identity","previous_hash")};expected=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
   if row["previous_hash"]!=previous or row["entry_hash"]!=expected:return False
   previous=row["entry_hash"]
  return True
 def export_zip(self,case_id:str,destination:Path,user:str)->Path:
  results=self.verify_case(case_id,user)
  if any(v!="MATCH" for v in results.values()):raise EvidenceError("Case integrity verification failed; export was blocked.")
  manifest=self.generate_manifest(case_id,user,collection_status="EXPORTED");base=self.root/case_id;destination.parent.mkdir(parents=True,exist_ok=True)
  with zipfile.ZipFile(destination,"w",zipfile.ZIP_DEFLATED) as z:
   for p in sorted(base.rglob("*")):
    if p.is_file() and not p.is_symlink():z.write(p,p.relative_to(base))
  destination.chmod(0o600);digest=hashlib.sha256(destination.read_bytes()).hexdigest();destination.with_suffix(destination.suffix+".sha256").write_text(digest+"  "+destination.name+"\n");self._custody(case_id,utc_now_iso(),user,"EXPORTED",f"{destination}; sha256={digest}");return destination
 def _case(self,case_id):
  row=self.db.execute("SELECT * FROM evidence_cases WHERE case_id=?",(case_id,)).fetchone()
  if not row:raise EvidenceError("Evidence case not found.")
  return row
 def _atomic(self,path,data):
  fd,temp=tempfile.mkstemp(prefix=".evidence-",dir=path.parent)
  try:
   os.fchmod(fd,0o600)
   with os.fdopen(fd,"wb") as h:h.write(data);h.flush();os.fsync(h.fileno())
   os.replace(temp,path)
  finally:
   if os.path.exists(temp):os.unlink(temp)
 def _custody(self,evidence_id,timestamp,user,action,reason):
  prior=self.db.execute("SELECT entry_hash FROM evidence_custody ORDER BY sequence DESC LIMIT 1").fetchone();previous=prior[0] if prior else "";value={"event_id":f"custody-{uuid4().hex}","evidence_id":evidence_id,"timestamp":timestamp,"user":user,"action":action,"reason":reason,"system_identity":socket.gethostname(),"previous_hash":previous};value["entry_hash"]=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest();self.db.execute("INSERT INTO evidence_custody(event_id,evidence_id,timestamp,user,action,reason,system_identity,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?,?)",tuple(value.values()));self.db.commit()
 def _reject_secrets(self,value,path="evidence"):
  if isinstance(value,dict):
   for k,v in value.items():
    if any(x in str(k).lower() for x in FORBIDDEN):raise EvidenceError(f"Unauthorized secret-bearing field rejected: {path}.{k}")
    self._reject_secrets(v,path+"."+str(k))
  elif isinstance(value,(list,tuple)):
   for i,v in enumerate(value):self._reject_secrets(v,f"{path}[{i}]")
__all__=["EvidenceArtifact","EvidenceCase","EvidenceError","EvidenceRepository"]
