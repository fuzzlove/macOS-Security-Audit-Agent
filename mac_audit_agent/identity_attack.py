"""Privacy-preserving identity attack correlation over existing MSAA telemetry."""
from __future__ import annotations
import hashlib,json,socket,sqlite3
from dataclasses import asdict,dataclass,field
from pathlib import Path
from typing import Any
from uuid import uuid4
from mac_audit_agent.models import BackgroundMonitorEvent,utc_now_iso

FORBIDDEN=("password","token","secret","private_key","credential_value","key_material","cookie_value")
MITRE={"keychain_access":["T1555.001"],"browser_credential_access":["T1555.003"],"account_change":["T1098"],"ssh_identity_change":["T1098"],"privilege_escalation":["T1548"],"account_discovery":["T1087"],"valid_account_anomaly":["T1078"]}

class IdentityDetectionError(RuntimeError):pass
@dataclass
class IdentityEvent:
 event_id:str;timestamp:str;hostname:str;username:str;event_type:str;process_name:str="";process_path:str="";parent_process:str="";signature_status:str="unknown";developer_identity:str="";resource_accessed:str="";identity_action:str="";mitre_attack:list[str]=field(default_factory=list);severity:str="medium";confidence_score:int=50;description:str="";recommendation:str="";analyst_status:str="open";evidence:list[str]=field(default_factory=list);baseline_status:str="unknown"
 def to_dict(self):return asdict(self)
 def to_finding(self):return {"finding_id":self.event_id,"title":self.description,"severity":self.severity,"confidence":"high" if self.confidence_score>=80 else "medium" if self.confidence_score>=55 else "low","event_type":self.event_type,"process_name":self.process_name,"path":self.process_path,"parent_process":self.parent_process,"signature_status":self.signature_status,"mitre_attack":self.mitre_attack,"evidence":self.evidence,"recommended_action":self.recommendation,"timestamp":self.timestamp}

class IdentityEventStore:
 def __init__(self,path:Path):
  self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True);self.connection=sqlite3.connect(self.path);self.connection.row_factory=sqlite3.Row
  self.connection.execute("CREATE TABLE IF NOT EXISTS identity_events(event_id TEXT PRIMARY KEY,timestamp TEXT,hostname TEXT,username TEXT,event_type TEXT,process_name TEXT,process_path TEXT,parent_process TEXT,signature_status TEXT,developer_identity TEXT,resource_accessed TEXT,identity_action TEXT,mitre_attack_json TEXT,severity TEXT,confidence_score INTEGER,description TEXT,recommendation TEXT,analyst_status TEXT,evidence_json TEXT,baseline_status TEXT,payload_hash TEXT)");self.connection.commit()
 def record(self,event:IdentityEvent):
  payload=event.to_dict();encoded=json.dumps(payload,sort_keys=True).encode();values=[payload[k] for k in ("event_id","timestamp","hostname","username","event_type","process_name","process_path","parent_process","signature_status","developer_identity","resource_accessed","identity_action")]+[json.dumps(event.mitre_attack),event.severity,event.confidence_score,event.description,event.recommendation,event.analyst_status,json.dumps(event.evidence),event.baseline_status,hashlib.sha256(encoded).hexdigest()]
  self.connection.execute("INSERT INTO identity_events VALUES("+",".join("?" for _ in values)+")",values);self.connection.commit()
 def recent(self,limit=100):return [dict(r) for r in self.connection.execute("SELECT * FROM identity_events ORDER BY timestamp DESC LIMIT ?",(limit,)).fetchall()]

class IdentityAttackDetector:
 def __init__(self,store:IdentityEventStore,shared_event_store:Any|None=None):self.store,self.shared=store,shared_event_store
 def process(self,telemetry:dict[str,Any])->IdentityEvent|None:
  self._validate(telemetry);kind=str(telemetry.get("event_type","")).lower();score=0;evidence=[]
  signed=str(telemetry.get("signature_status","unknown")).lower();path=str(telemetry.get("process_path","") or "")
  if signed in {"unsigned","invalid"}:score+=25;evidence.append(f"process signature status: {signed}")
  if any(x in path for x in ("/tmp/","/private/tmp/","/var/tmp/")):score+=20;evidence.append("process originated from a temporary location")
  if telemetry.get("new_behavior"):score+=20;evidence.append("behavior is new relative to the approved identity baseline")
  if kind in {"keychain_access","browser_credential_access"}:
   if not telemetry.get("trusted_process_telemetry"):raise IdentityDetectionError("Credential-access detection requires trusted process telemetry.")
   score+=35;evidence.append("trusted telemetry observed access to a credential-store resource")
  elif kind=="account_change":
   if telemetry.get("administrator_added"):score+=85;evidence.append("administrator membership was added")
   else:score+=30;evidence.append("account or group membership changed")
  elif kind=="ssh_identity_change":score+=65;evidence.append("authorized SSH identity metadata changed")
  elif kind=="privilege_escalation":
   failures=int(telemetry.get("failure_count",0) or 0);score+=min(50,failures*10)
   if failures>=3:evidence.append(f"{failures} failed elevation attempts observed")
   if telemetry.get("approved_maintenance"):score=max(0,score-35);evidence.append("approved maintenance context reduced risk")
  elif kind=="authentication_event":
   failures=int(telemetry.get("failure_count",0) or 0);unusual=bool(telemetry.get("unusual_time") or telemetry.get("new_source"));score+=min(45,failures*7)+(20 if unusual else 0)
   if failures:evidence.append(f"{failures} authentication failures observed; no attempted passwords collected")
   kind="valid_account_anomaly"
  elif kind=="identity_command":
   commands={str(x).lower() for x in telemetry.get("commands",[])}
   if not commands.intersection({"security","dscl","sudo","ssh","login","id","groups"}):return None
   if signed in {"unsigned","invalid"} and len(commands)>=2:kind="account_discovery";score+=35;evidence.append("untrusted process invoked multiple identity-related commands")
   else:return None
  else:raise IdentityDetectionError("Unsupported identity telemetry event type.")
  if score<25:return None
  severity="critical" if score>=80 else "high" if score>=60 else "medium"
  event=IdentityEvent(f"identity-{uuid4().hex}",str(telemetry.get("timestamp") or utc_now_iso()),socket.gethostname(),str(telemetry.get("username") or "unknown"),kind,str(telemetry.get("process_name") or ""),path,str(telemetry.get("parent_process") or ""),signed,str(telemetry.get("developer_identity") or ""),str(telemetry.get("resource_accessed") or ""),str(telemetry.get("identity_action") or ""),MITRE.get(kind,[]),severity,min(100,score),_description(kind),"Preserve identity and process evidence; verify authorization, provenance, related sessions, persistence, and network activity before changing any account.","open",evidence,str(telemetry.get("baseline_status") or "unknown"))
  self.store.record(event)
  if self.shared:self.shared.record_background_monitor_event(_shared_event(event),dedupe_window_seconds=0)
  return event
 def _validate(self,value:Any,path="telemetry"):
  if isinstance(value,dict):
   for k,v in value.items():
    if any(secret in str(k).lower() for secret in FORBIDDEN):raise IdentityDetectionError(f"Secret-bearing field rejected: {path}.{k}")
    self._validate(v,f"{path}.{k}")
  elif isinstance(value,(list,tuple)):
   for i,v in enumerate(value):self._validate(v,f"{path}[{i}]")

class IdentityBaseline:
 def __init__(self,path:Path):self.path=Path(path)
 def save(self,accounts:list[dict],approved_apps:list[dict]):
  payload={"created_at":utc_now_iso(),"accounts":accounts,"approved_apps":approved_apps};self.path.parent.mkdir(parents=True,exist_ok=True);self.path.write_text(json.dumps(payload,sort_keys=True,indent=2));self.path.chmod(0o600)
 def compare_accounts(self,current:list[dict])->dict:
  if not self.path.exists():return {"status":"missing","new_accounts":[],"new_admins":[]}
  old=json.loads(self.path.read_text());prior={x["username"]:x for x in old.get("accounts",[])};return {"status":"compared","new_accounts":[x for x in current if x["username"] not in prior],"new_admins":[x for x in current if x.get("admin") and not prior.get(x["username"],{}).get("admin")]}

def _description(kind):return {"keychain_access":"Suspicious Keychain access metadata observed","browser_credential_access":"Possible browser credential-store access","account_change":"Account or group membership change","ssh_identity_change":"SSH identity metadata changed","privilege_escalation":"Suspicious privilege escalation behavior","valid_account_anomaly":"Unusual authentication behavior","account_discovery":"Contextual identity command activity"}.get(kind,"Identity security event")
def _shared_event(e):
 metadata=e.to_dict();return BackgroundMonitorEvent(event_id=e.event_id,timestamp=e.timestamp,event_type=e.event_type,severity=e.severity,source="identity_attack_detection",process_name=e.process_name,evidence="; ".join(e.evidence),confidence="high" if e.confidence_score>=80 else "medium",recommendation=e.recommendation,metadata_json=json.dumps(metadata,sort_keys=True),related_process=e.process_path,related_user=e.username,correlation_id=e.event_id)
__all__=["IdentityAttackDetector","IdentityBaseline","IdentityDetectionError","IdentityEvent","IdentityEventStore"]
