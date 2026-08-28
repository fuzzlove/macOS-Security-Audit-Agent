from __future__ import annotations
import hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
from uuid import uuid4
class FirewallAuditLog:
    def __init__(self,path:Path): self.path=path
    def append(self,operation:str,result:str,**evidence):
        self.path.parent.mkdir(parents=True,exist_ok=True); previous="0"*64
        try:
            last=self.path.read_text(encoding="utf-8").splitlines()[-1]; previous=json.loads(last)["digest"]
        except (OSError,IndexError,json.JSONDecodeError): pass
        payload={"event_id":f"fw-{uuid4().hex}","timestamp":datetime.now(timezone.utc).isoformat(),"uid":os.getuid(),"pid":os.getpid(),"operation":operation,"result":result,"evidence":evidence,"previous_digest":previous}
        payload["digest"]=hashlib.sha256((previous+json.dumps(payload,sort_keys=True,separators=(",",":"))).encode()).hexdigest()
        with self.path.open("a",encoding="utf-8") as handle: handle.write(json.dumps(payload,sort_keys=True)+"\n")
        return payload
