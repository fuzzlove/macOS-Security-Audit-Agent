from __future__ import annotations
import hashlib,json

def artifact_hash(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def chain_event(previous_hash:str,event:dict)->str:
    if len(previous_hash)!=64:raise ValueError("previous evidence hash must be SHA-256")
    return hashlib.sha256((previous_hash+json.dumps(event,sort_keys=True,separators=(",",":"))).encode()).hexdigest()
