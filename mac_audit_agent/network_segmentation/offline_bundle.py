from __future__ import annotations
import hashlib,hmac,json
from typing import Any

MAX_BUNDLE_BYTES=1024*1024
def create_bundle(kind:str,payload:dict[str,Any],key:bytes)->bytes:
    if kind not in {"job","result"}:raise ValueError("unsupported offline bundle type")
    body=json.dumps({"schema":"msaa.segmentation.offline.v1","kind":kind,"payload":payload},sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    if len(body)>MAX_BUNDLE_BYTES:raise ValueError("offline bundle exceeds size limit")
    signature=hmac.new(key,body,hashlib.sha256).hexdigest()
    return json.dumps({"body":body.decode(),"signature":signature},sort_keys=True,separators=(",",":")).encode()
def verify_bundle(blob:bytes,key:bytes)->dict[str,Any]:
    if len(blob)>MAX_BUNDLE_BYTES:raise ValueError("offline bundle exceeds size limit")
    envelope=json.loads(blob);body=str(envelope["body"]).encode();expected=hmac.new(key,body,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,str(envelope["signature"])):raise PermissionError("offline bundle signature invalid")
    payload=json.loads(body)
    if payload.get("schema")!="msaa.segmentation.offline.v1":raise ValueError("unsupported offline bundle schema")
    return payload
