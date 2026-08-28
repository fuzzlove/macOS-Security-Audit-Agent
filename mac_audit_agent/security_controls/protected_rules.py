from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuleBundleStatus:
    valid:bool
    rule_version:str
    error_code:str
    bundle_digest:str


def verify_rule_bundle(bundle_path:Path,signature_path:Path,public_key_pem:bytes)->RuleBundleStatus:
    data=bundle_path.read_bytes();digest=hashlib.sha256(data).hexdigest()
    try:
        envelope=json.loads(signature_path.read_text(encoding="utf-8"));signature=base64.b64decode(envelope["signature"],validate=True)
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        key=load_pem_public_key(public_key_pem);key.verify(signature,data)
        payload=json.loads(data);version=str(payload.get("rule_version") or "")
        if not version:return RuleBundleStatus(False,"","RULE_BUNDLE_VERSION_MISSING",digest)
        return RuleBundleStatus(True,version,"",digest)
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError,ImportError):
        return RuleBundleStatus(False,"","RULE_BUNDLE_SIGNATURE_INVALID",digest)
