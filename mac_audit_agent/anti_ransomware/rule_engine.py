from __future__ import annotations

import base64, hashlib, json
from dataclasses import dataclass
from datetime import datetime, timezone


class RulePackageError(ValueError): pass


@dataclass(frozen=True)
class VerifiedRulePackage:
    version: int
    ruleset_version: str
    payload_sha256: str
    rule_count: int


def verify_rule_package(document: dict, public_key_pem: bytes, *, current_version: int, now=None) -> VerifiedRulePackage:
    required={"schema_version","version","ruleset_version","expires_at","rules","signature"}
    if not required.issubset(document) or document["schema_version"] != "1.0": raise RulePackageError("invalid rule package schema")
    version=int(document["version"])
    if version <= current_version: raise RulePackageError("rule package rollback or replay rejected")
    expiration=datetime.fromisoformat(str(document["expires_at"]).replace("Z","+00:00"))
    if expiration <= (now or datetime.now(timezone.utc)): raise RulePackageError("rule package expired")
    rules=document["rules"]
    if not isinstance(rules,list) or len(rules)>10000: raise RulePackageError("invalid or oversized rule list")
    ids=[item.get("rule_id") for item in rules if isinstance(item,dict)]
    if len(ids)!=len(rules) or len(set(ids))!=len(ids): raise RulePackageError("duplicate or malformed rule identifiers")
    unsigned={key:value for key,value in document.items() if key!="signature"}
    payload=json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        key=load_pem_public_key(public_key_pem); key.verify(base64.b64decode(document["signature"],validate=True),payload)
    except Exception as exc: raise RulePackageError("rule package signature invalid") from exc
    return VerifiedRulePackage(version,str(document["ruleset_version"]),hashlib.sha256(payload).hexdigest(),len(rules))
