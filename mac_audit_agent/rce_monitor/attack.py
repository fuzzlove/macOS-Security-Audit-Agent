from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib,json
from datetime import datetime,timezone,timedelta

from mac_audit_agent.mission_governance import LocalAttackSTIXProvider


class RCEAttackValidator:
    """Validates ATT&CK identifiers against an administrator-supplied STIX file."""
    def __init__(self,path:Path|None,*,freshness_hours:int=720)->None:
        self.path=path; self.freshness_hours=freshness_hours; self.provider=LocalAttackSTIXProvider(path) if path and path.exists() else None; self.metadata=self._metadata()

    def _metadata(self)->dict[str,Any]:
        if not self.path or not self.path.is_file():return {"status":"UNAVAILABLE","version":"Not configured","retrieval_date":"Not verified","source_hash":""}
        try:
            raw=self.path.read_bytes(); payload=json.loads(raw.decode("utf-8")); retrieved=str(payload.get("x_msaa_retrieved_at") or payload.get("retrieved_at") or datetime.fromtimestamp(self.path.stat().st_mtime,timezone.utc).isoformat()); parsed=datetime.fromisoformat(retrieved.replace("Z","+00:00")); stale=datetime.now(timezone.utc)-parsed>timedelta(hours=self.freshness_hours)
            return {"status":"STALE" if stale else "CURRENT","version":str(payload.get("x_mitre_version") or payload.get("spec_version") or "Not supplied"),"retrieval_date":retrieved,"source_hash":hashlib.sha256(raw).hexdigest()}
        except (OSError,ValueError,json.JSONDecodeError):return {"status":"INVALID","version":"Not verified","retrieval_date":"Not verified","source_hash":""}

    def validate(self,technique_id:str)->dict[str,Any]:
        if self.provider is None:
            return {"technique_id":technique_id,"validation_status":"UNVERIFIED","reason":"ATT&CK data unavailable",**self.metadata}
        record=self.provider.validate(technique_id)
        if record is None:
            return {"technique_id":technique_id,"validation_status":"REJECTED","reason":"identifier absent from configured ATT&CK data",**self.metadata}
        return {"technique_id":technique_id,"validation_status":"VALIDATED","record":dict(record),**self.metadata}

    def status(self)->dict[str,Any]:return dict(self.metadata)
