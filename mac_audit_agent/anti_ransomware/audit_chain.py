from __future__ import annotations

import hashlib, json, time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class AuditEntry:
    sequence: int; previous_hash: str; entry_hash: str; utc_timestamp: str; monotonic_ns: int
    actor: str; component: str; action: str; policy_version: str; schema_version: str; details: dict


class TamperEvidentAuditLog:
    """Append-only logical hash chain; not claimed to be physically immutable."""
    def __init__(self,path:Path): self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
    def _entries(self):
        if not self.path.exists(): return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line]
    def append(self,*,actor,component,action,policy_version,details):
        rows=self._entries(); sequence=len(rows)+1; previous=rows[-1]["entry_hash"] if rows else "0"*64
        base={"sequence":sequence,"previous_hash":previous,"utc_timestamp":datetime.now(timezone.utc).isoformat(),"monotonic_ns":time.monotonic_ns(),"actor":actor,"component":component,"action":action,"policy_version":policy_version,"schema_version":"1.0","details":details}
        entry_hash=hashlib.sha256(json.dumps(base,sort_keys=True,separators=(",",":")).encode()).hexdigest(); entry={**base,"entry_hash":entry_hash}
        with self.path.open("a",encoding="utf-8") as handle: handle.write(json.dumps(entry,sort_keys=True,separators=(",",":"))+"\n"); handle.flush()
        return AuditEntry(**entry)
    def verify(self):
        previous="0"*64
        for expected,row in enumerate(self._entries(),1):
            entry_hash=row.pop("entry_hash","")
            if row.get("sequence")!=expected or row.get("previous_hash")!=previous or hashlib.sha256(json.dumps(row,sort_keys=True,separators=(",",":")).encode()).hexdigest()!=entry_hash:return False
            previous=entry_hash
        return True
