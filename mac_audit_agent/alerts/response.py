from __future__ import annotations

import hashlib
import json
from typing import Any

from mac_audit_agent.models import utc_now_iso


def action_idempotency_key(policy_id: str, fingerprint: str, action_type: str, target_identity: str, incident_id: str) -> str:
    canonical = json.dumps([policy_id,fingerprint,action_type,target_identity,incident_id],separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def reserve_action(db: Any, *, policy_id: str, fingerprint: str, action_type: str, target_identity: str, incident_id: str, previous_state: dict[str, Any] | None = None) -> tuple[str, bool]:
    key = action_idempotency_key(policy_id,fingerprint,action_type,target_identity,incident_id)
    now = utc_now_iso()
    cursor = db.conn.execute("INSERT OR IGNORE INTO resilient_action_idempotency(idempotency_key,action_type,target_identity,status,attempt_count,previous_state_json,result_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (key,action_type,target_identity,"reserved",0,json.dumps(previous_state or {},sort_keys=True),"{}",now,now))
    db.conn.commit()
    return key, bool(cursor.rowcount)


def complete_action(db: Any, key: str, *, success: bool, result: dict[str, Any]) -> None:
    db.conn.execute("UPDATE resilient_action_idempotency SET status=?,attempt_count=attempt_count+1,result_json=?,updated_at=? WHERE idempotency_key=?", ("succeeded" if success else "failed",json.dumps(result,sort_keys=True),utc_now_iso(),key))
    db.conn.commit()
