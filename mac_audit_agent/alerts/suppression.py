from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from mac_audit_agent.alerts.resilient_models import SecurityEvent
from mac_audit_agent.alerts.resilient_store import ResilientEventStore


@dataclass(frozen=True)
class SuppressionRequest:
    scope: str
    conditions: dict[str, str]
    owner: str
    created_at: str
    expires_at: str
    reason: str
    ticket_id: str
    authorizing_identity: str
    policy_version: str = "1"
    approval_identity: str = ""
    rule_id: str = ""


class SuppressionPolicy:
    SAFE_FIELDS = {"rule_id", "event_type", "source_id", "process_signing_identifier", "user_uid", "host_id"}

    def __init__(self, store: ResilientEventStore, *, two_person_protected: bool = False) -> None:
        self.store = store
        self.db = store.db
        self.two_person_protected = two_person_protected

    def create(self, request: SuppressionRequest, *, protected_scope: bool = False) -> str:
        if not request.reason.strip() or not request.ticket_id.strip() or not request.authorizing_identity.strip():
            raise ValueError("reason, ticket identifier, and authorizing identity are required")
        if not request.conditions or any(key not in self.SAFE_FIELDS for key in request.conditions):
            raise ValueError("suppression conditions must use supported exact-match fields")
        if any(value in {"", "*", ".*"} for value in request.conditions.values()):
            raise ValueError("global or wildcard suppression is prohibited")
        now = datetime.now(timezone.utc)
        try:
            expires = datetime.fromisoformat(request.expires_at)
            if expires.tzinfo is None:
                raise ValueError
        except ValueError as exc:
            raise ValueError("expiration must be an explicit timezone-aware ISO timestamp") from exc
        if expires <= now:
            raise ValueError("suppression expiration must be in the future")
        if (expires - now).total_seconds() > self.store.config.maximum_suppression_duration_seconds:
            raise ValueError("suppression duration exceeds the configured maximum")
        if protected_scope and (not request.approval_identity or request.approval_identity == request.authorizing_identity):
            raise PermissionError("protected-event suppression requires a distinct approval identity")
        rule_id = request.rule_id or f"suppression-{uuid4()}"
        self.db.conn.execute(
            "INSERT INTO resilient_suppressions(rule_id,scope,conditions_json,owner,created_at,expires_at,reason,ticket_id,authorizing_identity,approval_identity,policy_version) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (rule_id,request.scope,json.dumps(request.conditions,sort_keys=True),request.owner,request.created_at,request.expires_at,request.reason,request.ticket_id,request.authorizing_identity,request.approval_identity,request.policy_version),
        )
        self.store.audit("suppression_created",actor=request.authorizing_identity,reason=request.reason,object_id=rule_id,details={"scope":request.scope,"conditions":request.conditions,"expires_at":request.expires_at,"ticket_id":request.ticket_id,"protected_scope":protected_scope})
        self.db.conn.commit()
        return rule_id

    def revoke(self, rule_id: str, *, actor: str, reason: str) -> bool:
        if not actor.strip() or not reason.strip():
            raise ValueError("actor and reason are required")
        cursor = self.db.conn.execute("UPDATE resilient_suppressions SET revoked_at=? WHERE rule_id=? AND revoked_at=''", (datetime.now(timezone.utc).isoformat(),rule_id))
        if cursor.rowcount:
            self.store.audit("suppression_revoked",actor=actor,reason=reason,object_id=rule_id,details={})
            self.db.conn.commit()
            return True
        return False

    def matching_rule(self, event: SecurityEvent) -> str:
        now = datetime.now(timezone.utc).isoformat()
        for row in self.db.conn.execute("SELECT * FROM resilient_suppressions WHERE revoked_at='' AND expires_at>? ORDER BY created_at", (now,)):
            if event.protected:
                continue
            conditions = json.loads(str(row["conditions_json"]))
            if all(str(getattr(event, key, "")) == str(value) for key, value in conditions.items()):
                return str(row["rule_id"])
        return ""

    def list(self, *, include_expired: bool = False) -> list[dict[str, Any]]:
        where = "" if include_expired else "WHERE revoked_at='' AND expires_at>?"
        params: tuple[Any, ...] = () if include_expired else (datetime.now(timezone.utc).isoformat(),)
        return [dict(row) for row in self.db.conn.execute(f"SELECT * FROM resilient_suppressions {where} ORDER BY created_at DESC", params)]
