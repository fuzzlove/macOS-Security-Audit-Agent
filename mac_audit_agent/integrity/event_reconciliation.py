from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import sqlite3
from typing import Any

from mac_audit_agent.integrity.dev_manifest import utc_now_iso


ACTIVE_INTEGRITY_EVENT_TYPES = {
    "integrity_unknown",
    "signed_manifest_validation_failed",
    "unsigned_or_modified_manifest",
    "release_artifact_mismatch",
    "source_integrity_changed",
    "integrity_validation_failed",
}


@dataclass(slots=True)
class IntegrityEventReconciliationResult:
    status: str
    superseded_event_ids: list[str] = field(default_factory=list)
    active_event_ids: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def reconcile_integrity_events_after_verified_repair(current_status: Any, db: Any | None = None) -> IntegrityEventReconciliationResult:
    if getattr(current_status, "status", "") != "verified":
        return IntegrityEventReconciliationResult(
            status="not_reconciled",
            message="current integrity status is not verified",
        )
    if db is None:
        return IntegrityEventReconciliationResult(
            status="no_event_store",
            message="no event database was supplied; reconciliation is a no-op",
        )

    events = _load_active_integrity_events(db)
    superseded: list[str] = []
    active: list[str] = []
    now = utc_now_iso()
    manifest_sha = getattr(current_status, "manifest_sha256", "")
    evidence_path = getattr(current_status, "evidence_path", "")
    for event in events:
        event_id = str(event.get("id") or event.get("event_id") or event.get("uuid") or "")
        event_type = str(event.get("event_type") or event.get("type") or event.get("finding_id") or "")
        if event_type not in ACTIVE_INTEGRITY_EVENT_TYPES:
            continue
        if not event_id:
            active.append(event_type)
            continue
        payload = {
            "superseded_by_manifest_sha256": manifest_sha,
            "superseded_at": now,
            "repair_evidence_path": evidence_path,
            "resolution": "Superseded by verified developer-machine signed manifest.",
        }
        if _mark_superseded(db, event_id, payload):
            superseded.append(event_id)
        else:
            active.append(event_id)
    return IntegrityEventReconciliationResult(
        status="reconciled" if not active else "partial",
        superseded_event_ids=superseded,
        active_event_ids=active,
        message="active integrity events superseded" if superseded else "no active integrity events found",
    )


def _load_active_integrity_events(db: Any) -> list[dict[str, Any]]:
    for name in ("list_active_integrity_events", "get_active_integrity_events"):
        method = getattr(db, name, None)
        if callable(method):
            return [dict(item) for item in method()]
    method = getattr(db, "list_events", None)
    if callable(method):
        rows = method()
        return [
            dict(row)
            for row in rows
            if str(dict(row).get("event_type") or dict(row).get("type") or dict(row).get("finding_id") or "") in ACTIVE_INTEGRITY_EVENT_TYPES
            and not dict(row).get("superseded_at")
            and str(dict(row).get("status", "active")) not in {"resolved", "superseded"}
        ]
    return []


def _mark_superseded(db: Any, event_id: str, payload: dict[str, Any]) -> bool:
    for name in ("mark_integrity_event_superseded", "mark_event_superseded"):
        method = getattr(db, name, None)
        if callable(method):
            method(event_id, payload)
            return True
    method = getattr(db, "update_event", None)
    if callable(method):
        method(event_id, payload | {"status": "superseded"})
        return True
    return False


class SQLiteIntegrityEventStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)

    def list_active_integrity_events(self) -> list[dict[str, Any]]:
        if not self.db_path.exists():
            return []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            table = "background_monitor_events" if "background_monitor_events" in tables else "events" if "events" in tables else ""
            if not table:
                return []
            columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            id_col = "id" if "id" in columns else "event_id" if "event_id" in columns else "rowid"
            type_col = "event_type" if "event_type" in columns else "type" if "type" in columns else "finding_id" if "finding_id" in columns else ""
            status_col = "status" if "status" in columns else ""
            if not type_col:
                return []
            rows = conn.execute(f"SELECT {id_col} AS id, {type_col} AS event_type{', ' + status_col + ' AS status' if status_col else ''} FROM {table}").fetchall()
            return [
                dict(row)
                for row in rows
                if str(dict(row).get("event_type", "")) in ACTIVE_INTEGRITY_EVENT_TYPES
                and str(dict(row).get("status", "active")) not in {"resolved", "superseded", "historical"}
            ]

    def mark_integrity_event_superseded(self, event_id: str, payload: dict[str, Any]) -> None:
        with sqlite3.connect(self.db_path) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            table = "background_monitor_events" if "background_monitor_events" in tables else "events" if "events" in tables else ""
            if not table:
                return
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            id_col = "id" if "id" in columns else "event_id" if "event_id" in columns else "rowid"
            if "status" in columns:
                conn.execute(f"UPDATE {table} SET status = ? WHERE {id_col} = ?", ("superseded", event_id))
            for column, value in payload.items():
                if column in columns:
                    conn.execute(f"UPDATE {table} SET {column} = ? WHERE {id_col} = ?", (str(value), event_id))


__all__ = [
    "ACTIVE_INTEGRITY_EVENT_TYPES",
    "IntegrityEventReconciliationResult",
    "SQLiteIntegrityEventStore",
    "reconcile_integrity_events_after_verified_repair",
]
