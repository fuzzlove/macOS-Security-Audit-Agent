from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Tuple

from .models import ClickFixIncident, ClickFixShortcutEvent

GENESIS = "0" * 64
SCHEMA_VERSION = 1


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("ascii")


class ClickFixEvidenceStore:
    """Dedicated append-only hash chain with atomic event/incident commits."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), timeout=5.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self._migrate()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _migrate(self) -> None:
        with self.connection:
            self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS clickfix_schema(version INTEGER NOT NULL, checksum TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS clickfix_records(
              sequence INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT UNIQUE NOT NULL,
              record_type TEXT NOT NULL CHECK(record_type IN ('shortcut','incident','health','action','correlation')),
              occurred_at TEXT NOT NULL, payload_json TEXT NOT NULL, previous_digest TEXT NOT NULL,
              record_digest TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS clickfix_records_no_update BEFORE UPDATE ON clickfix_records BEGIN SELECT RAISE(ABORT,'CLICKFIX_APPEND_ONLY'); END;
            CREATE TRIGGER IF NOT EXISTS clickfix_records_no_delete BEFORE DELETE ON clickfix_records BEGIN SELECT RAISE(ABORT,'CLICKFIX_APPEND_ONLY'); END;
            CREATE TABLE IF NOT EXISTS clickfix_links(incident_id TEXT NOT NULL, shortcut_event_id TEXT NOT NULL UNIQUE, PRIMARY KEY(incident_id,shortcut_event_id));
            CREATE TABLE IF NOT EXISTS clickfix_alerts(
              alert_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, incident_id TEXT, severity TEXT NOT NULL,
              title TEXT NOT NULL, message TEXT NOT NULL, payload_json TEXT NOT NULL,
              persistent INTEGER NOT NULL, acknowledged_at TEXT, acknowledged_by TEXT, acknowledgment_reason TEXT,
              native_request_status TEXT NOT NULL DEFAULT 'not_requested', created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS clickfix_checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), record_count INTEGER NOT NULL, head_digest TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS clickfix_health(key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL);
            """)
            row = self.connection.execute("SELECT version FROM clickfix_schema LIMIT 1").fetchone()
            checksum = hashlib.sha256(b"msaa-clickfix-schema-v1").hexdigest()
            if row is None:
                self.connection.execute("INSERT INTO clickfix_schema VALUES(?,?)", (SCHEMA_VERSION, checksum))
            elif int(row[0]) != SCHEMA_VERSION:
                raise RuntimeError("CFX014_EVIDENCE_PERSISTENCE_FAILED: unsupported schema")

    def _append(self, record_id: str, record_type: str, occurred_at: str, payload: dict[str, Any]) -> str:
        last = self.connection.execute("SELECT record_digest FROM clickfix_records ORDER BY sequence DESC LIMIT 1").fetchone()
        previous = str(last[0]) if last else GENESIS
        payload_json = canonical_json(payload).decode("ascii")
        digest = hashlib.sha256(previous.encode("ascii") + record_type.encode("ascii") + payload_json.encode("ascii")).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        self.connection.execute("INSERT INTO clickfix_records(record_id,record_type,occurred_at,payload_json,previous_digest,record_digest,created_at) VALUES(?,?,?,?,?,?,?)", (record_id, record_type, occurred_at, payload_json, previous, digest, now))
        count = int(self.connection.execute("SELECT COUNT(*) FROM clickfix_records").fetchone()[0])
        self.connection.execute("INSERT INTO clickfix_checkpoint VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET record_count=excluded.record_count,head_digest=excluded.head_digest,updated_at=excluded.updated_at", (count, digest, now))
        return digest

    def persist_detection(self, event: ClickFixShortcutEvent, incident: Optional[ClickFixIncident], alerts: Tuple[dict[str, Any], ...]) -> tuple[ClickFixShortcutEvent, Optional[ClickFixIncident]]:
        """Commit shortcut, linked incident, and alerts before returning to Protect Mode."""
        with self.connection:
            event_payload = event.to_dict(); event_payload["integrity_digest"] = ""
            event_digest = self._append(event.event_id, "shortcut", event.detected_at_utc.isoformat(), event_payload)
            stored_event = replace(event, integrity_digest=event_digest, persisted_at_utc=datetime.now(timezone.utc))
            stored_incident = incident
            if incident is not None:
                incident_payload = incident.to_dict(); incident_payload["integrity_digest"] = ""
                incident_digest = self._append(incident.incident_id, "incident", incident.created_at_utc.isoformat(), incident_payload)
                stored_incident = replace(incident, integrity_digest=incident_digest)
                self.connection.execute("INSERT INTO clickfix_links VALUES(?,?)", (incident.incident_id, event.event_id))
            for alert in alerts:
                safe = dict(alert)
                self.connection.execute("INSERT INTO clickfix_alerts(alert_id,event_id,incident_id,severity,title,message,payload_json,persistent,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (safe["alert_id"], event.event_id, safe.get("incident_id"), safe["severity"], safe["title"], safe["message"], canonical_json(safe).decode("ascii"), int(bool(safe.get("persistent"))), datetime.now(timezone.utc).isoformat()))
        return stored_event, stored_incident

    def append_auxiliary(self, record_id: str, record_type: str, payload: dict[str, Any]) -> str:
        if record_type not in {"health", "action", "correlation"}:
            raise ValueError("unsupported auxiliary record type")
        occurred = str(payload.get("occurred_at") or datetime.now(timezone.utc).isoformat())
        with self.connection:
            return self._append(record_id, record_type, occurred, payload)

    def persist_health_alert(self, record_id: str, error_code: str, payload: dict[str, Any]) -> None:
        titles = {
            "CFX009_CLASSIFIER_SIGNATURE_INVALID": "ClickFix Classifier Integrity Degraded",
            "CFX010_EVENT_TAP_DISABLED": "ClickFix Guard Event Tap Disabled",
            "CFX011_EVENT_TAP_TIMEOUT": "ClickFix Guard Event Tap Timed Out",
            "CFX013_EVENT_QUEUE_OVERFLOW": "ClickFix Guard Event Queue Overflow",
            "CFX014_EVIDENCE_PERSISTENCE_FAILED": "ClickFix Evidence Persistence Failed",
        }
        title = titles.get(error_code, "ClickFix Guard Sensor Health Warning")
        severity = "critical" if error_code == "CFX014_EVIDENCE_PERSISTENCE_FAILED" else "high"
        now = datetime.now(timezone.utc).isoformat(); alert_id = "cfx-alert-" + hashlib.sha256(record_id.encode()).hexdigest()[:24]
        alert = {"alert_id": alert_id, "event_id": record_id, "severity": severity, "title": title,
                 "message": f"ClickFix Guard reported {error_code}. Protection is degraded until sensor health is restored.",
                 "description": f"ClickFix Guard reported {error_code}. Protection is degraded until sensor health is restored.",
                 "persistent": True, "timestamp": now, "error_code": error_code, "sensor_health": payload}
        with self.connection:
            self._append(record_id, "health", now, {"error_code": error_code, "native_health": payload, "occurred_at": now})
            existing = self.connection.execute(
                "SELECT 1 FROM clickfix_alerts WHERE acknowledged_at IS NULL AND json_extract(payload_json, '$.error_code') = ? LIMIT 1",
                (error_code,),
            ).fetchone()
            if existing is not None:
                return
            self.connection.execute("INSERT INTO clickfix_alerts(alert_id,event_id,severity,title,message,payload_json,persistent,created_at) VALUES(?,?,?,?,?,?,?,?)", (alert_id, record_id, severity, title, alert["message"], canonical_json(alert).decode("ascii"), 1, now))

    def reconcile_health_alerts(self, active_error_codes: set[str]) -> int:
        """Resolve recovered sensor-health warnings without touching incidents."""
        now = datetime.now(timezone.utc).isoformat(); resolved = 0
        with self.connection:
            rows = self.connection.execute(
                "SELECT alert_id,payload_json FROM clickfix_alerts WHERE acknowledged_at IS NULL"
            ).fetchall()
            for row in rows:
                try: code = str(json.loads(str(row["payload_json"])).get("error_code", ""))
                except (TypeError, json.JSONDecodeError): continue
                if not code or code in active_error_codes:
                    continue
                self.connection.execute(
                    "UPDATE clickfix_alerts SET acknowledged_at=?,acknowledged_by=?,acknowledgment_reason=? WHERE alert_id=?",
                    (now, "sensor-health-recovery", f"{code} cleared by a subsequent native health snapshot.", row["alert_id"]),
                )
                resolved += 1
        return resolved

    def pending_alerts(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload_json FROM clickfix_alerts WHERE acknowledged_at IS NULL ORDER BY created_at").fetchall()
        return [json.loads(str(row[0])) for row in rows]

    def acknowledge(self, alert_id: str, actor: str, reason: str) -> None:
        if not actor.strip() or not reason.strip():
            raise ValueError("actor and reason are required")
        now = datetime.now(timezone.utc).isoformat()
        action_id = "cfx-action-" + hashlib.sha256((alert_id + now).encode()).hexdigest()[:24]
        with self.connection:
            row = self.connection.execute("SELECT acknowledged_at FROM clickfix_alerts WHERE alert_id=?", (alert_id,)).fetchone()
            if row is None:
                raise KeyError(alert_id)
            if row[0] is not None:
                return
            self.connection.execute("UPDATE clickfix_alerts SET acknowledged_at=?,acknowledged_by=?,acknowledgment_reason=? WHERE alert_id=?", (now, actor, reason, alert_id))
            self._append(action_id, "action", now, {"action": "ACKNOWLEDGE_POTENTIAL_CLICKFIX", "alert_id": alert_id, "actor": actor, "reason": reason, "occurred_at": now})

    def set_health(self, payload: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connection:
            for key, value in payload.items():
                self.connection.execute("INSERT INTO clickfix_health VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at", (key, canonical_json(value).decode("ascii"), now))

    def health(self) -> dict[str, Any]:
        return {str(row[0]): json.loads(str(row[1])) for row in self.connection.execute("SELECT key,value_json FROM clickfix_health")}

    def verify(self) -> dict[str, Any]:
        previous = GENESIS; count = 0
        for row in self.connection.execute("SELECT sequence,record_type,payload_json,previous_digest,record_digest FROM clickfix_records ORDER BY sequence"):
            expected = hashlib.sha256(previous.encode("ascii") + str(row["record_type"]).encode("ascii") + str(row["payload_json"]).encode("ascii")).hexdigest()
            if row["previous_digest"] != previous or row["record_digest"] != expected:
                return {"valid": False, "error_code": "CFX014_EVIDENCE_PERSISTENCE_FAILED", "sequence": row["sequence"], "records_verified": count}
            previous = str(row["record_digest"]); count += 1
        checkpoint = self.connection.execute("SELECT record_count,head_digest FROM clickfix_checkpoint WHERE id=1").fetchone()
        valid = checkpoint is None and count == 0 or checkpoint is not None and int(checkpoint[0]) == count and str(checkpoint[1]) == previous
        return {"valid": bool(valid), "error_code": "" if valid else "CFX014_EVIDENCE_PERSISTENCE_FAILED", "records_verified": count, "head_digest": previous}

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "ClickFixEvidenceStore": return self
    def __exit__(self, *_args: object) -> None: self.close()
