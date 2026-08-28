from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
from dataclasses import asdict, dataclass
from typing import Any

from mac_audit_agent.alerts.configuration import AlertingConfig
from mac_audit_agent.alerts.resilient_models import SEVERITY_RANK, SecurityEvent


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class IngestDecision:
    accepted: bool
    fingerprint: str
    disposition: str
    lifecycle: str
    occurrence_count: int
    notify: bool
    summary: bool = False
    material_change: bool = False
    severity_escalation: bool = False
    overflowed: bool = False


def ensure_resilient_alert_schema(db: Any) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS resilient_alert_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS resilient_security_events (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            schema_version INTEGER NOT NULL,
            received_at TEXT NOT NULL,
            monotonic_timestamp REAL NOT NULL,
            priority INTEGER NOT NULL,
            protected INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            source_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            material_digest TEXT NOT NULL,
            disposition TEXT NOT NULL,
            raw_retained INTEGER NOT NULL DEFAULT 1,
            canonical_json TEXT NOT NULL DEFAULT '',
            event_digest TEXT NOT NULL,
            previous_integrity_hash TEXT NOT NULL,
            integrity_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_resilient_events_fingerprint ON resilient_security_events(fingerprint, sequence_number);
        CREATE INDEX IF NOT EXISTS idx_resilient_events_priority ON resilient_security_events(priority, sequence_number);
        CREATE INDEX IF NOT EXISTS idx_resilient_events_received ON resilient_security_events(received_at);
        CREATE TABLE IF NOT EXISTS resilient_alert_aggregates (
            fingerprint TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL,
            current_severity TEXT NOT NULL,
            highest_severity TEXT NOT NULL,
            current_confidence TEXT NOT NULL,
            material_digest TEXT NOT NULL,
            latest_event_id TEXT NOT NULL,
            last_notification_count INTEGER NOT NULL DEFAULT 0,
            last_notification_at TEXT NOT NULL DEFAULT '',
            unique_users_json TEXT NOT NULL DEFAULT '[]',
            unique_processes_json TEXT NOT NULL DEFAULT '[]',
            unique_hashes_json TEXT NOT NULL DEFAULT '[]',
            unique_destinations_json TEXT NOT NULL DEFAULT '[]',
            unique_objects_json TEXT NOT NULL DEFAULT '[]',
            source_distribution_json TEXT NOT NULL DEFAULT '{}',
            rolling_digest TEXT NOT NULL,
            compacted_count INTEGER NOT NULL DEFAULT 0,
            fidelity_reduced INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_resilient_aggregates_state ON resilient_alert_aggregates(lifecycle, last_seen);
        CREATE TABLE IF NOT EXISTS resilient_notification_queue (
            queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            priority INTEGER NOT NULL,
            reason TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT NOT NULL DEFAULT '',
            UNIQUE(event_id, reason)
        );
        CREATE INDEX IF NOT EXISTS idx_resilient_notify_pending ON resilient_notification_queue(state, priority, queue_id);
        CREATE TABLE IF NOT EXISTS resilient_pipeline_audit (
            audit_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            object_id TEXT NOT NULL,
            details_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS resilient_suppressions (
            rule_id TEXT PRIMARY KEY, scope TEXT NOT NULL, conditions_json TEXT NOT NULL, owner TEXT NOT NULL,
            created_at TEXT NOT NULL, expires_at TEXT NOT NULL, reason TEXT NOT NULL, ticket_id TEXT NOT NULL,
            authorizing_identity TEXT NOT NULL, approval_identity TEXT NOT NULL DEFAULT '', policy_version TEXT NOT NULL,
            revoked_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS resilient_compactions (
            compaction_id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, started_at TEXT NOT NULL,
            ended_at TEXT NOT NULL, compacted_count INTEGER NOT NULL, policy_version TEXT NOT NULL, reason TEXT NOT NULL,
            digest TEXT NOT NULL, fidelity_reduced INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS resilient_action_idempotency (
            idempotency_key TEXT PRIMARY KEY, action_type TEXT NOT NULL, target_identity TEXT NOT NULL,
            status TEXT NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, previous_state_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS resilient_metrics (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL);
        INSERT OR IGNORE INTO resilient_alert_metadata(key, value) VALUES ('schema_version', '1');
        """
    )
    db.conn.commit()


class ResilientEventStore:
    def __init__(self, db: Any, config: AlertingConfig, *, integrity_key: bytes | None = None) -> None:
        self.db = db
        self.config = config
        self._key = integrity_key or self._load_or_create_local_key()
        self._transaction_lock = threading.RLock()
        ensure_resilient_alert_schema(db)

    def _load_or_create_local_key(self) -> bytes:
        key_path = self.db.path.with_name(self.db.path.name + ".audit-integrity.key")
        try:
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            key_info = key_path.stat()
            mode = stat.S_IMODE(key_info.st_mode)
            db_info = self.db.path.stat()
            protected_shared_key = (
                mode == 0o640
                and key_info.st_uid == 0
                and db_info.st_uid == 0
                and key_info.st_gid == db_info.st_gid
                and stat.S_IMODE(db_info.st_mode) == 0o660
            )
            if mode != 0o600 and not protected_shared_key:
                raise PermissionError(f"audit integrity key permissions are too broad: {oct(mode)}")
            key = key_path.read_bytes()
            if len(key) != 32:
                raise ValueError("audit integrity key has an invalid length")
            return key
        key = os.urandom(32)
        try:
            os.write(descriptor, key)
        finally:
            os.close(descriptor)
        return key

    def _metric(self, name: str, amount: int = 1) -> None:
        allowed = {
            "events_received", "events_rejected", "events_persisted", "events_compacted",
            "duplicate_occurrences", "notifications_delivered", "notifications_consolidated",
            "notification_failures", "notification_queue_saturation", "cardinality_pressure",
            "suppression_matches", "protected_events", "storage_pressure", "store_failures",
            "time_integrity_events", "flood_detections",
        }
        if name not in allowed:
            raise ValueError("unregistered bounded metric name")
        self.db.conn.execute(
            "INSERT INTO resilient_metrics(name,value,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value, updated_at=excluded.updated_at",
            (name, amount, self._utc()),
        )

    @staticmethod
    def _utc() -> str:
        from mac_audit_agent.models import utc_now_iso
        return utc_now_iso()

    def _last_hash(self, table: str, column: str) -> str:
        allowed = {
            ("resilient_pipeline_audit", "record_hash"),
            ("resilient_security_events", "integrity_hash"),
        }
        if (table, column) not in allowed:
            raise ValueError("unregistered integrity-chain table or column")
        row = self.db.conn.execute(f"SELECT {column} FROM {table} ORDER BY rowid DESC LIMIT 1").fetchone()
        return str(row[column] or "") if row else ""

    def _database_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            path = type(self.db.path)(str(self.db.path) + suffix)
            try:
                if path.is_file() and not path.is_symlink():
                    total += path.stat().st_size
            except OSError:
                continue
        return total

    def _storage_pressure(self, event: SecurityEvent) -> tuple[bool, bool]:
        used = self._database_bytes()
        maximum = self.config.maximum_size_mb * 1024 * 1024
        reserve = self.config.emergency_reserved_size_mb * 1024 * 1024
        return used >= maximum - reserve, used >= maximum and event.priority.value > 1

    def _chain(self, previous: str, sequence: int, canonical: str) -> str:
        return hmac.new(self._key, previous.encode() + str(sequence).encode() + canonical.encode(), hashlib.sha256).hexdigest()

    def audit(self, action: str, *, actor: str, reason: str, object_id: str, details: dict[str, Any]) -> None:
        previous = self._last_hash("resilient_pipeline_audit", "record_hash")
        next_row = self.db.conn.execute("SELECT COALESCE(MAX(audit_sequence),0)+1 AS value FROM resilient_pipeline_audit").fetchone()
        sequence = int(next_row["value"])
        timestamp = self._utc()
        safe_details = json.dumps(details, sort_keys=True, separators=(",", ":"))
        canonical = json.dumps({"sequence": sequence, "timestamp": timestamp, "action": action, "actor": actor, "reason": reason, "object_id": object_id, "details": safe_details}, sort_keys=True)
        digest = self._chain(previous, sequence, canonical)
        self.db.conn.execute("INSERT INTO resilient_pipeline_audit VALUES(?,?,?,?,?,?,?,?,?)", (sequence, timestamp, action, actor, reason, object_id, safe_details, previous, digest))

    @staticmethod
    def _bounded_set(raw: str, value: Any, limit: int = 128) -> str:
        try:
            values = set(json.loads(raw or "[]"))
        except (json.JSONDecodeError, TypeError):
            values = set()
        if value not in (None, "") and len(values) < limit:
            values.add(value)
        return json.dumps(sorted(values, key=str), separators=(",", ":"))

    def ingest(self, event: SecurityEvent) -> IngestDecision:
        with self._transaction_lock:
            return self._ingest_transaction(event)

    def _ingest_transaction(self, event: SecurityEvent) -> IngestDecision:
        event.validate(self.config.maximum_event_size_bytes,maximum_string_length=self.config.maximum_string_length,maximum_nesting_depth=self.config.maximum_nesting_depth,maximum_collection_items=self.config.maximum_collection_items)
        canonical = event.canonical_json()
        event_digest = hashlib.sha256(canonical.encode()).hexdigest()
        self.db.conn.execute("BEGIN IMMEDIATE")
        try:
            existing_event = self.db.conn.execute("SELECT fingerprint FROM resilient_security_events WHERE event_id=?", (event.event_id,)).fetchone()
            if existing_event:
                self.audit("duplicate_event_id_rejected", actor=event.source_id, reason="event IDs are idempotent", object_id=event.event_id, details={"fingerprint": event.fingerprint})
                self.db.conn.commit()
                return IngestDecision(False, str(existing_event["fingerprint"]), "duplicate_event_id", "ACTIVE", 0, False)
            aggregate = self.db.conn.execute("SELECT * FROM resilient_alert_aggregates WHERE fingerprint=?", (event.fingerprint,)).fetchone()
            active_count = int(self.db.conn.execute("SELECT COUNT(*) AS count FROM resilient_alert_aggregates WHERE lifecycle IN ('NEW','ACTIVE','QUIET','REOPENED')").fetchone()["count"])
            overflowed = not aggregate and active_count >= self.config.maximum_active_fingerprints and event.priority.value >= 3
            storage_fingerprint = event.fingerprint
            if overflowed:
                storage_fingerprint = hashlib.sha256(f"overflow:{event.rule_id}:{event.source_id}:{event.priority.value}".encode()).hexdigest()
                aggregate = self.db.conn.execute("SELECT * FROM resilient_alert_aggregates WHERE fingerprint=?", (storage_fingerprint,)).fetchone()
                self._metric("cardinality_pressure")
                self.audit("cardinality_overflow", actor="pipeline", reason="bounded active fingerprint capacity", object_id=event.event_id, details={"original_fingerprint_digest": event.fingerprint, "overflow_bucket": storage_fingerprint, "fidelity_reduced": True})
            count = int(aggregate["occurrence_count"] if aggregate else 0) + 1
            escalation = bool(aggregate and SEVERITY_RANK.get(event.severity, 0) > SEVERITY_RANK.get(str(aggregate["current_severity"]), 0))
            material_change = bool(aggregate and event.material_digest != str(aggregate["material_digest"]))
            reopened = bool(aggregate and str(aggregate["lifecycle"]) == "RESOLVED")
            threshold = count in self.config.summary_thresholds or (count > 1000 and str(count).startswith("1") and set(str(count)[1:]) == {"0"})
            suppressed = bool(event.suppression_rule_id) and not event.protected
            notify = (aggregate is None or escalation or material_change or reopened or threshold) and not suppressed
            reason = "first_occurrence" if aggregate is None else "severity_escalation" if escalation else "material_change" if material_change else "reopened" if reopened else "threshold_summary" if threshold else "exact_duplicate_consolidated"
            if suppressed:
                reason = "notification_suppressed_evidence_retained"
            storage_pressure, emergency_exhausted = self._storage_pressure(event)
            compacted_digest = ""
            compact_previous = bool(aggregate and not notify and not event.protected and (count > self.config.individual_duplicate_retention_limit or storage_pressure))
            if compact_previous:
                previous_raw = self.db.conn.execute(
                    "SELECT sequence_number,event_digest FROM resilient_security_events WHERE fingerprint=? AND raw_retained=1 AND disposition NOT IN ('first_occurrence','threshold_summary','severity_escalation','material_change','reopened') AND sequence_number>(SELECT sequence_number FROM resilient_security_events WHERE fingerprint=? ORDER BY sequence_number LIMIT 1 OFFSET ?) ORDER BY sequence_number DESC LIMIT 1",
                    (storage_fingerprint,storage_fingerprint,max(0,self.config.individual_duplicate_retention_limit-1)),
                ).fetchone()
                if previous_raw:
                    self.db.conn.execute("UPDATE resilient_security_events SET raw_retained=0,canonical_json='' WHERE sequence_number=?",(previous_raw["sequence_number"],))
                    compacted_digest = str(previous_raw["event_digest"])
                if storage_pressure:
                    self._metric("storage_pressure")
            if emergency_exhausted and aggregate:
                reason = "storage_quota_degraded_latest_preserved"
            # Preserve the first raw event and always retain the newest raw event.
            raw_retained = True
            previous = self._last_hash("resilient_security_events", "integrity_hash")
            next_sequence = int(self.db.conn.execute("SELECT COALESCE(MAX(sequence_number),0)+1 AS value FROM resilient_security_events").fetchone()["value"])
            integrity_hash = self._chain(previous, next_sequence, event_digest)
            self.db.conn.execute(
                "INSERT INTO resilient_security_events(sequence_number,event_id,schema_version,received_at,monotonic_timestamp,priority,protected,event_type,rule_id,severity,confidence,source_id,fingerprint,material_digest,disposition,raw_retained,canonical_json,event_digest,previous_integrity_hash,integrity_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (next_sequence,event.event_id,event.schema_version,event.ingestion_timestamp_utc,event.monotonic_timestamp,event.priority.value,int(event.protected),event.event_type,event.rule_id,event.severity,event.confidence,event.source_id,storage_fingerprint,event.material_digest,reason,int(raw_retained),canonical if raw_retained else "",event_digest,previous,integrity_hash),
            )
            rolling = hashlib.sha256(((str(aggregate["rolling_digest"]) if aggregate else "") + event_digest).encode()).hexdigest()
            highest = event.severity if not aggregate or SEVERITY_RANK.get(event.severity,0) >= SEVERITY_RANK.get(str(aggregate["highest_severity"]),0) else str(aggregate["highest_severity"])
            sources = json.loads(str(aggregate["source_distribution_json"])) if aggregate else {}
            if len(sources) < 128 or event.source_id in sources:
                sources[event.source_id] = int(sources.get(event.source_id, 0)) + 1
            values = {
                "users": self._bounded_set(str(aggregate["unique_users_json"]) if aggregate else "[]", event.user_uid),
                "processes": self._bounded_set(str(aggregate["unique_processes_json"]) if aggregate else "[]", event.process_path or event.source_process),
                "hashes": self._bounded_set(str(aggregate["unique_hashes_json"]) if aggregate else "[]", event.process_hash),
                "destinations": self._bounded_set(str(aggregate["unique_destinations_json"]) if aggregate else "[]", f"{event.remote_address}:{event.remote_port}" if event.remote_address else ""),
                "objects": self._bounded_set(str(aggregate["unique_objects_json"]) if aggregate else "[]", event.object_path),
            }
            lifecycle = "REOPENED" if reopened else "NEW" if aggregate is None else "ACTIVE"
            self.db.conn.execute(
                "INSERT INTO resilient_alert_aggregates(fingerprint,alert_id,rule_id,lifecycle,first_seen,last_seen,occurrence_count,current_severity,highest_severity,current_confidence,material_digest,latest_event_id,last_notification_count,last_notification_at,unique_users_json,unique_processes_json,unique_hashes_json,unique_destinations_json,unique_objects_json,source_distribution_json,rolling_digest,compacted_count,fidelity_reduced) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET lifecycle=excluded.lifecycle,last_seen=excluded.last_seen,occurrence_count=excluded.occurrence_count,current_severity=excluded.current_severity,highest_severity=excluded.highest_severity,current_confidence=excluded.current_confidence,material_digest=excluded.material_digest,latest_event_id=excluded.latest_event_id,last_notification_count=CASE WHEN ? THEN excluded.occurrence_count ELSE resilient_alert_aggregates.last_notification_count END,last_notification_at=CASE WHEN ? THEN excluded.last_seen ELSE resilient_alert_aggregates.last_notification_at END,unique_users_json=excluded.unique_users_json,unique_processes_json=excluded.unique_processes_json,unique_hashes_json=excluded.unique_hashes_json,unique_destinations_json=excluded.unique_destinations_json,unique_objects_json=excluded.unique_objects_json,source_distribution_json=excluded.source_distribution_json,rolling_digest=excluded.rolling_digest,compacted_count=resilient_alert_aggregates.compacted_count+?,fidelity_reduced=MAX(resilient_alert_aggregates.fidelity_reduced,excluded.fidelity_reduced)",
                (storage_fingerprint, f"alert-{event.event_id}", event.rule_id,lifecycle,event.timestamp_utc,event.timestamp_utc,count,event.severity,highest,event.confidence,event.material_digest,event.event_id,count if notify else 0,event.timestamp_utc if notify else "",values["users"],values["processes"],values["hashes"],values["destinations"],values["objects"],json.dumps(sources,sort_keys=True),rolling,int(bool(compacted_digest)),int(overflowed),int(notify),int(notify),int(bool(compacted_digest))),
            )
            if notify:
                pending = int(self.db.conn.execute("SELECT COUNT(*) AS count FROM resilient_notification_queue WHERE state='pending'").fetchone()["count"])
                low_capacity = self.config.notification_capacity - self.config.protected_capacity
                accepted_queue = event.priority.value <= 1 or pending < low_capacity
                if accepted_queue and pending < self.config.notification_capacity:
                    self.db.conn.execute("INSERT OR IGNORE INTO resilient_notification_queue(event_id,fingerprint,priority,reason,created_at) VALUES(?,?,?,?,?)", (event.event_id,storage_fingerprint,event.priority.value,reason,event.ingestion_timestamp_utc))
                else:
                    reason = "notification_queue_pressure_log_only"
                    self._metric("notification_queue_saturation")
                    self.audit("notification_queue_overflow", actor="pipeline", reason="bounded notification queue", object_id=event.event_id, details={"priority": event.priority.value, "reserved_capacity_preserved": True})
            if suppressed:
                self._metric("suppression_matches")
            self._metric("events_received")
            self._metric("events_persisted")
            self._metric("protected_events", int(event.protected))
            if aggregate:
                self._metric("duplicate_occurrences")
            if compacted_digest:
                self._metric("events_compacted")
                row = self.db.conn.execute("SELECT compaction_id,compacted_count,digest FROM resilient_compactions WHERE fingerprint=? ORDER BY compaction_id DESC LIMIT 1", (storage_fingerprint,)).fetchone()
                if row:
                    rolling_compaction_digest = hashlib.sha256((str(row["digest"]) + compacted_digest).encode()).hexdigest()
                    self.db.conn.execute("UPDATE resilient_compactions SET ended_at=?,compacted_count=?,digest=?,fidelity_reduced=1 WHERE compaction_id=?", (event.ingestion_timestamp_utc,int(row["compacted_count"])+1,rolling_compaction_digest,row["compaction_id"]))
                else:
                    self.db.conn.execute("INSERT INTO resilient_compactions(fingerprint,started_at,ended_at,compacted_count,policy_version,reason,digest,fidelity_reduced) VALUES(?,?,?,?,?,?,?,1)", (storage_fingerprint,event.ingestion_timestamp_utc,event.ingestion_timestamp_utc,1,"1","exact duplicate retention limit or storage pressure",compacted_digest))
            if not notify:
                self._metric("notifications_consolidated")
            self.audit("event_aggregation_decision", actor="pipeline", reason=reason, object_id=event.event_id, details={"fingerprint":storage_fingerprint,"occurrence_count":count,"raw_retained":raw_retained,"previous_raw_compacted":bool(compacted_digest),"material_change":material_change,"severity_escalation":escalation,"overflowed":overflowed,"suppression_rule_id":event.suppression_rule_id,"storage_pressure":storage_pressure})
            self.db.conn.commit()
            return IngestDecision(True, storage_fingerprint, reason, lifecycle, count, notify, threshold, material_change, escalation, overflowed)
        except Exception:
            self.db.conn.rollback()
            raise

    def verify_integrity(self) -> dict[str, Any]:
        previous = ""
        checked = 0
        failures: list[int] = []
        for row in self.db.conn.execute("SELECT * FROM resilient_security_events ORDER BY sequence_number"):
            canonical = str(row["canonical_json"] or "")
            if canonical:
                expected_digest = hashlib.sha256(canonical.encode()).hexdigest()
                expected_hash = self._chain(previous, int(row["sequence_number"]), str(row["event_digest"]))
                if expected_digest != str(row["event_digest"]) or expected_hash != str(row["integrity_hash"]) or str(row["previous_integrity_hash"]) != previous:
                    failures.append(int(row["sequence_number"]))
            elif self._chain(previous, int(row["sequence_number"]), str(row["event_digest"])) != str(row["integrity_hash"]):
                failures.append(int(row["sequence_number"]))
            previous = str(row["integrity_hash"])
            checked += 1
        audit_previous = ""
        audit_failures: list[int] = []
        for row in self.db.conn.execute("SELECT * FROM resilient_pipeline_audit ORDER BY audit_sequence"):
            canonical = json.dumps({"sequence":int(row["audit_sequence"]),"timestamp":row["timestamp_utc"],"action":row["action"],"actor":row["actor"],"reason":row["reason"],"object_id":row["object_id"],"details":row["details_json"]},sort_keys=True)
            expected = self._chain(audit_previous,int(row["audit_sequence"]),canonical)
            if str(row["previous_hash"]) != audit_previous or not hmac.compare_digest(str(row["record_hash"]),expected):
                audit_failures.append(int(row["audit_sequence"]))
            audit_previous = str(row["record_hash"])
        return {"ok": not failures and not audit_failures, "records_checked": checked, "failed_sequences": failures[:100], "audit_failed_sequences": audit_failures[:100], "limitations": "Local tamper evidence cannot resist an attacker with unrestricted access to the database and local integrity key material."}

    def health(self) -> dict[str, Any]:
        metrics = {str(row["name"]): int(row["value"]) for row in self.db.conn.execute("SELECT * FROM resilient_metrics")}
        pending = int(self.db.conn.execute("SELECT COUNT(*) AS count FROM resilient_notification_queue WHERE state='pending'").fetchone()["count"])
        active = int(self.db.conn.execute("SELECT COUNT(*) AS count FROM resilient_alert_aggregates WHERE lifecycle!='RESOLVED'").fetchone()["count"])
        storage_bytes = self._database_bytes()
        storage_limit = self.config.maximum_size_mb * 1024 * 1024
        degraded = any(metrics.get(name,0) for name in ("notification_queue_saturation","storage_pressure","store_failures"))
        integrity = self.verify_integrity()
        return {"status": "degraded" if degraded or not integrity["ok"] else "healthy", "pending_notifications": pending, "notification_capacity": self.config.notification_capacity, "active_fingerprints": active, "maximum_active_fingerprints": self.config.maximum_active_fingerprints, "storage_bytes":storage_bytes,"storage_limit_bytes":storage_limit,"storage_pressure":storage_bytes >= storage_limit-self.config.emergency_reserved_size_mb*1024*1024,"integrity_ok":integrity["ok"],"metrics": metrics}

    def pending_notifications(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return durable notifications by priority with FIFO order per class."""
        bounded = max(1, min(int(limit), self.config.notification_capacity))
        return [dict(row) for row in self.db.conn.execute(
            "SELECT * FROM resilient_notification_queue WHERE state='pending' ORDER BY priority ASC, queue_id ASC LIMIT ?",
            (bounded,),
        )]

    def queue_periodic_summary(self, event: SecurityEvent, fingerprint: str) -> bool:
        """Queue a summary only after its triggering event is durably committed."""
        with self._transaction_lock:
            pending = int(self.db.conn.execute("SELECT COUNT(*) AS count FROM resilient_notification_queue WHERE state='pending'").fetchone()["count"])
            if pending >= self.config.notification_capacity:
                self._metric("notification_queue_saturation")
                self.audit("notification_queue_overflow",actor="pipeline",reason="periodic summary queue full",object_id=event.event_id,details={"priority":event.priority.value})
                self.db.conn.commit()
                return False
            self.db.conn.execute("INSERT OR IGNORE INTO resilient_notification_queue(event_id,fingerprint,priority,reason,created_at) VALUES(?,?,?,?,?)",(event.event_id,fingerprint,event.priority.value,"periodic_summary",event.ingestion_timestamp_utc))
            changed = bool(self.db.conn.execute("SELECT changes() AS value").fetchone()["value"])
            if changed:
                self.db.conn.execute("UPDATE resilient_alert_aggregates SET last_notification_count=occurrence_count,last_notification_at=last_seen WHERE fingerprint=?",(fingerprint,))
                self.audit("periodic_summary_queued",actor="pipeline",reason="active storm summary interval",object_id=event.event_id,details={"fingerprint":fingerprint})
            self.db.conn.commit()
            return changed

    def mark_notification(self, queue_id: int, *, delivered: bool, error: str = "") -> None:
        state = "delivered" if delivered else "failed"
        self.db.conn.execute("UPDATE resilient_notification_queue SET state=?, attempts=attempts+1 WHERE queue_id=?", (state, int(queue_id)))
        self.audit("notification_delivery", actor="user_notifier", reason=state, object_id=str(queue_id), details={"error_digest": hashlib.sha256(error.encode()).hexdigest() if error else ""})
        self._metric("notifications_delivered" if delivered else "notification_failures")
        self.db.conn.commit()

    def advance_lifecycle(self, now_utc: str) -> dict[str, int]:
        from datetime import datetime

        now = datetime.fromisoformat(now_utc)
        quiet = resolved = 0
        for row in self.db.conn.execute("SELECT fingerprint,lifecycle,last_seen FROM resilient_alert_aggregates WHERE lifecycle!='RESOLVED'"):
            try:
                age = (now - datetime.fromisoformat(str(row["last_seen"]))).total_seconds()
            except ValueError:
                continue
            target = "RESOLVED" if age >= self.config.resolve_after_seconds else "QUIET" if age >= self.config.dedup_window_seconds else ""
            if target and target != str(row["lifecycle"]):
                self.db.conn.execute("UPDATE resilient_alert_aggregates SET lifecycle=? WHERE fingerprint=?", (target,row["fingerprint"]))
                self.audit("alert_lifecycle_changed",actor="pipeline",reason=f"inactivity interval reached: {target.lower()}",object_id=str(row["fingerprint"]),details={"previous":row["lifecycle"],"current":target,"age_seconds":age})
                quiet += target == "QUIET"; resolved += target == "RESOLVED"
        self.db.conn.commit()
        return {"quiet": quiet, "resolved": resolved}
