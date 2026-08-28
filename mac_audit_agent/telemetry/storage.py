from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from mac_audit_agent.telemetry.models import (
    BehavioralAnomaly, BehavioralIncident, FeatureBaseline, NormalizedTelemetryEvent, TelemetryBucket, utc_now_iso,
)


SCHEMA_VERSION = "1.0"


class _SerializedConnection:
    """Serialize an analytics connection shared by its worker and GUI readers."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._lock = threading.RLock()

    def execute(self, *args, **kwargs):
        with self._lock:
            return self._connection.execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        with self._lock:
            return self._connection.executemany(*args, **kwargs)

    def executescript(self, *args, **kwargs):
        with self._lock:
            return self._connection.executescript(*args, **kwargs)

    def commit(self) -> None:
        with self._lock:
            self._connection.commit()

    def rollback(self) -> None:
        with self._lock:
            self._connection.rollback()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __getattr__(self, name: str):
        return getattr(self._connection, name)


def open_telemetry_connection(path) -> _SerializedConnection:
    connection = sqlite3.connect(path, timeout=30, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA busy_timeout=5000")
    return _SerializedConnection(connection)


def migrate(connection: Any) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS telemetry_event_links (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            host_ref TEXT NOT NULL,
            user_ref TEXT NOT NULL,
            dimension TEXT NOT NULL,
            feature_values_json TEXT NOT NULL,
            entity_keys_json TEXT NOT NULL DEFAULT '{}',
            security_context_json TEXT NOT NULL DEFAULT '{}',
            sensor_id TEXT NOT NULL,
            coverage TEXT NOT NULL,
            baseline_training_eligible INTEGER NOT NULL DEFAULT 1,
            feature_schema_version TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_telemetry_links_time ON telemetry_event_links(timestamp);
        CREATE INDEX IF NOT EXISTS idx_telemetry_links_user_time ON telemetry_event_links(user_ref, timestamp);

        CREATE TABLE IF NOT EXISTS telemetry_buckets (
            bucket_id INTEGER PRIMARY KEY AUTOINCREMENT,
            bucket_start TEXT NOT NULL,
            bucket_end TEXT NOT NULL,
            host_ref TEXT NOT NULL,
            user_ref TEXT NOT NULL,
            time_cohort TEXT NOT NULL,
            context_cohort TEXT NOT NULL,
            feature_values_json TEXT NOT NULL,
            dimension_values_json TEXT NOT NULL,
            coverage_json TEXT NOT NULL,
            entity_sets_json TEXT NOT NULL DEFAULT '{}',
            evidence_refs_json TEXT NOT NULL DEFAULT '[]',
            training_eligible INTEGER NOT NULL DEFAULT 1,
            event_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(bucket_start, host_ref, user_ref, context_cohort)
        );
        CREATE INDEX IF NOT EXISTS idx_telemetry_buckets_time ON telemetry_buckets(bucket_start);
        CREATE INDEX IF NOT EXISTS idx_telemetry_buckets_user_time ON telemetry_buckets(user_ref, bucket_start);
        CREATE TABLE IF NOT EXISTS telemetry_bucket_analysis (
            bucket_key TEXT PRIMARY KEY,
            event_count INTEGER NOT NULL,
            analyzed_at TEXT NOT NULL,
            anomaly_ids_json TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS telemetry_baseline_versions (
            baseline_version INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            training_start TEXT NOT NULL,
            training_end TEXT NOT NULL,
            bucket_count INTEGER NOT NULL,
            excluded_bucket_count INTEGER NOT NULL,
            feature_schema_version TEXT NOT NULL,
            behavior_model_version TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS telemetry_baselines (
            baseline_id TEXT PRIMARY KEY,
            host_ref TEXT NOT NULL,
            user_ref TEXT NOT NULL,
            feature_name TEXT NOT NULL,
            time_cohort TEXT NOT NULL,
            context_cohort TEXT NOT NULL,
            median_value REAL NOT NULL,
            mad_value REAL NOT NULL,
            p05 REAL NOT NULL,
            p25 REAL NOT NULL,
            p50 REAL NOT NULL,
            p75 REAL NOT NULL,
            p95 REAL NOT NULL,
            sample_count INTEGER NOT NULL,
            confidence REAL NOT NULL,
            state TEXT NOT NULL,
            version INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(host_ref, user_ref, feature_name, time_cohort, context_cohort, version)
        );
        CREATE INDEX IF NOT EXISTS idx_telemetry_baseline_lookup
            ON telemetry_baselines(host_ref, user_ref, feature_name, time_cohort, context_cohort, version);

        CREATE TABLE IF NOT EXISTS behavioral_anomalies (
            anomaly_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            host_ref TEXT NOT NULL,
            user_ref TEXT NOT NULL,
            dimension TEXT NOT NULL,
            anomaly_score INTEGER NOT NULL,
            security_severity TEXT NOT NULL,
            detection_confidence REAL NOT NULL,
            baseline_value REAL,
            observed_value REAL,
            normal_low REAL,
            normal_high REAL,
            reason_codes_json TEXT NOT NULL,
            reasons_json TEXT NOT NULL,
            related_entities_json TEXT NOT NULL,
            evidence_refs_json TEXT NOT NULL,
            sensor_coverage_json TEXT NOT NULL,
            baseline_version INTEGER NOT NULL,
            active_behavior_policy TEXT NOT NULL,
            baseline_training_eligible INTEGER NOT NULL DEFAULT 0,
            behavior_model_version TEXT NOT NULL,
            feature_schema_version TEXT NOT NULL,
            incident_id TEXT NOT NULL DEFAULT '',
            disposition TEXT NOT NULL DEFAULT 'NEW',
            recommendation TEXT NOT NULL,
            explanation TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_behavioral_anomalies_time ON behavioral_anomalies(timestamp);
        CREATE INDEX IF NOT EXISTS idx_behavioral_anomalies_incident ON behavioral_anomalies(incident_id);

        CREATE TABLE IF NOT EXISTS behavioral_incidents (
            incident_id TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            host_ref TEXT NOT NULL,
            user_ref TEXT NOT NULL,
            primary_entity TEXT NOT NULL,
            anomaly_ids_json TEXT NOT NULL,
            reason_codes_json TEXT NOT NULL,
            anomaly_score INTEGER NOT NULL,
            security_severity TEXT NOT NULL,
            detection_confidence REAL NOT NULL,
            evidence_refs_json TEXT NOT NULL,
            status TEXT NOT NULL,
            alert_event_id TEXT NOT NULL DEFAULT '',
            flight_recorder_snapshot_id TEXT NOT NULL DEFAULT '',
            occurrence_count INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_behavioral_incidents_status_time ON behavioral_incidents(status, last_seen);

        CREATE TABLE IF NOT EXISTS behavioral_evidence_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            anchor_time TEXT NOT NULL,
            pre_window_seconds INTEGER NOT NULL,
            post_window_seconds INTEGER NOT NULL,
            canonical_event_refs_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            finalized_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS behavioral_entity_profiles (
            entity_type TEXT NOT NULL,
            entity_ref TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            seen_count INTEGER NOT NULL,
            attributes_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY(entity_type, entity_ref)
        );
        CREATE TABLE IF NOT EXISTS behavioral_feedback (
            feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            disposition TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            baseline_change_requested INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS behavioral_audit_trail (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            previous_json TEXT NOT NULL DEFAULT '{}',
            current_json TEXT NOT NULL DEFAULT '{}',
            reason TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS telemetry_runtime_state (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    connection.execute(
        "INSERT OR REPLACE INTO telemetry_runtime_state(key,value_json,updated_at) VALUES('schema_version',?,?)",
        (json.dumps(SCHEMA_VERSION), utc_now_iso()),
    )
    connection.commit()


class TelemetryRepository:
    def __init__(self, database: Any) -> None:
        self.db = database
        self.connection = database.conn if hasattr(database, "conn") else database
        migrate(self.connection)

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _load(value: Any, fallback: Any) -> Any:
        try:
            parsed = json.loads(str(value or ""))
            return parsed
        except (TypeError, ValueError, json.JSONDecodeError):
            return fallback

    def record_event_link(self, event: NormalizedTelemetryEvent, *, raw_retention_days: int) -> None:
        expires = (_parse_time(event.timestamp) + timedelta(days=raw_retention_days)).isoformat()
        self.connection.execute(
            """INSERT OR IGNORE INTO telemetry_event_links
            (event_id,timestamp,host_ref,user_ref,dimension,feature_values_json,entity_keys_json,security_context_json,sensor_id,coverage,baseline_training_eligible,feature_schema_version,expires_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event.event_id, event.timestamp, event.host_ref, event.user_ref, event.dimension.value,
                self._json(event.features), self._json(event.entity_keys), self._json(event.security_context),
                event.sensor_id, event.coverage.value, int(event.baseline_training_eligible), event.feature_schema_version, expires,
            ),
        )

    def get_bucket(self, bucket_start: str, host_ref: str, user_ref: str, context_cohort: str) -> TelemetryBucket | None:
        row = self.connection.execute(
            "SELECT * FROM telemetry_buckets WHERE bucket_start=? AND host_ref=? AND user_ref=? AND context_cohort=?",
            (bucket_start, host_ref, user_ref, context_cohort),
        ).fetchone()
        return self._bucket(row) if row else None

    def upsert_bucket(self, bucket: TelemetryBucket) -> None:
        now = utc_now_iso()
        bucket.created_at = bucket.created_at or now
        bucket.updated_at = now
        self.connection.execute(
            """INSERT INTO telemetry_buckets
            (bucket_start,bucket_end,host_ref,user_ref,time_cohort,context_cohort,feature_values_json,dimension_values_json,coverage_json,entity_sets_json,evidence_refs_json,training_eligible,event_count,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(bucket_start,host_ref,user_ref,context_cohort) DO UPDATE SET
            bucket_end=excluded.bucket_end,time_cohort=excluded.time_cohort,feature_values_json=excluded.feature_values_json,
            dimension_values_json=excluded.dimension_values_json,coverage_json=excluded.coverage_json,
            entity_sets_json=excluded.entity_sets_json,evidence_refs_json=excluded.evidence_refs_json,
            training_eligible=excluded.training_eligible,event_count=excluded.event_count,updated_at=excluded.updated_at""",
            (
                bucket.bucket_start, bucket.bucket_end, bucket.host_ref, bucket.user_ref, bucket.time_cohort,
                bucket.context_cohort, self._json(bucket.feature_values), self._json(bucket.dimension_values),
                self._json(bucket.coverage), self._json(bucket.entity_sets), self._json(bucket.evidence_refs),
                int(bucket.training_eligible), bucket.event_count, bucket.created_at, bucket.updated_at,
            ),
        )

    def list_buckets(
        self, *, since: str = "", until: str = "", user_ref: str | None = None,
        training_eligible: bool | None = None, limit: int = 20_000,
    ) -> list[TelemetryBucket]:
        clauses: list[str] = []
        params: list[Any] = []
        if since: clauses.append("bucket_start>=?"); params.append(since)
        if until: clauses.append("bucket_start<=?"); params.append(until)
        if user_ref is not None: clauses.append("user_ref=?"); params.append(user_ref)
        if training_eligible is not None: clauses.append("training_eligible=?"); params.append(int(training_eligible))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(int(limit), 100_000)))
        rows = self.connection.execute(f"SELECT * FROM telemetry_buckets{where} ORDER BY bucket_start ASC LIMIT ?", params).fetchall()
        return [self._bucket(row) for row in rows]

    def _bucket(self, row: Any) -> TelemetryBucket:
        return TelemetryBucket(
            bucket_start=str(row["bucket_start"]), bucket_end=str(row["bucket_end"]), host_ref=str(row["host_ref"]),
            user_ref=str(row["user_ref"]), time_cohort=str(row["time_cohort"]), context_cohort=str(row["context_cohort"]),
            feature_values=self._load(row["feature_values_json"], {}), dimension_values=self._load(row["dimension_values_json"], {}),
            coverage=self._load(row["coverage_json"], {}), entity_sets=self._load(row["entity_sets_json"], {}),
            evidence_refs=self._load(row["evidence_refs_json"], []), training_eligible=bool(row["training_eligible"]),
            event_count=int(row["event_count"]), created_at=str(row["created_at"]), updated_at=str(row["updated_at"]),
        )

    def bucket_needs_analysis(self, bucket: TelemetryBucket) -> bool:
        key = self.bucket_key(bucket)
        row = self.connection.execute("SELECT event_count FROM telemetry_bucket_analysis WHERE bucket_key=?", (key,)).fetchone()
        return row is None or int(row["event_count"]) != bucket.event_count

    def mark_bucket_analyzed(self, bucket: TelemetryBucket, anomaly_ids: list[str]) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO telemetry_bucket_analysis(bucket_key,event_count,analyzed_at,anomaly_ids_json) VALUES(?,?,?,?)",
            (self.bucket_key(bucket), bucket.event_count, utc_now_iso(), self._json(anomaly_ids)),
        )

    @staticmethod
    def bucket_key(bucket: TelemetryBucket) -> str:
        return "|".join((bucket.bucket_start, bucket.host_ref, bucket.user_ref, bucket.context_cohort))

    def create_baseline_version(self, *, training_start: str, training_end: str, bucket_count: int, excluded_count: int, feature_schema_version: str, behavior_model_version: str, reason: str) -> int:
        cursor = self.connection.execute(
            """INSERT INTO telemetry_baseline_versions
            (created_at,training_start,training_end,bucket_count,excluded_bucket_count,feature_schema_version,behavior_model_version,reason)
            VALUES(?,?,?,?,?,?,?,?)""",
            (utc_now_iso(), training_start, training_end, bucket_count, excluded_count, feature_schema_version, behavior_model_version, reason[:512]),
        )
        return int(cursor.lastrowid)

    def save_baselines(self, baselines: Iterable[FeatureBaseline]) -> None:
        self.connection.executemany(
            """INSERT OR REPLACE INTO telemetry_baselines
            (baseline_id,host_ref,user_ref,feature_name,time_cohort,context_cohort,median_value,mad_value,p05,p25,p50,p75,p95,sample_count,confidence,state,version,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (item.baseline_id,item.host_ref,item.user_ref,item.feature_name,item.time_cohort,item.context_cohort,item.median_value,item.mad_value,item.p05,item.p25,item.p50,item.p75,item.p95,item.sample_count,item.confidence,item.state.value,item.version,item.updated_at)
                for item in baselines
            ],
        )

    def latest_baseline_version(self) -> int:
        row = self.connection.execute("SELECT MAX(baseline_version) AS version FROM telemetry_baseline_versions").fetchone()
        return int(row["version"] or 0) if row else 0

    def list_baselines(self, *, user_ref: str | None = None, version: int | None = None, limit: int = 5000) -> list[dict[str, Any]]:
        selected = version or self.latest_baseline_version()
        if user_ref is None:
            rows = self.connection.execute(
                "SELECT * FROM telemetry_baselines WHERE version=? ORDER BY user_ref,feature_name,time_cohort LIMIT ?",
                (selected, max(1, min(limit, 20_000))),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM telemetry_baselines WHERE version=? AND user_ref=? ORDER BY feature_name,time_cohort LIMIT ?",
                (selected, user_ref, max(1, min(limit, 20_000))),
            ).fetchall()
        return [self._baseline(row).to_dict() for row in rows]

    def baselines_for(self, *, host_ref: str, user_ref: str, time_cohort: str, context_cohort: str, version: int | None = None) -> dict[str, FeatureBaseline]:
        selected = version or self.latest_baseline_version()
        rows = self.connection.execute(
            """SELECT * FROM telemetry_baselines WHERE host_ref=? AND user_ref=? AND version=?
            AND time_cohort IN (?, 'ALL') AND context_cohort IN (?, 'ALL')
            ORDER BY CASE WHEN time_cohort=? THEN 0 ELSE 1 END, CASE WHEN context_cohort=? THEN 0 ELSE 1 END""",
            (host_ref, user_ref, selected, time_cohort, context_cohort, time_cohort, context_cohort),
        ).fetchall()
        output: dict[str, FeatureBaseline] = {}
        for row in rows:
            name = str(row["feature_name"])
            if name not in output:
                output[name] = self._baseline(row)
        return output

    @staticmethod
    def _baseline(row: Any) -> FeatureBaseline:
        from mac_audit_agent.telemetry.models import BaselineState
        return FeatureBaseline(
            baseline_id=str(row["baseline_id"]),host_ref=str(row["host_ref"]),user_ref=str(row["user_ref"]),
            feature_name=str(row["feature_name"]),time_cohort=str(row["time_cohort"]),context_cohort=str(row["context_cohort"]),
            median_value=float(row["median_value"]),mad_value=float(row["mad_value"]),p05=float(row["p05"]),p25=float(row["p25"]),
            p50=float(row["p50"]),p75=float(row["p75"]),p95=float(row["p95"]),sample_count=int(row["sample_count"]),
            confidence=float(row["confidence"]),state=BaselineState(str(row["state"])),version=int(row["version"]),updated_at=str(row["updated_at"]),
        )

    def save_anomaly(self, anomaly: BehavioralAnomaly) -> None:
        anomaly.created_at = anomaly.created_at or utc_now_iso()
        self.connection.execute(
            """INSERT OR REPLACE INTO behavioral_anomalies
            (anomaly_id,timestamp,host_ref,user_ref,dimension,anomaly_score,security_severity,detection_confidence,baseline_value,observed_value,normal_low,normal_high,reason_codes_json,reasons_json,related_entities_json,evidence_refs_json,sensor_coverage_json,baseline_version,active_behavior_policy,baseline_training_eligible,behavior_model_version,feature_schema_version,incident_id,disposition,recommendation,explanation,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (anomaly.anomaly_id,anomaly.timestamp,anomaly.host_ref,anomaly.user_ref,anomaly.dimension,anomaly.anomaly_score,anomaly.security_severity,anomaly.detection_confidence,anomaly.baseline_value,anomaly.observed_value,anomaly.normal_low,anomaly.normal_high,self._json(anomaly.reason_codes),self._json(anomaly.reasons),self._json(anomaly.related_entities),self._json(anomaly.evidence_refs),self._json(anomaly.sensor_coverage),anomaly.baseline_version,anomaly.active_behavior_policy,int(anomaly.baseline_training_eligible),anomaly.behavior_model_version,anomaly.feature_schema_version,anomaly.incident_id,anomaly.disposition,anomaly.recommendation,anomaly.explanation,anomaly.created_at),
        )

    def list_anomalies(self, *, since: str = "", limit: int = 500, incident_id: str = "") -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if since: clauses.append("timestamp>=?"); params.append(since)
        if incident_id: clauses.append("incident_id=?"); params.append(incident_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(limit, 5000)))
        rows = self.connection.execute(f"SELECT * FROM behavioral_anomalies{where} ORDER BY timestamp DESC LIMIT ?", params).fetchall()
        return [self._anomaly_dict(row) for row in rows]

    def _anomaly_dict(self, row: Any) -> dict[str, Any]:
        payload = dict(row)
        for name in ("reason_codes", "reasons", "related_entities", "evidence_refs", "sensor_coverage"):
            payload[name] = self._load(payload.pop(name + "_json"), [] if name in {"reason_codes", "reasons", "evidence_refs"} else {})
        payload["baseline_training_eligible"] = bool(payload["baseline_training_eligible"])
        return payload

    def update_anomaly_disposition(self, anomaly_id: str, disposition: str, *, actor: str, reason: str = "") -> None:
        row = self.connection.execute("SELECT disposition FROM behavioral_anomalies WHERE anomaly_id=?", (anomaly_id,)).fetchone()
        if row is None:
            raise ValueError("unknown behavioral anomaly")
        previous = str(row["disposition"])
        self.connection.execute("UPDATE behavioral_anomalies SET disposition=? WHERE anomaly_id=?", (disposition, anomaly_id))
        self.connection.execute(
            "INSERT INTO behavioral_feedback(anomaly_id,timestamp,actor,disposition,reason,baseline_change_requested) VALUES(?,?,?,?,?,0)",
            (anomaly_id, utc_now_iso(), actor[:128], disposition, reason[:2048]),
        )
        self.audit(actor=actor, action="anomaly_disposition", object_type="behavioral_anomaly", object_id=anomaly_id, previous={"disposition": previous}, current={"disposition": disposition}, reason=reason)
        self.connection.commit()

    def save_incident(self, incident: BehavioralIncident) -> None:
        self.connection.execute(
            """INSERT OR REPLACE INTO behavioral_incidents
            (incident_id,first_seen,last_seen,host_ref,user_ref,primary_entity,anomaly_ids_json,reason_codes_json,anomaly_score,security_severity,detection_confidence,evidence_refs_json,status,alert_event_id,flight_recorder_snapshot_id,occurrence_count)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (incident.incident_id,incident.first_seen,incident.last_seen,incident.host_ref,incident.user_ref,incident.primary_entity,self._json(incident.anomaly_ids),self._json(incident.reason_codes),incident.anomaly_score,incident.security_severity,incident.detection_confidence,self._json(incident.evidence_refs),incident.status,incident.alert_event_id,incident.flight_recorder_snapshot_id,incident.occurrence_count),
        )
        self.connection.execute(
            f"UPDATE behavioral_anomalies SET incident_id=? WHERE anomaly_id IN ({','.join('?' for _ in incident.anomaly_ids)})",
            [incident.incident_id, *incident.anomaly_ids],
        )

    def list_incidents(self, *, status: str = "", since: str = "", limit: int = 500) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status: clauses.append("status=?"); params.append(status)
        if since: clauses.append("last_seen>=?"); params.append(since)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(max(1, min(limit, 5000)))
        rows = self.connection.execute(f"SELECT * FROM behavioral_incidents{where} ORDER BY anomaly_score DESC,last_seen DESC LIMIT ?", params).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            for name in ("anomaly_ids", "reason_codes", "evidence_refs"):
                item[name] = self._load(item.pop(name + "_json"), [])
            output.append(item)
        return output

    def find_correlatable_incident(self, *, host_ref: str, user_ref: str, primary_entity: str, since: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """SELECT * FROM behavioral_incidents WHERE host_ref=? AND user_ref=? AND status IN ('NEW','INVESTIGATING')
            AND last_seen>=? AND (primary_entity=? OR primary_entity='' OR ?='') ORDER BY last_seen DESC LIMIT 1""",
            (host_ref, user_ref, since, primary_entity, primary_entity),
        ).fetchone()
        if row is None: return None
        item = dict(row)
        for name in ("anomaly_ids", "reason_codes", "evidence_refs"):
            item[name] = self._load(item.pop(name + "_json"), [])
        return item

    def preserve_context(self, *, snapshot_id: str, incident_id: str, anchor_time: str, pre_seconds: int, post_seconds: int) -> list[str]:
        anchor = _parse_time(anchor_time)
        start = (anchor - timedelta(seconds=pre_seconds)).isoformat()
        end = (anchor + timedelta(seconds=post_seconds)).isoformat()
        rows = self.connection.execute(
            "SELECT event_id FROM background_monitor_events WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp ASC LIMIT 5000",
            (start, end),
        ).fetchall()
        refs = [str(row["event_id"]) for row in rows]
        self.connection.execute(
            "INSERT OR REPLACE INTO behavioral_evidence_snapshots(snapshot_id,incident_id,anchor_time,pre_window_seconds,post_window_seconds,canonical_event_refs_json,created_at,finalized_at) VALUES(?,?,?,?,?,?,?,?)",
            (snapshot_id,incident_id,anchor_time,pre_seconds,post_seconds,self._json(refs),utc_now_iso(),""),
        )
        return refs

    def update_entity_profiles(self, event: NormalizedTelemetryEvent) -> None:
        for entity_type, entity_ref in event.entity_keys.items():
            row = self.connection.execute("SELECT first_seen,seen_count FROM behavioral_entity_profiles WHERE entity_type=? AND entity_ref=?", (entity_type, entity_ref)).fetchone()
            first = str(row["first_seen"]) if row else event.timestamp
            count = int(row["seen_count"] or 0) + 1 if row else 1
            self.connection.execute(
                "INSERT OR REPLACE INTO behavioral_entity_profiles(entity_type,entity_ref,first_seen,last_seen,seen_count,attributes_json) VALUES(?,?,?,?,?,?)",
                (entity_type,entity_ref,first,event.timestamp,count,"{}"),
            )

    def entity_seen(self, entity_type: str, entity_ref: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM behavioral_entity_profiles WHERE entity_type=? AND entity_ref=? LIMIT 1",
            (str(entity_type)[:128], str(entity_ref)[:256]),
        ).fetchone()
        return row is not None

    def set_bucket_training_eligible(self, bucket: TelemetryBucket, eligible: bool) -> None:
        self.connection.execute(
            "UPDATE telemetry_buckets SET training_eligible=?,updated_at=? WHERE bucket_start=? AND host_ref=? AND user_ref=? AND context_cohort=?",
            (int(eligible), utc_now_iso(), bucket.bucket_start, bucket.host_ref, bucket.user_ref, bucket.context_cohort),
        )
        bucket.training_eligible = eligible

    def state(self, key: str, default: Any = None) -> Any:
        row = self.connection.execute("SELECT value_json FROM telemetry_runtime_state WHERE key=?", (key,)).fetchone()
        return self._load(row["value_json"], default) if row else default

    def set_state(self, key: str, value: Any) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO telemetry_runtime_state(key,value_json,updated_at) VALUES(?,?,?)",
            (key[:128], self._json(value), utc_now_iso()),
        )

    def audit(self, *, actor: str, action: str, object_type: str, object_id: str, previous: Any = None, current: Any = None, reason: str = "") -> None:
        self.connection.execute(
            "INSERT INTO behavioral_audit_trail(timestamp,actor,action,object_type,object_id,previous_json,current_json,reason) VALUES(?,?,?,?,?,?,?,?)",
            (utc_now_iso(), actor[:128], action[:128], object_type[:128], object_id[:256], self._json(previous or {}), self._json(current or {}), reason[:2048]),
        )

    def prune(self, *, aggregate_retention_days: int, anomaly_retention_days: int) -> dict[str, int]:
        now = datetime.now(timezone.utc)
        raw = self.connection.execute("DELETE FROM telemetry_event_links WHERE expires_at<?", (now.isoformat(),)).rowcount
        buckets = self.connection.execute("DELETE FROM telemetry_buckets WHERE bucket_start<?", ((now - timedelta(days=aggregate_retention_days)).isoformat(),)).rowcount
        anomalies = self.connection.execute("DELETE FROM behavioral_anomalies WHERE timestamp<? AND incident_id=''", ((now - timedelta(days=anomaly_retention_days)).isoformat(),)).rowcount
        self.connection.commit()
        return {"raw_links": int(raw), "buckets": int(buckets), "unlinked_anomalies": int(anomalies)}

    def commit(self) -> None:
        self.connection.commit()


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


__all__ = ["SCHEMA_VERSION", "TelemetryRepository", "migrate", "open_telemetry_connection"]
