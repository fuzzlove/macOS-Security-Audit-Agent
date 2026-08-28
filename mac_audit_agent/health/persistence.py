"""Durable, transition-oriented sensor health storage with hash chaining."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import HealthTransition, PlatformHealthReport, RecoveryResult, SensorHealthSnapshot, SensorState


SCHEMA_VERSION = 1


def _iso(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


class SensorHealthStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._closed = False
        self.connection = sqlite3.connect(str(self.path), timeout=5, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self.connection.close()
                self._closed = True

    def __del__(self) -> None:
        # A final safety net for short-lived GUI/test owners. Normal service and
        # CLI paths close explicitly; finalization must never raise at shutdown.
        try:
            self.close()
        except Exception:
            pass

    def _migrate(self) -> None:
        with self._lock:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sensor_health_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS background_monitor_state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sensor_health_current(
                    sensor_id TEXT PRIMARY KEY,state TEXT NOT NULL,health_score INTEGER NOT NULL,
                    reason_code TEXT NOT NULL,last_heartbeat TEXT,last_event TEXT,last_successful_check TEXT,
                    updated_at TEXT NOT NULL,snapshot_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sensor_health_history(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,sensor_id TEXT NOT NULL,previous_state TEXT,
                    new_state TEXT NOT NULL,reason_code TEXT NOT NULL,severity TEXT NOT NULL,
                    details_json TEXT NOT NULL,occurred_at TEXT NOT NULL,previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS sensor_health_incidents(
                    incident_id TEXT PRIMARY KEY,sensor_id TEXT NOT NULL,reason_code TEXT NOT NULL,
                    state TEXT NOT NULL,severity TEXT NOT NULL,root_cause_dependency TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,occurrence_count INTEGER NOT NULL,
                    affected_capabilities_json TEXT NOT NULL,latest_metrics_json TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,resolved_at TEXT NOT NULL DEFAULT ''
                );
                CREATE UNIQUE INDEX IF NOT EXISTS sensor_health_active_incident
                    ON sensor_health_incidents(sensor_id,reason_code,root_cause_dependency) WHERE active=1;
                CREATE TABLE IF NOT EXISTS sensor_recovery_actions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,sensor_id TEXT NOT NULL,recovery_type TEXT NOT NULL,
                    reason_code TEXT NOT NULL,result TEXT NOT NULL,details_json TEXT NOT NULL,
                    started_at TEXT NOT NULL,completed_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sensor_dependency_health(
                    sensor_id TEXT NOT NULL,dependency_id TEXT NOT NULL,state TEXT NOT NULL,required INTEGER NOT NULL,
                    reason TEXT NOT NULL,latency_ms REAL,last_checked TEXT,updated_at TEXT NOT NULL,
                    PRIMARY KEY(sensor_id,dependency_id)
                );
                CREATE TABLE IF NOT EXISTS sensor_health_summaries(
                    bucket_start TEXT NOT NULL,sensor_id TEXT NOT NULL,healthy_seconds REAL NOT NULL DEFAULT 0,
                    degraded_seconds REAL NOT NULL DEFAULT 0,failed_seconds REAL NOT NULL DEFAULT 0,
                    recovering_seconds REAL NOT NULL DEFAULT 0,incident_count INTEGER NOT NULL DEFAULT 0,
                    samples INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(bucket_start,sensor_id)
                );
                CREATE TABLE IF NOT EXISTS sensor_manager_state(
                    key TEXT PRIMARY KEY,value_json TEXT NOT NULL,updated_at TEXT NOT NULL
                );
                """
            )
            self.connection.execute("INSERT OR REPLACE INTO sensor_health_meta VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
            self.connection.commit()

    def current_snapshot(self, sensor_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute("SELECT snapshot_json FROM sensor_health_current WHERE sensor_id=?", (sensor_id,)).fetchone()
        if not row:
            return None
        try:
            payload = json.loads(str(row[0]))
            return payload if isinstance(payload, dict) else None
        except json.JSONDecodeError:
            return None

    def current_snapshots(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute("SELECT snapshot_json FROM sensor_health_current ORDER BY sensor_id").fetchall()
        output = []
        for row in rows:
            try:
                payload = json.loads(str(row[0]))
                if isinstance(payload, dict):
                    output.append(payload)
            except json.JSONDecodeError:
                continue
        return output

    def persist_report(self, report: PlatformHealthReport, previous_states: dict[str, SensorState]) -> list[HealthTransition]:
        transitions: list[HealthTransition] = []
        with self._lock:
            for snapshot in report.sensors:
                payload = snapshot.to_dict()
                prior = previous_states.get(snapshot.sensor_id, SensorState.UNKNOWN)
                self.connection.execute(
                    """INSERT INTO sensor_health_current(sensor_id,state,health_score,reason_code,last_heartbeat,last_event,last_successful_check,updated_at,snapshot_json)
                    VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(sensor_id) DO UPDATE SET state=excluded.state,health_score=excluded.health_score,
                    reason_code=excluded.reason_code,last_heartbeat=excluded.last_heartbeat,last_event=excluded.last_event,
                    last_successful_check=excluded.last_successful_check,updated_at=excluded.updated_at,snapshot_json=excluded.snapshot_json""",
                    (snapshot.sensor_id, snapshot.state.value, snapshot.health_score, snapshot.reason_code.value,
                     payload.get("last_process_heartbeat"), payload.get("last_collection_activity"), _iso(snapshot.sampled_at),
                     _iso(), _canonical(payload)),
                )
                for dependency in snapshot.dependencies:
                    self.connection.execute(
                        """INSERT INTO sensor_dependency_health VALUES(?,?,?,?,?,?,?,?)
                        ON CONFLICT(sensor_id,dependency_id) DO UPDATE SET state=excluded.state,required=excluded.required,
                        reason=excluded.reason,latency_ms=excluded.latency_ms,last_checked=excluded.last_checked,updated_at=excluded.updated_at""",
                        (snapshot.sensor_id, dependency.dependency_id, dependency.state.value, int(dependency.required), dependency.reason,
                         dependency.latency_ms, _iso(dependency.last_checked) if dependency.last_checked else None, _iso()),
                    )
                if prior != snapshot.state:
                    severity = self._severity(snapshot)
                    transition = HealthTransition(
                        event_type="sensor_health_transition", sensor_id=snapshot.sensor_id, timestamp=snapshot.sampled_at,
                        previous_state=prior, current_state=snapshot.state, reason_code=snapshot.reason_code,
                        reason=snapshot.reason, severity=severity,
                        affected_capabilities=tuple(item.capability_id for item in snapshot.capabilities if item.coverage.value != "FULL"),
                        metrics={"queue_depth": snapshot.queue_depth, "queue_capacity": snapshot.queue_capacity,
                                 "processing_latency_ms": snapshot.processing_latency_ms,
                                 "events_dropped": snapshot.events_dropped_total},
                        root_cause_dependency=self._root_dependency(snapshot),
                    )
                    self._record_transition(transition)
                    self._update_incident(transition)
                    transitions.append(transition)
            self.set_manager_state("latest_platform_report", report.to_dict(), commit=False)
            self.connection.commit()
        return transitions

    def _record_transition(self, transition: HealthTransition) -> None:
        prior_row = self.connection.execute("SELECT record_hash FROM sensor_health_history ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = str(prior_row[0]) if prior_row else "0" * 64
        details = {
            "event_type": transition.event_type, "sensor_id": transition.sensor_id,
            "timestamp": _iso(transition.timestamp), "previous_state": transition.previous_state.value,
            "current_state": transition.current_state.value, "reason_code": transition.reason_code.value,
            "reason": transition.reason, "severity": transition.severity,
            "affected_capabilities": list(transition.affected_capabilities), "metrics": transition.metrics,
            "automatic_recovery_attempted": transition.automatic_recovery_attempted,
            "root_cause_dependency": transition.root_cause_dependency,
        }
        record_hash = hashlib.sha256((previous_hash + _canonical(details)).encode()).hexdigest()
        self.connection.execute(
            "INSERT INTO sensor_health_history(sensor_id,previous_state,new_state,reason_code,severity,details_json,occurred_at,previous_hash,record_hash) VALUES(?,?,?,?,?,?,?,?,?)",
            (transition.sensor_id, transition.previous_state.value, transition.current_state.value,
             transition.reason_code.value, transition.severity, _canonical(details), _iso(transition.timestamp), previous_hash, record_hash),
        )

    def _update_incident(self, transition: HealthTransition) -> None:
        healthy = transition.current_state in {SensorState.HEALTHY, SensorState.HEALTHY_IDLE, SensorState.HEALTHY_WITH_WARNINGS}
        if healthy:
            self.connection.execute(
                "UPDATE sensor_health_incidents SET active=0,resolved_at=?,last_seen=? WHERE sensor_id=? AND active=1",
                (_iso(transition.timestamp), _iso(transition.timestamp), transition.sensor_id),
            )
            return
        key = (transition.sensor_id, transition.reason_code.value, transition.root_cause_dependency)
        row = self.connection.execute(
            "SELECT incident_id,occurrence_count FROM sensor_health_incidents WHERE sensor_id=? AND reason_code=? AND root_cause_dependency=? AND active=1", key
        ).fetchone()
        if row:
            self.connection.execute(
                "UPDATE sensor_health_incidents SET last_seen=?,occurrence_count=?,state=?,severity=?,latest_metrics_json=? WHERE incident_id=?",
                (_iso(transition.timestamp), int(row[1]) + 1, transition.current_state.value, transition.severity, _canonical(transition.metrics), str(row[0])),
            )
        else:
            incident_id = hashlib.sha256(("|".join(key) + _iso(transition.timestamp)).encode()).hexdigest()[:24]
            self.connection.execute(
                """INSERT INTO sensor_health_incidents(
                incident_id,sensor_id,reason_code,state,severity,root_cause_dependency,
                first_seen,last_seen,occurrence_count,affected_capabilities_json,latest_metrics_json,active,resolved_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,'')""",
                (incident_id, transition.sensor_id, transition.reason_code.value, transition.current_state.value,
                 transition.severity, transition.root_cause_dependency, _iso(transition.timestamp), _iso(transition.timestamp), 1,
                 _canonical(list(transition.affected_capabilities)), _canonical(transition.metrics)),
            )

    def record_recovery(self, sensor_id: str, reason_code: str, result: RecoveryResult, *, started_at: datetime) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT INTO sensor_recovery_actions(sensor_id,recovery_type,reason_code,result,details_json,started_at,completed_at) VALUES(?,?,?,?,?,?,?)",
                (sensor_id, result.action.value, reason_code, "succeeded" if result.succeeded else "failed" if result.attempted else "not_attempted",
                 _canonical({"detail": result.detail, "requires_operator": result.requires_operator, "verification_required": result.verification_required}),
                 _iso(started_at), _iso()),
            )
            self.connection.commit()

    def history(self, sensor_id: str = "", *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(1_000, int(limit)))
        query = "SELECT * FROM sensor_health_history"
        args: tuple[Any, ...] = ()
        if sensor_id:
            query += " WHERE sensor_id=?"
            args = (sensor_id,)
        query += " ORDER BY id DESC LIMIT ?"
        args += (limit,)
        with self._lock:
            rows = self.connection.execute(query, args).fetchall()
        return [dict(row) | {"details": json.loads(str(row["details_json"]))} for row in rows]

    def dependencies(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self.connection.execute("SELECT * FROM sensor_dependency_health ORDER BY sensor_id,dependency_id").fetchall()]

    def recoveries(self, sensor_id: str = "", *, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT * FROM sensor_recovery_actions"
        args: tuple[Any, ...] = ()
        if sensor_id:
            query += " WHERE sensor_id=?"
            args = (sensor_id,)
        query += " ORDER BY id DESC LIMIT ?"
        args += (max(1, min(1_000, int(limit))),)
        with self._lock:
            return [dict(row) for row in self.connection.execute(query, args).fetchall()]

    def set_manager_state(self, key: str, value: Any, *, commit: bool = True) -> None:
        payload = _canonical(value if isinstance(value, dict) else {"value": value})
        self.connection.execute(
            "INSERT INTO sensor_manager_state VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",
            (key, payload, _iso()),
        )
        if commit:
            self.connection.commit()

    def get_manager_state(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self.connection.execute("SELECT value_json FROM sensor_manager_state WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        try:
            payload = json.loads(str(row[0]))
            return payload.get("value") if isinstance(payload, dict) and set(payload) == {"value"} else payload
        except json.JSONDecodeError:
            return default

    @staticmethod
    def _severity(snapshot: SensorHealthSnapshot) -> str:
        if snapshot.state in {SensorState.FAILED, SensorState.UNAVAILABLE, SensorState.PERMISSION_BLOCKED}:
            return "CRITICAL"
        if snapshot.state in {SensorState.IMPAIRED, SensorState.DEPENDENCY_FAILED, SensorState.CONFIGURATION_ERROR}:
            return "HIGH"
        if snapshot.state in {SensorState.DEGRADED, SensorState.BACKPRESSURED, SensorState.STALE}:
            return "MEDIUM"
        return "INFO"

    @staticmethod
    def _root_dependency(snapshot: SensorHealthSnapshot) -> str:
        for dependency in snapshot.dependencies:
            if dependency.required and dependency.state.value in {"FAILED", "UNAVAILABLE"}:
                return dependency.dependency_id
        return ""


__all__ = ["SCHEMA_VERSION", "SensorHealthStore"]
