"""Adapters that translate existing MSAA runtime evidence into health contracts."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from .models import (
    CapabilityHealth,
    CoverageLevel,
    DependencyState,
    PermissionState,
    ReasonCode,
    RecoveryLevel,
    RecoveryReason,
    RecoveryResult,
    ResourceMetrics,
    RuleHealth,
    SelfTestResult,
    SensorDependency,
    SensorHealthSnapshot,
    SensorState,
    utc_now,
)

SYSTEM_DB = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3")
SENSOR_HEALTH_PATH = Path("/Library/Application Support/MacAuditAgent/run/endpoint-security-health.json")


def _timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), timezone.utc)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def _json_file(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or path.stat().st_size > 1_048_576:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def _db_state(path: Path) -> tuple[dict[str, str], float | None, int, int]:
    started = time.monotonic()
    uri = f"file:{path.resolve(strict=False).as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=1) as connection:
        rows = connection.execute("SELECT key,value FROM background_monitor_state").fetchall()
        event_count = int(connection.execute("SELECT COUNT(*) FROM background_monitor_events").fetchone()[0])
        pending = int(connection.execute("SELECT COUNT(*) FROM background_monitor_events WHERE notification_sent=0").fetchone()[0])
    return {str(key): str(value) for key, value in rows}, (time.monotonic() - started) * 1000, event_count, pending


def _ransomware_telemetry_state(path: Path) -> dict[str, Any]:
    """Read only telemetry produced by the ransomware pipeline itself.

    Endpoint Security counters describe the upstream transport.  They must not
    be reused as ransomware-analysis or evidence counters: the native sensor
    can be busy even when no ransomware analyzer consumes its output.
    """
    started = time.monotonic()
    try:
        uri = f"file:{path.resolve(strict=False).as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=1) as connection:
            rows = connection.execute(
                "SELECT key,value FROM background_monitor_state WHERE key GLOB 'anti_ransomware_*' "
                "OR key IN ('last_heartbeat','last_event_timestamp')"
            ).fetchall()
            finding = connection.execute(
                "SELECT COUNT(*),"
                "SUM(CASE WHEN notification_sent=0 THEN 1 ELSE 0 END),MAX(timestamp) "
                "FROM background_monitor_events WHERE source GLOB 'anti_ransomware_*'"
            ).fetchone()
        states = {str(key): str(value) for key, value in rows}
        return {
            "database_available": True,
            "database_latency_ms": (time.monotonic() - started) * 1000,
            "observer_running": states.get("anti_ransomware_prototype_status") == "running",
            "last_heartbeat": states.get("last_heartbeat", ""),
            "last_observation": states.get("anti_ransomware_prototype_last_event", ""),
            "observations_total": max(0, int(states.get("anti_ransomware_prototype_events_observed_total", "0") or 0)),
            "observations_dropped_total": max(0, int(states.get("anti_ransomware_prototype_events_dropped_total", "0") or 0)),
            "recent_window_count": max(0, int(states.get("anti_ransomware_prototype_window_count", "0") or 0)),
            "findings_total": max(0, int(finding[0] or 0)),
            "pending_findings": max(0, int(finding[1] or 0)),
            "last_finding": str(finding[2] or ""),
            "yara_active": states.get("anti_ransomware_yara_active") == "1",
            "yara_rule_count": max(0, int(states.get("anti_ransomware_yara_rule_count", "0") or 0)),
        }
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return {"database_available": False, "database_latency_ms": None, "observer_running": False}


class EndpointSecurityProvider:
    def __init__(self, *, health_path: Path = SENSOR_HEALTH_PATH, runtime_reader: Callable[[], dict[str, Any]] | None = None) -> None:
        self.health_path = health_path
        self.runtime_reader = runtime_reader or self._runtime_health

    def sensor_id(self) -> str:
        return "endpoint_security"

    @staticmethod
    def _runtime_health() -> dict[str, Any]:
        from mac_audit_agent.anti_ransomware.health import source_health

        return source_health().to_dict()

    def health_snapshot(self) -> SensorHealthSnapshot:
        health = self.runtime_reader()
        live = _json_file(self.health_path)
        recorded = _timestamp(live.get("recorded_at"))
        connected = bool(health.get("endpoint_security_connected"))
        signature = bool(health.get("sensor_signature_valid"))
        entitled = bool(health.get("entitlement_accepted"))
        permission = bool(health.get("tcc_approval_present"))
        pipeline_counters = "events_received_total" in live
        received = int(live.get("events_received_total", int(bool(live.get("live_event_seen")))))
        processed = int(live.get("events_processed_total", received))
        delivered = int(live.get("events_delivered_total", 0 if not pipeline_counters else processed))
        persisted = int(live.get("events_persisted_total", 0))
        dropped = int(live.get("events_dropped_total", int(bool(live.get("sequence_gap_detected")))))
        queue_depth = int(live.get("queue_depth", 0))
        queue_capacity = int(live.get("queue_capacity", 4096 if health.get("sensor_running") else 0))
        collection_time = _timestamp(live.get("last_collection_activity")) or (recorded if live.get("live_event_seen") else None)
        processing_time = _timestamp(live.get("last_processing_activity")) or collection_time
        delivery_time = _timestamp(live.get("last_delivery_activity"))
        persistence_time = _timestamp(live.get("last_persistence_activity"))
        dependencies = (
            SensorDependency("endpoint_security_client", True, DependencyState.HEALTHY if connected else DependencyState.FAILED, str(health.get("endpoint_security_client_result", "unknown")), last_checked=utc_now()),
            SensorDependency("full_disk_access", True, DependencyState.HEALTHY if permission else DependencyState.FAILED, "granted" if permission else "requires user action", last_checked=utc_now()),
            SensorDependency("signed_sensor", True, DependencyState.HEALTHY if signature and entitled else DependencyState.FAILED, "valid signed entitlement" if signature and entitled else "signature or entitlement unavailable", last_checked=utc_now()),
        )
        coverage = CoverageLevel.FULL if connected and signature and entitled and permission and not dropped else CoverageLevel.PARTIAL if connected else CoverageLevel.NONE
        return SensorHealthSnapshot(
            sensor_id=self.sensor_id(), sensor_version=str(health.get("sensor_version") or "unknown"),
            pid=int(live.get("pid")) if str(live.get("pid", "")).isdigit() else None,
            process_alive=bool(health.get("sensor_running")), initialized=connected and bool(health.get("endpoint_security_subscriptions_active")),
            last_process_heartbeat=recorded, last_collection_activity=collection_time,
            last_processing_activity=processing_time, last_delivery_activity=delivery_time,
            last_persistence_activity=persistence_time, events_received_total=received,
            events_processed_total=processed, events_delivered_total=delivered,
            events_persisted_total=persisted, events_dropped_total=dropped,
            events_failed_total=int(live.get("events_failed_total", 0)),
            events_rejected_total=int(live.get("events_rejected_total", 0)),
            queue_depth=queue_depth, queue_capacity=queue_capacity,
            peak_queue_depth=int(live.get("peak_queue_depth", queue_depth)),
            processing_latency_ms=float(live["processing_latency_ms"]) if live.get("processing_latency_ms") is not None else None,
            worker_sequence=processed, permission_state=PermissionState.GRANTED if permission else PermissionState.USER_ACTION_REQUIRED,
            dependencies=dependencies,
            capabilities=tuple(CapabilityHealth(item, coverage, "Live Endpoint Security readiness evidence." if coverage == CoverageLevel.FULL else "Endpoint Security readiness evidence is incomplete.") for item in ("process_execution", "file_modification", "ransomware_telemetry")),
            restart_count=int(live.get("restart_count", 0)),
            metadata={"signature_valid": signature, "entitlement_accepted": entitled,
                      "subscriptions_active": bool(health.get("endpoint_security_subscriptions_active")),
                      "sequence_gap_detected": bool(health.get("endpoint_security_sequence_gap_detected")),
                      "delivery_required": False, "persistence_required": False,
                      "native_pipeline_counters": pipeline_counters},
            remediation="Verify the signed sensor, Full Disk Access, and live Endpoint Security client connection.",
        )

    def dependencies(self) -> list[SensorDependency]:
        return list(self.health_snapshot().dependencies)

    def perform_self_test(self) -> SelfTestResult:
        before = _json_file(self.health_path)
        before_count = int(before.get("events_received_total", 0))
        canary_id = str(uuid4())
        started = time.monotonic()
        root = Path(tempfile.mkdtemp(prefix=f"msaa-health-canary-{canary_id[:8]}-"))
        try:
            marker = root / "health_canary.internal"
            marker.write_text(json.dumps({"type": "health_canary", "canary_id": canary_id}), encoding="utf-8")
            renamed = root / "health_canary_renamed.internal"
            marker.rename(renamed)
            subprocess.run(["/usr/bin/true", f"msaa-health-canary-{canary_id}"], timeout=2, check=False, capture_output=True)
            renamed.unlink(missing_ok=True)
            deadline = time.monotonic() + 4.0
            while time.monotonic() < deadline:
                current = _json_file(self.health_path)
                if int(current.get("events_received_total", 0)) > before_count:
                    return SelfTestResult(True, "endpoint_security_pipeline_canary", "Harmless process/filesystem canary increased the native collection counter.", (time.monotonic() - started) * 1000, canary_id, ("generated", "collected"))
                time.sleep(0.1)
            current = self.health_snapshot()
            passed = current.process_alive and current.initialized and bool(current.last_collection_activity)
            reason = "Native event counters are not available; connected live-event readiness remained valid." if passed else "The harmless canary did not produce functional collection evidence."
            return SelfTestResult(passed, "endpoint_security_pipeline_canary", reason, (time.monotonic() - started) * 1000, canary_id, ("generated", "readiness_validated") if passed else ("generated",))
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            return SelfTestResult(False, "endpoint_security_pipeline_canary", f"Safe canary failed: {type(exc).__name__}", (time.monotonic() - started) * 1000, canary_id)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def recover(self, reason: RecoveryReason) -> RecoveryResult:
        if reason.requested_level == RecoveryLevel.REQUEST_WATCHDOG:
            try:
                from mac_audit_agent.service_watchdog import request_service_recovery

                request_service_recovery(self.sensor_id(), reason.reason_code.value)
                return RecoveryResult(True, True, RecoveryLevel.REQUEST_WATCHDOG, "An allowlisted restart request was handed to the watchdog; functional validation is still required.")
            except (OSError, ValueError) as exc:
                return RecoveryResult(True, False, RecoveryLevel.REQUEST_WATCHDOG, f"Watchdog request failed safely: {type(exc).__name__}")
        return RecoveryResult(False, False, reason.requested_level, "No safe in-process Endpoint Security recovery is available.")


class RansomwareMonitorProvider:
    def __init__(
        self,
        endpoint: EndpointSecurityProvider,
        *,
        system_database: Path = SYSTEM_DB,
        telemetry_reader: Callable[[Path], dict[str, Any]] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.system_database = Path(system_database)
        self.telemetry_reader = telemetry_reader or _ransomware_telemetry_state

    def sensor_id(self) -> str:
        return "ransomware_monitor"

    def health_snapshot(self) -> SensorHealthSnapshot:
        endpoint = self.endpoint.health_snapshot()
        telemetry = self.telemetry_reader(self.system_database)
        database_available = bool(telemetry.get("database_available"))
        observer_running = bool(telemetry.get("observer_running"))

        # There is currently no production bridge from the native ES stdout
        # stream into the Python behavior/evidence pipeline.  Do not infer one
        # merely because Endpoint Security is connected.
        primary_pipeline_active = bool(telemetry.get("primary_pipeline_active", False))
        fallback = "development metadata observer" if observer_running and not primary_pipeline_active else ""
        findings = max(0, int(telemetry.get("findings_total", 0) or 0))
        pending_findings = min(findings, max(0, int(telemetry.get("pending_findings", 0) or 0)))
        last_observation = _timestamp(telemetry.get("last_observation"))
        last_finding = _timestamp(telemetry.get("last_finding"))
        heartbeat = _timestamp(telemetry.get("last_heartbeat"))
        dropped = max(0, int(telemetry.get("observations_dropped_total", 0) or 0))
        yara_rules = max(0, int(telemetry.get("yara_rule_count", 0) or 0)) if telemetry.get("yara_active") else 0
        rules_expected = 1 + yara_rules if observer_running else 1
        rules_loaded = rules_expected if observer_running else 1 if primary_pipeline_active else 0
        coverage = (
            CoverageLevel.FULL
            if primary_pipeline_active and not dropped
            else CoverageLevel.LIMITED
            if observer_running
            else CoverageLevel.NONE
        )
        evidence_coverage = CoverageLevel.LIMITED if database_available and observer_running else CoverageLevel.NONE
        endpoint_dependency = DependencyState.HEALTHY if endpoint.initialized else DependencyState.DEGRADED if observer_running else DependencyState.FAILED
        database_dependency = DependencyState.HEALTHY if database_available else DependencyState.FAILED
        process_alive = (primary_pipeline_active and endpoint.process_alive) or observer_running
        initialized = primary_pipeline_active or observer_running
        return SensorHealthSnapshot(
            sensor_id=self.sensor_id(), sensor_version=endpoint.sensor_version,
            process_alive=process_alive, initialized=initialized,
            last_process_heartbeat=heartbeat or (endpoint.last_process_heartbeat if primary_pipeline_active else None),
            last_collection_activity=last_observation or (endpoint.last_collection_activity if primary_pipeline_active else None),
            last_processing_activity=last_observation or (endpoint.last_processing_activity if primary_pipeline_active else None),
            last_delivery_activity=last_finding,
            last_persistence_activity=last_finding,
            events_received_total=findings,
            events_processed_total=findings,
            # A finding is delivered when the monitor commits it to the shared
            # event store. User notification is a separate downstream state.
            events_delivered_total=findings,
            events_persisted_total=findings,
            events_dropped_total=dropped,
            queue_depth=0, queue_capacity=0,
            permission_state=endpoint.permission_state if primary_pipeline_active else PermissionState.GRANTED if database_available else PermissionState.UNKNOWN,
            dependencies=(SensorDependency("endpoint_security", not observer_running, endpoint_dependency, "Endpoint Security transport initialized." if endpoint.initialized else "Endpoint Security transport unavailable; limited observer retained." if observer_running else "Endpoint Security transport unavailable."),
                          SensorDependency("evidence_database", True, database_dependency, "ransomware finding store available" if database_available else "ransomware finding store unavailable"),
                          SensorDependency("ruleset", True, DependencyState.HEALTHY if rules_loaded else DependencyState.FAILED, "behavior rules active" if rules_loaded else "rule readiness unavailable")),
            rules=RuleHealth(expected=rules_expected, loaded=rules_loaded, failed=rules_expected - rules_loaded, version="runtime"),
            capabilities=(CapabilityHealth("ransomware_detection", coverage, "The production behavior pipeline is active." if coverage == CoverageLevel.FULL else "Delayed metadata observation is active; raw Endpoint Security transport counts are not treated as analyzed ransomware telemetry." if observer_running else "No ransomware analysis pipeline is active.", fallback),
                          CapabilityHealth("ransomware_evidence", evidence_coverage, "Ransomware findings are stored locally when the limited observer emits one." if evidence_coverage != CoverageLevel.NONE else "No functional ransomware finding store is currently proven.")),
            fallback_mode=fallback, lost_capabilities=("preemptive_authorization",) if fallback else (),
            retained_capabilities=("delayed_metadata_observation",) if fallback else ("production_behavior_analysis",) if primary_pipeline_active else (),
            metadata={
                "delivery_required": False,
                "persistence_required": False,
                "telemetry_source": "development_observer" if observer_running else "production_pipeline" if primary_pipeline_active else "none",
                "upstream_endpoint_events_received_total": endpoint.events_received_total,
                "upstream_endpoint_events_processed_total": endpoint.events_processed_total,
                "observations_total": max(0, int(telemetry.get("observations_total", 0) or 0)),
                "recent_window_count": max(0, int(telemetry.get("recent_window_count", 0) or 0)),
                "findings_pending_notification": pending_findings,
                "database": str(self.system_database),
                "database_latency_ms": telemetry.get("database_latency_ms"),
                "primary_pipeline_active": primary_pipeline_active,
            },
            remediation="Restore Endpoint Security telemetry and validate behavior rules; containment readiness is reported separately.",
        )

    def dependencies(self) -> list[SensorDependency]:
        return list(self.health_snapshot().dependencies)

    def perform_self_test(self) -> SelfTestResult:
        result = self.endpoint.perform_self_test()
        return SelfTestResult(result.passed, "ransomware_observation_canary", result.reason, result.latency_ms, result.canary_id, result.stages)

    def recover(self, reason: RecoveryReason) -> RecoveryResult:
        return self.endpoint.recover(reason)


class SQLitePipelineProvider:
    def __init__(self, sensor: str, display_capabilities: tuple[str, ...], *, database: Path, receipt_database: Path | None = None) -> None:
        self._sensor = sensor
        self.capabilities = display_capabilities
        self.database = database
        self.receipt_database = receipt_database or database

    def sensor_id(self) -> str:
        return self._sensor

    def health_snapshot(self) -> SensorHealthSnapshot:
        try:
            states, latency, event_count, pending = _db_state(self.database)
            db_ok = True
        except (OSError, sqlite3.Error, ValueError):
            states, latency, event_count, pending, db_ok = {}, None, 0, 0, False
        notifier = self._sensor == "user_notifier"
        heartbeat_key = "user_notifier_heartbeat" if notifier else "last_heartbeat"
        heartbeat = _timestamp(states.get(heartbeat_key) or states.get("last_heartbeat"))
        last_event = _timestamp(states.get("last_event_timestamp"))
        last_processed = _timestamp(states.get("notifier_last_poll")) if notifier else heartbeat
        last_delivered = _timestamp(states.get("last_notification_time")) if notifier else last_event
        process_alive = states.get("notifier_running") == "1" if notifier else bool(heartbeat)
        if not notifier:
            process_alive = bool(heartbeat)
        error = states.get("notifier_last_error", "") if notifier else states.get("last_monitor_error", "")
        queue_capacity = max(1024, pending * 2) if db_ok else 0
        free = None
        try:
            disk = shutil.disk_usage(self.database.parent)
            free = ResourceMetrics(free_disk_bytes=disk.free, free_disk_percent=disk.free / disk.total * 100, database_latency_ms=latency)
        except OSError:
            free = ResourceMetrics(database_latency_ms=latency)
        deps = (SensorDependency("sqlite", True, DependencyState.HEALTHY if db_ok else DependencyState.FAILED, "lightweight read transaction succeeded" if db_ok else "database unavailable", latency, utc_now()),)
        if notifier:
            deps += (SensorDependency("user_session", True, DependencyState.HEALTHY if os.getuid() >= 0 else DependencyState.UNKNOWN, "current GUI-session validation is performed by launchd status"),)
        return SensorHealthSnapshot(
            sensor_id=self._sensor, process_alive=process_alive, initialized=db_ok and not error,
            last_process_heartbeat=heartbeat, last_collection_activity=last_event or heartbeat,
            last_processing_activity=last_processed or heartbeat, last_delivery_activity=last_delivered or last_processed,
            last_persistence_activity=last_event or heartbeat, events_received_total=event_count,
            events_processed_total=max(0, event_count - pending), events_delivered_total=max(0, event_count - pending),
            events_persisted_total=event_count, events_failed_total=1 if error else 0,
            consecutive_error_count=1 if error else 0, queue_depth=pending, queue_capacity=queue_capacity,
            permission_state=PermissionState.GRANTED if db_ok else PermissionState.UNKNOWN,
            dependencies=deps,
            capabilities=tuple(CapabilityHealth(item, CoverageLevel.FULL if process_alive and db_ok and not error else CoverageLevel.NONE, "Database and layered heartbeats are current." if process_alive and db_ok else "Functional database/heartbeat evidence is unavailable.") for item in self.capabilities),
            resources=free, metadata={"last_error": error[:256], "database": str(self.database)},
            remediation="Inspect the service heartbeat, SQLite writer queue, and launchd state; preserve database evidence before repair.",
        )

    def dependencies(self) -> list[SensorDependency]:
        return list(self.health_snapshot().dependencies)

    def perform_self_test(self) -> SelfTestResult:
        started = time.monotonic()
        try:
            _states, _latency, _events, _pending = _db_state(self.database)
            return SelfTestResult(True, f"{self._sensor}_database_probe", "Lightweight read-only transaction completed.", (time.monotonic() - started) * 1000, str(uuid4()), ("opened", "read", "closed"))
        except (OSError, sqlite3.Error, ValueError) as exc:
            return SelfTestResult(False, f"{self._sensor}_database_probe", f"Database probe failed: {type(exc).__name__}", (time.monotonic() - started) * 1000)

    def recover(self, reason: RecoveryReason) -> RecoveryResult:
        if reason.requested_level == RecoveryLevel.RECONNECT:
            result = self.perform_self_test()
            return RecoveryResult(True, result.passed, RecoveryLevel.RECONNECT, result.reason)
        if reason.requested_level == RecoveryLevel.REQUEST_WATCHDOG:
            try:
                from mac_audit_agent.service_watchdog import request_service_recovery

                request_service_recovery(self._sensor, reason.reason_code.value)
                return RecoveryResult(True, True, RecoveryLevel.REQUEST_WATCHDOG, "Allowlisted watchdog recovery requested; readiness validation remains pending.")
            except (OSError, ValueError) as exc:
                return RecoveryResult(True, False, RecoveryLevel.REQUEST_WATCHDOG, f"Watchdog request failed safely: {type(exc).__name__}")
        return RecoveryResult(False, False, reason.requested_level, "No targeted automatic action is defined.")


class BehavioralTelemetryProvider:
    def __init__(self, *, database: Path) -> None:
        self.database = Path(database)

    def sensor_id(self) -> str:
        return "behavioral_telemetry"

    def _state(self) -> dict[str, Any]:
        started = time.monotonic()
        uri = f"file:{self.database.resolve(strict=False).as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=1) as connection:
            connection.row_factory = sqlite3.Row
            state_row = connection.execute("SELECT value_json,updated_at FROM telemetry_runtime_state WHERE key='health_metrics'").fetchone()
            baseline_row = connection.execute("SELECT MAX(baseline_version) FROM telemetry_baseline_versions").fetchone()
            bucket_row = connection.execute("SELECT COUNT(*),MAX(bucket_end) FROM telemetry_buckets").fetchone()
            anomaly_row = connection.execute("SELECT COUNT(*),MAX(timestamp) FROM behavioral_anomalies").fetchone()
        try:
            metrics = json.loads(str(state_row["value_json"] or "{}")) if state_row else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            metrics = {}
        return {
            **(metrics if isinstance(metrics, dict) else {}),
            "database_latency_ms": (time.monotonic() - started) * 1000,
            "state_updated_at": str(state_row["updated_at"] or "") if state_row else "",
            "baseline_version": int(baseline_row[0] or 0) if baseline_row else 0,
            "bucket_count": int(bucket_row[0] or 0) if bucket_row else 0,
            "last_bucket": str(bucket_row[1] or "") if bucket_row else "",
            "anomaly_count_persisted": int(anomaly_row[0] or 0) if anomaly_row else 0,
            "last_anomaly": str(anomaly_row[1] or "") if anomaly_row else "",
        }

    def health_snapshot(self) -> SensorHealthSnapshot:
        try:
            state = self._state()
            db_ok = True
        except (OSError, sqlite3.Error, ValueError):
            state, db_ok = {}, False
        last_raw = _timestamp(state.get("last_raw_event"))
        last_bucket = _timestamp(state.get("last_bucket_completed") or state.get("last_bucket"))
        last_analysis = _timestamp(state.get("last_analysis"))
        last_baseline = _timestamp(state.get("last_baseline_update"))
        received = max(0, int(state.get("events_received", 0) or 0))
        aggregated = max(0, int(state.get("events_aggregated", 0) or 0))
        drops = max(0, int(state.get("dropped_telemetry", 0) or 0))
        errors = max(0, int(state.get("error_count", 0) or 0))
        queue_depth = max(0, int(state.get("queue_depth", 0) or 0))
        queue_capacity = max(0, int(state.get("queue_capacity", 0) or 0))
        baseline_ready = int(state.get("baseline_version", 0) or 0) > 0
        coverage = CoverageLevel.FULL if db_ok and baseline_ready and not drops else CoverageLevel.PARTIAL if db_ok else CoverageLevel.NONE
        return SensorHealthSnapshot(
            sensor_id=self.sensor_id(),process_alive=db_ok and bool(state.get("worker_alive", last_analysis is not None)),initialized=db_ok,
            last_process_heartbeat=_timestamp(state.get("state_updated_at")) or last_analysis,last_collection_activity=last_raw,
            last_processing_activity=last_analysis,last_delivery_activity=last_analysis,last_persistence_activity=last_bucket,
            events_received_total=received,events_processed_total=aggregated,events_delivered_total=int(state.get("analysis_count", 0) or 0),
            events_persisted_total=int(state.get("bucket_count", 0) or 0),events_dropped_total=drops,events_failed_total=errors,
            queue_depth=queue_depth,queue_capacity=queue_capacity,peak_queue_depth=int(state.get("queue_peak", queue_depth) or 0),
            processing_latency_ms=float(state.get("analysis_latency_ms", 0.0) or 0.0),permission_state=PermissionState.GRANTED if db_ok else PermissionState.UNKNOWN,
            dependencies=(
                SensorDependency("sqlite", True, DependencyState.HEALTHY if db_ok else DependencyState.FAILED, "Behavioral aggregate store is readable." if db_ok else "Behavioral aggregate store is unavailable."),
                SensorDependency("system_monitor", True, DependencyState.HEALTHY if last_raw else DependencyState.UNKNOWN, "Canonical event input has been observed." if last_raw else "No canonical event input has been observed yet."),
            ),
            capabilities=(
                CapabilityHealth("behavioral_aggregation", CoverageLevel.FULL if db_ok and aggregated else CoverageLevel.PARTIAL if db_ok else CoverageLevel.NONE, "Normalized event aggregation is available." if aggregated else "Aggregation is waiting for eligible events."),
                CapabilityHealth("behavioral_baseline", CoverageLevel.FULL if baseline_ready else CoverageLevel.PARTIAL if db_ok else CoverageLevel.NONE, "A versioned local baseline is available." if baseline_ready else "The baseline is still learning."),
                CapabilityHealth("anomaly_detection", coverage, "Coverage-aware robust comparison is available." if baseline_ready else "Anomaly scoring is confidence-limited during cold start."),
            ),
            resources=ResourceMetrics(database_latency_ms=float(state.get("database_latency_ms", 0.0) or 0.0)),
            metadata={"baseline_version":int(state.get("baseline_version", 0) or 0),"last_baseline_update":last_baseline.isoformat() if last_baseline else "","policy_profile":state.get("policy_profile", "Balanced")},
            remediation="Inspect telemetry queue health, canonical sensor coverage, and database writes. Rebuild the baseline only after preserving its current version metadata.",
        )

    def dependencies(self) -> list[SensorDependency]:
        return list(self.health_snapshot().dependencies)

    def perform_self_test(self) -> SelfTestResult:
        started = time.monotonic()
        try:
            state = self._state()
            return SelfTestResult(True,"behavioral_telemetry_read_probe",f"Aggregate database is readable; baseline version {state.get('baseline_version', 0)}.",(time.monotonic()-started)*1000,str(uuid4()),("database_read","aggregate_read","baseline_read"))
        except (OSError, sqlite3.Error, ValueError) as exc:
            return SelfTestResult(False,"behavioral_telemetry_read_probe",f"Behavioral storage probe failed: {type(exc).__name__}",(time.monotonic()-started)*1000)

    def recover(self, reason: RecoveryReason) -> RecoveryResult:
        result = self.perform_self_test()
        return RecoveryResult(True,result.passed,RecoveryLevel.RECONNECT,result.reason,requires_operator=not result.passed)


class ManagerSelfProvider:
    def __init__(self, state: dict[str, Any]) -> None:
        self.state = state

    def sensor_id(self) -> str:
        return "sensor_health_manager"

    def health_snapshot(self) -> SensorHealthSnapshot:
        started = self.state.get("cycle_started_at") or utc_now()
        return SensorHealthSnapshot(
            sensor_id=self.sensor_id(), process_alive=True, initialized=True,
            last_process_heartbeat=started, last_collection_activity=started,
            last_processing_activity=started, last_delivery_activity=started,
            last_persistence_activity=started, events_received_total=int(self.state.get("sensors_checked", 0)),
            events_processed_total=int(self.state.get("sensors_checked", 0)),
            events_delivered_total=int(self.state.get("sensors_checked", 0)),
            events_persisted_total=int(self.state.get("sensors_checked", 0)),
            events_failed_total=int(self.state.get("health_checks_failed", 0)),
            permission_state=PermissionState.GRANTED,
            dependencies=(SensorDependency("sqlite", True, DependencyState.HEALTHY, "health store open"),),
            capabilities=(CapabilityHealth("sensor_health_assurance", CoverageLevel.FULL, "Health cycle is executing with bounded provider isolation."),),
        )

    def dependencies(self) -> list[SensorDependency]:
        return list(self.health_snapshot().dependencies)

    def perform_self_test(self) -> SelfTestResult:
        return SelfTestResult(True, "health_manager_cycle_probe", "Coordinator cycle and health store are responsive.", 0.0)

    def recover(self, reason: RecoveryReason) -> RecoveryResult:
        return RecoveryResult(False, False, RecoveryLevel.REQUEST_WATCHDOG, "The external watchdog owns health-manager restart execution.")


class MalwareDefinitionsProvider:
    def sensor_id(self) -> str:
        return "malware_definitions"

    def health_snapshot(self) -> SensorHealthSnapshot:
        from mac_audit_agent.threat_definitions.manager import default_manager

        manager = default_manager()
        status = manager.status()
        active = bool(status.get("active_version"))
        state_name = str(status.get("state", "UNKNOWN"))
        state = {
            "HEALTHY": SensorState.HEALTHY,
            "UPDATING": SensorState.INITIALIZING,
            "STALE": SensorState.STALE,
            "DEGRADED": SensorState.DEGRADED,
            "FAILED": SensorState.FAILED,
            "ROLLBACK_ACTIVE": SensorState.HEALTHY_WITH_WARNINGS,
            "NEVER_UPDATED": SensorState.UNAVAILABLE,
            "PERMISSION_BLOCKED": SensorState.PERMISSION_BLOCKED,
        }.get(state_name, SensorState.UNKNOWN)
        checked = _timestamp(status.get("last_update_attempt"))
        successful = _timestamp(status.get("last_successful_update")) or _timestamp(status.get("activated_at"))
        counts = status.get("counts_by_type", {}) if isinstance(status.get("counts_by_type"), dict) else {}
        definition_count = int(status.get("definition_count", 0) or 0)
        hash_count = sum(int(counts.get(name, 0) or 0) for name in ("SHA256", "SHA1", "MD5"))
        yara_count = int(counts.get("YARA_RULE", 0) or 0)
        if active and not hash_count and not yara_count and state == SensorState.HEALTHY:
            state = SensorState.HEALTHY_WITH_WARNINGS
        reason_code = (
            ReasonCode.TELEMETRY_SOURCE_UNAVAILABLE if active and not hash_count and not yara_count
            else ReasonCode.NONE if state == SensorState.HEALTHY
            else ReasonCode.SIGNATURE_INVALID if state == SensorState.FAILED
            else ReasonCode.PERMISSION_REQUIRED if state == SensorState.PERMISSION_BLOCKED
            else ReasonCode.RULE_LOAD_FAILURE if active
            else ReasonCode.TELEMETRY_SOURCE_UNAVAILABLE
        )
        coverage = CoverageLevel.FULL if state == SensorState.HEALTHY else CoverageLevel.PARTIAL if active else CoverageLevel.NONE
        desynchronized = manager.reload_coordinator.desynchronized_sensors(str(status.get("active_version") or "")) if active else []
        dependencies = (
            SensorDependency("definition_store", True, DependencyState.HEALTHY if active else DependencyState.UNAVAILABLE, "A verified immutable release is active." if active else "No active release."),
            SensorDependency("ruleset", True, DependencyState.DEGRADED if desynchronized else DependencyState.HEALTHY if active else DependencyState.UNAVAILABLE, "Sensor release desynchronization detected." if desynchronized else "Sensor receipts are consistent with the active release." if active else "No ruleset is active."),
        )
        return SensorHealthSnapshot(
            sensor_id=self.sensor_id(), sensor_version=str(status.get("active_version") or "none"),
            process_alive=True, initialized=active, state=state, reason_code=reason_code,
            reason=(
                "The release is valid, but it contains no malware hashes or YARA rules; definition-backed malware matching is unavailable."
                if active and not hash_count and not yara_count
                else str(status.get("message") or "Definition health is unavailable.")
            ),
            process_health=SensorState.HEALTHY, collection_health=state, processing_health=state,
            delivery_health=SensorState.DEGRADED if desynchronized else state, storage_health=state,
            dependency_health=SensorState.DEGRADED if desynchronized else state,
            last_process_heartbeat=checked or utc_now(), last_collection_activity=checked,
            last_processing_activity=successful, last_delivery_activity=successful,
            last_persistence_activity=successful, events_received_total=definition_count,
            events_processed_total=definition_count, events_delivered_total=definition_count if active else 0,
            events_persisted_total=definition_count if active else 0,
            permission_state=PermissionState.USER_ACTION_REQUIRED if state == SensorState.PERMISSION_BLOCKED else PermissionState.GRANTED,
            dependencies=dependencies,
            capabilities=(
                CapabilityHealth("malware_hash_matching", coverage if hash_count else CoverageLevel.NONE, f"{hash_count} active hash indicators."),
                CapabilityHealth("malware_rule_matching", coverage if yara_count else CoverageLevel.NONE, f"{yara_count} active YARA rules."),
                CapabilityHealth("definition_provenance", coverage, "Release manifest and normalized source relationships are available." if active else "No release provenance is active."),
            ),
            rules=RuleHealth(
                expected=definition_count, loaded=definition_count if active else 0,
                failed=len(desynchronized), version=str(status.get("active_version") or ""),
                last_reload=successful,
            ),
            lost_capabilities=tuple(
                capability for capability, available in (
                    ("malware_hash_matching", bool(hash_count)),
                    ("malware_rule_matching", bool(yara_count)),
                ) if not available
            ),
            retained_capabilities=("last_known_good_definition_matching",) if active else (),
            operator_action_required=state in {SensorState.PERMISSION_BLOCKED, SensorState.FAILED, SensorState.UNAVAILABLE} or (active and not hash_count and not yara_count),
            remediation="Run Malware Definitions → Verify Active Release. If no release is active, configure an approved source and run the fixed administrator update command. Use rollback if a newly activated release is rejected by sensors.",
            metadata={"active_release": status.get("active_version"), "rollback_available": status.get("rollback_available"), "desynchronized_sensors": desynchronized},
        )

    def dependencies(self) -> list[SensorDependency]:
        return list(self.health_snapshot().dependencies)

    def perform_self_test(self) -> SelfTestResult:
        started = time.monotonic()
        try:
            from mac_audit_agent.threat_definitions.manager import default_manager
            result = default_manager().verify()
            passed = result.get("status") == "VALID"
            return SelfTestResult(passed, "malware_definition_release_verify", "Manifest, file hashes, YARA, SQLite, and sensor receipt verification completed.", (time.monotonic() - started) * 1000)
        except Exception as exc:  # noqa: BLE001 - self-test must convert every backend failure into health evidence
            return SelfTestResult(False, "malware_definition_release_verify", f"Definition verification failed: {type(exc).__name__}", (time.monotonic() - started) * 1000)

    def recover(self, reason: RecoveryReason) -> RecoveryResult:
        return RecoveryResult(False, False, RecoveryLevel.OPERATOR_REQUIRED, "Definition updates and rollback require an administrator-reviewed operation in Malware Definitions.", requires_operator=True)


def built_in_providers(*, system_db: Path = SYSTEM_DB, user_home: Path | None = None, manager_state: dict[str, Any] | None = None) -> tuple[Any, ...]:
    home = user_home or Path.home()
    endpoint = EndpointSecurityProvider()
    return (
        endpoint,
        RansomwareMonitorProvider(endpoint, system_database=system_db),
        SQLitePipelineProvider("system_monitor", ("system_activity", "event_correlation", "evidence_persistence"), database=system_db),
        BehavioralTelemetryProvider(database=system_db),
        MalwareDefinitionsProvider(),
        SQLitePipelineProvider("user_notifier", ("critical_alert_delivery",), database=home / "Library/Application Support/MacAuditAgent/alert_receipts.sqlite3"),
        ManagerSelfProvider(manager_state if manager_state is not None else {}),
    )


__all__ = ["BehavioralTelemetryProvider", "EndpointSecurityProvider", "MalwareDefinitionsProvider", "ManagerSelfProvider", "RansomwareMonitorProvider", "SQLitePipelineProvider", "built_in_providers"]
