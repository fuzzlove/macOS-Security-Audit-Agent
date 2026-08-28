from __future__ import annotations

import json
import os
import platform
import hashlib
import sqlite3
import socket
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any

from mac_audit_agent.alerts.configuration import AlertingConfig, load_alerting_config
from mac_audit_agent.alerts.fingerprint import DetectorRegistry, calculate_fingerprints
from mac_audit_agent.alerts.resilient_models import EventValidationError, SecurityEvent
from mac_audit_agent.alerts.resilient_store import IngestDecision, ResilientEventStore
from mac_audit_agent.alerts.suppression import SuppressionPolicy
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso


class ResilientAlertPipeline:
    """Durable security-event accounting and notification-coalescing boundary.

    The legacy background_monitor_events row remains the notifier transport. This
    pipeline is its authoritative receipt ledger and aggregate state, not a second
    detector or presentation path.
    """

    def __init__(self, db: Any, config: AlertingConfig | None = None, *, integrity_key: bytes | None = None) -> None:
        self.db = db
        self.config = config or load_alerting_config()
        self.registry = DetectorRegistry()
        self.store = ResilientEventStore(db, self.config, integrity_key=integrity_key)
        self.suppressions = SuppressionPolicy(self.store)
        self._last_wall = time.time()
        self._last_mono = time.monotonic()
        self._source_windows: OrderedDict[str, tuple[float, int, bool]] = OrderedDict()
        self._last_summary_mono: OrderedDict[str, float] = OrderedDict()
        self._emergency_buffer: deque[dict[str, Any]] = deque(maxlen=self.config.emergency_buffer_capacity)
        self._store_failed = False
        self._fallback_path = self.db.path.with_name(self.db.path.name + ".alert-fallback.jsonl")

    @staticmethod
    def _metadata(event: BackgroundMonitorEvent) -> dict[str, Any]:
        try:
            value = json.loads(event.metadata_json or "{}")
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            return {"metadata_parse_error": True}

    def from_background_event(self, event: BackgroundMonitorEvent) -> SecurityEvent:
        metadata = self._metadata(event)
        rule_id = str(event.rule_id or event.trigger_rule_id or event.event_type)
        source_id = str(event.trigger_source or event.source or "unknown-local-detector")
        security_event = SecurityEvent(
            event_id=str(event.event_id), event_type=str(event.event_type), rule_id=rule_id,
            rule_version=str(metadata.get("rule_version", "1")), severity=str(event.severity).lower(),
            confidence=str(event.confidence), timestamp_utc=str(event.timestamp), monotonic_timestamp=time.monotonic(),
            ingestion_timestamp_utc=utc_now_iso(), source_id=source_id, source_type="local_detector",
            source_process=str(event.process_name), source_pid=event.pid, host_id=str(metadata.get("host_id") or socket.gethostname()),
            hostname=socket.gethostname(), user_uid=metadata.get("user_uid") if isinstance(metadata.get("user_uid"), int) else None,
            user_name=str(event.related_user or ""), process_path=str(event.related_path or metadata.get("process_path") or ""),
            process_signing_identifier=str(metadata.get("signing_identifier") or ""), process_team_identifier=str(metadata.get("team_identifier") or ""),
            process_hash=str(event.related_file_hash or metadata.get("process_hash") or ""), parent_process=str(metadata.get("parent_process") or ""),
            remote_address=str(event.related_network_endpoint or metadata.get("remote_address") or ""),
            remote_port=metadata.get("remote_port") if isinstance(metadata.get("remote_port"), int) else None,
            object_path=str(event.related_path or metadata.get("object_path") or ""), action=str(metadata.get("action") or event.current_state or ""),
            outcome=str(metadata.get("outcome") or ""), attributes={"evidence": event.evidence, "recommendation": event.recommendation, "metadata": metadata},
            mitre_attack=[str(item) for item in metadata.get("mitre_attack", [])[:64]] if isinstance(metadata.get("mitre_attack"), list) else [],
            cve_ids=[str(item) for item in metadata.get("cve_ids", [])[:64]] if isinstance(metadata.get("cve_ids"), list) else [],
            threat_tags=[str(item) for item in metadata.get("threat_tags", [])[:64]] if isinstance(metadata.get("threat_tags"), list) else [],
            correlation_id=str(event.correlation_id or ""), incident_id=str(metadata.get("incident_id") or ""),
        )
        security_event.fingerprint, security_event.material_digest = calculate_fingerprints(security_event, self.registry.contract_for(security_event))
        return security_event

    def ingest_background_event(self, event: BackgroundMonitorEvent) -> IngestDecision:
        now_wall, now_mono = time.time(), time.monotonic()
        wall_delta, mono_delta = now_wall - self._last_wall, now_mono - self._last_mono
        self._last_wall, self._last_mono = now_wall, now_mono
        security_event = self.from_background_event(event)
        if wall_delta - mono_delta < -300:
            self._persist_meta_event("system_time_rollback", event.event_id, "critical", {"wall_delta_seconds":wall_delta,"monotonic_delta_seconds":mono_delta})
        self._track_source_pressure(security_event, now_mono)
        security_event.suppression_rule_id = self.suppressions.matching_rule(security_event)
        if security_event.suppression_rule_id:
            security_event.suppression_reason = "authorized exact-match suppression; evidence retained"
            security_event.notification_disposition = "suppressed"
        try:
            decision = self.store.ingest(security_event)
            if self._store_failed:
                self.store.audit("event_store_recovered",actor="pipeline",reason="durable writes resumed",object_id=event.event_id,details={"buffered_receipts":len(self._emergency_buffer)})
                self.db.conn.commit()
                self._store_failed = False
            last_summary = self._last_summary_mono.get(decision.fingerprint, now_mono)
            if decision.accepted and not decision.notify and now_mono - last_summary >= self.config.summary_interval_seconds:
                if self.store.queue_periodic_summary(security_event,decision.fingerprint):
                    decision = IngestDecision(**{**decision.__dict__,"notify":True,"summary":True,"disposition":"periodic_summary"})
                self._remember_summary(decision.fingerprint,now_mono)
            elif decision.notify:
                self._remember_summary(decision.fingerprint,now_mono)
            return decision
        except EventValidationError:
            self.store._metric("events_rejected")
            self.store.audit("event_rejected",actor="pipeline",reason="schema or size validation failed",object_id=hashlib.sha256(event.event_id.encode()).hexdigest(),details={"source_digest":hashlib.sha256(security_event.source_id.encode()).hexdigest()})
            self.db.conn.commit()
            raise
        except (sqlite3.Error, OSError) as exc:
            return self._fallback_failure(security_event,exc)

    def _remember_summary(self, fingerprint: str, now_mono: float) -> None:
        self._last_summary_mono[fingerprint] = now_mono
        self._last_summary_mono.move_to_end(fingerprint)
        while len(self._last_summary_mono) > self.config.maximum_active_fingerprints:
            self._last_summary_mono.popitem(last=False)

    def _track_source_pressure(self, event: SecurityEvent, now_mono: float) -> None:
        started,count,reported = self._source_windows.pop(event.source_id,(now_mono,0,False))
        if now_mono-started >= 1.0:
            started,count,reported = now_mono,0,False
        count += 1
        self._source_windows[event.source_id]=(started,count,reported)
        while len(self._source_windows)>self.config.maximum_source_windows:
            self._source_windows.popitem(last=False)
        if count > self.config.source_rate_per_second and not reported and event.event_type != "alert_flood_detected":
            self._source_windows[event.source_id]=(started,count,True)
            self._persist_meta_event("alert_flood_detected",event.event_id,"critical",{"source_digest":hashlib.sha256(event.source_id.encode()).hexdigest(),"window_count":count,"window_seconds":1})
            self.store._metric("flood_detections"); self.db.conn.commit()

    def _persist_meta_event(self, event_type: str, trigger_id: str, severity: str, attributes: dict[str, Any]) -> None:
        meta = SecurityEvent(event_id=f"meta-{event_type}-{trigger_id}",event_type=event_type,rule_id=f"MSAA-{event_type.upper()}",severity=severity,confidence="high",timestamp_utc=utc_now_iso(),monotonic_timestamp=time.monotonic(),ingestion_timestamp_utc=utc_now_iso(),source_id="msaa-alert-pipeline",source_type="internal_health",host_id=socket.gethostname(),hostname=socket.gethostname(),attributes=attributes)
        meta.fingerprint,meta.material_digest=calculate_fingerprints(meta,self.registry.contract_for(meta))
        try:
            self.store.ingest(meta)
        except (sqlite3.Error,OSError) as exc:
            self._fallback_failure(meta,exc)

    def _fallback_failure(self, event: SecurityEvent, error: BaseException) -> IngestDecision:
        """Non-recursive, bounded accounting when the authoritative store is unavailable."""
        self._store_failed=True
        receipt={"event_id_digest":hashlib.sha256(event.event_id.encode()).hexdigest(),"event_type":event.event_type[:128],"priority":event.priority.value,"event_digest":hashlib.sha256(event.canonical_json().encode()).hexdigest(),"error_type":type(error).__name__,"recorded_at":utc_now_iso()}
        self._emergency_buffer.append(receipt)
        encoded=(json.dumps(receipt,sort_keys=True,separators=(",",":"))+"\n").encode()
        try:
            if self._fallback_path.exists() and (self._fallback_path.is_symlink() or not self._fallback_path.is_file()):
                raise OSError("unsafe fallback path")
            flags=os.O_WRONLY|os.O_CREAT|os.O_APPEND|getattr(os,"O_NOFOLLOW",0)
            if self._fallback_path.exists() and self._fallback_path.stat().st_size+len(encoded)>self.config.fallback_audit_maximum_bytes:
                flags=os.O_WRONLY|os.O_TRUNC|getattr(os,"O_NOFOLLOW",0)
            descriptor=os.open(self._fallback_path,flags,0o600)
            try: os.write(descriptor,encoded); os.fsync(descriptor)
            finally: os.close(descriptor)
        except OSError:
            pass
        return IngestDecision(False,event.fingerprint,"logging_failure_emergency_buffer","ACTIVE",1,event.protected)

    def degraded_status(self) -> dict[str, Any]:
        return {"event_store_failed":self._store_failed,"emergency_buffer_count":len(self._emergency_buffer),"emergency_buffer_capacity":self.config.emergency_buffer_capacity,"fallback_path":str(self._fallback_path)}


def pipeline_for(db: Any) -> ResilientAlertPipeline:
    pipeline = getattr(db, "_resilient_alert_pipeline", None)
    if pipeline is None:
        pipeline = ResilientAlertPipeline(db)
        setattr(db, "_resilient_alert_pipeline", pipeline)
    return pipeline
