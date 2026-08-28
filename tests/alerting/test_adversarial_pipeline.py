from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.alerts.configuration import AlertingConfig
from mac_audit_agent.alerts.resilient_models import EventValidationError
from mac_audit_agent.alerts.resilient_pipeline import ResilientAlertPipeline
from mac_audit_agent.alerts.suppression import SuppressionRequest
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.storage import AuditDatabase


def _event(index: int, *, source: str = "detector", severity: str = "low", event_type: str = "fixture", metadata: dict | None = None) -> BackgroundMonitorEvent:
    return BackgroundMonitorEvent(event_id=f"event-{index}",timestamp=utc_now_iso(),event_type=event_type,severity=severity,source=source,evidence="bounded",confidence="medium",rule_id="RULE-1",metadata_json=json.dumps(metadata or {}))


def test_authorized_suppression_changes_notifications_not_evidence(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"s"*32)
    expires=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()
    pipeline.suppressions.create(SuppressionRequest("detector",{"rule_id":"RULE-1"},"owner",utc_now_iso(),expires,"maintenance","T-1","admin"))
    decision=pipeline.ingest_background_event(_event(1))
    assert decision.accepted and not decision.notify
    row=db.conn.execute("SELECT disposition,canonical_json FROM resilient_security_events").fetchone()
    assert row["disposition"]=="notification_suppressed_evidence_retained" and row["canonical_json"]
    assert pipeline.store.health()["metrics"]["suppression_matches"]==1


def test_protected_event_cannot_be_suppressed(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"p"*32)
    expires=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()
    pipeline.suppressions.create(SuppressionRequest("detector",{"event_type":"logging_failure"},"owner",utc_now_iso(),expires,"maintenance","T-1","admin"))
    decision=pipeline.ingest_background_event(_event(1,event_type="logging_failure",severity="critical"))
    assert decision.notify and db.conn.execute("SELECT protected FROM resilient_security_events").fetchone()["protected"]==1


def test_flood_meta_event_is_bounded_and_non_recursive(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); config=AlertingConfig(source_rate_per_second=2,maximum_source_windows=2)
    pipeline=ResilientAlertPipeline(db,config,integrity_key=b"f"*32)
    for index in range(5): pipeline.ingest_background_event(_event(index))
    assert db.conn.execute("SELECT COUNT(*) AS n FROM resilient_security_events WHERE event_type='alert_flood_detected'").fetchone()["n"]==1
    assert len(pipeline._source_windows)<=2


def test_logging_failure_uses_bounded_non_recursive_fallback(tmp_path,monkeypatch):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,AlertingConfig(emergency_buffer_capacity=2,fallback_audit_maximum_bytes=2048),integrity_key=b"e"*32)
    monkeypatch.setattr(pipeline.store,"ingest",lambda _event: (_ for _ in ()).throw(sqlite3.OperationalError("injected")))
    decisions=[pipeline.ingest_background_event(_event(index)) for index in range(5)]
    assert all(item.disposition=="logging_failure_emergency_buffer" for item in decisions)
    assert pipeline.degraded_status()["emergency_buffer_count"]==2
    assert pipeline._fallback_path.stat().st_size<=2048


def test_compaction_and_storage_pressure_are_explicit(tmp_path,monkeypatch):
    db=AuditDatabase(tmp_path/"events.sqlite3"); config=AlertingConfig(individual_duplicate_retention_limit=1,maximum_size_mb=2,emergency_reserved_size_mb=1)
    pipeline=ResilientAlertPipeline(db,config,integrity_key=b"c"*32)
    monkeypatch.setattr(pipeline.store,"_database_bytes",lambda:2*1024*1024)
    pipeline.ingest_background_event(_event(1)); pipeline.ingest_background_event(_event(2)); pipeline.ingest_background_event(_event(3))
    row=db.conn.execute("SELECT * FROM resilient_compactions").fetchone()
    assert row and row["compacted_count"]>=1 and row["fidelity_reduced"]==1
    assert db.conn.execute("SELECT COUNT(*) AS n FROM resilient_security_events").fetchone()["n"]==3
    latest=db.conn.execute("SELECT raw_retained,canonical_json FROM resilient_security_events ORDER BY sequence_number DESC LIMIT 1").fetchone()
    assert latest["raw_retained"]==1 and latest["canonical_json"]


def test_malformed_nesting_and_collection_size_are_rejected_and_counted(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,AlertingConfig(maximum_nesting_depth=2,maximum_collection_items=2),integrity_key=b"v"*32)
    with pytest.raises(EventValidationError): pipeline.ingest_background_event(_event(1,metadata={"a":{"b":{"c":{"d":1}}}}))
    with pytest.raises(EventValidationError): pipeline.ingest_background_event(_event(2,metadata={"items":[1,2,3]}))
    assert pipeline.store.health()["metrics"]["events_rejected"]==2


def test_audit_chain_tampering_is_detected(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"i"*32)
    pipeline.ingest_background_event(_event(1)); db.conn.execute("UPDATE resilient_pipeline_audit SET reason='tampered' WHERE audit_sequence=1"); db.conn.commit()
    result=pipeline.store.verify_integrity()
    assert not result["ok"] and result["audit_failed_sequences"]


def test_low_priority_flood_cannot_consume_protected_notification_reserve(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,AlertingConfig(notification_capacity=5,protected_capacity=2,maximum_active_fingerprints=100),integrity_key=b"q"*32)
    for index in range(10): pipeline.ingest_background_event(_event(index,metadata={"process_hash":f"hash-{index}"}))
    critical=pipeline.ingest_background_event(_event(99,severity="critical",event_type="agent_tampering",metadata={"process_hash":"critical"}))
    pending=pipeline.store.pending_notifications(limit=10)
    assert critical.notify and len(pending)<=5 and pending[0]["priority"]==0
    assert any(item["event_id"]=="event-99" for item in pending)


def test_suppressions_and_counters_survive_restart(tmp_path):
    path=tmp_path/"events.sqlite3"; db=AuditDatabase(path); first=ResilientAlertPipeline(db,integrity_key=b"r"*32)
    expires=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()
    rule=first.suppressions.create(SuppressionRequest("detector",{"rule_id":"RULE-1"},"owner",utc_now_iso(),expires,"maintenance","T-1","admin"))
    first.ingest_background_event(_event(1)); db.close()
    reopened_db=AuditDatabase(path); recovered=ResilientAlertPipeline(reopened_db,integrity_key=b"r"*32)
    decision=recovered.ingest_background_event(_event(2))
    assert decision.occurrence_count==2 and not decision.notify
    assert recovered.suppressions.list()[0]["rule_id"]==rule


def test_time_rollback_creates_one_protected_receipt(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"t"*32)
    pipeline._last_wall += 1_000
    pipeline.ingest_background_event(_event(1))
    row=db.conn.execute("SELECT protected FROM resilient_security_events WHERE event_type='system_time_rollback'").fetchone()
    assert row and row["protected"]==1


def test_periodic_summary_uses_monotonic_interval(tmp_path,monkeypatch):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,AlertingConfig(summary_interval_seconds=5),integrity_key=b"m"*32)
    first=pipeline.ingest_background_event(_event(1)); assert first.notify
    pipeline._last_summary_mono[first.fingerprint]=0
    monkeypatch.setattr("mac_audit_agent.alerts.resilient_pipeline.time.monotonic",lambda:10.0)
    summary=pipeline.ingest_background_event(_event(2))
    assert summary.notify and summary.summary and summary.disposition=="periodic_summary"
