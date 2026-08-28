from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from concurrent.futures import ThreadPoolExecutor

from mac_audit_agent.alerts.configuration import AlertingConfig
from mac_audit_agent.alerts.resilient_models import EventValidationError, SecurityEvent, redact
from mac_audit_agent.alerts.resilient_pipeline import ResilientAlertPipeline
from mac_audit_agent.alerts.response import reserve_action
from mac_audit_agent.alerts.suppression import SuppressionPolicy, SuppressionRequest
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.storage import AuditDatabase


def event(index: int, *, severity: str = "low", metadata: dict | None = None, evidence: str = "same") -> BackgroundMonitorEvent:
    return BackgroundMonitorEvent(event_id=f"event-{index}",timestamp=utc_now_iso(),event_type="test_detection",severity=severity,source="test-source",process_name="sample",evidence=evidence,confidence="medium",metadata_json=json.dumps(metadata or {}),rule_id="TEST-001")


def test_duplicate_storm_is_accounted_and_notifications_are_consolidated(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); config=AlertingConfig(individual_duplicate_retention_limit=100)
    pipeline=ResilientAlertPipeline(db,config,integrity_key=b"x"*32)
    decisions=[pipeline.ingest_background_event(event(index)) for index in range(10_000)]
    assert sum(item.notify for item in decisions)==5
    aggregate=db.conn.execute("SELECT * FROM resilient_alert_aggregates").fetchone()
    assert aggregate["occurrence_count"]==10_000
    assert db.conn.execute("SELECT COUNT(*) AS count FROM resilient_security_events").fetchone()["count"]==10_000
    # First 100 raw events, the latest raw duplicate, and the 1,000/10,000 summaries.
    assert db.conn.execute("SELECT COUNT(*) AS count FROM resilient_security_events WHERE raw_retained=1").fetchone()["count"]==103
    assert db.conn.execute("SELECT COUNT(*) AS count FROM resilient_notification_queue").fetchone()["count"]==5
    assert pipeline.store.verify_integrity()["ok"] is True


def test_material_change_and_escalation_bypass_consolidation(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"y"*32)
    assert pipeline.ingest_background_event(event(1)).notify
    assert not pipeline.ingest_background_event(event(2)).notify
    escalated=event(3,severity="high",metadata={"outcome":"success"})
    decision=pipeline.ingest_background_event(escalated)
    assert decision.notify and decision.severity_escalation and decision.material_change
    changed_identity=event(4,severity="high",metadata={"outcome":"success","process_hash":"abc"})
    identity_decision=pipeline.ingest_background_event(changed_identity)
    assert identity_decision.notify and identity_decision.occurrence_count==1


def test_cardinality_limit_uses_bounded_overflow_and_keeps_critical(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,AlertingConfig(maximum_active_fingerprints=2),integrity_key=b"z"*32)
    pipeline.ingest_background_event(event(1,evidence="a",metadata={"process_hash":"a"}))
    pipeline.ingest_background_event(event(2,evidence="b",metadata={"process_hash":"b"}))
    overflow=pipeline.ingest_background_event(event(3,evidence="c",metadata={"process_hash":"c"}))
    critical=pipeline.ingest_background_event(event(4,severity="critical",evidence="d",metadata={"process_hash":"d"}))
    assert overflow.overflowed is True
    assert critical.overflowed is False and critical.notify is True
    assert pipeline.store.health()["metrics"]["cardinality_pressure"]==1


def test_validation_and_redaction_are_bounded(tmp_path):
    assert redact({"password":"secret","Authorization":"Bearer abc","safe":"password=hunter2"})=={"password":"[REDACTED]","Authorization":"[REDACTED]","safe":"password=[REDACTED]"}
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,AlertingConfig(maximum_event_size_bytes=1024),integrity_key=b"q"*32)
    with pytest.raises(EventValidationError): pipeline.ingest_background_event(event(1,evidence="x"*10_000))


def test_suppression_requires_narrow_expiring_authorization(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"s"*32); policy=SuppressionPolicy(pipeline.store)
    expires=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
    with pytest.raises(ValueError): policy.create(SuppressionRequest("detector",{"rule_id":"*"},"owner",utc_now_iso(),expires,"reason","T-1","admin"))
    rule=policy.create(SuppressionRequest("detector",{"rule_id":"TEST-001"},"owner",utc_now_iso(),expires,"maintenance","T-1","admin"))
    assert rule.startswith("suppression-")


def test_automated_action_reservation_is_idempotent(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); ResilientAlertPipeline(db,integrity_key=b"a"*32)
    first=reserve_action(db,policy_id="P1",fingerprint="f",action_type="quarantine",target_identity="file",incident_id="i")
    second=reserve_action(db,policy_id="P1",fingerprint="f",action_type="quarantine",target_identity="file",incident_id="i")
    assert first[0]==second[0] and first[1] is True and second[1] is False


def test_integrity_detects_tampering(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"i"*32)
    pipeline.ingest_background_event(event(1)); db.conn.execute("UPDATE resilient_security_events SET event_digest='bad' WHERE event_id='event-1'"); db.conn.commit()
    assert pipeline.store.verify_integrity()["ok"] is False


def test_restart_recovers_aggregate_without_first_notification(tmp_path):
    path=tmp_path/"events.sqlite3"; db=AuditDatabase(path); first=ResilientAlertPipeline(db,integrity_key=b"r"*32)
    assert first.ingest_background_event(event(1)).notify; db.close()
    reopened_db=AuditDatabase(path); recovered=ResilientAlertPipeline(reopened_db,integrity_key=b"r"*32)
    decision=recovered.ingest_background_event(event(2))
    assert decision.notify is False and decision.occurrence_count==2


def test_lifecycle_quiet_resolved_and_reopened(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,AlertingConfig(dedup_window_seconds=1,resolve_after_seconds=2),integrity_key=b"l"*32)
    first=event(1); pipeline.ingest_background_event(first)
    future=(datetime.now(timezone.utc)+timedelta(seconds=3)).isoformat(); assert pipeline.store.advance_lifecycle(future)["resolved"]==1
    reopened=pipeline.ingest_background_event(event(2)); assert reopened.lifecycle=="REOPENED" and reopened.notify


def test_critical_notification_precedes_low_priority_fifo(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"p"*32)
    pipeline.ingest_background_event(event(1)); pipeline.ingest_background_event(event(2,severity="critical",evidence="critical"))
    pending=pipeline.store.pending_notifications(); assert pending[0]["priority"] < pending[1]["priority"]


def test_concurrent_producers_have_unique_sequences_and_counts(tmp_path):
    db=AuditDatabase(tmp_path/"events.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"c"*32)
    with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(lambda index:pipeline.ingest_background_event(event(index)),range(1,501)))
    row=db.conn.execute("SELECT COUNT(*) AS count,COUNT(DISTINCT sequence_number) AS sequences FROM resilient_security_events").fetchone()
    assert row["count"]==500 and row["sequences"]==500
    assert db.conn.execute("SELECT occurrence_count FROM resilient_alert_aggregates").fetchone()["occurrence_count"]==500
