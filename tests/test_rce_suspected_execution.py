from __future__ import annotations

from datetime import datetime, timedelta, timezone
import time

from mac_audit_agent.rce_monitor import RCEAnalyzer, RCEClassification, RCEConfig, RCERepository, RCESubtype, TelemetryEvent
from mac_audit_agent.rce_monitor.service import RCEMonitorService
from mac_audit_agent.rce_monitor.synthetic import suspected_rce_demo


def _time(offset: int) -> str:
    return (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=offset)).isoformat()


def test_required_crash_to_execution_demo_correlates_once() -> None:
    analyzer = RCEAnalyzer()
    findings = [finding for event in suspected_rce_demo() if (finding := analyzer.analyze(event))]
    final = findings[-1]
    assert final.event_type == "SUSPECTED_REMOTE_CODE_EXECUTION"
    assert final.rce_classification == RCEClassification.PROBABLE.value
    assert final.rce_subtype == RCESubtype.CRASH_TO_EXECUTION.value
    assert final.group_id == findings[0].group_id
    assert {"RCE-R001_MEMORY_FAULT", "RCE-R007_POST_CRASH_PROCESS", "RCE-R008_POST_CRASH_SHELL", "RCE-R009_UNEXPECTED_NETWORK", "RCE-R010_UNSIGNED_CHILD", "RCE-R011_TEMP_EXECUTION", "RCE-R013_MULTI_STAGE_CORRELATION"}.issubset(final.rule_ids)
    assert "do not prove" in final.why_flagged
    assert len(final.timeline) == 5


def test_ordinary_crash_is_not_labeled_suspected_rce() -> None:
    event = RCEAnalyzer().analyze(TelemetryEvent(kind="process_crash", process={"pid": 7, "executable": "/Applications/Fixture.app"}, memory_context={"abnormal_termination": True, "exception_type": "EXC_CRASH", "signal": "SIGABRT"}))
    assert event is not None
    assert event.rce_classification == RCEClassification.BENIGN_CRASH.value
    assert event.event_type != "SUSPECTED_REMOTE_CODE_EXECUTION"


def test_stack_heap_and_control_flow_are_explicit_primitives() -> None:
    for context, expected_code, subtype in (
        ({"memory_safety_crash": True, "stack_overflow": True, "exception_signal": "SIGSEGV"}, "RCE-R002_STACK_CORRUPTION", RCESubtype.STACK_OVERFLOW.value),
        ({"memory_safety_crash": True, "heap_corruption": True, "use_after_free": True}, "RCE-R003_HEAP_CORRUPTION", RCESubtype.USE_AFTER_FREE.value),
        ({"memory_safety_crash": True, "control_flow_anomaly": True, "unexpected_instruction_pointer": True}, "RCE-R004_CONTROL_FLOW_ANOMALY", RCESubtype.CONTROL_FLOW.value),
    ):
        finding = RCEAnalyzer().analyze(TelemetryEvent(kind="memory_safety_crash", process={"pid": 1, "executable": "/fixture"}, memory_context=context))
        assert finding and expected_code in finding.rule_ids and finding.rce_subtype == subtype


def test_write_then_execute_is_strong_but_not_automatically_confirmed() -> None:
    finding = RCEAnalyzer().analyze(TelemetryEvent(kind="memory", process={"pid": 1, "executable": "/fixture"}, memory_context={"writable_to_executable": True, "protection_transition": "RW->RX"}))
    assert finding and "RCE-R006_WX_TRANSITION" in finding.rule_ids
    assert finding.rce_classification != RCEClassification.HIGH_CONFIDENCE.value


def test_browser_jit_and_debugger_reduce_confidence_without_deleting_evidence() -> None:
    base = TelemetryEvent(kind="memory", process={"pid": 1, "executable": "/Applications/Safari"}, memory_context={"writable_to_executable": True, "jit_allocation": True})
    contextual = TelemetryEvent(**{**base.__dict__, "metadata": {"approved_jit_runtime": True, "debugger_attached": True}})
    plain = RCEAnalyzer().analyze(base)
    reduced = RCEAnalyzer().analyze(contextual)
    assert plain and reduced and reduced.confidence_score < plain.confidence_score
    assert "RCE-R006_WX_TRANSITION" in reduced.rule_ids and reduced.possible_benign_explanations


def test_fuzzing_mode_groups_duplicate_signature_but_preserves_unique(tmp_path) -> None:
    repo = RCERepository(tmp_path / "rce.sqlite3")
    analyzer = RCEAnalyzer(RCEConfig(operation_mode="FUZZING"))
    first = TelemetryEvent(kind="memory_safety_crash", observed_at=_time(0), process={"pid": 1, "executable": "/fixture", "sha256": "A" * 64}, memory_context={"memory_safety_crash": True, "exception_type": "EXC_BAD_ACCESS", "crash_signature": "same"})
    second = TelemetryEvent(**{**first.__dict__, "observed_at": _time(1)})
    third = TelemetryEvent(**{**first.__dict__, "observed_at": _time(2), "memory_context": {**first.memory_context, "crash_signature": "unique"}})
    repo.store_event(analyzer.analyze(first), raw_payload={"signature": "same"}, max_representatives=1)
    repo.store_event(analyzer.analyze(second), raw_payload={"signature": "same"}, max_representatives=1)
    repo.store_event(analyzer.analyze(third), raw_payload={"signature": "unique"}, max_representatives=1)
    assert repo.conn.execute("SELECT SUM(occurrence_count) FROM rce_crash_signatures").fetchone()[0] == 3
    assert repo.conn.execute("SELECT COUNT(*) FROM rce_crash_signatures").fetchone()[0] == 2


def test_missing_sensor_is_partial_not_no_activity() -> None:
    event = suspected_rce_demo()[0]
    event = TelemetryEvent(**{**event.__dict__, "metadata": {"sensor_coverage": {"Process telemetry": "AVAILABLE", "Network telemetry": "UNAVAILABLE", "Memory telemetry": "LIMITED"}}})
    finding = RCEAnalyzer().analyze(event)
    assert finding and finding.sensor_coverage["Network telemetry"] == "UNAVAILABLE"
    assert finding.evidence_completeness_label in {"PARTIAL", "LIMITED"}


def test_repository_migration_normalizes_evidence_and_preserves_original_disposition(tmp_path) -> None:
    repo = RCERepository(tmp_path / "rce.sqlite3")
    service = RCEMonitorService(repo, executor=lambda *args, **kwargs: None)
    findings = [finding for event in suspected_rce_demo() if (finding := service.ingest(event))]
    detail = repo.event_detail(findings[-1].event_id)
    assert detail and detail["reason_evidence"] and detail["timeline"] and detail["sensor_coverage"]
    repo.disposition(findings[-1].event_id, "FALSE_POSITIVE", reviewer="fixture-analyst", reason="benign fixture", case_reference="CASE-1", authorized=True)
    row = repo.conn.execute("SELECT original_classification,original_score,analyst_classification FROM rce_analyst_dispositions WHERE event_id=?", (findings[-1].event_id,)).fetchone()
    assert row["original_classification"] and row["original_score"] > 0 and row["analyst_classification"] == "FALSE_POSITIVE"


def test_service_preserves_raw_event_when_enrichment_fails(tmp_path, monkeypatch) -> None:
    repo = RCERepository(tmp_path / "rce.sqlite3")
    service = RCEMonitorService(repo, executor=lambda *args, **kwargs: None)
    monkeypatch.setattr(service.analyzer, "analyze", lambda event: (_ for _ in ()).throw(ValueError("fixture parser failure")))
    result = service.ingest(suspected_rce_demo()[0])
    assert result and result.event_type == "RCE_MONITOR_HEALTH_FAILURE"
    row = repo.conn.execute("SELECT status,error_type FROM rce_ingest_spool ORDER BY created_at DESC LIMIT 1").fetchone()
    assert row["status"] == "ENRICHMENT_FAILED" and row["error_type"] == "ValueError"


def test_correlation_window_expires() -> None:
    analyzer = RCEAnalyzer()
    crash = suspected_rce_demo()[0]
    analyzer.analyze(crash)
    shell = suspected_rce_demo()[1]
    shell = TelemetryEvent(**{**shell.__dict__, "observed_at": (datetime.fromisoformat(crash.observed_at) + timedelta(minutes=6)).isoformat()})
    result = analyzer.analyze(shell)
    assert result is None or "RCE-R008_POST_CRASH_SHELL" not in result.rule_ids


def test_same_process_input_and_post_crash_privilege_persistence_are_correlated() -> None:
    analyzer = RCEAnalyzer()
    process = {"pid": 90, "executable": "/Applications/Parser"}
    analyzer.analyze(TelemetryEvent(kind="network_input", observed_at=_time(0), process=process, network_context={"inbound": True}))
    crash = analyzer.analyze(TelemetryEvent(kind="memory_safety_crash", observed_at=_time(1), process=process, memory_context={"memory_safety_crash": True, "invalid_memory_access": True}))
    assert crash and len(crash.timeline) == 2
    privileged = analyzer.analyze(TelemetryEvent(kind="execution", observed_at=_time(2), process={"pid": 91, "ppid": 90, "executable": "/private/tmp/helper"}, parent_process=process, metadata={"privilege_context": {"previous_effective_uid": 501, "effective_uid": 0, "privilege_changed": True}}))
    assert privileged and "RCE-R014_PRIVILEGE_TRANSITION" in privileged.rule_ids
    persistence = analyzer.analyze(TelemetryEvent(kind="file_event", observed_at=_time(3), process=process, file_context={"path": "/Users/fixture/Library/LaunchAgents/com.fixture.plist", "action": "created"}))
    assert persistence and "RCE-R015_PERSISTENCE_OR_EXECUTABLE_FILE" in persistence.rule_ids


def test_rce_investigation_ui_exposes_explanation_timeline_and_disposition() -> None:
    from PySide6.QtWidgets import QApplication
    from mac_audit_agent.ui.rce_investigation_panel import RCEInvestigationPanel

    app = QApplication.instance() or QApplication([])
    analyzer = RCEAnalyzer()
    findings = [finding.to_dict() for event in suspected_rce_demo() if (finding := analyzer.analyze(event))]
    panel = RCEInvestigationPanel()
    panel.set_events([findings[-1]])
    assert "PROBABLE RCE" in panel.classification.text()
    assert "do not prove" in panel.why.toPlainText()
    assert panel.timeline.rowCount() == 5
    assert panel.apply_disposition.minimumHeight() >= 36
    panel.close()
    assert app is not None


def test_correlated_rce_alert_updates_one_operator_inbox_record(tmp_path) -> None:
    from mac_audit_agent.models import BackgroundMonitorEvent
    from mac_audit_agent.storage import AuditDatabase

    db = AuditDatabase(tmp_path / "audit.sqlite3", tmp_path / "logs")
    first = BackgroundMonitorEvent(event_id="rce-alert-1", timestamp=_time(1), event_type="execution_evidence_detected", severity="medium", source="rce_behavior_monitor", evidence="initial correlated shell evidence", confidence="high", metadata_json='{"confidence_score":62}', duplicate_group_key="rce:fixture-chain", duplicate_category="material_change")
    final = BackgroundMonitorEvent(event_id="rce-alert-2", timestamp=_time(2), event_type="execution_evidence_detected", severity="high", source="rce_behavior_monitor", evidence="final correlated file and network evidence", confidence="high", metadata_json='{"confidence_score":95}', duplicate_group_key="rce:fixture-chain", duplicate_category="material_change")
    assert db.record_background_monitor_event(first, dedupe_window_seconds=0)
    assert not db.record_background_monitor_event(final, dedupe_window_seconds=0)
    rows = db.conn.execute("SELECT severity,evidence,metadata_json,occurrence_count FROM background_monitor_events WHERE duplicate_group_key=?", ("rce:fixture-chain",)).fetchall()
    assert len(rows) == 1 and rows[0]["severity"] == "high"
    assert rows[0]["evidence"] == "final correlated file and network evidence"
    assert '"confidence_score": 95' in rows[0]["metadata_json"] and rows[0]["occurrence_count"] == 2


def test_nonblocking_sensor_submission_uses_bounded_worker_queue(tmp_path) -> None:
    repo = RCERepository(tmp_path / "rce.sqlite3")
    service = RCEMonitorService(repo, executor=lambda *args, **kwargs: None)
    service.start()
    assert all(service.submit(event) for event in suspected_rce_demo())
    deadline = time.monotonic() + 3
    findings = []
    while time.monotonic() < deadline and len(findings) < 5:
        findings.extend(service.drain_async_findings())
        if len(findings) < 5:
            time.sleep(0.02)
    service.stop()
    assert findings[-1].event_type == "SUSPECTED_REMOTE_CODE_EXECUTION"
    status = service.status()
    assert status["ingest_queue_limit"] == service.config.queue_limit
    assert status["dropped_delivery_events"] == 0
