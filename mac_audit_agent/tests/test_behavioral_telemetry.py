from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from PySide6.QtWidgets import QApplication

from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.telemetry.anomaly import AnomalyDetectionEngine
from mac_audit_agent.telemetry.manager import TelemetryManager
from mac_audit_agent.telemetry.models import AnalyticsAvailability, TelemetryBucket
from mac_audit_agent.telemetry.policies import BehavioralTelemetryPolicy
from mac_audit_agent.telemetry.privacy import redact_command_line
from mac_audit_agent.telemetry.synthetic import normal_workday, process_storm, required_demonstration, telemetry_event
from mac_audit_agent.ui.behavioral_telemetry import BehavioralTelemetryPanel


def _manager(tmp_path, **policy_values) -> tuple[AuditDatabase, TelemetryManager]:
    database = AuditDatabase(tmp_path / "telemetry.sqlite", tmp_path / "logs")
    policy = BehavioralTelemetryPolicy(
        minimum_baseline_samples=4,
        established_baseline_samples=8,
        mature_baseline_samples=16,
        **policy_values,
    )
    return database, TelemetryManager(database, policy, autostart=False)


def test_sensitive_arguments_are_redacted_before_persistence() -> None:
    value = redact_command_line("curl --token secret-value -H 'Authorization: Bearer abc123' --password=hunter2")
    assert "secret-value" not in value
    assert "abc123" not in value
    assert "hunter2" not in value
    assert value.count("<REDACTED>") >= 3


def test_normal_routine_builds_local_user_and_host_baselines(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    start = datetime.now(timezone.utc) - timedelta(hours=3)
    manager.process_events_sync(normal_workday(start, buckets=12), force_analysis=False)
    outcome = manager.rebuild_baseline(actor="test", reason="golden normal routine")

    assert outcome["baseline_count"] > 0
    user_refs = {item.user_ref for item in manager.repository.list_buckets()}
    assert "" in user_refs
    assert any(user_refs)
    assert manager.summary(hours=24)["state"] in {"NORMAL", "LEARNING"}
    database.close()


def test_process_spike_uses_stable_reason_code(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    start = datetime.now(timezone.utc) - timedelta(hours=5)
    manager.process_events_sync(normal_workday(start, buckets=16), force_analysis=False)
    manager.rebuild_baseline(actor="test", reason="process spike baseline")
    anomalies = manager.process_events_sync(process_storm(datetime.now(timezone.utc) - timedelta(minutes=10), count_value=50))

    assert any("PROCESS_RATE_ANOMALY" in item["reason_codes"] for item in anomalies)
    assert all("proof of malicious intent" in item["explanation"] for item in anomalies)
    database.close()


def test_first_seen_application_is_not_automatically_high_severity(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    start = datetime.now(timezone.utc) - timedelta(hours=3)
    manager.process_events_sync(normal_workday(start, buckets=12), force_analysis=False)
    manager.rebuild_baseline(actor="test", reason="first seen baseline")
    event = telemetry_event(
        datetime.now(timezone.utc) - timedelta(minutes=10),
        "process_execution",
        process="NewLegitimateApp",
        path="/Applications/NewLegitimateApp.app/Contents/MacOS/NewLegitimateApp",
        metadata={"first_seen": True, "signing_status": "developer_id"},
    )
    anomalies = manager.process_events_sync([event])

    assert all(item["security_severity"] in {"info", "low", "medium"} for item in anomalies)
    database.close()


def test_missing_network_sensor_is_unknown_not_zero(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    bucket = TelemetryBucket(
        bucket_start="2026-01-01T00:00:00+00:00",
        bucket_end="2026-01-01T00:05:00+00:00",
        host_ref="host",
        user_ref="user",
        time_cohort="WEEKDAY:00",
        feature_values={"network_connection_count": 0.0},
        dimension_values={"NETWORK_ACTIVITY": None},
        coverage={"NETWORK_ACTIVITY": AnalyticsAvailability.UNAVAILABLE.value},
        event_count=1,
    )
    assert AnomalyDetectionEngine(manager.repository, manager.policy).analyze_bucket(bucket) == []
    assert bucket.dimension_values["NETWORK_ACTIVITY"] is None
    database.close()


def test_sleep_and_wake_use_separate_context_cohort(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    event = telemetry_event(datetime.now(timezone.utc), "wake_process_execution", process="loginwindow", path="/System/loginwindow")
    normalized = manager.normalizer.normalize(event)
    assert normalized is not None
    buckets = manager.aggregator.aggregate([normalized])
    assert all(bucket.context_cohort == "WAKE_GRACE" for bucket in buckets)
    database.close()


def test_queue_is_bounded_and_reports_degradation(tmp_path) -> None:
    database, manager = _manager(tmp_path, queue_capacity=64, batch_size=16)
    events = process_storm(datetime.now(timezone.utc), count_value=65)
    accepted = [manager.submit_background_event(event) for event in events]
    assert sum(accepted) == 64
    assert manager.health()["dropped_telemetry"] == 1
    assert manager.health()["analysis_availability"] == "DEGRADED"
    database.close()


def test_first_seen_tracking_is_shared_and_not_repeated_per_event(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    now = datetime.now(timezone.utc) - timedelta(minutes=10)
    events = [
        telemetry_event(now + timedelta(seconds=index), "process_execution", process="new-tool", path="/Applications/NewTool.app/Contents/MacOS/NewTool", metadata={"signing_status": "developer_id"}, sequence=index)
        for index in range(3)
    ]
    manager.process_events_sync(events)
    user_bucket = next(item for item in manager.repository.list_buckets() if item.user_ref)

    assert user_bucket.feature_values["first_seen_process_count"] == 1.0
    assert manager.repository.entity_seen("process", next(iter(user_bucket.entity_sets["process"])))
    database.close()


def test_serious_deviation_is_excluded_from_host_and_user_training(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    now = datetime.now(timezone.utc)
    manager.process_events_sync(normal_workday(now - timedelta(hours=4), buckets=16), force_analysis=False)
    manager.rebuild_baseline(actor="test", reason="poisoning baseline")
    manager.process_events_sync(process_storm(now - timedelta(minutes=10), count_value=60))
    affected = [item for item in manager.repository.list_buckets() if item.bucket_start >= (now - timedelta(minutes=15)).isoformat()]

    assert affected
    assert all(item.training_eligible is False for item in affected)
    database.close()


def test_coverage_override_records_unavailable_without_false_zero(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    event = telemetry_event(
        datetime.now(timezone.utc) - timedelta(minutes=10),
        "sensor_degraded",
        metadata={"coverage_overrides": {"NETWORK_ACTIVITY": "UNAVAILABLE"}},
    )
    manager.process_events_sync([event])
    user_bucket = next(item for item in manager.repository.list_buckets() if item.user_ref)

    assert user_bucket.coverage["NETWORK_ACTIVITY"] == "UNAVAILABLE"
    assert user_bucket.dimension_values["NETWORK_ACTIVITY"] is None
    database.close()


def test_thousand_event_batch_is_bounded_and_incremental(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    events = process_storm(datetime.now(timezone.utc) - timedelta(minutes=10), count_value=1000)
    started = time.monotonic()
    manager.process_events_sync(events)
    elapsed = time.monotonic() - started
    user_events = sum(item.event_count for item in manager.repository.list_buckets() if item.user_ref)

    assert user_events == 1000
    assert elapsed < 10
    assert database.path.stat().st_size < 50 * 1024 * 1024
    database.close()


def test_required_demo_correlates_to_one_incident_and_one_alert(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    scenario = required_demonstration(datetime.now(timezone.utc) - timedelta(hours=3))
    manager.process_events_sync(scenario["history"], force_analysis=False)
    manager.rebuild_baseline(actor="test", reason="required demonstration history")
    manager.process_events_sync(scenario["normal"], force_analysis=False)
    anomalies = manager.process_events_sync(scenario["deviation"])
    incidents = manager.repository.list_incidents()
    alert_rows = database.conn.execute(
        "SELECT event_id FROM background_monitor_events WHERE source='behavioral_telemetry_correlation'"
    ).fetchall()

    assert anomalies
    assert len(incidents) == 1
    assert incidents[0]["flight_recorder_snapshot_id"]
    assert incidents[0]["anomaly_score"] >= manager.policy.alert_threshold
    assert len(alert_rows) == 1
    assert "COMPOSITE_BEHAVIORAL_ANOMALY" in incidents[0]["reason_codes"]
    database.close()


def test_operator_disposition_is_audited_without_rewriting_baseline(tmp_path) -> None:
    database, manager = _manager(tmp_path)
    now = datetime.now(timezone.utc)
    manager.process_events_sync(normal_workday(now - timedelta(hours=3), buckets=12), force_analysis=False)
    manager.rebuild_baseline(actor="test", reason="feedback baseline")
    before = manager.repository.latest_baseline_version()
    anomalies = manager.process_events_sync(process_storm(now - timedelta(minutes=10), count_value=50))
    manager.repository.update_anomaly_disposition(anomalies[0]["anomaly_id"], "FALSE_POSITIVE", actor="analyst", reason="approved build")
    audit = database.conn.execute("SELECT action FROM behavioral_audit_trail WHERE object_id=?", (anomalies[0]["anomaly_id"],)).fetchone()

    assert audit["action"] == "anomaly_disposition"
    assert manager.repository.latest_baseline_version() == before
    database.close()


def test_behavioral_panel_empty_state_and_responsive_actions(tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    database = AuditDatabase(tmp_path / "ui.sqlite", tmp_path / "logs")
    panel = BehavioralTelemetryPanel(database)
    panel.resize(900, 800)
    panel.show()
    app.processEvents()

    assert panel.summary_labels["state"].text() == "LEARNING"
    assert panel.chart.minimumHeight() >= 300
    assert panel.dimension_table.rowCount() == 12
    panel.close()
    database.close()


def test_workstation_profile_deviation_is_flagged_without_malware_claim(tmp_path) -> None:
    database, manager = _manager(tmp_path, profile="Office")
    event = telemetry_event(
        datetime.now(timezone.utc) - timedelta(minutes=10),
        "process_execution",
        process="authorized-research-tool",
        path="/Applications/ResearchTool.app/Contents/MacOS/ResearchTool",
        metadata={"research_mode": True, "signing_status": "developer_id"},
    )

    anomalies = manager.process_events_sync([event])

    assert any("WORKSTATION_PROFILE_DEVIATION" in item["reason_codes"] for item in anomalies)
    assert any("PROFILE_UNEXPECTED_RESEARCH_ACTIVITY" in item["reason_codes"] for item in anomalies)
    assert all(item["security_severity"] in {"info", "low", "medium"} for item in anomalies)
    assert all("not proof of malicious intent" in item["explanation"] for item in anomalies)
    database.close()


def test_research_profile_accepts_declared_research_context(tmp_path) -> None:
    database, manager = _manager(tmp_path, profile="Research")
    event = telemetry_event(
        datetime.now(timezone.utc) - timedelta(minutes=10),
        "process_execution",
        process="authorized-research-tool",
        path="/Applications/ResearchTool.app/Contents/MacOS/ResearchTool",
        metadata={"research_mode": True, "signing_status": "developer_id"},
    )

    anomalies = manager.process_events_sync([event])

    assert all("WORKSTATION_PROFILE_DEVIATION" not in item["reason_codes"] for item in anomalies)
    database.close()


def test_workstation_profile_change_is_live_and_persisted(tmp_path) -> None:
    database, manager = _manager(tmp_path)

    selected = manager.set_workstation_profile("Developer", actor="test")

    assert selected == "Developer"
    assert manager.policy.profile == "Developer"
    assert manager.health()["policy_profile"] == "Developer"
    assert database.get_background_monitor_state("behavioral_telemetry_profile") == "Developer"
    database.close()
