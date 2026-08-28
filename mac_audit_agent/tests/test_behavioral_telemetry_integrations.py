from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mac_audit_agent.health.models import CoverageLevel
from mac_audit_agent.health.providers import BehavioralTelemetryProvider, built_in_providers
from mac_audit_agent.investigation_priority import InvestigationPriorityEngine
from mac_audit_agent.security_operations import SecurityOperationsOverviewBuilder
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.telemetry.manager import TelemetryManager
from mac_audit_agent.telemetry.cli import main as telemetry_cli_main
from mac_audit_agent.telemetry.policies import BehavioralTelemetryPolicy
from mac_audit_agent.telemetry.synthetic import normal_workday, process_storm
from mac_audit_agent.workflow_layer import InvestigatorWorkflowLayer


def _ready_manager(tmp_path):
    database = AuditDatabase(tmp_path / "integrations.sqlite", tmp_path / "logs")
    policy = BehavioralTelemetryPolicy(minimum_baseline_samples=4, established_baseline_samples=8, mature_baseline_samples=16)
    manager = TelemetryManager(database, policy, autostart=False)
    start = datetime.now(timezone.utc) - timedelta(hours=4)
    manager.process_events_sync(normal_workday(start, buckets=16), force_analysis=False)
    manager.rebuild_baseline(actor="integration_test", reason="integration baseline")
    return database, manager


def test_dashboard_builder_has_concise_behavior_card_and_attention() -> None:
    overview = SecurityOperationsOverviewBuilder().build(
        behavioral_status={
            "state": "HIGH_DEVIATION",
            "anomalies_today": 3,
            "high_risk_anomalies": 1,
            "health": {"analysis_availability": "AVAILABLE"},
        },
        scan_available=True,
    )
    card = next(item for item in overview.cards if item.card_id == "behavior")
    assert card.route == "Behavioral Telemetry"
    assert card.evidence_count == 3
    assert "1 high-risk" in card.summary
    assert any(item.route == "Behavioral Telemetry" for item in overview.needs_attention)


def test_sensor_health_provider_reports_learning_without_claiming_full_coverage(tmp_path) -> None:
    database = AuditDatabase(tmp_path / "health.sqlite", tmp_path / "logs")
    provider = BehavioralTelemetryProvider(database=database.path)
    snapshot = provider.health_snapshot()
    capabilities = {item.capability_id: item.coverage for item in snapshot.capabilities}

    assert snapshot.sensor_id == "behavioral_telemetry"
    assert capabilities["behavioral_baseline"] == CoverageLevel.PARTIAL
    assert snapshot.initialized is True
    database.close()


def test_builtin_health_providers_register_behavioral_telemetry(tmp_path) -> None:
    database = AuditDatabase(tmp_path / "providers.sqlite", tmp_path / "logs")
    ids = {provider.sensor_id() for provider in built_in_providers(system_db=database.path, user_home=tmp_path)}
    assert "behavioral_telemetry" in ids
    database.close()


def test_serious_behavioral_incident_enters_investigation_priority(tmp_path) -> None:
    database, manager = _ready_manager(tmp_path)
    manager.process_events_sync(process_storm(datetime.now(timezone.utc) - timedelta(minutes=10), count_value=60))
    engine = InvestigationPriorityEngine(database, InvestigatorWorkflowLayer(database))
    queue = engine.build_priorities().full_queue

    assert any(item.finding_id.startswith("BINC-") and "Behavioral incident" in item.title for item in queue)
    database.close()


def test_telemetry_cli_status_supports_json(tmp_path, capsys) -> None:
    path = tmp_path / "cli.sqlite"
    assert telemetry_cli_main(["status", "--db", str(path), "--json"]) == 0
    output = capsys.readouterr().out
    assert '"queue_capacity"' in output
    assert '"state"' in output
