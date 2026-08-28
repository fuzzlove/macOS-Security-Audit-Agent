from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from mac_audit_agent.anti_ransomware import simulator
from mac_audit_agent.anti_ransomware.live_fixture import (
    LIVE_FIXTURE_STAGES,
    fixture_challenge,
    fixture_directory_prefix,
    parse_fixture_receipt,
    stage_marker_name,
)
from mac_audit_agent.anti_ransomware.sensor_inspector import (
    _development_observer_status,
)
from mac_audit_agent.monitor import MONITOR_ROLE_SYSTEM, BackgroundMonitorService


def _observer_payload(**observer):
    return {
        "sensor_details": {"development_observer": observer},
        "endpoint_security_observe_ready": False,
    }


def _state_database(path, values):
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE background_monitor_state(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO background_monitor_state(key,value) VALUES(?,?)",
            [(key, str(value)) for key, value in values.items()],
        )


def test_fixture_receipt_exposes_only_random_challenge_and_known_stage(tmp_path):
    nonce = "a1b2c3d4e5f60718"
    root = tmp_path / f"{fixture_directory_prefix(nonce)}suffix"
    marker = root / stage_marker_name("atomic-replacement")

    receipt = parse_fixture_receipt(marker)

    assert receipt == {
        "challenge": fixture_challenge(nonce),
        "stage": "atomic-replacement",
    }
    assert str(tmp_path) not in json.dumps(receipt)
    assert parse_fixture_receipt(tmp_path / "unrelated.txt") is None


def test_stale_system_heartbeat_cannot_claim_observer_is_running(tmp_path):
    now = datetime(2026, 8, 27, tzinfo=timezone.utc)
    database = tmp_path / "monitor.sqlite3"
    _state_database(database, {
        "anti_ransomware_prototype_status": "running",
        "anti_ransomware_prototype_roots": '["Documents"]',
        "last_heartbeat": (now - timedelta(minutes=5)).isoformat(),
    })

    status = _development_observer_status(database, now=now)

    assert status["configured_state"] == "running"
    assert status["system_heartbeat_fresh"] is False
    assert status["running"] is False


def test_fresh_observer_status_returns_bounded_fixture_receipts(tmp_path):
    now = datetime(2026, 8, 27, tzinfo=timezone.utc)
    database = tmp_path / "monitor.sqlite3"
    receipts = [
        {"challenge": "a" * 64, "stage": "rapid-file-creation", "operation": "created"}
    ]
    _state_database(database, {
        "anti_ransomware_prototype_status": "running",
        "anti_ransomware_prototype_roots": '["Documents"]',
        "anti_ransomware_prototype_fixture_receipts": json.dumps(receipts),
        "anti_ransomware_prototype_last_fixture_challenge": "a" * 64,
        "last_heartbeat": (now - timedelta(seconds=2)).isoformat(),
    })

    status = _development_observer_status(database, now=now)

    assert status["running"] is True
    assert status["fixture_receipts"] == receipts
    assert status["last_fixture_challenge"] == "a" * 64


def test_live_validation_requires_every_challenge_bound_stage(monkeypatch, tmp_path):
    (tmp_path / "Documents").mkdir()
    monkeypatch.setattr(simulator.Path, "home", lambda: tmp_path)
    challenge = "b" * 64
    expected = list(LIVE_FIXTURE_STAGES)
    calls = 0

    def health_provider():
        nonlocal calls
        calls += 1
        receipts = [] if calls == 1 else [
            {"challenge": challenge, "stage": stage, "operation": "created"}
            for stage in expected
        ]
        return _observer_payload(
            running=True,
            roots=["Documents"],
            fixture_receipts=receipts,
            last_fixture_challenge=challenge if receipts else "",
        )

    def simulation_runner(**kwargs):
        assert kwargs["parent_root"] == tmp_path / "Documents"
        return {
            "all_stages_passed": True,
            "fixture_challenge": challenge,
            "expected_live_stages": expected,
            "detection_validation": {"passed": True},
        }

    result = simulator.run_safe_detection_validation(
        health_provider=health_provider,
        sleeper=lambda _seconds: None,
        simulation_runner=simulation_runner,
    )

    assert result["status"] == "PASS"
    assert result["caught"] is True
    assert result["fixture_challenge_seen"] is True
    assert result["missing_live_stages"] == []
    assert result["live_observation"] == "fixture_challenge_and_stages_observed"


def test_unrelated_observer_activity_cannot_satisfy_live_validation(monkeypatch, tmp_path):
    (tmp_path / "Documents").mkdir()
    monkeypatch.setattr(simulator.Path, "home", lambda: tmp_path)
    expected = list(LIVE_FIXTURE_STAGES)

    result = simulator.run_safe_detection_validation(
        health_provider=lambda: _observer_payload(
            running=True,
            roots=["Documents"],
            fixture_receipts=[{"challenge": "c" * 64, "stage": stage} for stage in expected],
            last_event="new-unrelated-event",
        ),
        sleeper=lambda _seconds: None,
        simulation_runner=lambda **_kwargs: {
            "all_stages_passed": True,
            "fixture_challenge": "d" * 64,
            "expected_live_stages": expected,
            "detection_validation": {"passed": True},
        },
        poll_attempts=1,
    )

    assert result["status"] == "INCONCLUSIVE"
    assert result["fixture_challenge_seen"] is False
    assert result["missing_live_stages"] == sorted(expected)
    assert result["repair_required"] is True


def test_system_daemon_records_a_bounded_fixture_stage_receipt(tmp_path):
    service = BackgroundMonitorService(
        tmp_path / "events.sqlite3",
        mode=MONITOR_ROLE_SYSTEM,
        record_startup=False,
    )
    nonce = "1122334455667788"
    fixture_root = tmp_path / f"{fixture_directory_prefix(nonce)}receipt"
    fixture_root.mkdir()
    event = SimpleNamespace(
        path=str(fixture_root / stage_marker_name("canary-modification")),
        operation="created",
    )

    service._handle_ransomware_prototype_event(event)

    receipts = json.loads(
        service.db.get_background_monitor_state("anti_ransomware_prototype_fixture_receipts", "[]")
    )
    assert receipts[-1]["challenge"] == fixture_challenge(nonce)
    assert receipts[-1]["stage"] == "canary-modification"
    assert str(tmp_path) not in json.dumps(receipts[-1])
    service.db.close()


def test_rce_schema_failure_does_not_terminate_shared_ransomware_monitor(monkeypatch, tmp_path):
    def incompatible_repository(_path):
        raise RuntimeError("unsupported RCE database schema")

    monkeypatch.setattr("mac_audit_agent.monitor.RCERepository", incompatible_repository)
    service = BackgroundMonitorService(
        tmp_path / "events.sqlite3",
        mode=MONITOR_ROLE_SYSTEM,
        record_startup=False,
    )

    assert service.rce_monitor is None
    assert service._run_rce_detector() == []
    assert service.db.get_background_monitor_state("rce_monitor_status", "") == "DEGRADED_INITIALIZATION_FAILED"
    assert service.db.get_background_monitor_state("rce_monitor_initialization", "").startswith("degraded:")
    service.db.close()


def test_safe_fixture_exercises_twelve_disposable_live_stages():
    report = simulator.run_safe_simulation(file_count=5, bytes_per_file=1024)
    stages = {item["stage"] for item in report["stages"]}

    assert stages == set(LIVE_FIXTURE_STAGES)
    assert report["all_stages_passed"] is True
    assert report["expected_live_stages"] == list(LIVE_FIXTURE_STAGES)
    assert len(report["fixture_challenge"]) == 64
