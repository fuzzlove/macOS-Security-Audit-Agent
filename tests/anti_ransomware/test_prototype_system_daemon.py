from __future__ import annotations

import json
import os
import time
from pathlib import Path

from mac_audit_agent.anti_ransomware.health import RuntimeEvidence, source_health
from mac_audit_agent.anti_ransomware.prototype_observer import PrototypeRansomwareObserver, read_prototype_status
from mac_audit_agent.launch_agent import build_launch_agent_plist
from mac_audit_agent.monitor import BackgroundMonitorService, MONITOR_ROLE_SYSTEM


def test_prototype_observer_runs_and_writes_privacy_safe_metadata(tmp_path: Path) -> None:
    root = tmp_path / "watched"; root.mkdir()
    state = tmp_path / "state"
    observer = PrototypeRansomwareObserver(root, state_directory=state, interval_seconds=0.05, heartbeat_seconds=0.05)
    started = observer.start()
    assert started.running and started.mode == "DEVELOPMENT_OBSERVATION_ONLY"
    (root / "example.txt").write_text("benign test", encoding="utf-8")
    deadline = time.monotonic() + 2
    while observer.status().events_observed == 0 and time.monotonic() < deadline: time.sleep(0.02)
    stopped = observer.stop()
    assert not stopped.running and stopped.events_observed >= 1
    record = json.loads((state / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert record["operation"] == "created" and len(record["path_token"]) == 64
    assert "example.txt" not in json.dumps(record)
    assert record["containment_performed"] is False
    assert stat_mode(state / "health.json") == 0o600


def test_prototype_health_reader_rejects_untrusted_permissions(tmp_path: Path) -> None:
    path = tmp_path / "health.json"
    path.write_text(json.dumps({"running": True, "heartbeat_at": "2099-01-01T00:00:00+00:00"}), encoding="utf-8")
    path.chmod(0o644)
    assert read_prototype_status(path)["health_state"] == "untrusted"


def test_production_health_reports_operational_fallback_without_claiming_enforcement() -> None:
    evidence = RuntimeEvidence(
        system_engine_running=True,
        sensor_details={"development_observer": {"running": True, "mode": "DEVELOPMENT_OBSERVATION_ONLY"}},
    )
    health = source_health(evidence=evidence)
    payload = health.to_dict()
    assert health.error_code == "AR022"
    assert health.full_active_protection is False
    assert health.state.value == "OBSERVE_READY"
    assert payload["operational_state"] == "OBSERVE"
    assert payload["development_observer_running"] is True
    assert "Fallback Behavioral Detection Operational" in health.status_badge


def test_system_launchdaemon_receives_explicit_desktop_user_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MSAA_GUI_HOME", str(tmp_path / "Users/tester"))
    monkeypatch.setenv("MSAA_GUI_UID", "501")
    payload = build_launch_agent_plist(db_path=tmp_path / "db.sqlite", scope="system", python_executable="/usr/bin/python3")
    environment = payload["EnvironmentVariables"]
    assert environment["MSAA_GUI_HOME"] == str(tmp_path / "Users/tester")
    assert environment["MSAA_GUI_UID"] == "501"


def test_system_daemon_starts_only_explicit_standard_roots(monkeypatch, tmp_path: Path) -> None:
    home = tmp_path / "home"; (home / "Desktop").mkdir(parents=True); (home / "Documents").mkdir()
    monkeypatch.setenv("MSAA_GUI_HOME", str(home))
    started = []
    class FakeObserver:
        def __init__(self, root, **kwargs): self.root = root
        def start(self): started.append(self.root)
        def stop(self): return None
    monkeypatch.setattr("mac_audit_agent.monitor.PrototypeRansomwareObserver", FakeObserver)
    service = BackgroundMonitorService(tmp_path / "events.sqlite", mode=MONITOR_ROLE_SYSTEM, record_startup=False)
    service._start_ransomware_prototype_observers()
    assert started == [home / "Desktop", home / "Documents"]
    assert service.db.get_background_monitor_state("anti_ransomware_prototype_status", "") == "running"
    service.db.close()


def test_clickfix_user_session_journal_bridges_only_potential_incidents(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MSAA_GUI_HOME", str(tmp_path / "home"))
    service = BackgroundMonitorService(tmp_path / "events.sqlite", mode=MONITOR_ROLE_SYSTEM, record_startup=False)
    class FakeConsumer:
        def consume(self):
            return [
                {"disposition": "NONE"},
                {"disposition": "POTENTIAL_CLICKFIX", "incident_id": "private-id-not-forwarded"},
            ]
    service._clickfix_consumer = FakeConsumer()
    events = service._consume_clickfix_events()
    assert len(events) == 1
    assert events[0].event_type == "potential_clickfix_command_detected"
    assert events[0].severity == "critical"
    assert "private-id-not-forwarded" not in events[0].evidence
    assert service.db.get_background_monitor_state("clickfix_daemon_bridge_status", "") == "active"
    service.db.close()


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
