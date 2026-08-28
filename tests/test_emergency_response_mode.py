from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mac_audit_agent.emergency_response import AuthorizationContext, EmergencyResponseError, EmergencyResponseManager, ResponseState
from mac_audit_agent.storage import AuditDatabase


def auth(*, admin: bool = True) -> AuthorizationContext:
    return AuthorizationContext("responder", "local_admin_auth", True, admin, (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat())


class NetworkFixture:
    def restrict(self, incident_id, *, preserve_management):
        return {"success": True, "previous_state": {"mode": "normal"}, "current_state": {"mode": "restricted", "management_preserved": preserve_management}}
    def restore(self, incident_id, previous_state):
        return {"success": previous_state == {"mode": "normal"}}


class ProcessFixture:
    def contain(self, incident_id, process_identity, *, terminate):
        return {"success": True, "action": "terminate" if terminate else "suspend", "simulated": True}


def manager(tmp_path: Path):
    db = AuditDatabase(tmp_path / "audit.sqlite3")
    value = EmergencyResponseManager(db, tmp_path / "evidence", snapshot_collectors={"processes": lambda: [{"pid": 10}], "persistence": lambda: []})
    return db, value


def test_activation_snapshot_containment_recovery_and_exit_are_audited(tmp_path: Path) -> None:
    db, response = manager(tmp_path)
    incident = response.activate("Critical ransomware correlation", auth(), trigger_event_id="ar-1")
    assert incident.state == ResponseState.INVESTIGATION.value
    snapshot = response.collect_snapshot(auth())
    assert Path(snapshot["path"]).is_file() and len(snapshot["sha256"]) == 64
    response.restrict_network(auth(), NetworkFixture())
    response.enter_recovery(auth(), "Threat activity stopped")
    completed = response.exit(auth(), "Recovery validation complete", network_adapter=NetworkFixture())
    assert completed.state == ResponseState.NORMAL.value
    assert len(response.timeline(incident.incident_id)) == 5
    assert len(db.recent_background_monitor_events(limit=20)) == 5


def test_unauthorized_activation_is_blocked_and_logged(tmp_path: Path) -> None:
    db, response = manager(tmp_path)
    with pytest.raises(EmergencyResponseError, match="administrator authorization"):
        response.activate("test", auth(admin=False))
    event = db.recent_background_monitor_events(limit=1)[0]
    assert event.event_type == "unauthorized_emergency_action"
    assert event.severity == "critical"


def test_containment_requires_preserved_evidence_and_stable_high_confidence_identity(tmp_path: Path) -> None:
    _db, response = manager(tmp_path)
    response.activate("investigation", auth())
    identity = {"pid": 42, "executable_path": "/tmp/fixture", "sha256": "a" * 64, "process_start_time": 123}
    with pytest.raises(EmergencyResponseError, match="evidence"):
        response.contain_process(auth(), ProcessFixture(), identity, confidence_score=95)
    response.collect_snapshot(auth())
    with pytest.raises(EmergencyResponseError, match="confidence"):
        response.contain_process(auth(), ProcessFixture(), identity, confidence_score=50)
    result = response.contain_process(auth(), ProcessFixture(), identity, confidence_score=95)
    assert result["simulated"] is True


def test_snapshot_collector_failure_is_preserved_as_explicit_partial_evidence(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite3")
    response = EmergencyResponseManager(db, tmp_path / "evidence", snapshot_collectors={"network": lambda: (_ for _ in ()).throw(PermissionError("denied"))})
    response.activate("investigation", auth())
    result = response.collect_snapshot(auth())
    assert result["collector_errors"]["network"]["error_type"] == "PermissionError"
    assert db.recent_background_monitor_events(limit=1)[0].metadata_json.find('"result": "partial"') >= 0
