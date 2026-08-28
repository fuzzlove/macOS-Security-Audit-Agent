from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.anti_ransomware.evidence import EvidenceRecord, RansomwareEvidenceStore
from mac_audit_agent.anti_ransomware.ipc_protocol import AuthenticatedPeer, ReplayCache, SenderRole, authenticate_peer, normalize_relative_path, parse_envelope
from mac_audit_agent.anti_ransomware.notifier_channel import NotificationState, PendingNotificationQueue, SanitizedNotification


def envelope(**changes):
    expiry = datetime.now(timezone.utc) + timedelta(minutes=1)
    payload = {"action": "ACKNOWLEDGE"}
    data = {"protocol_version":"1.0","schema_version":"1.0","message_type":"ACKNOWLEDGEMENT","message_id":"m","correlation_id":"c","incident_id":"i","event_id":"e","boot_session_id":"boot","sender_role":"USER_NOTIFIER","sender_build_id":"build","created_at":datetime.now(timezone.utc).isoformat(),"expires_at":expiry.isoformat(),"nonce":"0123456789abcdef","payload_length":len(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()),"payload":payload}
    data.update(changes); return json.dumps(data).encode()


def test_protocol_replay_oversize_role_boot_and_traversal_rejected():
    replay = ReplayCache(2)
    assert parse_envelope(envelope(), connection_id="conn", replay_cache=replay, expected_boot_session="boot", allowed_role=SenderRole.USER_NOTIFIER)["incident_id"] == "i"
    with pytest.raises(PermissionError, match="nonce"):
        parse_envelope(envelope(), connection_id="conn", replay_cache=replay, expected_boot_session="boot", allowed_role=SenderRole.USER_NOTIFIER)
    with pytest.raises(ValueError, match="65,536"):
        parse_envelope(b"x" * 65537, connection_id="x", replay_cache=ReplayCache(), expected_boot_session="boot", allowed_role=SenderRole.USER_NOTIFIER)
    with pytest.raises(ValueError, match="traversal"):
        normalize_relative_path("../escape")


def test_production_peer_requires_audit_identity_signature_and_role():
    good = AuthenticatedPeer("a"*64, "TEAM", "com.example.notifier", "anchor apple generic", False, SenderRole.USER_NOTIFIER)
    authenticate_peer(good, production=True, expected_team_id="TEAM", allowed_signing_ids={"com.example.notifier"}, expected_role=SenderRole.USER_NOTIFIER)
    with pytest.raises(PermissionError, match="Ad-hoc"):
        authenticate_peer(AuthenticatedPeer("a"*64,"TEAM","com.example.notifier","req",True,SenderRole.USER_NOTIFIER), production=True, expected_team_id="TEAM", allowed_signing_ids={"com.example.notifier"}, expected_role=SenderRole.USER_NOTIFIER)


def test_full_vault_schema_foreign_keys_indexes_chain_and_integrity(tmp_path):
    store = RansomwareEvidenceStore(tmp_path / "vault.sqlite3")
    tables = {row[0] for row in store.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {"anti_ransomware_incidents","anti_ransomware_process_identities","anti_ransomware_file_mutations","anti_ransomware_detection_signals","anti_ransomware_containment_leases","anti_ransomware_notification_deliveries","anti_ransomware_chain_of_custody"}
    assert required <= tables
    assert store.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    first = store.append_chain_entry(incident_id="i",created_at="2026-01-01T00:00:00Z",actor="engine",action="created",object_id="i",details={"redacted":True})
    assert len(first) == 64 and store.verify_chain() and store.integrity_check()
    store.close()


def test_notifier_queue_is_sanitized_bounded_and_does_not_start_displayed(tmp_path):
    queue = PendingNotificationQueue(tmp_path / "user" / "pending.json", max_items=2)
    expiry = (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()
    for i in range(3):
        queue.enqueue(SanitizedNotification(str(i),"incident","high","high","Fixture","<protected-path>",5,("rapid encryption",),"PAUSED",("ACKNOWLEDGE",),expiry,"security@example.invalid"))
    items = queue.read_all()
    assert len(items) == 2
    assert all(item.state.value == "QUEUED" for item in items)
    raw = queue.path.read_text()
    assert "/Users/" not in raw and "DISPLAYED" not in raw


def test_pending_notification_replay_and_acknowledgement_are_persisted(tmp_path):
    queue = PendingNotificationQueue(tmp_path / "pending.json")
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    queue.enqueue(SanitizedNotification("n2", "i2", "high", "high", "fixture", "<redacted>", 5, ("rapid replacement",), "PAUSED", ("ACKNOWLEDGE",), expiry, "admin"))
    assert [entry.notification_id for entry in queue.replay_pending()] == ["n2"]
    queue.transition("n2", NotificationState.DELIVERED_TO_NOTIFIER)
    assert queue.replay_pending()[0].state is NotificationState.DELIVERED_TO_NOTIFIER
    queue.acknowledge("n2")
    assert queue.read_all()[0].state is NotificationState.ACKNOWLEDGED
    assert queue.replay_pending() == []


def test_vault_export_and_authorized_retention(tmp_path):
    store = RansomwareEvidenceStore(tmp_path / "vault.sqlite3")
    old = "2020-01-01T00:00:00+00:00"
    with store.connection:
        store.connection.execute(
            "INSERT INTO anti_ransomware_incidents(incident_id,first_event_time,last_event_time,boot_session_id,endpoint_id,severity,confidence,score,policy_version,ruleset_version,containment_state,notification_state,resolution,limitations_json,created_at,updated_at,closed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("incident-old", old, old, "boot", "endpoint", "high", "high", 90, "1", "1", "CLOSED", "ACKNOWLEDGED", "resolved", "[]", old, old, old),
        )
    store.append(EvidenceRecord("e-old", "incident-old", old, "summary", {"redacted": True}))
    manifest = store.export_incident("incident-old", tmp_path / "export.json")
    assert len(manifest["sha256"]) == 64 and store.verify("e-old")
    with pytest.raises(PermissionError):
        store.apply_retention(days=30, authorized=False)
    assert store.apply_retention(days=30, authorized=True) == 1
    assert store.connection.execute("SELECT count(*) FROM anti_ransomware_incidents").fetchone()[0] == 0
    store.close()
