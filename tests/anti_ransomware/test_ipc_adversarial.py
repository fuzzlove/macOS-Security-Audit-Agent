from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.anti_ransomware.ipc_protocol import AuthenticatedPeer, AuthorizedConnection, SenderRole


def encoded(*, role=SenderRole.USER_NOTIFIER, message_type="ACTION_REQUEST", action="ALLOW_ONCE", identity=True, nonce="abcdefghijklmnop", incident="incident-1", boot="boot-1", created=None, extra_payload=None):
    now = created or datetime.now(timezone.utc)
    payload = {"action": action, "idempotency_key": "key-1", "rationale": "reviewed"}
    if identity:
        payload["process_identity"] = {"pid": 123, "pid_version": 7, "boot_session_id": boot, "executable_sha256": "a" * 64, "effective_uid": 501}
    if extra_payload:
        payload.update(extra_payload)
    envelope = {
        "protocol_version": "1.0", "schema_version": "1.0", "message_type": message_type,
        "message_id": "message-1", "correlation_id": "correlation-1", "incident_id": incident,
        "event_id": "event-1", "boot_session_id": boot, "sender_role": role.value,
        "sender_build_id": "build-1", "created_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=1)).isoformat(), "nonce": nonce,
        "payload_length": len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()), "payload": payload,
    }
    return json.dumps(envelope, allow_nan=True).encode()


def connection(role=SenderRole.USER_NOTIFIER, *, production=True):
    peer = AuthenticatedPeer("a" * 64, "TEAM", "com.example.notifier", "anchor apple generic", False, role)
    return AuthorizedConnection("connection-1", peer, production=production, expected_team_id="TEAM", allowed_signing_ids={"com.example.notifier"}, expected_role=role, expected_boot_session="boot-1")


def test_connection_authentication_expires_on_disconnect_and_replay_is_bound():
    channel = connection()
    assert channel.receive(encoded(), expected_incident_id="incident-1")["incident_id"] == "incident-1"
    with pytest.raises(PermissionError, match="nonce"):
        channel.receive(encoded())
    channel.close()
    with pytest.raises(PermissionError, match="no longer valid"):
        channel.receive(encoded(nonce="differentnonce123"))


@pytest.mark.parametrize("action", ["TERMINATE_EXACT_PROCESS", "TRUST_EXACT_IDENTITY", "PAUSE_EXACT_PROCESS"])
def test_user_notifier_cannot_request_admin_or_engine_actions(action):
    with pytest.raises(PermissionError, match="outside"):
        connection().receive(encoded(action=action))


def test_privileged_action_requires_exact_identity_incident_event_and_idempotency():
    with pytest.raises(PermissionError, match="exact bounded"):
        connection().receive(encoded(identity=False))
    with pytest.raises(PermissionError, match="incident"):
        connection().receive(encoded(nonce="abcdefghijklmnop2"), expected_incident_id="other")
    with pytest.raises(PermissionError, match="unknown fields"):
        connection().receive(encoded(nonce="abcdefghijklmnop3", extra_payload={"command": "kill -9 1"}))


def test_wrong_boot_generation_hash_and_stale_creation_are_rejected():
    raw = json.loads(encoded(nonce="abcdefghijklmnop4"))
    raw["payload"]["process_identity"]["boot_session_id"] = "other"
    raw["payload_length"] = len(json.dumps(raw["payload"], sort_keys=True, separators=(",", ":")).encode())
    with pytest.raises(PermissionError, match="another boot"):
        connection().receive(json.dumps(raw).encode())
    stale = json.loads(encoded(nonce="abcdefghijklmnop5"))
    stale["created_at"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    with pytest.raises(PermissionError, match="creation time"):
        connection().receive(json.dumps(stale).encode())


def test_nonfinite_number_invalid_nonce_and_source_client_production_policy():
    raw = json.loads(encoded(nonce="abcdefghijklmnop6"))
    raw["payload"]["risk"] = float("nan")
    raw["payload_length"] = len(json.dumps(raw["payload"], sort_keys=True, separators=(",", ":")).encode())
    with pytest.raises(ValueError, match="non-finite"):
        connection().receive(json.dumps(raw, allow_nan=True).encode())
    with pytest.raises(PermissionError, match="nonce"):
        connection().receive(encoded(nonce="bad nonce value!"))
    peer = AuthenticatedPeer("a" * 64, "", "python-source", "", True, SenderRole.SYSTEM_ENGINE)
    with pytest.raises(PermissionError, match="Ad-hoc"):
        AuthorizedConnection("source-1", peer, production=True, expected_team_id="TEAM", allowed_signing_ids={"engine"}, expected_role=SenderRole.SYSTEM_ENGINE, expected_boot_session="boot-1")
