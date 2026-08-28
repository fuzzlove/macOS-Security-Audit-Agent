from __future__ import annotations

import json
import math
import re
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from mac_audit_agent.compat.enum import StrEnum
from pathlib import PurePosixPath
from threading import Lock
from typing import Any

PROTOCOL_VERSION = "1.0"
SCHEMA_VERSION = "1.0"
MAX_MESSAGE_BYTES = 65536
MAX_STRING = 4096
MAX_CLOCK_SKEW_SECONDS = 30
MAX_MESSAGE_AGE_SECONDS = 300
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class MessageType(StrEnum):
    SENSOR_EVENT = "SENSOR_EVENT"
    HEALTH_QUERY = "HEALTH_QUERY"
    HEALTH_RESPONSE = "HEALTH_RESPONSE"
    NOTIFICATION = "NOTIFICATION"
    ACKNOWLEDGEMENT = "ACKNOWLEDGEMENT"
    ACTION_REQUEST = "ACTION_REQUEST"
    ACTION_RESPONSE = "ACTION_RESPONSE"


class SenderRole(StrEnum):
    NATIVE_SENSOR = "NATIVE_SENSOR"
    SYSTEM_ENGINE = "SYSTEM_ENGINE"
    USER_NOTIFIER = "USER_NOTIFIER"
    ADMIN_CLIENT = "ADMIN_CLIENT"
    DIAGNOSTIC_CLIENT = "DIAGNOSTIC_CLIENT"


ALLOWED_FIELDS = {"protocol_version", "schema_version", "message_type", "message_id", "correlation_id", "incident_id", "event_id", "boot_session_id", "sender_role", "sender_build_id", "created_at", "expires_at", "nonce", "payload_length", "payload"}
REQUIRED_FIELDS = ALLOWED_FIELDS - {"incident_id", "event_id"}


@dataclass(frozen=True)
class AuthenticatedPeer:
    audit_token_hash: str
    team_id: str
    signing_id: str
    designated_requirement: str
    ad_hoc: bool
    role: SenderRole


PRIVILEGED_ACTIONS: dict[SenderRole, frozenset[str]] = {
    SenderRole.USER_NOTIFIER: frozenset({"ACKNOWLEDGE", "ALLOW_ONCE", "KEEP_PAUSED", "REQUEST_ADMIN_REVIEW"}),
    SenderRole.ADMIN_CLIENT: frozenset({"ACKNOWLEDGE", "ALLOW_ONCE", "KEEP_PAUSED", "RESUME_EXACT_PROCESS", "TERMINATE_EXACT_PROCESS", "BLOCK_EXACT_IDENTITY", "TRUST_EXACT_IDENTITY"}),
    SenderRole.SYSTEM_ENGINE: frozenset({"PAUSE_EXACT_PROCESS", "INCREASE_TELEMETRY", "EXPIRE_CONTAINMENT", "ROLLBACK_CONTAINMENT"}),
}

ACTION_REQUIRED_IDENTITY = frozenset({
    "ALLOW_ONCE", "KEEP_PAUSED", "RESUME_EXACT_PROCESS", "TERMINATE_EXACT_PROCESS",
    "BLOCK_EXACT_IDENTITY", "TRUST_EXACT_IDENTITY", "PAUSE_EXACT_PROCESS",
    "EXPIRE_CONTAINMENT", "ROLLBACK_CONTAINMENT",
})
PROCESS_IDENTITY_FIELDS = frozenset({"pid", "pid_version", "boot_session_id", "executable_sha256", "effective_uid"})


class ReplayCache:
    def __init__(self, capacity: int = 4096) -> None:
        self.capacity = capacity
        self._items: OrderedDict[str, None] = OrderedDict()
        self._lock = Lock()

    def accept(self, connection_id: str, nonce: str) -> bool:
        key = f"{connection_id}:{nonce}"
        with self._lock:
            if key in self._items:
                return False
            self._items[key] = None
            self._items.move_to_end(key)
            while len(self._items) > self.capacity:
                self._items.popitem(last=False)
            return True


def authenticate_peer(peer: AuthenticatedPeer, *, production: bool, expected_team_id: str, allowed_signing_ids: set[str], expected_role: SenderRole) -> None:
    if not peer.audit_token_hash or len(peer.audit_token_hash) < 32:
        raise PermissionError("[AR014] IPC audit-token identity is missing or malformed.")
    if peer.role is not expected_role:
        raise PermissionError("[AR014] IPC caller role is not authorized for this channel.")
    if production and peer.ad_hoc:
        raise PermissionError("[AR014] Ad-hoc or unsigned IPC clients are rejected in managed production mode.")
    if production and (peer.team_id != expected_team_id or peer.signing_id not in allowed_signing_ids or not peer.designated_requirement):
        raise PermissionError("[AR014] IPC code-signing requirement did not match the managed policy.")


class AuthorizedConnection:
    """Authentication and replay state bound to one native connection lifetime."""

    def __init__(self, connection_id: str, peer: AuthenticatedPeer, *, production: bool, expected_team_id: str, allowed_signing_ids: set[str], expected_role: SenderRole, expected_boot_session: str, replay_capacity: int = 4096) -> None:
        if not IDENTIFIER_PATTERN.fullmatch(connection_id):
            raise PermissionError("[AR014] IPC connection identifier is malformed.")
        authenticate_peer(peer, production=production, expected_team_id=expected_team_id, allowed_signing_ids=allowed_signing_ids, expected_role=expected_role)
        self.connection_id = connection_id
        self.peer = peer
        self.expected_boot_session = expected_boot_session
        self.replay_cache = ReplayCache(replay_capacity)
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def receive(self, raw: bytes, *, expected_incident_id: str | None = None) -> dict[str, Any]:
        if self.closed:
            raise PermissionError("[AR014] IPC connection authentication is no longer valid.")
        envelope = parse_envelope(raw, connection_id=self.connection_id, replay_cache=self.replay_cache, expected_boot_session=self.expected_boot_session, allowed_role=self.peer.role)
        if expected_incident_id is not None and envelope.get("incident_id") != expected_incident_id:
            raise PermissionError("[AR014] IPC action is bound to a different incident.")
        if envelope["message_type"] == MessageType.ACTION_REQUEST.value:
            authorize_action(envelope, self.peer.role)
        return envelope


def authorize_action(envelope: dict[str, Any], role: SenderRole) -> None:
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or set(payload) - {"action", "process_identity", "idempotency_key", "rationale"}:
        raise PermissionError("[AR014] Privileged action payload has unknown fields.")
    action = payload.get("action")
    if action not in PRIVILEGED_ACTIONS.get(role, frozenset()):
        raise PermissionError("[AR014] Requested action is outside the authenticated caller role.")
    if not envelope.get("incident_id") or not envelope.get("event_id"):
        raise PermissionError("[AR014] Privileged action must bind incident and event identifiers.")
    idempotency_key = payload.get("idempotency_key")
    if not isinstance(idempotency_key, str) or not IDENTIFIER_PATTERN.fullmatch(idempotency_key):
        raise PermissionError("[AR014] Privileged action idempotency key is missing or malformed.")
    if action in ACTION_REQUIRED_IDENTITY:
        identity = payload.get("process_identity")
        if not isinstance(identity, dict) or set(identity) != PROCESS_IDENTITY_FIELDS:
            raise PermissionError("[AR014] Privileged action requires an exact bounded process identity.")
        if not isinstance(identity["pid"], int) or identity["pid"] <= 0 or not isinstance(identity["pid_version"], int) or identity["pid_version"] < 0:
            raise PermissionError("[AR014] Process generation identity is invalid.")
        if identity["boot_session_id"] != envelope["boot_session_id"]:
            raise PermissionError("[AR014] Process identity belongs to another boot session.")
        digest = identity["executable_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PermissionError("[AR014] Exact executable identity hash is invalid.")


def parse_envelope(raw: bytes, *, connection_id: str, replay_cache: ReplayCache, expected_boot_session: str, allowed_role: SenderRole) -> dict[str, Any]:
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("[AR014] IPC message exceeds 65,536 bytes.")
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"[AR014] IPC message is not valid UTF-8 JSON: {type(exc).__name__}") from exc
    if not isinstance(payload, dict) or set(payload) - ALLOWED_FIELDS or REQUIRED_FIELDS - set(payload):
        raise ValueError("[AR014] IPC envelope has missing or unknown fields.")
    if payload["protocol_version"] != PROTOCOL_VERSION or payload["schema_version"] != SCHEMA_VERSION:
        raise ValueError("[AR024] Native protocol version mismatch or downgrade request.")
    MessageType(payload["message_type"])
    for field in ("message_id", "correlation_id", "boot_session_id", "sender_build_id"):
        if not isinstance(payload[field], str) or not IDENTIFIER_PATTERN.fullmatch(payload[field]):
            raise ValueError(f"[AR014] IPC {field} is malformed.")
    for field in ("incident_id", "event_id"):
        if field in payload and (not isinstance(payload[field], str) or not IDENTIFIER_PATTERN.fullmatch(payload[field])):
            raise ValueError(f"[AR014] IPC {field} is malformed.")
    if SenderRole(payload["sender_role"]) is not allowed_role:
        raise PermissionError("[AR014] Sender role is not valid for this IPC channel.")
    if payload["boot_session_id"] != expected_boot_session:
        raise PermissionError("[AR014] IPC request belongs to a different boot session.")
    try:
        created = datetime.fromisoformat(str(payload["created_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("[AR014] IPC timestamps are malformed.") from exc
    now = datetime.now(timezone.utc)
    if created.tzinfo is None or expires.tzinfo is None or expires <= now or expires <= created:
        raise PermissionError("[AR014] IPC request is expired.")
    if (created - now).total_seconds() > MAX_CLOCK_SKEW_SECONDS or (now - created).total_seconds() > MAX_MESSAGE_AGE_SECONDS:
        raise PermissionError("[AR014] IPC request creation time is outside the permitted window.")
    nonce = str(payload["nonce"])
    if not NONCE_PATTERN.fullmatch(nonce) or not replay_cache.accept(connection_id, nonce):
        raise PermissionError("[AR014] IPC nonce is malformed or has already been used.")
    encoded_payload = json.dumps(payload["payload"], sort_keys=True, separators=(",", ":")).encode()
    if isinstance(payload["payload_length"], bool) or not isinstance(payload["payload_length"], int) or payload["payload_length"] != len(encoded_payload):
        raise ValueError("[AR014] IPC payload length does not match the envelope.")
    _validate_value(payload["payload"], depth=0)
    return payload


def normalize_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("[AR014] IPC path traversal or absolute path is prohibited.")
    return str(path)


def _validate_value(value: Any, *, depth: int) -> None:
    if depth > 6:
        raise ValueError("[AR014] IPC object nesting exceeds the protocol limit.")
    if isinstance(value, str) and len(value) > MAX_STRING:
        raise ValueError("[AR014] IPC string exceeds the protocol limit.")
    if isinstance(value, list):
        if len(value) > 256:
            raise ValueError("[AR014] IPC list exceeds the protocol limit.")
        for item in value:
            _validate_value(item, depth=depth + 1)
    elif isinstance(value, dict):
        if len(value) > 64:
            raise ValueError("[AR014] IPC object exceeds the field limit.")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError("[AR014] IPC field name is invalid.")
            _validate_value(item, depth=depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("[AR014] IPC non-finite numbers are prohibited.")
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise ValueError("[AR014] IPC value type is not permitted.")
