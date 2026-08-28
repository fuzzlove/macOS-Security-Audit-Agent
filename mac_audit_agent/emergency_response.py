"""Auditable emergency-response orchestration with inert privileged defaults.

This module coordinates existing MSAA evidence and containment capabilities.  It
does not implement a second process killer, firewall, or persistence scanner.
Privileged actions require an authenticated adapter supplied by the installed
service boundary; source-mode callers can only collect evidence and record state.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol
from uuid import uuid4

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso


STATE_KEY = "emergency_response_state_v1"
TIMELINE_KEY = "emergency_response_timeline_v1"


class ResponseState(str, Enum):
    NORMAL = "NORMAL"
    WARNING = "WARNING"
    INVESTIGATION = "INVESTIGATION"
    CONTAINMENT_ACTIVE = "CONTAINMENT ACTIVE"
    RECOVERY_MODE = "RECOVERY MODE"


@dataclass(frozen=True)
class AuthorizationContext:
    username: str
    authorization_source: str
    authenticated: bool
    administrator: bool
    expires_at: str

    def valid(self, now: datetime | None = None) -> bool:
        if not self.username.strip() or not self.authorization_source.strip():
            return False
        try:
            expiry = datetime.fromisoformat(self.expires_at)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return False
        return self.authenticated and self.administrator and expiry > (now or datetime.now(timezone.utc))


@dataclass
class EmergencyIncident:
    incident_id: str
    state: str
    threat_level: str
    reason: str
    activated_at: str
    activated_by: str
    authorization_source: str
    containment_status: str = "not_active"
    network_state: dict[str, Any] = field(default_factory=dict)
    evidence_bundle: str = ""
    evidence_sha256: str = ""
    analyst_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StateStore(Protocol):
    def get_background_monitor_state(self, key: str, default: str = "") -> str: ...
    def set_background_monitor_state(self, key: str, value: str) -> None: ...
    def record_background_monitor_event(self, event: BackgroundMonitorEvent, dedupe_window_seconds: int = 60) -> bool: ...


class NetworkContainmentAdapter(Protocol):
    def restrict(self, incident_id: str, *, preserve_management: bool) -> dict[str, Any]: ...
    def restore(self, incident_id: str, previous_state: dict[str, Any]) -> dict[str, Any]: ...


class ProcessContainmentAdapter(Protocol):
    def contain(self, incident_id: str, process_identity: dict[str, Any], *, terminate: bool) -> dict[str, Any]: ...


class EmergencyResponseError(RuntimeError):
    pass


class EmergencyResponseManager:
    def __init__(self, store: StateStore, evidence_dir: Path, *, snapshot_collectors: dict[str, Callable[[], Any]] | None = None) -> None:
        self.store = store
        self.evidence_dir = Path(evidence_dir)
        self.snapshot_collectors = dict(snapshot_collectors or {})

    def current(self) -> EmergencyIncident | None:
        raw = self.store.get_background_monitor_state(STATE_KEY, "")
        if not raw:
            return None
        try:
            return EmergencyIncident(**json.loads(raw))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise EmergencyResponseError("Emergency response state is corrupt; no action was performed.") from exc

    def activate(self, reason: str, authorization: AuthorizationContext, *, threat_level: str = "critical", trigger_event_id: str = "") -> EmergencyIncident:
        self._require_authorization(authorization, "activate", reason=reason)
        if not reason.strip():
            raise EmergencyResponseError("An incident reason is required.")
        existing = self.current()
        if existing and existing.state != ResponseState.NORMAL.value:
            raise EmergencyResponseError(f"Emergency response is already active for {existing.incident_id}.")
        incident = EmergencyIncident(
            incident_id=f"er-{uuid4().hex}", state=ResponseState.INVESTIGATION.value,
            threat_level=threat_level.lower(), reason=reason.strip(), activated_at=utc_now_iso(),
            activated_by=authorization.username, authorization_source=authorization.authorization_source,
        )
        self._save(incident)
        self._audit(incident, authorization, "emergency_mode_activated", "success", reason, trigger_event_id=trigger_event_id)
        return incident

    def collect_snapshot(self, authorization: AuthorizationContext) -> dict[str, Any]:
        incident = self._require_active()
        self._require_authorization(authorization, "collect_evidence", incident=incident)
        payload: dict[str, Any] = {
            "schema_version": 1, "incident_id": incident.incident_id, "collected_at": utc_now_iso(),
            "hostname": socket.gethostname(), "platform": platform.platform(),
            "collector_results": {}, "collector_errors": {},
        }
        for name, collector in sorted(self.snapshot_collectors.items()):
            try:
                payload["collector_results"][name] = collector()
            except Exception as exc:  # evidence gaps must be explicit
                payload["collector_errors"][name] = {"error_type": type(exc).__name__, "message": str(exc)}
        encoded = json.dumps(payload, sort_keys=True, indent=2, default=str).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        self.evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination = self.evidence_dir / f"{incident.incident_id}-snapshot.json"
        fd, temporary_name = tempfile.mkstemp(prefix=".emergency-", dir=self.evidence_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary_name, destination)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        incident.evidence_bundle, incident.evidence_sha256 = str(destination), digest
        self._save(incident)
        result = {"path": str(destination), "sha256": digest, "collector_errors": payload["collector_errors"]}
        self._audit(incident, authorization, "emergency_evidence_collected", "partial" if payload["collector_errors"] else "success", "Emergency snapshot preserved.", evidence=result)
        return result

    def restrict_network(self, authorization: AuthorizationContext, adapter: NetworkContainmentAdapter, *, preserve_management: bool = True) -> dict[str, Any]:
        incident = self._require_active()
        self._require_authorization(authorization, "restrict_network", incident=incident)
        self._require_evidence(incident)
        result = adapter.restrict(incident.incident_id, preserve_management=preserve_management)
        if not result.get("success"):
            self._audit(incident, authorization, "emergency_network_restriction", "failed", "Network restriction failed safely.", evidence=result)
            raise EmergencyResponseError(str(result.get("error") or "Network restriction was not verified."))
        incident.network_state = {"previous": result.get("previous_state", {}), "current": result.get("current_state", {})}
        incident.state, incident.containment_status = ResponseState.CONTAINMENT_ACTIVE.value, "network_restricted"
        self._save(incident)
        self._audit(incident, authorization, "emergency_network_restriction", "success", "Reversible network restriction applied.", evidence=result)
        return result

    def contain_process(self, authorization: AuthorizationContext, adapter: ProcessContainmentAdapter, process_identity: dict[str, Any], *, confidence_score: int, terminate: bool = False) -> dict[str, Any]:
        incident = self._require_active()
        self._require_authorization(authorization, "contain_process", incident=incident)
        self._require_evidence(incident)
        required = {"pid", "executable_path", "sha256", "process_start_time"}
        if confidence_score < 80 or not required.issubset(k for k, value in process_identity.items() if value not in {None, ""}):
            self._audit(incident, authorization, "emergency_process_containment", "blocked", "Process response lacked confidence or stable identity.", evidence={"confidence_score": confidence_score})
            raise EmergencyResponseError("Process containment requires confidence >= 80 and stable identity evidence.")
        result = adapter.contain(incident.incident_id, process_identity, terminate=terminate)
        self._audit(incident, authorization, "emergency_process_containment", "success" if result.get("success") else "failed", "Authorized process response requested.", affected_processes=[process_identity], evidence=result)
        if not result.get("success"):
            raise EmergencyResponseError(str(result.get("error") or "Process containment was not verified."))
        incident.state, incident.containment_status = ResponseState.CONTAINMENT_ACTIVE.value, "process_contained"
        self._save(incident)
        return result

    def enter_recovery(self, authorization: AuthorizationContext, reason: str) -> EmergencyIncident:
        incident = self._require_active()
        self._require_authorization(authorization, "enter_recovery", incident=incident)
        self._require_evidence(incident)
        incident.state = ResponseState.RECOVERY_MODE.value
        self._save(incident); self._audit(incident, authorization, "emergency_recovery_started", "success", reason)
        return incident

    def exit(self, authorization: AuthorizationContext, reason: str, *, network_adapter: NetworkContainmentAdapter | None = None) -> EmergencyIncident:
        incident = self._require_active()
        self._require_authorization(authorization, "exit", incident=incident)
        self._require_evidence(incident)
        if incident.network_state:
            if network_adapter is None:
                raise EmergencyResponseError("Network restoration must be verified before emergency mode can exit.")
            restored = network_adapter.restore(incident.incident_id, dict(incident.network_state.get("previous", {})))
            if not restored.get("success"):
                self._audit(incident, authorization, "emergency_network_restore", "failed", "Network restoration failed; emergency mode remains active.", evidence=restored)
                raise EmergencyResponseError("Network restoration was not verified.")
            incident.network_state = {}
        incident.state, incident.containment_status = ResponseState.NORMAL.value, "released"
        self._save(incident); self._audit(incident, authorization, "emergency_mode_exited", "success", reason)
        return incident

    def timeline(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        try:
            rows = json.loads(self.store.get_background_monitor_state(TIMELINE_KEY, "[]"))
        except json.JSONDecodeError as exc:
            raise EmergencyResponseError("Emergency timeline is corrupt.") from exc
        return [row for row in rows if not incident_id or row.get("incident_id") == incident_id]

    def export_timeline(self, destination: Path, incident_id: str) -> Path:
        rows = self.timeline(incident_id)
        destination.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps({"incident_id": incident_id, "events": rows}, indent=2, sort_keys=True).encode()
        destination.write_bytes(encoded); destination.chmod(0o600)
        return destination

    def _require_active(self) -> EmergencyIncident:
        incident = self.current()
        if incident is None or incident.state == ResponseState.NORMAL.value:
            raise EmergencyResponseError("Emergency response is not active.")
        return incident

    def _require_evidence(self, incident: EmergencyIncident) -> None:
        path = Path(incident.evidence_bundle) if incident.evidence_bundle else None
        if path is None or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != incident.evidence_sha256:
            raise EmergencyResponseError("Verified emergency evidence is required before containment or recovery.")

    def _require_authorization(self, authorization: AuthorizationContext, action: str, *, incident: EmergencyIncident | None = None, reason: str = "") -> None:
        if authorization.valid():
            return
        target = incident or EmergencyIncident("unassigned", ResponseState.NORMAL.value, "critical", reason, utc_now_iso(), authorization.username or "unknown", authorization.authorization_source or "unknown")
        self._audit(target, authorization, "unauthorized_emergency_action", "blocked", f"Unauthorized emergency action blocked: {action}")
        raise EmergencyResponseError("Valid time-limited administrator authorization is required.")

    def _save(self, incident: EmergencyIncident) -> None:
        self.store.set_background_monitor_state(STATE_KEY, json.dumps(incident.to_dict(), sort_keys=True))

    def _audit(self, incident: EmergencyIncident, authorization: AuthorizationContext, action: str, result: str, reason: str, **extra: Any) -> None:
        timestamp = utc_now_iso()
        metadata = {
            "hostname": socket.gethostname(), "username": authorization.username or "unknown", "action": action,
            "reason": reason, "authorization_source": authorization.authorization_source or "unknown",
            "incident_id": incident.incident_id, "affected_processes": extra.get("affected_processes", []),
            "affected_files": extra.get("affected_files", []), "network_state": incident.network_state,
            "evidence_bundle": incident.evidence_bundle, "severity": "critical" if action in {"unauthorized_emergency_action", "emergency_mode_activated"} else "high",
            "status": incident.state, "result": result, "analyst_notes": incident.analyst_notes,
            "evidence": extra.get("evidence", {}), "security_score_impact": -50 if action in {"unauthorized_emergency_action", "emergency_mode_activated"} else -30,
            "recommended_action": "Preserve evidence, validate authorization, and follow the approved incident response plan.",
        }
        event = BackgroundMonitorEvent(
            event_id=f"emergency-{uuid4().hex}", timestamp=timestamp, event_type=action,
            severity=metadata["severity"], source="emergency_response", evidence=reason,
            confidence="high", recommendation=metadata["recommended_action"], metadata_json=json.dumps(metadata, sort_keys=True),
            related_user=authorization.username, correlation_id=incident.incident_id,
        )
        self.store.record_background_monitor_event(event, dedupe_window_seconds=0)
        try:
            rows = json.loads(self.store.get_background_monitor_state(TIMELINE_KEY, "[]"))
        except json.JSONDecodeError:
            rows = []
        rows.append({"event_id": event.event_id, "timestamp": timestamp, **metadata})
        self.store.set_background_monitor_state(TIMELINE_KEY, json.dumps(rows[-5000:], sort_keys=True))


__all__ = ["AuthorizationContext", "EmergencyIncident", "EmergencyResponseError", "EmergencyResponseManager", "ResponseState"]
