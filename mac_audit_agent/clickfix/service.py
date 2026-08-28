from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from .evidence import ClickFixEvidenceStore
from .models import Classification, ClickFixIncident, ClickFixShortcutEvent
from .policy import ClickFixPolicy

MEDIUM_TITLE = "Spotlight Keyboard Shortcut Detected"
MEDIUM_MESSAGE = ("Command + Space was pressed. MSAA inspected the current clipboard for\n"
                  "command or script content associated with ClickFix social-engineering\n"
                  "activity. No command-like clipboard content was identified.")
CRITICAL_TITLE = "Potential ClickFix Command Detected"
CRITICAL_MESSAGE = ("Command or script content was present on the clipboard when Command +\n"
                    "Space was pressed. Do not paste or execute the clipboard contents.\n\n"
                    "MSAA has recorded this event as a potential ClickFix social-engineering\n"
                    "incident. Review the evidence and contact the appropriate security or\n"
                    "incident-response team.")
UNAVAILABLE_TITLE = "ClickFix Clipboard Inspection Unavailable"
UNAVAILABLE_MESSAGE = ("Command + Space was pressed, but MSAA could not inspect the clipboard\n"
                       "because the required clipboard or privacy permission was unavailable.\n"
                       "The clipboard safety state is unknown.")
RISKY = frozenset(item.value for item in (
    Classification.COMMAND_LIKE, Classification.SCRIPT_LIKE, Classification.ENCODED_COMMAND,
    Classification.DOWNLOAD_AND_EXECUTE, Classification.SECURITY_IMPAIRMENT,
    Classification.CREDENTIAL_ACCESS, Classification.PERSISTENCE_COMMAND,
    Classification.POTENTIAL_CLICKFIX,
))


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def _risk(classification: str) -> float:
    if classification in {Classification.SECURITY_IMPAIRMENT.value, Classification.CREDENTIAL_ACCESS.value}: return 10.0
    if classification == Classification.ENCODED_COMMAND.value: return 9.9
    if classification == Classification.DOWNLOAD_AND_EXECUTE.value: return 9.8
    if classification in {Classification.COMMAND_LIKE.value, Classification.SCRIPT_LIKE.value}: return 9.5
    if classification == Classification.SOURCE_CODE_FRAGMENT.value: return 9.0
    if classification == Classification.CLASSIFICATION_FAILED.value: return 7.5
    return 5.0


class ClickFixService:
    """Validates native envelopes and atomically persists pre-continuation decisions."""

    def __init__(self, store: ClickFixEvidenceStore, policy: ClickFixPolicy) -> None:
        self.store = store
        self.policy = policy
        self.active_incidents: dict[str, datetime] = {}

    def ingest_shortcut(self, envelope: dict[str, Any]) -> dict[str, Any]:
        if int(envelope.get("schema_version", 0)) != 1:
            raise ValueError("CFX012_XPC_AUTHENTICATION_FAILED: unsupported protocol")
        if len(json.dumps(envelope, ensure_ascii=True)) > 256 * 1024:
            raise ValueError("CFX012_XPC_AUTHENTICATION_FAILED: envelope too large")
        if bool(envelope.get("replay_event")):
            return {"accepted": False, "reason": "synthetic replay ignored", "replay_shortcut": False}
        event_id = str(envelope.get("event_id") or "cfx-event-" + uuid4().hex)
        classification = str(envelope.get("clipboard_classification") or Classification.CLASSIFICATION_FAILED.value)
        access_state = str(envelope.get("clipboard_access_state") or "CLIPBOARD_ACCESS_UNKNOWN")
        unavailable = access_state not in {"CLIPBOARD_ACCESS_GRANTED"} or classification == Classification.CLASSIFICATION_FAILED.value
        risky = classification in RISKY and not unavailable
        severity = "high" if unavailable else "medium"
        score = 7.5 if unavailable else 5.0
        detected = _parse_time(envelope.get("detected_at_utc"))
        event = ClickFixShortcutEvent(
            event_id=event_id, schema_version=1, detected_at_utc=detected,
            monotonic_timestamp_ns=int(envelope.get("monotonic_timestamp_ns") or time.monotonic_ns()),
            key_code=int(envelope.get("key_code", 49)), modifier_flags=int(envelope.get("modifier_flags", 0)),
            physical_event=bool(envelope.get("physical_event", True)), replay_event=False,
            foreground_pid=envelope.get("foreground_pid"), foreground_bundle_id=envelope.get("foreground_bundle_id"),
            foreground_signing_identifier=envelope.get("foreground_signing_identifier"),
            foreground_team_identifier=envelope.get("foreground_team_identifier"), audit_session_id=envelope.get("audit_session_id"),
            console_user=envelope.get("console_user"), display_session=envelope.get("display_session"),
            clipboard_change_count=envelope.get("clipboard_change_count"), clipboard_access_state=access_state,
            clipboard_classification=classification, clipboard_sha256=envelope.get("clipboard_sha256"),
            clipboard_byte_length=envelope.get("clipboard_byte_length"), classifier_version=envelope.get("classifier_version"),
            msaa_incident_risk_score=score, severity=severity, sensor_mode=str(envelope.get("sensor_mode", "OBSERVE")),
            input_monitoring_state=str(envelope.get("input_monitoring_state", "INPUT_MONITORING_UNKNOWN")),
            accessibility_state=str(envelope.get("accessibility_state", "ACCESSIBILITY_UNKNOWN")),
            persisted_at_utc=datetime.now(timezone.utc), integrity_digest="",
            spotlight_suppressed=bool(envelope.get("spotlight_suppressed", False)),
            missing_telemetry=tuple(str(item) for item in envelope.get("missing_telemetry", ())),
        )
        # Command+Space is a correlation signal, not an alert by itself. Clean
        # clipboard content and unavailable inspection remain auditable without
        # interrupting the user on every Spotlight invocation.
        alerts = []
        incident: Optional[ClickFixIncident] = None
        if risky:
            incident_id = str(envelope.get("incident_id") or "cfx-incident-" + uuid4().hex)
            score = _risk(classification)
            event = ClickFixShortcutEvent(**{**event.__dict__, "msaa_incident_risk_score": 5.0})
            incident = ClickFixIncident(
                incident_id=incident_id, shortcut_event_id=event_id, disposition="POTENTIAL_CLICKFIX",
                created_at_utc=detected, first_seen_utc=detected, last_seen_utc=detected,
                severity="critical", risk_score=score, confidence=float(envelope.get("confidence", 0.8)),
                command_categories=tuple(str(item) for item in envelope.get("matched_categories", ())),
                attack_mappings=("T1204.004",), clipboard_quarantined=bool(envelope.get("clipboard_quarantined", False)),
                spotlight_suppressed=bool(envelope.get("spotlight_suppressed", False)), terminal_launch_observed=False,
                follow_on_execution_observed=False, containment_status="NOT_REQUESTED", acknowledgment_status="UNACKNOWLEDGED",
                integrity_digest="",
            )
            alerts.append(self._alert(event_id, incident_id, "critical", CRITICAL_TITLE, CRITICAL_MESSAGE, True, envelope))
            self.active_incidents[incident_id] = detected + timedelta(seconds=self.policy.correlation_window_seconds)
        stored_event, stored_incident = self.store.persist_detection(event, incident, tuple(alerts))
        fail_closed = unavailable and self.policy.fail_closed
        replay = self.policy.protect and not risky and not fail_closed
        return {
            "accepted": True, "event_id": stored_event.event_id,
            "incident_id": stored_incident.incident_id if stored_incident else None,
            "persisted": True, "replay_shortcut": replay,
            "suppress_shortcut": bool(self.policy.protect and (risky or fail_closed)),
            "quarantine_clipboard": bool(risky and self.policy.clipboard_quarantine),
            "native_notification_required": bool(risky and self.policy.notification_enabled),
            "native_notification_status": "native_agent_pending" if risky and self.policy.notification_enabled else "not_requested",
            "disposition": "POTENTIAL_CLICKFIX" if risky else "INSPECTION_UNAVAILABLE" if unavailable else "NONE",
        }

    def _alert(self, event_id: str, incident_id: Optional[str], severity: str, title: str, message: str, persistent: bool, envelope: dict[str, Any]) -> dict[str, Any]:
        if bool(envelope.get("test_event")):
            title = "SYNTHETIC CLICKFIX TEST — NO REAL INCIDENT DETECTED"
            message = "SYNTHETIC CLICKFIX TEST — NO REAL INCIDENT DETECTED\n\n" + message
        return {
            "alert_id": "cfx-alert-" + uuid4().hex, "event_id": event_id, "incident_id": incident_id,
            "severity": severity, "title": title, "message": message, "description": message,
            "persistent": persistent, "timestamp": str(envelope.get("detected_at_utc") or datetime.now(timezone.utc).isoformat()),
            "foreground_application": envelope.get("foreground_bundle_id"),
            "clipboard_classification": envelope.get("clipboard_classification"),
            "clipboard_sha256": envelope.get("clipboard_sha256"), "redacted_preview": envelope.get("redacted_preview"),
            "risk_categories": list(envelope.get("matched_categories", ())), "attack_mapping": "T1204.004",
            "sensor_confidence": envelope.get("confidence"), "permission_state": {
                "input_monitoring": envelope.get("input_monitoring_state"), "accessibility": envelope.get("accessibility_state"),
                "clipboard": envelope.get("clipboard_access_state")},
            "spotlight_suppressed": bool(envelope.get("spotlight_suppressed")),
            "clipboard_quarantined": bool(envelope.get("clipboard_quarantined")), "terminal_execution_observed": False,
            "disposition": "POTENTIAL_CLICKFIX" if severity == "critical" else "SHORTCUT_AUDIT",
        }

    def correlate_process(self, *, occurred_at: datetime, audit_session_id: Optional[int], process: str, categories: tuple[str, ...]) -> list[str]:
        now = occurred_at.astimezone(timezone.utc); escalated = []
        relevant = process.lower() in {"terminal", "iterm2", "warp", "alacritty", "kitty", "wezterm", "bash", "zsh", "sh", "osascript", "python", "python3"} or bool(categories)
        if not relevant: return escalated
        for incident_id, expires in list(self.active_incidents.items()):
            if now > expires:
                del self.active_incidents[incident_id]; continue
            record_id = "cfx-correlation-" + uuid4().hex
            self.store.append_auxiliary(record_id, "correlation", {"incident_id": incident_id, "occurred_at": now.isoformat(), "audit_session_id": audit_session_id, "process": process, "categories": categories, "disposition": "POTENTIAL_CLICKFIX_EXECUTION_CHAIN"})
            escalated.append(incident_id)
        return escalated
