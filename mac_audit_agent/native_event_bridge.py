from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.process_explorer import redact_environment
from mac_audit_agent.rules import canonical_event_type, correlation_id_for, evidence_hash, normalized_signal, rule_for_event


NATIVE_EVENT_LOG_ENV = "MAC_AUDIT_AGENT_NATIVE_EVENT_LOG"
DEFAULT_NATIVE_EVENT_LOG = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "native_events.jsonl"
NATIVE_EVENT_TYPE_ALIASES = {
    "lid_state_open": "lid_opened",
    "lid_state_closed": "lid_closed",
    "clamshell_opened": "lid_opened",
    "clamshell_closed": "lid_closed",
    "display_turned_on": "display_wake",
    "display_turned_off": "display_sleep",
    "mouse_activity_detected": "mouse_or_keyboard_activity_after_idle",
    "keyboard_activity_detected": "mouse_or_keyboard_activity_after_idle",
    "trackpad_activity_detected": "mouse_or_keyboard_activity_after_idle",
    "input_activity_after_idle": "mouse_or_keyboard_activity_after_idle",
    "hid_activity_after_idle": "mouse_or_keyboard_activity_after_idle",
    "usb_inventory_changed": "usb_device_connected",
    "bluetooth_inventory_changed": "bluetooth_device_connected",
    "camera_on": "camera_activity_confirmed",
    "camera_started": "camera_activity_confirmed",
    "video_capture_started": "camera_activity_confirmed",
    "camera_off": "camera_activity_stopped",
    "camera_stopped": "camera_activity_stopped",
    "video_capture_stopped": "camera_activity_stopped",
    "mic_on": "microphone_activity_confirmed",
    "microphone_on": "microphone_activity_confirmed",
    "microphone_started": "microphone_activity_confirmed",
    "audio_capture_started": "microphone_activity_confirmed",
    "mic_off": "microphone_activity_stopped",
    "microphone_off": "microphone_activity_stopped",
    "microphone_stopped": "microphone_activity_stopped",
    "audio_capture_stopped": "microphone_activity_stopped",
    "av_device_connected": "capture_device_connected",
    "av_device_disconnected": "capture_device_disconnected",
    "keyboard_event_tap_added": "possible_keylogger_detected",
    "key_event_tap_added": "possible_keylogger_detected",
    "dylib_loaded_from_shadowed_rpath": "dylib_hijack_detected",
    "suspicious_dylib_loaded": "dylib_hijack_detected",
    "kernel_extension_loaded": "suspicious_kernel_extension_detected",
    "kext_loaded": "suspicious_kernel_extension_detected",
}

AV_START_EVENTS = {"camera_activity_confirmed", "microphone_activity_confirmed"}
AV_STOP_EVENTS = {"camera_activity_stopped", "microphone_activity_stopped"}


@dataclass
class NativeEventFrame:
    event_type: str
    source: str
    timestamp: str = field(default_factory=utc_now_iso)
    confidence: str = "medium"
    severity: str = "info"
    evidence: dict[str, Any] = field(default_factory=dict)
    previous_state: str = ""
    current_state: str = ""
    related_process: str = ""
    related_path: str = ""
    related_user: str = ""
    related_network_endpoint: str = ""
    related_url: str = ""
    related_dom_selector: str = ""
    related_file_hash: str = ""
    process_name: str = ""
    process_arguments: list[str] = field(default_factory=list)
    process_ancestry: list[dict[str, Any]] = field(default_factory=list)
    process_signing_id: str = ""
    process_team_id: str = ""
    process_platform_binary: bool = False
    pid: int | None = None
    parent_pid: int | None = None
    responsible_pid: int | None = None
    uid: int | None = None
    architecture: str = "unknown"
    code_signing_flags: int | None = None
    cdhash: str = ""
    environment: dict[str, str] = field(default_factory=dict)
    rule_id: str = ""
    rule_name: str = ""
    trigger_subsource: str = ""
    raw_signal_summary: str = ""
    note: str = ""

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "NativeEventFrame":
        evidence = payload.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {"value": str(evidence)}
        return cls(
            event_type=str(payload.get("event_type", "")),
            source=str(payload.get("source", "native_helper")),
            timestamp=str(payload.get("timestamp", utc_now_iso())),
            confidence=str(payload.get("confidence", "medium")),
            severity=str(payload.get("severity", "info")),
            evidence=evidence,
            previous_state=str(payload.get("previous_state", "")),
            current_state=str(payload.get("current_state", "")),
            related_process=str(payload.get("related_process", payload.get("process_name", ""))),
            related_path=str(payload.get("related_path", "")),
            related_user=str(payload.get("related_user", "")),
            related_network_endpoint=str(payload.get("related_network_endpoint", "")),
            related_url=str(payload.get("related_url", "")),
            related_dom_selector=str(payload.get("related_dom_selector", "")),
            related_file_hash=str(payload.get("related_file_hash", "")),
            process_name=str(payload.get("process_name", "")),
            process_arguments=[str(value) for value in payload.get("process_arguments", payload.get("arguments", []))[:64]] if isinstance(payload.get("process_arguments", payload.get("arguments", [])), list) else [],
            process_ancestry=[dict(value) for value in payload.get("process_ancestry", payload.get("ancestors", []))[:32] if isinstance(value, dict)] if isinstance(payload.get("process_ancestry", payload.get("ancestors", [])), list) else [],
            process_signing_id=str(payload.get("process_signing_id", payload.get("signing_id", ""))),
            process_team_id=str(payload.get("process_team_id", payload.get("team_id", ""))),
            process_platform_binary=bool(payload.get("process_platform_binary", payload.get("platform_binary", False))),
            pid=payload.get("pid"),
            parent_pid=payload.get("parent_pid"),
            responsible_pid=payload.get("responsible_pid", payload.get("rpid")),
            uid=payload.get("uid"),
            architecture=str(payload.get("architecture", "unknown")),
            code_signing_flags=payload.get("code_signing_flags", payload.get("cs_flags")),
            cdhash=str(payload.get("cdhash", "")),
            environment=redact_environment(payload.get("environment", {})) if isinstance(payload.get("environment", {}), dict) else {},
            rule_id=str(payload.get("rule_id", "")),
            rule_name=str(payload.get("rule_name", "")),
            trigger_subsource=str(payload.get("trigger_subsource", payload.get("subsource", "native_event"))),
            raw_signal_summary=str(payload.get("raw_signal_summary", "")),
            note=str(payload.get("note", "")),
        )


def normalize_native_event_type(event_type: str) -> str:
    canonical = canonical_event_type(str(event_type or "").strip())
    return NATIVE_EVENT_TYPE_ALIASES.get(canonical, canonical)


def native_event_log_path() -> Path:
    return Path(os.environ.get(NATIVE_EVENT_LOG_ENV, str(DEFAULT_NATIVE_EVENT_LOG))).expanduser()


def native_event_supported_types() -> set[str]:
    return {
        "lid_opened",
        "lid_closed",
        "display_wake",
        "display_sleep",
        "screen_locked",
        "screen_unlocked",
        "idle_resume_detected",
        "mouse_or_keyboard_activity_after_idle",
        "usb_device_connected",
        "usb_device_removed",
        "new_usb_device_detected",
        "bluetooth_device_connected",
        "bluetooth_device_disconnected",
        "bluetooth_inventory_changed",
        "unknown_hid_device_detected",
        "launchagent_added",
        "launchagent_modified",
        "launchagent_removed",
        "launchdaemon_added",
        "launchdaemon_modified",
        "launchdaemon_removed",
        "login_item_added",
        "persistence_artifact_added",
        "persistence_artifact_modified",
        "persistence_artifact_removed",
        "mitre_persistence_method_detected",
        "possible_shellcode_memory_detected",
        "camera_activity_confirmed",
        "camera_activity_stopped",
        "microphone_activity_confirmed",
        "microphone_activity_stopped",
        "capture_device_connected",
        "capture_device_disconnected",
        "possible_keylogger_detected",
        "dylib_hijack_detected",
        "suspicious_kernel_extension_detected",
    }


def native_event_frame_to_event(frame: NativeEventFrame) -> BackgroundMonitorEvent:
    normalized_event_type = normalize_native_event_type(frame.event_type)
    rule = rule_for_event(normalized_event_type)
    payload = dict(frame.evidence)
    payload.update({
        "process_arguments": frame.process_arguments,
        "process_ancestry": frame.process_ancestry,
        "process_signing_id": frame.process_signing_id,
        "process_team_id": frame.process_team_id,
        "process_platform_binary": frame.process_platform_binary,
        "responsible_pid": frame.responsible_pid,
        "uid": frame.uid,
        "architecture": frame.architecture,
        "code_signing_flags": frame.code_signing_flags,
        "cdhash": frame.cdhash,
        "environment": frame.environment,
    })
    raw_summary = frame.raw_signal_summary or payload.get("summary") or json.dumps(payload, sort_keys=True)
    timestamp = frame.timestamp or utc_now_iso()
    severity = frame.severity
    confidence = frame.confidence
    recommendation = str(payload.get("recommendation", "Review the surrounding timeline and verify whether the event was expected."))
    if normalized_event_type in AV_START_EVENTS:
        # A device-state transition is useful evidence even when process attribution
        # arrives later. Session context raises urgency without claiming attribution.
        if severity in {"info", "low"}:
            severity = "high"
        if bool(payload.get("screen_locked") or payload.get("session_locked") or payload.get("after_idle")):
            severity = "critical"
            payload["suspicious_context"] = "capture began while the session was locked or idle"
        if not (frame.pid or frame.process_name or frame.related_process):
            payload["attribution_status"] = "unattributed"
            confidence = "medium" if confidence == "high" else confidence
        else:
            payload["attribution_status"] = "attributed"
        recommendation = str(payload.get("recommendation", "Confirm the capture was expected; review the process identity, signing details, and nearby session events."))
    elif normalized_event_type in AV_STOP_EVENTS:
        severity = "info" if severity in {"info", "low"} else severity
        recommendation = str(payload.get("recommendation", "Correlate this stop transition with the expected application lifecycle and its matching start event."))
    elif normalized_event_type == "capture_device_connected":
        severity = "high" if bool(payload.get("external") or payload.get("virtual") or payload.get("first_seen")) else "medium"
        recommendation = str(payload.get("recommendation", "Confirm the new camera or microphone is authorized, especially if it is external or virtual."))
    return BackgroundMonitorEvent(
        event_id=str(payload.get("event_id") or f"{normalized_event_type}-{timestamp}-{frame.source}"),
        timestamp=timestamp,
        event_type=normalized_event_type,
        severity=severity,
        source=frame.source,
        process_name=frame.process_name,
        pid=frame.pid,
        evidence=raw_summary,
        confidence=confidence,
        recommendation=recommendation,
        simulated=bool(payload.get("simulated", False)),
        notification_sent=False,
        notification_error="",
        notification_returncode=None,
        notification_decision="log_only",
        notification_reason="native_helper",
        cooldown_remaining_seconds=0,
        popup_allowed=False,
        visible_alert_shown=False,
        alert_style="neutral_grey",
        cooldown_suppressed=False,
        last_suppression_reason="",
        metadata_json=json.dumps(payload, sort_keys=True),
        rule_id=frame.rule_id or rule.rule_id,
        rule_name=frame.rule_name or rule.name,
        trigger_source="native_event_helper",
        trigger_subsource=frame.trigger_subsource or frame.source,
        trigger_rule_id=frame.rule_id or rule.rule_id,
        trigger_rule_name=frame.rule_name or rule.name,
        raw_signal_summary=raw_summary,
        normalized_signal=normalized_signal(normalized_event_type, raw_summary, payload),
        evidence_hash=evidence_hash(normalized_event_type, raw_summary, payload),
        related_process=frame.related_process or frame.process_name,
        related_pid=frame.pid,
        related_parent_pid=frame.parent_pid,
        related_path=frame.related_path,
        related_user=frame.related_user,
        related_network_endpoint=frame.related_network_endpoint,
        related_url=frame.related_url,
        related_dom_selector=frame.related_dom_selector,
        related_file_hash=frame.related_file_hash,
        first_seen=timestamp,
        last_seen=timestamp,
        previous_state=frame.previous_state,
        current_state=frame.current_state,
        baseline_status="native helper event",
        correlation_id=correlation_id_for(normalized_event_type, frame.source, frame.related_process or frame.process_name, frame.related_path, frame.related_user, timestamp=timestamp),
        false_positive_hints=list(rule.false_positive_hints),
        recommended_verification_steps=list(rule.verification_steps),
        source_trace=f"Native helper source={frame.source}; rule={rule.rule_id}; evidence={raw_summary}",
    )


def parse_native_event_line(line: str) -> NativeEventFrame | None:
    raw = line.strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return NativeEventFrame.from_payload(payload)


class NativeEventBridge:
    def __init__(self, db, event_log_path: Path | None = None) -> None:
        self.db = db
        self.event_log_path = event_log_path or native_event_log_path()
        self.offset_state_key = "native_event_bridge_offset"

    def available(self) -> bool:
        return self.event_log_path.exists()

    def drain(self, limit: int = 100) -> list[BackgroundMonitorEvent]:
        if not self.event_log_path.exists():
            return []
        offset = 0
        try:
            offset = int(self.db.get_background_monitor_state(self.offset_state_key, "0") or "0")
        except ValueError:
            offset = 0
        events: list[BackgroundMonitorEvent] = []
        try:
            with self.event_log_path.open("r", encoding="utf-8") as handle:
                if offset > 0:
                    handle.seek(offset)
                start_offset = handle.tell()
                for _index, line in enumerate(handle):
                    frame = parse_native_event_line(line)
                    if frame is None:
                        continue
                    event = native_event_frame_to_event(frame)
                    events.append(event)
                    if len(events) >= limit:
                        break
                end_offset = handle.tell()
        except OSError:
            return []
        if end_offset != start_offset:
            try:
                self.db.set_background_monitor_state(self.offset_state_key, str(end_offset))
            except Exception:
                pass
        return events
