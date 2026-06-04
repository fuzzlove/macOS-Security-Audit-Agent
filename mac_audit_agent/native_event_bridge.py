from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
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
}


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
    pid: int | None = None
    parent_pid: int | None = None
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
            pid=payload.get("pid"),
            parent_pid=payload.get("parent_pid"),
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
        "launchdaemon_added",
        "login_item_added",
    }


def native_event_frame_to_event(frame: NativeEventFrame) -> BackgroundMonitorEvent:
    normalized_event_type = normalize_native_event_type(frame.event_type)
    rule = rule_for_event(normalized_event_type)
    payload = dict(frame.evidence)
    raw_summary = frame.raw_signal_summary or payload.get("summary") or json.dumps(payload, sort_keys=True)
    timestamp = frame.timestamp or utc_now_iso()
    return BackgroundMonitorEvent(
        event_id=str(payload.get("event_id") or f"{normalized_event_type}-{timestamp}-{frame.source}"),
        timestamp=timestamp,
        event_type=normalized_event_type,
        severity=frame.severity,
        source=frame.source,
        process_name=frame.process_name,
        pid=frame.pid,
        evidence=raw_summary,
        confidence=frame.confidence,
        recommendation=str(payload.get("recommendation", "Review the surrounding timeline and verify whether the event was expected.")),
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
