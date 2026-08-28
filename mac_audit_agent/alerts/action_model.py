from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.compat.enum import StrEnum


class AlertActionType(StrEnum):
    PRESERVE_EVIDENCE_SNAPSHOT = "preserve_evidence_snapshot"
    OPEN_TIMELINE = "open_timeline"
    OPEN_EVENT_DETAILS = "open_event_details"
    OPEN_FINDING = "open_finding"
    OPEN_INTEGRITY_DETAILS = "open_integrity_details"
    OPEN_NETWORK_INTELLIGENCE = "open_network_intelligence"
    OPEN_PERSISTENCE_INTELLIGENCE = "open_persistence_intelligence"
    OPEN_ROOTKIT_REVIEW = "open_rootkit_review"
    EXPORT_APPLE_EVIDENCE = "export_apple_evidence"
    ACKNOWLEDGE = "acknowledge"
    DISMISS = "dismiss"


HEADLESS_ACTIONS = {
    AlertActionType.PRESERVE_EVIDENCE_SNAPSHOT.value,
    AlertActionType.ACKNOWLEDGE.value,
    AlertActionType.DISMISS.value,
}

GUI_ACTIONS = {
    AlertActionType.OPEN_TIMELINE.value,
    AlertActionType.OPEN_EVENT_DETAILS.value,
    AlertActionType.OPEN_FINDING.value,
    AlertActionType.OPEN_INTEGRITY_DETAILS.value,
    AlertActionType.OPEN_NETWORK_INTELLIGENCE.value,
    AlertActionType.OPEN_PERSISTENCE_INTELLIGENCE.value,
    AlertActionType.OPEN_ROOTKIT_REVIEW.value,
}


@dataclass
class AlertActionRequest:
    action_type: str
    source_component: str
    event_id: str
    trace_id: str
    action_id: str = field(default_factory=lambda: f"alert-action-{uuid4()}")
    created_at: str = field(default_factory=utc_now_iso)
    finding_id: str = ""
    scan_id: str = ""
    assessment_id: str = ""
    severity: str = ""
    category: str = ""
    title: str = ""
    summary: str = ""
    source_db_path: str = ""
    timeline_focus_time: str = ""
    requested_by_user: bool = True
    requires_main_gui: bool = False
    can_run_headless: bool = False
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    error: str = ""
    result: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.action_type = str(self.action_type)
        if not self.requires_main_gui:
            self.requires_main_gui = self.action_type in GUI_ACTIONS
        if not self.can_run_headless:
            self.can_run_headless = self.action_type in HEADLESS_ACTIONS

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AlertActionRequest":
        data = dict(payload)
        data["payload"] = data.get("payload") if isinstance(data.get("payload"), dict) else {}
        data["result"] = data.get("result") if isinstance(data.get("result"), dict) else {}
        return cls(**{key: value for key, value in data.items() if key in cls.__dataclass_fields__})

    @classmethod
    def from_json(cls, raw: str) -> "AlertActionRequest":
        return cls.from_dict(json.loads(raw))


@dataclass
class AlertActionResult:
    action_id: str
    action_type: str
    event_id: str
    trace_id: str
    status: str
    started_at: str = ""
    completed_at: str = field(default_factory=utc_now_iso)
    artifact_paths: list[str] = field(default_factory=list)
    opened_route: dict[str, Any] | None = None
    failure_stage: str = ""
    user_message: str = ""
    diagnostic_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AlertActionResult":
        return cls(**{key: value for key, value in dict(payload).items() if key in cls.__dataclass_fields__})


def request_from_alert_payload(
    payload: dict[str, Any],
    action_type: str,
    *,
    source_component: str,
    source_db_path: str = "",
) -> AlertActionRequest:
    event_id = str(payload.get("event_id") or payload.get("background_event_id") or payload.get("monitor_event_id") or "")
    trace_id = str(payload.get("trace_id") or payload.get("alert_trace_id") or payload.get("visible_alert_id") or "")
    return AlertActionRequest(
        action_type=action_type,
        source_component=source_component,
        event_id=event_id,
        trace_id=trace_id,
        finding_id=str(payload.get("finding_id") or ""),
        scan_id=str(payload.get("scan_id") or ""),
        assessment_id=str(payload.get("assessment_id") or ""),
        severity=str(payload.get("severity") or ""),
        category=str(payload.get("category") or payload.get("event_type") or ""),
        title=str(payload.get("title") or ""),
        summary=str(payload.get("summary") or payload.get("details") or payload.get("evidence") or ""),
        source_db_path=source_db_path or str(payload.get("source_db_path") or payload.get("db_path") or ""),
        timeline_focus_time=str(payload.get("timestamp") or payload.get("focus_time") or ""),
        requested_by_user=True,
        payload={key: value for key, value in payload.items() if key not in {"secret", "password", "token"}},
    )
