from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.models import BackgroundMonitorEvent, InvestigationNote, ScanResult, utc_now_iso
from mac_audit_agent.storage import AuditDatabase, json_safe


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
APPLE_LEVEL_SEVERITY = {"clear": "info", "watch": "low", "elevated": "medium", "urgent": "high", "emergency": "critical"}


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    severity: str
    confidence: str
    source: str
    title: str
    summary: str
    evidence: Any = ""
    related_event_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    event_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence"] = json_safe(payload["evidence"])
        return payload


def _parse_timestamp(value: str) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _event_id(prefix: str, *parts: object) -> str:
    raw = ":".join(str(part) for part in parts if part not in (None, ""))
    return f"{prefix}:{raw}" if raw else f"{prefix}:{utc_now_iso()}"


def _severity(value: object, default: str = "info") -> str:
    text = str(value or default).lower()
    if text in SEVERITY_ORDER:
        return text
    return APPLE_LEVEL_SEVERITY.get(text, default)


def sort_timeline_events(events: list[TimelineEvent | dict[str, Any]]) -> list[TimelineEvent]:
    normalized = [event if isinstance(event, TimelineEvent) else timeline_event_from_dict(event) for event in events]
    return sorted(normalized, key=lambda event: (_parse_timestamp(event.timestamp), SEVERITY_ORDER.get(event.severity, 0), event.event_id))


def timeline_event_from_dict(payload: dict[str, Any]) -> TimelineEvent:
    return TimelineEvent(
        event_id=str(payload.get("event_id", "")),
        timestamp=str(payload.get("timestamp", "")),
        event_type=str(payload.get("event_type", "")),
        severity=str(payload.get("severity", "info")),
        confidence=str(payload.get("confidence", "medium")),
        source=str(payload.get("source", "")),
        title=str(payload.get("title", "")),
        summary=str(payload.get("summary", "")),
        evidence=payload.get("evidence", ""),
        related_event_ids=[str(item) for item in payload.get("related_event_ids", [])],
        tags=[str(item) for item in payload.get("tags", [])],
    )


def filter_timeline_events(
    events: list[TimelineEvent | dict[str, Any]],
    *,
    severity: str = "",
    category: str = "",
    source: str = "",
    search: str = "",
) -> list[TimelineEvent]:
    severity = severity.strip().lower()
    category = category.strip().lower()
    source = source.strip().lower()
    search = search.strip().lower()
    filtered: list[TimelineEvent] = []
    for event in sort_timeline_events(events):
        tags = [tag.lower() for tag in event.tags]
        haystack = " ".join(
            [
                event.event_id,
                event.timestamp,
                event.event_type,
                event.severity,
                event.confidence,
                event.source,
                event.title,
                event.summary,
                json.dumps(json_safe(event.evidence), sort_keys=True),
                " ".join(event.tags),
            ]
        ).lower()
        if severity and event.severity.lower() != severity:
            continue
        if category and category not in tags and category not in event.event_type.lower():
            continue
        if source and event.source.lower() != source:
            continue
        if search and search not in haystack:
            continue
        filtered.append(event)
    return filtered


def context_window(events: list[TimelineEvent | dict[str, Any]], event_id: str, *, minutes: int = 15) -> list[TimelineEvent]:
    sorted_events = sort_timeline_events(events)
    selected = next((event for event in sorted_events if event.event_id == event_id), None)
    if selected is None:
        return []
    selected_at = _parse_timestamp(selected.timestamp)
    start = selected_at - timedelta(minutes=minutes)
    end = selected_at + timedelta(minutes=minutes)
    return [event for event in sorted_events if start <= _parse_timestamp(event.timestamp) <= end]


def export_timeline_json(events: list[TimelineEvent | dict[str, Any]], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": utc_now_iso(),
        "timeline": [event.to_dict() for event in sort_timeline_events(events)],
    }
    output_path.write_text(json.dumps(json_safe(payload), indent=2, sort_keys=True), encoding="utf-8")
    return output_path


class SecurityTimelineBuilder:
    def __init__(self, db: AuditDatabase | None = None) -> None:
        self.db = db

    def build(
        self,
        *,
        scan_result: ScanResult | None = None,
        monitor_events: list[BackgroundMonitorEvent | dict[str, Any]] | None = None,
        baseline_drift: dict[str, Any] | None = None,
        apple_exposure: dict[str, Any] | None = None,
        evidence_snapshots: list[dict[str, Any]] | None = None,
        notes: list[InvestigationNote | dict[str, Any]] | None = None,
        alert_traces: list[Any] | None = None,
        alert_delivery_records: list[Any] | None = None,
    ) -> dict[str, Any]:
        artifacts = scan_result.collected_artifacts if scan_result is not None else {}
        baseline_drift = baseline_drift if baseline_drift is not None else artifacts.get("baseline_drift", {})
        apple_exposure = apple_exposure if apple_exposure is not None else artifacts.get("apple_security_forecast", artifacts.get("cve_radar", {}))
        evidence_snapshots = evidence_snapshots if evidence_snapshots is not None else list(artifacts.get("packet_captures", []))
        events: list[TimelineEvent] = []
        events.extend(self._scan_finding_events(scan_result))
        events.extend(self._monitor_events(monitor_events or []))
        events.extend(self._baseline_drift_events(baseline_drift or {}))
        events.extend(self._apple_exposure_events(apple_exposure or {}))
        events.extend(self._evidence_snapshot_events(evidence_snapshots or []))
        events.extend(self._note_events(notes or []))
        events.extend(self._alert_failure_events(alert_traces or [], alert_delivery_records or []))
        events = sort_timeline_events(events)
        return {
            "generated_at": utc_now_iso(),
            "event_count": len(events),
            "events": [event.to_dict() for event in events],
            "summary": self._summary(events),
        }

    def build_from_db(self, scan_result: ScanResult | None = None, *, monitor_limit: int = 1000, notes_limit: int = 1000) -> dict[str, Any]:
        monitor_events: list[BackgroundMonitorEvent] = []
        notes: list[InvestigationNote] = []
        evidence_snapshots: list[dict[str, Any]] = []
        alert_traces: list[Any] = []
        alert_delivery_records: list[Any] = []
        if self.db is not None:
            monitor_events = self.db.recent_background_monitor_events(limit=monitor_limit)
            scan_id = scan_result.scan_id if scan_result is not None else None
            notes = self.db.list_investigation_notes(linked_scan_id=scan_id, limit=notes_limit) if scan_id else self.db.list_investigation_notes(limit=notes_limit)
            evidence_snapshots = self.db.list_system_recovery_snapshots(limit=200)
            alert_traces = self.db.latest_event_alert_traces(limit=200)
            alert_delivery_records = self.db.latest_alert_delivery_records(limit=200)
        if scan_result is not None:
            evidence_snapshots.extend(scan_result.collected_artifacts.get("packet_captures", []))
        return self.build(
            scan_result=scan_result,
            monitor_events=monitor_events,
            evidence_snapshots=evidence_snapshots,
            notes=notes,
            alert_traces=alert_traces,
            alert_delivery_records=alert_delivery_records,
        )

    def _scan_finding_events(self, scan_result: ScanResult | None) -> list[TimelineEvent]:
        if scan_result is None:
            return []
        events = []
        for finding in scan_result.findings:
            payload = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
            event_id = _event_id("finding", payload.get("id") or payload.get("title"))
            events.append(
                TimelineEvent(
                    event_id=event_id,
                    timestamp=str(payload.get("timestamp") or scan_result.timestamp),
                    event_type="scan_finding",
                    severity=_severity(payload.get("severity", "info")),
                    confidence=str(payload.get("confidence", "medium")),
                    source=str(payload.get("source_detector") or payload.get("command_used") or "scan"),
                    title=str(payload.get("title", "Scan finding")),
                    summary=str(payload.get("description") or payload.get("summary") or "Scan finding recorded."),
                    evidence=payload.get("evidence", ""),
                    related_event_ids=[str(payload.get("id", ""))] if payload.get("id") else [],
                    tags=["scan", str(payload.get("category", "")).lower()],
                )
            )
        return events

    def _monitor_events(self, monitor_events: list[BackgroundMonitorEvent | dict[str, Any]]) -> list[TimelineEvent]:
        events = []
        for item in monitor_events:
            payload = item.to_dict() if hasattr(item, "to_dict") else dict(item)
            event_type = str(payload.get("event_type", "monitor_event"))
            process = str(payload.get("process_name", ""))
            events.append(
                TimelineEvent(
                    event_id=_event_id("monitor", payload.get("event_id") or event_type),
                    timestamp=str(payload.get("timestamp", "")),
                    event_type=event_type,
                    severity=_severity(payload.get("severity", "info")),
                    confidence=str(payload.get("confidence", "medium")),
                    source=str(payload.get("source", "monitor")),
                    title=event_type.replace("_", " ").title(),
                    summary=f"{process} {payload.get('recommendation', '')}".strip() or "Monitor event recorded.",
                    evidence=payload.get("evidence", ""),
                    related_event_ids=[str(payload.get("event_id", ""))] if payload.get("event_id") else [],
                    tags=["monitor", event_type.lower(), str(payload.get("source", "")).lower()],
                )
            )
        return events

    def _baseline_drift_events(self, baseline_drift: dict[str, Any]) -> list[TimelineEvent]:
        events = []
        for item in baseline_drift.get("findings", []) if isinstance(baseline_drift, dict) else []:
            if not isinstance(item, dict):
                continue
            category = str(item.get("category", "baseline"))
            change_type = str(item.get("change_type", "changed"))
            events.append(
                TimelineEvent(
                    event_id=_event_id("baseline_drift", item.get("drift_id") or category),
                    timestamp=str(item.get("last_seen") or item.get("first_seen") or utc_now_iso()),
                    event_type="baseline_drift",
                    severity=_severity(item.get("severity", "medium"), "medium"),
                    confidence=str(item.get("confidence", "medium")),
                    source="baseline_drift",
                    title=f"{category.replace('_', ' ').title()} {change_type}",
                    summary=str(item.get("why_it_matters", "Baseline drift changed; review recommended.")),
                    evidence={"previous_state": item.get("previous_state"), "current_state": item.get("current_state")},
                    related_event_ids=[str(item.get("drift_id", ""))] if item.get("drift_id") else [],
                    tags=["baseline", category, change_type],
                )
            )
        return events

    def _apple_exposure_events(self, apple_exposure: dict[str, Any]) -> list[TimelineEvent]:
        if not isinstance(apple_exposure, dict) or not apple_exposure:
            return []
        timestamp = str(apple_exposure.get("generated_at") or apple_exposure.get("timestamp") or utc_now_iso())
        events = [
            TimelineEvent(
                event_id=_event_id("apple_exposure", apple_exposure.get("generated_at") or timestamp),
                timestamp=timestamp,
                event_type="apple_exposure_assessment",
                severity=_severity(apple_exposure.get("severity") or apple_exposure.get("level") or apple_exposure.get("forecast_level") or "info"),
                confidence=str(apple_exposure.get("confidence") or apple_exposure.get("applicability_confidence") or "medium"),
                source="apple_exposure_assessment",
                title="Apple Exposure Assessment updated",
                summary=str(apple_exposure.get("summary") or "Apple exposure assessment data changed or was refreshed."),
                evidence={key: apple_exposure.get(key) for key in ("cve_count", "kev_count", "sources_used", "level", "forecast_level") if key in apple_exposure},
                tags=["apple_exposure", "vulnerability"],
            )
        ]
        cards = apple_exposure.get("display_cards") or apple_exposure.get("cards") or apple_exposure.get("alerts") or []
        for card in cards:
            if not isinstance(card, dict):
                continue
            if card.get("simulated") or str(card.get("source_mode", "")).startswith("demo"):
                continue
            if str(card.get("applicability", card.get("applicability_confidence", ""))) == "review_needed":
                continue
            family_text = " ".join(
                [
                    str(card.get("category", "")),
                    str(card.get("affected_local_product", "")),
                    " ".join(str(item) for item in card.get("affected_products", [])),
                ]
            ).lower()
            if any(platform in family_text for platform in ["ios", "iphone", "ipados", "watchos", "tvos", "visionos"]):
                continue
            cve = str(card.get("cve_id") or card.get("id") or card.get("card_id") or "")
            events.append(
                TimelineEvent(
                    event_id=_event_id("apple_exposure_item", cve or card.get("title")),
                    timestamp=str(card.get("last_modified_date") or card.get("published_date") or card.get("first_seen") or timestamp),
                    event_type="apple_exposure_item",
                    severity=_severity(card.get("severity") or card.get("risk_level") or card.get("forecast_level") or "medium", "medium"),
                    confidence=str(card.get("confidence") or card.get("applicability_confidence") or "medium"),
                    source="apple_exposure_assessment",
                    title=str(card.get("title") or cve or "Apple exposure item"),
                    summary=str(card.get("summary") or card.get("description") or "Apple exposure item recorded."),
                    evidence=card,
                    tags=["apple_exposure", "vulnerability", cve.lower()],
                )
            )
        return events

    def _evidence_snapshot_events(self, snapshots: list[dict[str, Any]]) -> list[TimelineEvent]:
        events = []
        for item in snapshots:
            if not isinstance(item, dict):
                continue
            snapshot_id = str(item.get("snapshot_id") or item.get("capture_id") or item.get("pcap_path") or item.get("snapshot_path") or "")
            events.append(
                TimelineEvent(
                    event_id=_event_id("evidence_snapshot", snapshot_id),
                    timestamp=str(item.get("created_at") or item.get("timestamp") or utc_now_iso()),
                    event_type="evidence_snapshot",
                    severity="info",
                    confidence="high",
                    source=str(item.get("source") or "evidence_snapshot"),
                    title="Evidence snapshot recorded",
                    summary=str(item.get("reason") or item.get("status") or "Evidence snapshot was preserved locally."),
                    evidence=item,
                    related_event_ids=[snapshot_id] if snapshot_id else [],
                    tags=["evidence", "snapshot"],
                )
            )
        return events

    def _note_events(self, notes: list[InvestigationNote | dict[str, Any]]) -> list[TimelineEvent]:
        events = []
        for item in notes:
            payload = item.to_dict() if hasattr(item, "to_dict") else dict(item)
            tags = [str(tag) for tag in payload.get("tags", [])]
            note_id = str(payload.get("note_id", ""))
            linked = [str(value) for value in [payload.get("linked_finding_id"), payload.get("linked_scan_id")] if value]
            events.append(
                TimelineEvent(
                    event_id=_event_id("note", note_id or payload.get("title")),
                    timestamp=str(payload.get("updated_at") or payload.get("created_at") or utc_now_iso()),
                    event_type="analyst_note",
                    severity=_severity(payload.get("priority") or "info"),
                    confidence="high",
                    source="investigation_notes",
                    title=str(payload.get("title", "Analyst note")),
                    summary=str(payload.get("body", "")),
                    evidence=payload,
                    related_event_ids=linked,
                    tags=["note", *tags],
                )
            )
        return events

    def _alert_failure_events(self, alert_traces: list[Any], alert_delivery_records: list[Any]) -> list[TimelineEvent]:
        events: list[TimelineEvent] = []
        for trace in alert_traces:
            payload = trace.to_dict() if hasattr(trace, "to_dict") else dict(trace)
            overlay_error = str(payload.get("overlay_error", ""))
            failed_queue = bool(payload.get("alert_required")) and not bool(payload.get("alert_queue_enqueued"))
            if not overlay_error and not failed_queue:
                continue
            event_id = str(payload.get("event_id") or payload.get("trace_id") or "")
            events.append(
                TimelineEvent(
                    event_id=_event_id("alert_failure", event_id),
                    timestamp=str(payload.get("overlay_dispatch_at") or payload.get("created_at") or utc_now_iso()),
                    event_type="alert_pipeline_failure",
                    severity="high" if overlay_error else "medium",
                    confidence="high",
                    source="alert_pipeline",
                    title="Alert pipeline failure",
                    summary=overlay_error or "Alert was required but was not enqueued.",
                    evidence=payload,
                    related_event_ids=[event_id] if event_id else [],
                    tags=["alert", "pipeline", "failure"],
                )
            )
        for record in alert_delivery_records:
            payload = record.to_dict() if hasattr(record, "to_dict") else dict(record)
            attempted = any(bool(payload.get(key)) for key in ("overlay_attempted", "dialog_attempted", "notification_attempted"))
            success = any(bool(payload.get(key)) for key in ("overlay_success", "dialog_success", "notification_success"))
            if not attempted or success:
                continue
            event_id = str(payload.get("event_id", ""))
            events.append(
                TimelineEvent(
                    event_id=_event_id("alert_delivery_failure", event_id),
                    timestamp=str(payload.get("updated_at") or utc_now_iso()),
                    event_type="alert_pipeline_failure",
                    severity="high",
                    confidence="high",
                    source="alert_delivery",
                    title="Alert delivery failed",
                    summary="Alert delivery was attempted but no delivery method succeeded.",
                    evidence=payload,
                    related_event_ids=[event_id] if event_id else [],
                    tags=["alert", "delivery", "failure"],
                )
            )
        return events

    def _summary(self, events: list[TimelineEvent]) -> dict[str, Any]:
        by_severity = {severity: 0 for severity in SEVERITY_ORDER}
        by_source: dict[str, int] = {}
        for event in events:
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
            by_source[event.source] = by_source.get(event.source, 0) + 1
        return {
            "by_severity": by_severity,
            "by_source": by_source,
            "first_event": events[0].timestamp if events else "",
            "last_event": events[-1].timestamp if events else "",
        }
