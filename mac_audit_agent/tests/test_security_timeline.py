from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.models import BackgroundMonitorEvent, Finding, InvestigationNote, ScanResult
from mac_audit_agent.reporting import export_scan_result_json
from mac_audit_agent.security_timeline import SecurityTimelineBuilder, export_timeline_json, filter_timeline_events, sort_timeline_events


def test_events_sort_correctly() -> None:
    events = [
        {"event_id": "late", "timestamp": "2026-06-27T12:10:00+00:00", "event_type": "note", "severity": "low", "confidence": "high", "source": "test", "title": "Late", "summary": "", "evidence": "", "related_event_ids": [], "tags": []},
        {"event_id": "early", "timestamp": "2026-06-27T12:00:00+00:00", "event_type": "finding", "severity": "high", "confidence": "high", "source": "test", "title": "Early", "summary": "", "evidence": "", "related_event_ids": [], "tags": []},
    ]

    sorted_events = sort_timeline_events(events)

    assert [event.event_id for event in sorted_events] == ["early", "late"]


def test_timeline_includes_notes() -> None:
    note = InvestigationNote(
        note_id="note-1",
        created_at="2026-06-27T12:00:00+00:00",
        updated_at="2026-06-27T12:05:00+00:00",
        title="Analyst observation",
        body="User confirmed this was expected maintenance.",
        tags=["timeline", "maintenance"],
        linked_scan_id="scan-1",
    )

    timeline = SecurityTimelineBuilder().build(notes=[note])

    assert timeline["event_count"] == 1
    assert timeline["events"][0]["event_type"] == "analyst_note"
    assert "maintenance" in timeline["events"][0]["tags"]


def test_filter_by_severity_works() -> None:
    monitor_events = [
        BackgroundMonitorEvent(
            event_id="event-high",
            timestamp="2026-06-27T12:00:00+00:00",
            event_type="new_listener_detected",
            severity="high",
            source="network_monitor",
            evidence="127.0.0.1:7000",
            confidence="high",
        ),
        BackgroundMonitorEvent(
            event_id="event-low",
            timestamp="2026-06-27T12:01:00+00:00",
            event_type="heartbeat",
            severity="low",
            source="monitor",
            evidence="heartbeat ok",
            confidence="high",
        ),
    ]
    timeline = SecurityTimelineBuilder().build(monitor_events=monitor_events)

    filtered = filter_timeline_events(timeline["events"], severity="high")

    assert len(filtered) == 1
    assert filtered[0].event_id == "monitor:event-high"


def test_export_includes_timeline(tmp_path: Path) -> None:
    scan_result = ScanResult(
        scan_id="scan-1",
        timestamp="2026-06-27T12:00:00+00:00",
        hostname="mac.local",
        current_user="m",
        findings=[
            Finding(
                id="finding-1",
                category="Network",
                title="Unexpected listener",
                severity="medium",
                description="A local listener was detected.",
                evidence="127.0.0.1:7000",
                command_used="lsof",
                remediation_suggestion="Verify the owning process.",
                warning="Review before changing services.",
                confidence="medium",
            )
        ],
        collected_artifacts={
            "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
            "processes": {"all": [], "suspicious": [], "errors": []},
            "localhost_scan": {},
        },
    )
    note = {
        "note_id": "note-1",
        "created_at": "2026-06-27T12:02:00+00:00",
        "updated_at": "2026-06-27T12:02:00+00:00",
        "title": "Timeline note",
        "body": "Follow-up requested.",
        "tags": ["timeline"],
        "linked_scan_id": "scan-1",
    }
    report_path = tmp_path / "report.json"
    export_path = tmp_path / "timeline.json"

    export_scan_result_json(scan_result, report_path, include_investigation_notes=True, investigation_notes=[note])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    export_timeline_json(report["security_timeline"]["events"], export_path)
    timeline_export = json.loads(export_path.read_text(encoding="utf-8"))

    assert report["security_timeline"]["event_count"] == 2
    assert report["report_summary"]["security_timeline"]["event_count"] == 2
    assert timeline_export["timeline"][0]["timestamp"] <= timeline_export["timeline"][1]["timestamp"]
