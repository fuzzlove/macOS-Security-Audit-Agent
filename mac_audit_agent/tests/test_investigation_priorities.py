from __future__ import annotations

from pathlib import Path

from mac_audit_agent.investigation_priority import InvestigationPriorityEngine
from mac_audit_agent.models import BackgroundMonitorEvent, Finding, ScanResult
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.workflow_layer import InvestigatorWorkflowLayer


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    *,
    category: str,
    evidence: str,
    confidence: str = "high",
    recommended_next_steps: str = "Review in context.",
    source_trace: str = "",
) -> Finding:
    return Finding(
        id=finding_id,
        category=category,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        description=title,
        evidence=evidence,
        command_used=evidence,
        remediation_suggestion=recommended_next_steps,
        warning="",
        evidence_summary=evidence,
        recommended_next_steps=recommended_next_steps,
        confidence=confidence,  # type: ignore[arg-type]
        source_trace=source_trace,
    )


def _scan_result() -> ScanResult:
    return ScanResult(
        scan_id="scan-1",
        timestamp="2026-06-01T12:00:00+00:00",
        hostname="mac.local",
        current_user="m",
        findings=[
            _finding("f-admin", "New Admin User Detected", "high", category="Identity", evidence="admin user added to local administrators", recommended_next_steps="Verify approved onboarding."),
            _finding("f-persist", "LaunchDaemon Added", "medium", category="Persistence", evidence="/Library/LaunchDaemons/com.example.plist", recommended_next_steps="Inspect plist target and ownership."),
            _finding("f-network", "New Network Connection Detected", "medium", category="Network", evidence="VPN connected and new IP assigned", recommended_next_steps="Confirm the endpoint and address assignment."),
            _finding("f-trust", "Suspicious Process Observed", "high", category="Execution", evidence="/tmp/evil trust_score=22", recommended_next_steps="Review the binary path and hash."),
            _finding("f-browser", "Browser Helper Activity", "critical", category="Execution", evidence="Chrome Helper and Safari Web Content", confidence="medium", recommended_next_steps="Confirm expected browser activity."),
        ],
        collected_artifacts={
            "processes": {
                "all": [
                    {
                        "pid": 101,
                        "ppid": 1,
                        "user": "m",
                        "command_path": "/tmp/evil",
                        "process_name": "evil",
                        "signed_status": "unsigned",
                        "trust_level": "untrusted",
                        "trust_score": 22,
                        "trust_summary": "Low trust.",
                        "reasons": ["nonstandard_path"],
                    },
                    {
                        "pid": 202,
                        "ppid": 1,
                        "user": "m",
                        "command_path": "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)",
                        "process_name": "Google Chrome Helper (Renderer)",
                        "signed_status": "signed",
                        "trust_level": "trusted",
                        "trust_score": 95,
                        "trust_summary": "Common browser helper.",
                        "reasons": ["browser_helper"],
                    },
                ],
                "suspicious": [],
                "errors": [],
            },
            "file_issues": [
                {
                    "path": "/tmp/evil",
                    "issue_type": "executable",
                    "modified_at": "2026-06-01T11:58:00+00:00",
                    "executable": True,
                    "world_writable": False,
                    "hidden": False,
                    "signed_status": "unsigned",
                    "trust_score": 18,
                    "trust_label": "untrusted",
                    "trust_summary": "Low trust binary.",
                }
            ],
            "network_discovery": {
                "review_needed_count": 1,
                "devices": [
                    {
                        "ip_address": "192.168.1.50",
                        "likely_hostname": "Unknown",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                        "vendor": "Unknown",
                        "device_type": "Unknown",
                        "confidence": "low",
                        "discovery_methods": ["arp"],
                        "review_needed": True,
                        "review_flags": ["unknown device"],
                        "baseline_status": "review needed",
                        "first_seen": "2026-06-01T11:50:00+00:00",
                        "last_seen": "2026-06-01T12:00:00+00:00",
                    }
                ],
                "comparison": {},
                "debug_logs": [],
                "errors": [],
            },
        },
        baseline_diff={},
        raw_logs=[],
        errors=[],
    )


def test_investigation_priority_engine_ranks_actual_value_above_severity(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    scan = _scan_result()
    db.record_background_monitor_event(
        BackgroundMonitorEvent(
            event_id="event-1",
            timestamp="2026-06-01T11:59:00+00:00",
            event_type="screen_unlocked",
            severity="info",
            source="session_monitor",
            evidence="Screen unlocked after idle.",
            confidence="high",
            recommendation="Review nearby activity.",
        )
    )
    db.record_background_monitor_event(
        BackgroundMonitorEvent(
            event_id="event-2",
            timestamp="2026-06-01T11:59:30+00:00",
            event_type="usb_device_connected",
            severity="low",
            source="hardware_detector",
            evidence="USB device connected.",
            confidence="high",
            recommendation="Confirm the device is expected.",
        )
    )
    db.set_review_status(
        item_type="finding",
        item_key="f-browser",
        label="Browser Helper Activity",
        review_state="false positive",
        linked_scan_id="scan-1",
        linked_finding_id="f-browser",
        notes="Expected browser helper.",
    )
    db.record_finding_suppression(scan.findings[-1], review_state="false positive", rationale="Expected browser helper.")

    engine = InvestigationPriorityEngine(db, InvestigatorWorkflowLayer(db))
    report = engine.build_priorities(scan_result=scan)

    titles = [item.title for item in report.full_queue]
    assert titles[0] in {"New Admin User Detected", "LaunchDaemon Added", "New Network Connection Detected", "Suspicious Process Observed"}
    assert titles.index("Browser Helper Activity") > titles.index("LaunchDaemon Added")
    assert titles.index("Browser Helper Activity") > titles.index("New Admin User Detected")
    assert report.top_3
    assert any(item.persistence_involvement for item in report.full_queue if item.title == "LaunchDaemon Added")
    assert any(item.admin_involvement for item in report.full_queue if item.title == "New Admin User Detected")
    assert any(item.network_involvement for item in report.full_queue if item.title == "New Network Connection Detected")
    assert any(item.trust_score_impact > 0 for item in report.full_queue if item.title == "Suspicious Process Observed")
    assert any(item.user_presence_correlation for item in report.full_queue)
    browser_item = next(item for item in report.full_queue if item.title == "Browser Helper Activity")
    assert browser_item.review_state == "false positive"
    assert browser_item.suppressed is True
    assert browser_item.suppression_history_count > 0
    assert browser_item.rank_score < next(item.rank_score for item in report.full_queue if item.title == "LaunchDaemon Added")


def test_investigation_priority_report_counts_are_stable(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    scan = _scan_result()
    engine = InvestigationPriorityEngine(db, InvestigatorWorkflowLayer(db))
    report = engine.build_priorities(scan_result=scan)

    assert report.scan_id == "scan-1"
    assert len(report.full_queue) == len(scan.findings)
    assert len(report.top_3) == min(3, len(scan.findings))
    assert len(report.top_10) == len(scan.findings)
    assert "investigative value" in report.summary

