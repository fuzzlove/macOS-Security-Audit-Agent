from __future__ import annotations

from pathlib import Path

from mac_audit_agent.assessment import (
    build_security_assessment,
    export_security_assessment_html,
    export_security_assessment_json,
    export_security_assessment_markdown,
)
from mac_audit_agent.models import BackgroundMonitorEvent, BackgroundMonitorStatus, ScanResult, make_finding, utc_now_iso
from mac_audit_agent.storage import AuditDatabase


def _scan(findings=None) -> ScanResult:
    return ScanResult(
        scan_id="scan-1",
        timestamp=utc_now_iso(),
        hostname="test-mac",
        current_user="tester",
        findings=findings or [],
        collected_artifacts={"ports": {"listening": []}},
        baseline_diff={"drift_score": 90, "drift_label": "stable", "high_risk_change_count": 0},
    )


def test_assessment_builder_scores_and_groups_real_findings() -> None:
    critical = make_finding(
        id="f-critical",
        category="Persistence",
        title="LaunchDaemon Added",
        severity="critical",
        description="Unexpected daemon",
        evidence="path=/Library/LaunchDaemons/com.example.plist",
        command_used="launchctl",
        remediation_suggestion="Review and remove only if unauthorized.",
        warning="Persistence may survive restart.",
    )
    high = make_finding(
        id="f-high",
        category="Network",
        title="Unexpected Listener",
        severity="high",
        description="Unexpected local listener",
        evidence="port=4444",
        command_used="lsof",
        remediation_suggestion="Identify owning process.",
        warning="Unexpected listeners may expose services.",
    )

    assessment = build_security_assessment(_scan([critical, high]), BackgroundMonitorStatus(status_text="healthy"), [], {})

    assert assessment.overall_score == 70
    assert assessment.risk_level == "high"
    assert len(assessment.critical_findings) == 1
    assert len(assessment.high_findings) == 1
    assert assessment.framework_summary
    assert assessment.recommended_actions


def test_assessment_handles_missing_scan_without_fake_findings() -> None:
    assessment = build_security_assessment(None, None, [], {})

    assert assessment.assessment_status == "unavailable"
    assert assessment.overall_score is None
    assert assessment.top_risks == []
    assert "Latest scan unavailable" in " ".join(assessment.limitations)
    assert "No assessment is available yet" in assessment.executive_summary or "No current security assessment" in assessment.executive_summary


def test_applicable_apple_exposure_is_the_primary_recommended_action() -> None:
    apple = {
        "cards": [
            {
                "card_id": "apple-critical",
                "applicability": "confirmed_applicable",
                "forecast_level": "critical",
                "status": "new",
            }
        ]
    }

    assessment = build_security_assessment(
        _scan(),
        BackgroundMonitorStatus(status_text="healthy"),
        [],
        {},
        apple_exposure=apple,
    )

    assert assessment.recommended_actions[0]["title"] == "Apple Exposure Assessment"
    assert assessment.recommended_actions[0]["primary"] is True
    assert assessment.recommended_actions[0]["priority"] == "Immediate"


def test_assessment_marks_collected_clean_categories_without_placeholder_risks() -> None:
    scan = _scan()
    scan.collected_artifacts.update(
        {
            "ports": {"listening": [], "active_connections": [], "errors": []},
            "users": [{"username": "tester", "admin": True}],
            "launch_items": [],
            "launch_snapshots": [],
        }
    )

    assessment = build_security_assessment(scan, BackgroundMonitorStatus(status_text="healthy"), [], {})

    assert assessment.network_activity_summary["status"] == "no findings"
    assert assessment.network_activity_summary["summary"] == "Network data was collected; no network findings were recorded."
    assert assessment.admin_persistence_summary["status"] == "no findings"
    assert assessment.admin_persistence_summary["admin_user_count"] == 1
    assert assessment.top_risks == []


def test_assessment_includes_monitor_usb_and_network_events() -> None:
    event = BackgroundMonitorEvent(
        event_id="event-1",
        timestamp=utc_now_iso(),
        event_type="usb_network_adapter_connected",
        severity="critical",
        source="test",
        evidence="New USB network adapter connected.",
        confidence="high",
        recommendation="Preserve evidence and verify the device.",
        rule_id="usb_network_adapter_connected",
        rule_name="USB Network Adapter Connected",
    )

    assessment = build_security_assessment(None, BackgroundMonitorStatus(status_text="healthy"), [event], {})

    assert assessment.assessment_status == "partial"
    assert assessment.top_risks[0]["event_type"] == "usb_network_adapter_connected"
    assert assessment.physical_device_summary["count"] == 1
    assert assessment.network_activity_summary["count"] == 1


def test_assessment_storage_history_roundtrip(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    assessment = build_security_assessment(_scan(), BackgroundMonitorStatus(status_text="healthy"), [], {})

    db.record_security_assessment(assessment)

    latest = db.latest_security_assessment()
    history = db.assessment_history()
    assert latest is not None
    assert latest["assessment_id"] == assessment.assessment_id
    assert history[0]["assessment_id"] == assessment.assessment_id


def test_assessment_exports_do_not_use_unsupported_compliance_wording(tmp_path: Path) -> None:
    assessment = build_security_assessment(_scan(), BackgroundMonitorStatus(status_text="healthy"), [], {})

    html_path = export_security_assessment_html(assessment, tmp_path / "assessment.html")
    json_path = export_security_assessment_json(assessment, tmp_path / "assessment.json")
    md_path = export_security_assessment_markdown(assessment, tmp_path / "assessment.md")

    combined = html_path.read_text(encoding="utf-8") + json_path.read_text(encoding="utf-8") + md_path.read_text(encoding="utf-8")
    assert "CMMC Readiness Summary" in html_path.read_text(encoding="utf-8")
    assert "cmmc_readiness" in json_path.read_text(encoding="utf-8")
    assert "demo" not in combined.lower()
    assert "sample finding" not in combined.lower()
    assert "Compliant" not in combined
    assert "Certified" not in combined
    assert "Government approved" not in combined
