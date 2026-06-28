from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.baseline_drift import BaselineDriftEngine
from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.storage import AuditDatabase


def _payload(
    *,
    launchdaemons: list[dict] | None = None,
    admin_users: list[dict] | None = None,
    dns_servers: list[str] | None = None,
) -> dict:
    return {
        "launchdaemons": launchdaemons or [],
        "admin_users": admin_users or [],
        "dns_servers": dns_servers or [],
        "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
        "processes": {"all": [], "suspicious": [], "errors": []},
    }


def _categories(drift: dict) -> set[str]:
    return {item["category"] for item in drift["findings"]}


def test_new_launchdaemon_detected_as_drift() -> None:
    engine = BaselineDriftEngine()
    baseline = engine.create_trusted_baseline(
        _payload(launchdaemons=[{"path": "/Library/LaunchDaemons/com.example.old.plist", "label": "com.example.old"}])
    )
    drift = engine.compare_current_state(
        _payload(
            launchdaemons=[
                {"path": "/Library/LaunchDaemons/com.example.old.plist", "label": "com.example.old"},
                {"path": "/Library/LaunchDaemons/com.example.new.plist", "label": "com.example.new"},
            ]
        ),
        baseline=baseline,
    )

    assert _categories(drift) == {"launchdaemons"}
    finding = drift["findings"][0]
    assert finding["change_type"] == "added"
    assert finding["item_key"] == "/Library/LaunchDaemons/com.example.new.plist"
    assert finding["severity"] == "high"
    assert "malicious" not in json.dumps(finding).lower()


def test_admin_user_change_detected_as_drift() -> None:
    engine = BaselineDriftEngine()
    baseline = engine.create_trusted_baseline(_payload(admin_users=[{"username": "m", "admin": True}]))
    drift = engine.compare_current_state(
        _payload(admin_users=[{"username": "m", "admin": True}, {"username": "auditor", "admin": True}]),
        baseline=baseline,
    )

    assert _categories(drift) == {"users_admins"}
    assert drift["findings"][0]["item_key"] == "auditor"
    assert drift["findings"][0]["severity"] == "high"


def test_dns_change_detected_as_drift() -> None:
    engine = BaselineDriftEngine()
    baseline = engine.create_trusted_baseline(_payload(dns_servers=["1.1.1.1"]))
    drift = engine.compare_current_state(_payload(dns_servers=["9.9.9.9"]), baseline=baseline)

    assert _categories(drift) == {"dns_servers"}
    assert {item["change_type"] for item in drift["findings"]} == {"added", "removed"}
    assert drift["summary"]["review_recommended"] == 2


def test_mark_expected_suppresses_future_noise(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    try:
        engine = BaselineDriftEngine(db)
        engine.create_trusted_baseline(_payload(dns_servers=["1.1.1.1"]))
        drift = engine.compare_current_state(_payload(dns_servers=["1.1.1.1", "9.9.9.9"]))
        assert len(drift["findings"]) == 1

        engine.mark_expected(drift["findings"][0]["drift_id"], note="Approved VPN DNS resolver.")
        suppressed = engine.compare_current_state(_payload(dns_servers=["1.1.1.1", "9.9.9.9"]))

        assert suppressed["findings"] == []
        assert suppressed["summary"]["suppressed_expected"] == 1
    finally:
        db.close()


def test_reports_include_baseline_drift_section(tmp_path: Path) -> None:
    engine = BaselineDriftEngine()
    baseline = engine.create_trusted_baseline(_payload(dns_servers=["1.1.1.1"]))
    drift = engine.compare_current_state(_payload(dns_servers=["1.1.1.1", "9.9.9.9"]), baseline=baseline)
    scan_result = ScanResult(
        scan_id="scan-baseline-drift",
        timestamp="2026-06-27T00:00:00Z",
        hostname="mac.local",
        current_user="m",
        collected_artifacts={
            "baseline_drift": drift,
            "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
            "processes": {"all": [], "suspicious": [], "errors": []},
            "localhost_scan": {},
        },
    )

    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    export_scan_result_json(scan_result, json_path)
    export_scan_result_html(scan_result, html_path)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")
    assert payload["baseline_drift"]["summary"]["total"] == 1
    assert payload["report_summary"]["baseline_drift"]["summary"]["total"] == 1
    assert "Baseline Drift" in html
    assert "Changes are review signals only" in html
