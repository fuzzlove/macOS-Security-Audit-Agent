from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.models import ScanResult
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.system_integrity import SystemIntegrityEngine


def _titles(report) -> set[str]:
    return {finding.title for finding in report.findings}


def test_hidden_port_mismatch_creates_finding() -> None:
    report = SystemIntegrityEngine().analyze_artifacts(
        {
            "localhost_scan": {
                "nmap": {
                    "ports": [
                        {
                            "host": "127.0.0.1",
                            "port": 7000,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                        }
                    ]
                }
            },
            "ports": {
                "listening": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "local_address": "127.0.0.1:22",
                        "process_name": "sshd",
                    }
                ]
            },
        }
    )

    assert "Port ownership visibility mismatch" in _titles(report)
    finding = report.findings[0]
    assert finding.category == "System Integrity"
    assert "visibility mismatch" in finding.normalized_signal
    assert "tcp/7000" in finding.evidence


def test_temp_unsigned_binary_creates_finding() -> None:
    report = SystemIntegrityEngine().analyze_artifacts(
        {
            "processes": {
                "all": [
                    {
                        "pid": 4242,
                        "ppid": 1,
                        "user": "m",
                        "process_name": ".worker",
                        "command_path": "/private/tmp/.cache/.worker",
                        "signed_status": "unsigned",
                        "trust_level": "untrusted",
                        "reasons": ["suspicious_execution_path"],
                    }
                ]
            }
        }
    )

    assert "Suspicious execution location" in _titles(report)
    finding = report.findings[0]
    assert finding.severity == "high"
    assert "/private/tmp/.cache/.worker" in finding.evidence
    assert "review recommended" in finding.normalized_signal


def test_stale_detector_creates_monitoring_blindness_finding() -> None:
    report = SystemIntegrityEngine().analyze_artifacts(
        {
            "visibility_integrity": {
                "components": [
                    {
                        "component_name": "Detector Freshness",
                        "status": "degraded",
                        "last_success": "2026-06-27T00:00:00+00:00",
                        "evidence": "Detector last ran 1200s ago.",
                        "recommended_fix": "Restart monitoring.",
                    }
                ]
            }
        }
    )

    assert "Monitoring blindness indicator" in _titles(report)
    finding = report.findings[0]
    assert finding.confidence == "high"
    assert "Detector Freshness" in finding.evidence


def test_no_rootkit_detected_wording_appears() -> None:
    report = SystemIntegrityEngine().analyze_artifacts(
        {
            "localhost_scan": {"nmap": {"ports": [{"port": 7000, "protocol": "tcp", "state": "open"}]}},
            "ports": {"listening": []},
            "processes": {"all": [{"pid": 1, "command_path": "/tmp/tool", "signed_status": "unsigned", "reasons": ["suspicious_execution_path"]}]},
            "visibility_integrity": {"components": [{"component_name": "Monitor Heartbeat", "status": "failing", "evidence": "Heartbeat stale."}]},
        }
    )

    payload = json.dumps(report.to_dict()).lower()
    assert "rootkit detected" not in payload


def test_reports_include_system_integrity_section(tmp_path: Path) -> None:
    report = SystemIntegrityEngine().analyze_artifacts(
        {
            "visibility_integrity": {
                "components": [
                    {
                        "component_name": "Monitor Heartbeat",
                        "status": "failing",
                        "evidence": "Heartbeat stale.",
                    }
                ]
            }
        }
    )
    scan_result = ScanResult(
        scan_id="scan-integrity",
        timestamp="2026-06-27T00:00:00+00:00",
        hostname="mac.local",
        current_user="m",
        collected_artifacts={
            "system_integrity": report.to_dict(),
            "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
            "processes": {"all": [], "suspicious": [], "errors": []},
            "localhost_scan": {},
        },
    )

    json_path = export_scan_result_json(scan_result, tmp_path / "report.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "report.html")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")
    assert payload["system_integrity"]["finding_count"] == 1
    assert payload["report_summary"]["system_integrity"]["finding_count"] == 1
    assert "System Integrity" in html
    assert "Monitoring blindness indicator" in html
