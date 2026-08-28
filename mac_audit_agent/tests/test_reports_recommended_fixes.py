from __future__ import annotations

import json

from mac_audit_agent.models import Finding, ScanResult, utc_now_iso
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json


def _scan() -> ScanResult:
    return ScanResult(
        scan_id="scan-1",
        timestamp=utc_now_iso(),
        hostname="test-mac",
        current_user="tester",
        findings=[
            Finding(
                id="f1",
                category="Persistence",
                title="New LaunchAgent added",
                severity="medium",
                description="A new LaunchAgent was found.",
                evidence="/Users/tester/Library/LaunchAgents/com.example.plist",
                command_used="launchctl print",
                remediation_suggestion="Review the LaunchAgent and referenced binary.",
                warning="Do not delete until reviewed.",
            )
        ],
        collected_artifacts={},
    )


def test_json_report_includes_recommended_fix_payload(tmp_path) -> None:
    path = export_scan_result_json(_scan(), tmp_path / "scan.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    finding = payload["findings"][0]
    assert finding["recommended_fix"]["recommended_fix"]
    assert finding["false_positive_review"]["checks"]
    assert finding["remediation_sources"]
    assert finding["poam"]["recommended_fix"]


def test_html_report_includes_recommended_fix_sections(tmp_path) -> None:
    path = export_scan_result_html(_scan(), tmp_path / "scan.html")
    html = path.read_text(encoding="utf-8")
    assert "Recommended Fix" in html
    assert "False-positive review" in html
    assert "Standards/source mappings" in html
