from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.explanations import ensure_finding_explanations
from mac_audit_agent.models import Finding, ScanResult, ScanSummary
from mac_audit_agent.reporting import export_html_report, export_json_report, export_scan_result_html, export_scan_result_json


def _high_finding() -> Finding:
    return Finding(
        id="finding-high-1",
        category="Persistence",
        title="LaunchDaemon Added",
        severity="high",
        description="LaunchDaemon added at /Library/LaunchDaemons/example.plist.",
        evidence="/Library/LaunchDaemons/example.plist",
        command_used="launchctl print system",
        remediation_suggestion="Verify the LaunchDaemon owner, permissions, signature, and target program.",
        warning="Unexpected automatic startup items can persist across restarts.",
    )


def test_high_finding_has_technical_explanation() -> None:
    payload = _high_finding().to_dict()

    assert payload["technical_explanation"]
    assert "LaunchDaemon" in payload["technical_explanation"]


def test_high_finding_has_plain_english_explanation() -> None:
    payload = _high_finding().to_dict()

    assert payload["plain_english_explanation"]
    assert "start automatically" in payload["plain_english_explanation"]
    assert payload["analyst_next_step"]


def test_dict_high_finding_is_enriched() -> None:
    payload = ensure_finding_explanations(
        {
            "id": "finding-high-2",
            "category": "Network",
            "title": "Unexpected Listening Port",
            "severity": "critical",
            "description": "Port 4444 is listening.",
            "evidence": "127.0.0.1:4444",
        }
    )

    assert payload["technical_explanation"]
    assert payload["plain_english_explanation"]
    assert payload["analyst_next_step"]


def test_reports_include_technical_and_plain_english_explanations(tmp_path: Path) -> None:
    summary = ScanSummary(
        scan_id="scan-explain",
        started_at="2026-06-27T00:00:00Z",
        completed_at="2026-06-27T00:01:00Z",
        findings_count=1,
        security_score=70,
        notes="explanation test",
    )
    finding = _high_finding()
    json_path = export_json_report(summary, [finding], tmp_path / "report.json")
    html_path = export_html_report(summary, [finding], tmp_path / "report.html")

    json_payload = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")

    assert json_payload["findings"][0]["technical_explanation"]
    assert json_payload["findings"][0]["plain_english_explanation"]
    assert "Technical Explanation" in html
    assert "Plain-English Explanation" in html


def test_scan_result_reports_include_explanations(tmp_path: Path) -> None:
    finding = _high_finding()
    scan_result = ScanResult(
        scan_id="scan-explain",
        timestamp="2026-06-27T00:01:00Z",
        hostname="mac.local",
        current_user="student",
        findings=[finding],
        raw_logs=[],
        collected_artifacts={"ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []}},
        baseline_diff={},
        errors=[],
    )

    json_path = export_scan_result_json(scan_result, tmp_path / "scan.json")
    html_path = export_scan_result_html(scan_result, tmp_path / "scan.html")
    json_payload = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")

    assert json_payload["findings"][0]["technical_explanation"]
    assert json_payload["findings"][0]["plain_english_explanation"]
    assert "Technical Explanation" in html
    assert "Plain-English Explanation" in html
