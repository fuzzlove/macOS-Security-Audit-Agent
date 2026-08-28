from __future__ import annotations

from pathlib import Path

from mac_audit_agent.keylogger_detection import KeyloggerFinding, KeyloggerScanReport
from mac_audit_agent.keylogger_reporting import REPORT_FORMATS, build_keylogger_report, export_keylogger_report


def _report() -> KeyloggerScanReport:
    finding = KeyloggerFinding(
        finding_id="event-tap-1-42", title="Process can intercept keyboard events", severity="high", confidence="high", score=75,
        process_name="example", pid=42, path="/tmp/example", signals=["enabled keyboard event tap", "system-wide event tap"],
        evidence={"signature": {"valid": False}}, recommendation="Validate and contain through authorized incident response.",
        classification="suspicious_capability", attack_techniques=[{"id": "T1056.001", "name": "Keylogging"}],
    )
    return KeyloggerScanReport("2026-07-22T00:00:00Z", "2026-07-22T00:01:00Z", [finding], 1, 2, {"event_taps": "available", "tcc": "available", "signing": "available"})


def test_static_report_formats_are_prioritized_and_office_formats_are_macro_free() -> None:
    assert [item[0] for item in REPORT_FORMATS] == ["txt", "pdf", "csv", "json", "html", "docx", "xlsx"]
    assert all(format_id not in {"docm", "xlsm"} for format_id, _label, _filter in REPORT_FORMATS)


def test_report_payload_has_operational_statistics_and_qualification() -> None:
    payload = build_keylogger_report(_report())
    assert payload["executive_summary"]["high_or_critical_count"] == 1
    assert payload["threat_statistics"]["by_severity"] == {"high": 1}
    assert "not, by itself, proof" in payload["handling_notice"]
    assert "no macros" in payload["report_safety"]
    assert payload["executive_summary"]["measured_accuracy_rate_percent"] is None
    assert payload["executive_summary"]["accuracy_basis"] == "not_measured_no_adjudicated_outcomes"
    assert "average_false_positive_risk_percent" in payload["executive_summary"]


def test_all_professional_formats_export(tmp_path: Path) -> None:
    report = _report()
    for format_id, _label, _filter in REPORT_FORMATS:
        path = export_keylogger_report(report, tmp_path / f"report.{format_id}", format_id)
        assert path.exists()
        assert path.stat().st_size > 50


def test_csv_neutralizes_spreadsheet_formula_prefixes(tmp_path: Path) -> None:
    report = _report(); report.findings[0].process_name = "=HYPERLINK(\"unsafe\")"
    path = export_keylogger_report(report, tmp_path / "report.csv", "csv")
    assert "'=HYPERLINK" in path.read_text(encoding="utf-8")
