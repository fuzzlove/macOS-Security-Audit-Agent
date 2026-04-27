from __future__ import annotations

import html
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from mac_audit_agent.assets import get_asset_data_uri
from mac_audit_agent.models import BaselineComparison, Finding, ScanResult, ScanSummary
from mac_audit_agent.storage import json_safe

SEVERITY_COLOR_MAP = {
    "info": {"bg": "#2C3E50", "fg": "#ECF0F1"},
    "low": {"bg": "#27AE60", "fg": "#FFFFFF"},
    "medium": {"bg": "#F39C12", "fg": "#000000"},
    "high": {"bg": "#E74C3C", "fg": "#FFFFFF"},
    "critical": {"bg": "#8E0000", "fg": "#FFFFFF"},
}
SCORE_WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}
LOGGER = logging.getLogger(__name__)


def get_reports_dir() -> Path:
    base = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "reports"
    base.mkdir(parents=True, exist_ok=True)
    return base


def finding_to_dict(finding) -> dict:
    if isinstance(finding, dict):
        return finding
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    if hasattr(finding, "__dict__"):
        return dict(finding.__dict__)
    return {}


def default_html_report_path(base_dir: Path | None = None, now: datetime | None = None) -> Path:
    reports_dir = (base_dir / "reports") if base_dir is not None else get_reports_dir()
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")
    return reports_dir / f"mac_audit_report_{timestamp}.html"


def default_json_report_path(base_dir: Path | None = None, now: datetime | None = None) -> Path:
    reports_dir = (base_dir / "reports") if base_dir is not None else get_reports_dir()
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")
    return reports_dir / f"mac_audit_report_{timestamp}.json"


def severity_css_class(severity: str) -> str:
    return f"severity-{severity}"


def report_logo_markup() -> str:
    data_uri = get_asset_data_uri("logo.png")
    if not data_uri:
        return ""
    return (
        '<div class="report-brand">'
        f'<img class="report-logo" src="{html.escape(data_uri)}" alt="Mac Audit Agent logo">'
        '<div><h1>Mac Audit Agent</h1><p class="report-brand-subtitle">macOS Security Audit</p></div>'
        "</div>"
    )


def format_utc_timestamp(value: str) -> str:
    if not value:
        return ""
    candidate = str(value).strip()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return candidate
    if parsed.tzinfo is None:
        return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def summarize_findings_by_severity(findings: list[Finding]) -> dict[str, int]:
    normalized = [finding_to_dict(finding) for finding in findings]
    counts = Counter(finding.get("severity", "info") for finding in normalized)
    return {severity: counts.get(severity, 0) for severity in SEVERITY_COLOR_MAP}


def score_from_findings(findings: list[Finding]) -> tuple[int | None, str]:
    if findings is None:
        return None, "Unavailable"
    if not findings:
        return 100, "Good"
    normalized = [finding_to_dict(finding) for finding in findings]
    score = max(0, min(100, 100 - sum(SCORE_WEIGHTS.get(finding.get("severity", "info"), 0) for finding in normalized)))
    if score >= 90:
        return score, "Good"
    if score >= 70:
        return score, "Needs Review"
    if score >= 40:
        return score, "Concerning"
    return score, "High Risk"


def export_json_report(
    summary: ScanSummary,
    findings: list[Finding],
    output_path: Path | None,
    *,
    comparison: BaselineComparison | None = None,
    dashboard: dict | None = None,
) -> Path:
    payload = {
        "summary": summary.to_dict(),
        "security_score": summary.security_score,
        "score_label": summary.score_label or score_from_findings(findings)[1],
        "dashboard": dashboard or {},
        "findings": [finding_to_dict(finding) for finding in findings],
        "comparison": comparison.to_dict() if comparison else {},
    }
    output_path = output_path or default_json_report_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    LOGGER.info("Report saved to: %s", output_path)
    return output_path


def export_monitor_events_json(events: list[dict], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"background_monitor_events": events}, indent=2), encoding="utf-8")
    LOGGER.info("Report saved to: %s", output_path)
    return output_path


def export_investigation_notes_json(
    notes: list[dict],
    audit_trail: list[dict],
    output_path: Path,
    *,
    redact: bool = False,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "investigation_notes": _serialize_notes(notes, redact=redact),
        "investigation_audit_trail": audit_trail,
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    LOGGER.info("Report saved to: %s", output_path)
    return output_path


def export_investigation_notes_html(
    notes: list[dict],
    audit_trail: list[dict],
    output_path: Path,
    *,
    redact: bool = False,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    notes_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('updated_at', '')))}</td><td>{html.escape(str(item.get('title', '')))}</td><td>{html.escape(str(item.get('status', '')))}</td><td>{html.escape(str(item.get('priority', '')))}</td><td>{html.escape(str(item.get('linked_finding_id', '')))}</td><td>{html.escape(str(item.get('body', '')))}</td></tr>"
        for item in _serialize_notes(notes, redact=redact)
    )
    audit_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('timestamp', '')))}</td><td>{html.escape(str(item.get('action_type', '')))}</td><td>{html.escape(str(item.get('entity_type', '')))}</td><td>{html.escape(str(item.get('details', '')))}</td><td>{html.escape(str(item.get('previous_status', '')))}</td><td>{html.escape(str(item.get('new_status', '')))}</td></tr>"
        for item in audit_trail
    )
    logo_markup = report_logo_markup()
    output_path.write_text(
        (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Investigation Notes</title></head><body>"
            f"{logo_markup}<h1>Investigation Notes</h1><p>These notes remain local. They are not uploaded anywhere by this app.</p>"
            "<h2>Notes</h2><table border='1'><thead><tr><th>Updated</th><th>Title</th><th>Status</th><th>Priority</th><th>Finding</th><th>Body</th></tr></thead>"
            f"<tbody>{notes_rows}</tbody></table><h2>Audit Trail</h2><table border='1'><thead><tr><th>Timestamp</th><th>Action</th><th>Entity</th><th>Details</th><th>Previous</th><th>New</th></tr></thead><tbody>{audit_rows}</tbody></table></body></html>"
        ),
        encoding="utf-8",
    )
    LOGGER.info("Report saved to: %s", output_path)
    return output_path


def export_monitor_events_html(events: list[dict], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = "".join(
        f"<tr><td>{html.escape(str(item.get('timestamp', '')))}</td><td>{html.escape(str(item.get('event_type', '')))}</td><td>{html.escape(str(item.get('severity', '')))}</td><td>{html.escape(str(item.get('source', '')))}</td><td>{html.escape(str(item.get('process_name', '')))}</td><td>{html.escape(str(item.get('confidence', '')))}</td><td>{html.escape(str(item.get('evidence', '')))}</td></tr>"
        for item in events
    )
    logo_markup = report_logo_markup()
    output_path.write_text(
        (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Background Monitor Events</title></head><body>"
            f"{logo_markup}<h1>Background Monitor Events</h1><table border='1'><thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Source</th><th>Process</th><th>Confidence</th><th>Evidence</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></body></html>"
        ),
        encoding="utf-8",
    )
    LOGGER.info("Report saved to: %s", output_path)
    return output_path


def export_scan_result_json(
    scan_result: ScanResult,
    output_path: Path | None = None,
    *,
    include_background_monitor_logs: bool = False,
    background_monitor_events: list[dict] | None = None,
    include_investigation_notes: bool = False,
    investigation_notes: list[dict] | None = None,
    investigation_audit_trail: list[dict] | None = None,
) -> Path:
    output_path = output_path or default_json_report_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json_safe(scan_result.to_dict())
    ports = payload.get("collected_artifacts", {}).get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []})
    processes = payload.get("collected_artifacts", {}).get("processes", {"all": [], "suspicious": [], "errors": []})
    localhost_scan = payload.get("collected_artifacts", {}).get("localhost_scan", {})
    packet_captures = payload.get("collected_artifacts", {}).get("packet_captures", [])
    network_discovery = payload.get("collected_artifacts", {}).get("network_discovery", {})
    score, score_label = score_from_findings(scan_result.findings)
    payload["security_score"] = score
    payload["score_label"] = score_label
    payload["report_summary"] = {
        "security_score": score,
        "score_label": score_label,
        "ports_listening_count": len(ports.get("listening", [])),
        "active_connections_count": len(ports.get("active_connections", [])),
        "suspicious_ports_count": len(ports.get("suspicious_review_needed", [])),
        "process_count": len(processes.get("all", [])),
        "suspicious_process_count": len(processes.get("suspicious", [])),
        "collector_errors": {
            "ports": ports.get("errors", []),
            "processes": processes.get("errors", []),
        },
        "localhost_scan": localhost_scan,
        "packet_captures": packet_captures,
        "network_discovery": network_discovery,
        "packet_capture_privacy_warning": "Packet captures may contain sensitive traffic metadata or contents. Reports include only local metadata and file paths, not packet contents.",
    }
    if include_background_monitor_logs:
        payload["background_monitor_events"] = background_monitor_events or []
    if include_investigation_notes:
        payload["investigation_notes"] = investigation_notes or []
        payload["investigation_audit_trail"] = investigation_audit_trail or []
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    LOGGER.info("Report saved to: %s", output_path)
    return output_path


def export_html_report(
    summary: ScanSummary,
    findings: list[Finding],
    output_path: Path | None = None,
    *,
    comparison: BaselineComparison | None = None,
    dashboard: dict | None = None,
) -> Path:
    dashboard = dashboard or {}
    comparison = comparison or BaselineComparison()
    output_path = output_path or default_html_report_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    normalized_findings = [finding_to_dict(finding) for finding in findings]
    severity_counts = summarize_findings_by_severity(normalized_findings)
    dashboard_cards = "".join(
        f'<div class="metric"><span class="metric-label">{html.escape(str(key).replace("_", " ").title())}</span><span class="metric-value">{html.escape(str(value))}</span></div>'
        for key, value in dashboard.items()
    )
    severity_cards = "".join(
        f'<div class="metric severity-card {severity_css_class(severity)}"><span class="metric-label">{html.escape(severity.title())}</span><span class="metric-value">{count}</span></div>'
        for severity, count in severity_counts.items()
    )
    finding_rows = "".join(
        f"""
        <tr class="{severity_css_class(finding.get('severity', 'info'))}">
          <td><span class="severity-badge {severity_css_class(finding.get('severity', 'info'))}">{html.escape(str(finding.get('severity', 'info')))}</span></td>
          <td>{html.escape(str(finding.get('category', '')))}</td>
          <td>{html.escape(str(finding.get('title', '')))}</td>
          <td>{html.escape(str(finding.get('description', '')))}</td>
          <td>{html.escape(str(finding.get('evidence', '')))}</td>
          <td>{html.escape(str(finding.get('recommended_next_steps', finding.get('remediation_suggestion', ''))))}
          {"<br><br><strong>Business Impact:</strong><br>" + html.escape(str(finding.get('business_impact', ''))) if finding.get('business_impact') else ""}
          {"<br><br><strong>Local Network Impact:</strong><br>" + html.escape(str(finding.get('local_network_impact', ''))) if finding.get('local_network_impact') else ""}
          {"<br><br><strong>Privilege Escalation:</strong><br>" + html.escape(str(finding.get('privilege_escalation_context', ''))) if finding.get('privilege_escalation_context') else ""}
          {"<br><br><strong>References:</strong><br>" + "<br>".join(html.escape(str(item)) for item in finding.get('remediation_references', [])) if finding.get('remediation_references') else ""}</td>
          <td>{html.escape(str(finding.get('what_can_go_wrong', finding.get('warning', ''))))}</td>
          <td>{html.escape(str(finding.get('command_used', finding.get('command_or_source', ''))))}</td>
        </tr>
        """
        for finding in normalized_findings
    )
    comparison_rows = "".join(
        f"<tr><td>{html.escape(group)}</td><td>{len(items)}</td></tr>"
        for group, items in [
            ("New Ports", comparison.new_ports),
            ("New Users", comparison.new_users),
            ("New Admin Users", comparison.new_admin_users),
            ("New Launch Items", comparison.new_launch_items),
            ("Changed Permissions", comparison.changed_permissions),
            ("New History Indicators", comparison.new_history_indicators),
            ("New Suspicious Files", comparison.new_suspicious_files),
        ]
    )
    logo_markup = report_logo_markup()
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>macOS Audit Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 32px; color: #10212b; background: #f5f7f9; }}
    .card {{ background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 18px #D0D7DE; margin-bottom: 20px; }}
    .report-brand {{ display: flex; align-items: center; gap: 16px; margin-bottom: 16px; }}
    .report-brand-subtitle {{ margin: 0; color: #50626f; letter-spacing: 0.04em; font-size: 12px; }}
    .report-logo {{ width: 72px; height: 72px; object-fit: contain; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }}
    .metric {{ background: #eef4f7; border-radius: 10px; padding: 12px; }}
    .metric-label {{ display: block; font-size: 12px; text-transform: uppercase; color: #50626f; }}
    .metric-value {{ display: block; font-size: 28px; font-weight: 700; margin-top: 8px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #d9e1e7; padding: 10px; text-align: left; vertical-align: top; }}
    .score {{ font-size: 40px; font-weight: 700; color: #0f766e; }}
    .severity-badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; display: inline-block; }}
    .severity-card .metric-label, .severity-card .metric-value {{ color: inherit; }}
    .severity-info {{ background-color: #2C3E50; color: #ECF0F1; }}
    .severity-low {{ background-color: #27AE60; color: #FFFFFF; }}
    .severity-medium {{ background-color: #F39C12; color: #000000; }}
    .severity-high {{ background-color: #E74C3C; color: #FFFFFF; }}
    .severity-critical {{ background-color: #8E0000; color: #FFFFFF; }}
  </style>
</head>
<body>
  <div class="card">
    {logo_markup}
    <h2>Report Summary</h2>
    <p>Scan Timestamp: {html.escape(format_utc_timestamp(summary.completed_at))}</p>
    <p>Scan ID: {html.escape(summary.scan_id)}</p>
    <p>Started: {html.escape(format_utc_timestamp(summary.started_at))}</p>
    <p>Completed: {html.escape(format_utc_timestamp(summary.completed_at))}</p>
    <p class="score">{html.escape('unavailable' if summary.security_score is None else f'{summary.security_score}/100')} &mdash; {html.escape(summary.score_label or score_from_findings(findings)[1])}</p>
    <p>Higher is better. This score is based on findings severity, not proof of compromise.</p>
    <p>{html.escape(summary.notes)}</p>
  </div>
  <div class="card">
    <h2>Severity Summary</h2>
    <div class="metrics">{severity_cards}</div>
  </div>
  <div class="card">
    <h2>Dashboard</h2>
    <div class="metrics">{dashboard_cards}</div>
  </div>
  <div class="card">
    <h2>Baseline Comparison</h2>
    <p>Drift score: {html.escape(str(comparison.drift_score))}/100 | Label: {html.escape(str(comparison.drift_label))} | High-risk changes: {html.escape(str(comparison.high_risk_change_count))}</p>
    <p>{html.escape(str(comparison.drift_summary))}</p>
    <table>
      <thead><tr><th>Change Group</th><th>Count</th></tr></thead>
      <tbody>{comparison_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Category</th>
          <th>Title</th>
          <th>Description</th>
          <th>Evidence</th>
          <th>Recommendations</th>
          <th>What Can Go Wrong</th>
          <th>Command Used</th>
        </tr>
      </thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    output_path.write_text(document, encoding="utf-8")
    LOGGER.info("Report saved to: %s", output_path)
    return output_path


def export_scan_result_html(
    scan_result: ScanResult,
    output_path: Path | None = None,
    *,
    include_background_monitor_logs: bool = False,
    background_monitor_events: list[dict] | None = None,
    include_investigation_notes: bool = False,
    investigation_notes: list[dict] | None = None,
    investigation_audit_trail: list[dict] | None = None,
) -> Path:
    output_path = output_path or default_html_report_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    findings = [finding_to_dict(finding) for finding in scan_result.findings]
    background_monitor_events = background_monitor_events or []
    artifacts = json_safe(scan_result.to_dict()["collected_artifacts"])
    ports = artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []})
    processes = artifacts.get("processes", {"all": [], "suspicious": [], "errors": []})
    localhost_scan = artifacts.get("localhost_scan", {})
    packet_captures = artifacts.get("packet_captures", [])
    network_discovery = artifacts.get("network_discovery", {})
    score, score_label = score_from_findings(findings)
    severity_counts = summarize_findings_by_severity(findings)
    severity_cards = "".join(
        f'<div class="metric severity-card {severity_css_class(severity)}"><span class="metric-label">{html.escape(severity.title())}</span><span class="metric-value">{count}</span></div>'
        for severity, count in severity_counts.items()
    )
    overview_cards = "".join(
        f'<div class="metric"><span class="metric-label">{html.escape(label)}</span><span class="metric-value">{value}</span></div>'
        for label, value in [
            ("Listening Ports", len(ports.get("listening", []))),
            ("Active Connections", len(ports.get("active_connections", []))),
            ("Ports Review Needed", len(ports.get("suspicious_review_needed", []))),
            ("Localhost Missing Ports", len(localhost_scan.get("missing_from_enumeration", []))),
            ("Processes", len(processes.get("all", []))),
            ("Suspicious Processes", len(processes.get("suspicious", []))),
            ("Collector Errors", len(ports.get("errors", [])) + len(processes.get("errors", []))),
        ]
    )
    findings_rows = "".join(
        f"""
        <tr class="{severity_css_class(finding.get('severity', 'info'))}">
          <td><span class="severity-badge {severity_css_class(finding.get('severity', 'info'))}">{html.escape(str(finding.get('severity', 'info')))}</span></td>
          <td>{html.escape(str(finding.get('category', '')))}</td>
          <td>{html.escape(str(finding.get('title', '')))}</td>
          <td>{html.escape(str(finding.get('description', '')))}</td>
          <td>{html.escape(str(finding.get('evidence', '')))}</td>
          <td>{html.escape(str(finding.get('command_or_source', finding.get('command_used', ''))))}</td>
          <td>{html.escape(str(finding.get('recommended_next_steps', finding.get('remediation_suggestion', ''))))}
          {"<br><br><strong>Business Impact:</strong><br>" + html.escape(str(finding.get('business_impact', ''))) if finding.get('business_impact') else ""}
          {"<br><br><strong>Local Network Impact:</strong><br>" + html.escape(str(finding.get('local_network_impact', ''))) if finding.get('local_network_impact') else ""}
          {"<br><br><strong>Privilege Escalation:</strong><br>" + html.escape(str(finding.get('privilege_escalation_context', ''))) if finding.get('privilege_escalation_context') else ""}
          {"<br><br><strong>References:</strong><br>" + "<br>".join(html.escape(str(item)) for item in finding.get('remediation_references', [])) if finding.get('remediation_references') else ""}</td>
          <td>{html.escape(str(finding.get('what_can_go_wrong', finding.get('warning', ''))))}</td>
        </tr>
        """
        for finding in findings
    )
    ports_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(item.get('process_name', '')))}</td>
          <td>{html.escape(str(item.get('pid', '')) if item.get('pid') is not None else '')}</td>
          <td>{html.escape(str(item.get('protocol', '')))}</td>
          <td>{html.escape(str(item.get('local_address', '')))}</td>
          <td>{html.escape(str(item.get('port', '')) if item.get('port') is not None else '')}</td>
          <td>{html.escape(str(item.get('state', '')))}</td>
          <td>{html.escape(str(item.get('concern', '')))}</td>
        </tr>
        """
        for item in ports.get("listening", [])
    ) or '<tr><td colspan="7">No listening ports found.</td></tr>'
    processes_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(item.get('user', '')))}</td>
          <td>{html.escape(str(item.get('pid', '')) if item.get('pid') is not None else '')}</td>
          <td>{html.escape(str(item.get('ppid', '')) if item.get('ppid') is not None else '')}</td>
          <td>{html.escape(str(item.get('command_path', '')))}</td>
          <td>{html.escape(str(item.get('trust_level', '')))}</td>
          <td>{html.escape(str(item.get('trust_score', '')))}</td>
          <td>{html.escape(','.join(item.get('reasons', [])))}</td>
        </tr>
        """
        for item in processes.get("all", [])
    ) or '<tr><td colspan="7">No processes parsed.</td></tr>'
    collector_error_rows = "".join(
        f"<tr><td>{html.escape(source)}</td><td>{html.escape(error)}</td></tr>"
        for source, errors in [("ports", ports.get("errors", [])), ("processes", processes.get("errors", []))]
        for error in errors
    ) or '<tr><td colspan="2">No collector errors recorded.</td></tr>'
    raw_logs_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(entry.collector_name)}</td>
          <td>{html.escape(entry.command_or_source)}</td>
          <td>{html.escape(entry.timestamp)}</td>
          <td>{html.escape(str(entry.exit_code) if entry.exit_code is not None else "")}</td>
          <td>{html.escape(entry.stderr_summary)}</td>
          <td>{html.escape(entry.stdout_summary)}</td>
        </tr>
        """
        for entry in scan_result.raw_logs
    )
    baseline_rows = "".join(
        f"<tr><td>{html.escape(key.replace('_', ' ').title())}</td><td>{html.escape(str(len(value) if isinstance(value, list) else value))}</td></tr>"
        for key, value in scan_result.baseline_diff.items()
    )
    history_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(item.get('shell_type', '')))}</td>
          <td>{html.escape(str(item.get('pattern_id', '')))}</td>
          <td>{html.escape(str(item.get('match_count', '')))}</td>
          <td>{html.escape(str(item.get('snippet', '')))}</td>
        </tr>
        """
        for item in artifacts.get("history_indicators", [])
    )
    localhost_open_ports = localhost_scan.get("open_ports", [])
    if isinstance(localhost_open_ports, dict):
        localhost_open_ports_text = ", ".join(
            f"{proto.upper()}: {', '.join(str(port) for port in values) if values else 'none'}"
            for proto, values in localhost_open_ports.items()
        )
    else:
        localhost_open_ports_text = ", ".join(str(port) for port in localhost_open_ports) if localhost_open_ports else "none"
    localhost_rows = "".join(
        f"<tr><td>{html.escape(label)}</td><td>{html.escape(value)}</td></tr>"
        for label, value in [
            ("Target", str(localhost_scan.get("target", "127.0.0.1"))),
            ("Scan Mode", str(localhost_scan.get("mode", "safe"))),
            ("Protocol", str(localhost_scan.get("protocol", "tcp")).upper()),
            ("Scanned Port Count", str(localhost_scan.get("scanned_port_count", 0))),
            ("Open Ports Found", localhost_open_ports_text),
            (
                "Ports Missing From Process Enumeration",
                ", ".join(str(port) for port in localhost_scan.get("missing_from_enumeration", [])) or "none",
            ),
            ("Explanation", "This does not scan your network. It only attempts TCP/UDP localhost traffic to 127.0.0.1."),
        ]
    )
    packet_capture_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(item.get('capture_id', '')))}</td>
          <td>{html.escape(str(item.get('status', '')))}</td>
          <td>{html.escape(str(item.get('interface', '')))}</td>
          <td>{html.escape(str(item.get('duration_seconds', '')))}</td>
          <td>{html.escape(str(item.get('filter', '')))}</td>
          <td>{html.escape(str(item.get('pcap_path', '')))}</td>
          <td>{html.escape(str(item.get('pcap_sha256', '')))}</td>
        </tr>
        """
        for item in packet_captures
    ) or '<tr><td colspan="7">No packet captures recorded.</td></tr>'
    network_devices = network_discovery.get("devices", network_discovery.get("hosts", []))
    network_host_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(item.get('ip_address', '')))}</td>
          <td>{html.escape(str(item.get('likely_hostname', '') or 'Unknown Host'))}</td>
          <td>{html.escape(str(item.get('mac_address', '')))}</td>
          <td>{html.escape(str(item.get('vendor', item.get('vendor_guess', ''))))}</td>
          <td>{html.escape(str(item.get('device_type', '')))}</td>
          <td>{html.escape(str(item.get('interface', '')))}</td>
          <td>{html.escape(', '.join(str(value) for value in item.get('discovery_methods', [])))}</td>
          <td>{html.escape(', '.join(
              value for value in [
                  str(item.get('hostname', '')),
                  str(item.get('mdns_name', '')),
                  str(item.get('reverse_dns', '')),
                  str(item.get('netbios_name', '')),
                  str(item.get('dhcp_hostname', '')),
              ] if value
          ) or 'none')}</td>
          <td>{html.escape(str(item.get('confidence', '')))}</td>
          <td>{html.escape(str(item.get('baseline_status', 'matched baseline')))}</td>
          <td>{html.escape('yes' if item.get('review_needed') else 'no')}</td>
          <td>{html.escape(', '.join(str(value) for value in item.get('review_flags', [])) or str(item.get('notes', '')))}</td>
        </tr>
        """
        for item in network_devices
    ) or '<tr><td colspan="11">No devices discovered. Check WiFi interface, subnet detection, and permissions.</td></tr>'
    network_change_rows = "".join(
        f"<tr><td>{html.escape(str(change_type).replace('_', ' ').title())}</td><td>{html.escape(json.dumps(item, sort_keys=True))}</td></tr>"
        for change_type, items in network_discovery.get("comparison", {}).items()
        if isinstance(items, list)
        for item in items
    ) or '<tr><td colspan="2">No baseline changes.</td></tr>'
    suspicious_network_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(finding.get('severity', '')))}</td>
          <td>{html.escape(str(finding.get('title', '')))}</td>
          <td>{html.escape(str(finding.get('evidence', '')))}</td>
        </tr>
        """
        for finding in findings
        if finding.get("category") == "Network Discovery"
    ) or '<tr><td colspan="3">No suspicious devices identified.</td></tr>'
    logo_markup = report_logo_markup()
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>macOS Audit Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 32px; color: #10212b; background: #f5f7f9; }}
    .card {{ background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 18px #D0D7DE; margin-bottom: 20px; }}
    .report-brand {{ display: flex; align-items: center; gap: 16px; margin-bottom: 16px; }}
    .report-brand-subtitle {{ margin: 0; color: #50626f; letter-spacing: 0.04em; font-size: 12px; }}
    .report-logo {{ width: 72px; height: 72px; object-fit: contain; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }}
    .metric {{ background: #eef4f7; border-radius: 10px; padding: 12px; }}
    .metric-label {{ display: block; font-size: 12px; text-transform: uppercase; color: inherit; }}
    .metric-value {{ display: block; font-size: 28px; font-weight: 700; margin-top: 8px; color: inherit; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #d9e1e7; padding: 10px; text-align: left; vertical-align: top; }}
    .severity-badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; display: inline-block; }}
    .severity-info {{ background-color: #2C3E50; color: #ECF0F1; }}
    .severity-low {{ background-color: #27AE60; color: #FFFFFF; }}
    .severity-medium {{ background-color: #F39C12; color: #000000; }}
    .severity-high {{ background-color: #E74C3C; color: #FFFFFF; }}
    .severity-critical {{ background-color: #8E0000; color: #FFFFFF; }}
  </style>
</head>
<body>
  <div class="card">
    {logo_markup}
    <h2>Report Summary</h2>
    <p>Scan Timestamp: {html.escape(format_utc_timestamp(scan_result.timestamp))}</p>
    <p>Scan ID: {html.escape(scan_result.scan_id)}</p>
    <p>Hostname: {html.escape(scan_result.hostname)}</p>
    <p>Current User: {html.escape(scan_result.current_user)}</p>
    <p>Security Score: {html.escape('unavailable' if score is None else f'{score}/100')} &mdash; {html.escape(score_label)}</p>
    <p>Higher is better. This score is based on findings severity, not proof of compromise.</p>
  </div>
  <div class="card">
    <h2>Severity Summary</h2>
    <div class="metrics">{severity_cards}</div>
  </div>
  <div class="card">
    <h2>Ports and Processes Overview</h2>
    <div class="metrics">{overview_cards}</div>
  </div>
  <div class="card">
    <h2>Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Evidence</th><th>Command/Source</th><th>Recommendations</th><th>What Can Go Wrong</th></tr></thead>
      <tbody>{findings_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Ports</h2>
    <table>
      <thead><tr><th>Process</th><th>PID</th><th>Protocol</th><th>Local Address</th><th>Port</th><th>State</th><th>Review Needed</th></tr></thead>
      <tbody>{ports_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Processes</h2>
    <table>
      <thead><tr><th>User</th><th>PID</th><th>PPID</th><th>Path</th><th>Trust</th><th>Score</th><th>Reasons</th></tr></thead>
      <tbody>{processes_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Localhost Port Scan</h2>
    <table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>{localhost_rows}</tbody></table>
  </div>
  <div class="card">
    <h2>Packet Capture Snapshot</h2>
    <p>Privacy warning: packet captures may contain sensitive traffic metadata or contents. This report includes only local file metadata and paths, not packet contents.</p>
    <table>
      <thead><tr><th>Capture ID</th><th>Status</th><th>Interface</th><th>Duration Seconds</th><th>Filter</th><th>PCAP Path</th><th>SHA256</th></tr></thead>
      <tbody>{packet_capture_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Network Discovery</h2>
    <p>This scan identifies devices visible on your local network. A new or unknown device is not proof of compromise, but it may be worth investigating if you do not recognize it.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>
        <tr><td>Interface</td><td>{html.escape(str(network_discovery.get('interface', '')))}</td></tr>
        <tr><td>Subnet</td><td>{html.escape(str(network_discovery.get('subnet', '')))}</td></tr>
        <tr><td>Scope</td><td>{html.escape(str(network_discovery.get('scope', '')))}</td></tr>
        <tr><td>Gateway</td><td>{html.escape(str(network_discovery.get('gateway', '')))}</td></tr>
        <tr><td>Gateway IP</td><td>{html.escape(str(network_discovery.get('gateway_ip', network_discovery.get('gateway', ''))))}</td></tr>
        <tr><td>Gateway MAC</td><td>{html.escape(str(network_discovery.get('gateway_mac', '')) or 'unknown')}</td></tr>
        <tr><td>Host Count</td><td>{html.escape(str(network_discovery.get('host_count', len(network_discovery.get('hosts', [])))))}</td></tr>
        <tr><td>Review Needed Devices</td><td>{html.escape(str(network_discovery.get('review_needed_count', 0)))}</td></tr>
        <tr><td>Methods Used</td><td>{html.escape(', '.join(str(item) for item in network_discovery.get('methods_used', [])) or 'none')}</td></tr>
      </tbody>
    </table>
    <h3>Discovered Hosts</h3>
    <table>
      <thead><tr><th>IP</th><th>Likely Hostname</th><th>MAC</th><th>Vendor</th><th>Device Type</th><th>Methods</th><th>Hostname Sources</th><th>Confidence</th><th>Baseline Status</th><th>Review Needed</th><th>Review Flags</th></tr></thead>
      <tbody>{network_host_rows}</tbody>
    </table>
    <h3>Baseline Changes</h3>
    <table>
      <thead><tr><th>Change</th><th>Details</th></tr></thead>
      <tbody>{network_change_rows}</tbody>
    </table>
    <h3>Suspicious / Review Needed Devices</h3>
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Evidence</th></tr></thead>
      <tbody>{suspicious_network_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Collector Errors</h2>
    <table>
      <thead><tr><th>Collector</th><th>Error</th></tr></thead>
      <tbody>{collector_error_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Raw Logs</h2>
    <table>
      <thead><tr><th>Collector</th><th>Command/Source</th><th>Timestamp</th><th>Exit Code</th><th>stderr</th><th>stdout</th></tr></thead>
      <tbody>{raw_logs_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Baseline Comparison</h2>
    <p>Drift score: {html.escape(str(scan_result.baseline_diff.get('drift_score', 0)))}/100 | Label: {html.escape(str(scan_result.baseline_diff.get('drift_label', 'stable')))} | High-risk changes: {html.escape(str(scan_result.baseline_diff.get('high_risk_change_count', 0)))}</p>
    <p>{html.escape(str(scan_result.baseline_diff.get('drift_summary', '')))}</p>
    <table><thead><tr><th>Change</th><th>Count</th></tr></thead><tbody>{baseline_rows}</tbody></table>
  </div>
  <div class="card">
    <h2>History Indicators</h2>
    <table><thead><tr><th>Shell</th><th>Pattern</th><th>Matches</th><th>Redacted Evidence</th></tr></thead><tbody>{history_rows}</tbody></table>
  </div>
</body>
</html>
"""
    if include_background_monitor_logs:
        event_rows = "".join(
            f"<tr><td>{html.escape(str(item.get('timestamp', '')))}</td><td>{html.escape(str(item.get('event_type', '')))}</td><td>{html.escape(str(item.get('severity', '')))}</td><td>{html.escape(str(item.get('source', '')))}</td><td>{html.escape(str(item.get('process_name', '')))}</td><td>{html.escape(str(item.get('confidence', '')))}</td><td>{html.escape(str(item.get('evidence', '')))}</td></tr>"
            for item in background_monitor_events
        )
        document = document.replace(
            "</body>",
            (
                "<div class='card'><h2>Background Monitor Events</h2><p>Optional local privacy and session indicators. "
                "These logs do not contain camera images, audio, screen contents, keystrokes, or packet contents.</p>"
                "<table><thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Source</th><th>Process</th><th>Confidence</th><th>Evidence</th></tr></thead>"
                f"<tbody>{event_rows}</tbody></table></div></body>"
            ),
        )
    if include_investigation_notes:
        note_rows = "".join(
            f"<tr><td>{html.escape(str(item.get('updated_at', '')))}</td><td>{html.escape(str(item.get('title', '')))}</td><td>{html.escape(str(item.get('status', '')))}</td><td>{html.escape(str(item.get('priority', '')))}</td><td>{html.escape(str(item.get('linked_finding_id', '')))}</td><td>{html.escape(str(item.get('body', '')))}</td></tr>"
            for item in (investigation_notes or [])
        )
        audit_rows = "".join(
            f"<tr><td>{html.escape(str(item.get('timestamp', '')))}</td><td>{html.escape(str(item.get('action_type', '')))}</td><td>{html.escape(str(item.get('details', '')))}</td><td>{html.escape(str(item.get('previous_status', '')))}</td><td>{html.escape(str(item.get('new_status', '')))}</td></tr>"
            for item in (investigation_audit_trail or [])
        )
        document = document.replace(
            "</body>",
            (
                "<div class='card'><h2>Investigation Notes</h2><p>These notes may contain sensitive case information and remain local to the exported report.</p>"
                "<table><thead><tr><th>Updated</th><th>Title</th><th>Status</th><th>Priority</th><th>Finding</th><th>Body</th></tr></thead>"
                f"<tbody>{note_rows}</tbody></table><h3>Review Audit Trail</h3><table><thead><tr><th>Timestamp</th><th>Action</th><th>Details</th><th>Previous</th><th>New</th></tr></thead><tbody>{audit_rows}</tbody></table></div></body>"
            ),
        )
    output_path.write_text(document, encoding="utf-8")
    return output_path


def _serialize_notes(notes: list[dict], *, redact: bool) -> list[dict]:
    if not redact:
        return notes
    serialized = []
    for item in notes:
        cleaned = dict(item)
        cleaned["body"] = "[REDACTED]"
        serialized.append(cleaned)
    return serialized
