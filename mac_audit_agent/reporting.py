from __future__ import annotations

import html
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from mac_audit_agent.assets import get_asset_data_uri
from mac_audit_agent.investigation_priority import build_investigation_priority_report_from_scan
from mac_audit_agent.cve_radar import group_forecast_cards_for_display
from mac_audit_agent.execution_evidence import ExecutionEvidenceEngine
from mac_audit_agent.evidence_graph import EvidenceGraphBuilder
from mac_audit_agent.explanations import ensure_finding_explanations
from mac_audit_agent.frameworks import framework_summary_for_findings, mappings_for_finding
from mac_audit_agent.models import BaselineComparison, Finding, ScanResult, ScanSummary
from mac_audit_agent.nmap_wrapper import NMAP_CREDIT_TEXT, NMAP_URL
from mac_audit_agent.privacy import redact_structure, redact_text
from mac_audit_agent.security_timeline import SecurityTimelineBuilder
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


def _production_forecast_cards(apple_security_forecast: dict) -> list[dict]:
    cards = apple_security_forecast.get("display_cards", [])
    if not cards and apple_security_forecast.get("cards"):
        cards = group_forecast_cards_for_display(apple_security_forecast.get("cards", []))
    filtered: list[dict] = []
    for card in cards or []:
        if not isinstance(card, dict):
            continue
        if card.get("simulated") or str(card.get("source_mode", "")).startswith("demo"):
            continue
        if str(card.get("applicability", card.get("applicability_confidence", ""))) == "review_needed":
            continue
        if str(card.get("forecast_level", "clear")) == "clear":
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
        filtered.append(card)
    return filtered


def get_reports_dir() -> Path:
    base = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "reports"
    base.mkdir(parents=True, exist_ok=True)
    return base


def finding_to_dict(finding) -> dict:
    if isinstance(finding, dict):
        return ensure_finding_explanations(finding)
    if hasattr(finding, "to_dict"):
        return ensure_finding_explanations(finding.to_dict())
    if hasattr(finding, "__dict__"):
        return ensure_finding_explanations(dict(finding.__dict__))
    return {}


def _framework_mapping_summary_text(finding: dict) -> str:
    mappings = mappings_for_finding(finding)
    if not mappings:
        return "Unmapped"
    grouped: dict[str, list[str]] = {}
    for mapping in mappings:
        label = {
            "NIST_CSF_2_0": "NIST CSF 2.0",
            "NIST_800_53_REV5": "NIST SP 800-53 Rev. 5",
            "NIST_800_61_REV3": "NIST SP 800-61 Rev. 3",
            "MITRE_ATTACK_MACOS": "MITRE ATT&CK macOS",
            "CISA_KEV": "CISA KEV",
            "NVD_CVE": "NVD/CVE",
        }.get(mapping.framework, mapping.framework)
        value = f"{mapping.id} {mapping.name}".strip()
        grouped.setdefault(label, [])
        if value not in grouped[label]:
            grouped[label].append(value)
    return "; ".join(f"{framework}: {', '.join(values)}" for framework, values in grouped.items())


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


def execution_evidence_from_scan(scan_result: ScanResult) -> list[dict]:
    return [item.to_dict() for item in ExecutionEvidenceEngine().analyze_scan(scan_result)]


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
        f"<tr><td>{html.escape(str(item.get('timestamp', '')))}</td><td>{html.escape(str(item.get('event_type', '')))}</td><td>{html.escape(str(item.get('severity', '')))}</td><td>{html.escape(str(item.get('source', '')))}</td><td>{html.escape(str(item.get('rule_id', item.get('trigger_rule_id', ''))))}</td><td>{html.escape(str(item.get('trigger_source', '')))}</td><td>{html.escape(str(item.get('confidence', '')))}</td><td>{html.escape(str(item.get('previous_state', '')))}</td><td>{html.escape(str(item.get('current_state', '')))}</td><td>{html.escape(str(item.get('evidence', '')))}</td></tr>"
        for item in events
    )
    logo_markup = report_logo_markup()
    output_path.write_text(
        (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Background Monitor Events</title></head><body>"
            f"{logo_markup}<h1>Background Monitor Events</h1><table border='1'><thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Source</th><th>Rule ID</th><th>Trigger Source</th><th>Confidence</th><th>Previous State</th><th>Current State</th><th>Evidence</th></tr></thead>"
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
    investigation_priorities: dict | None = None,
    reliability: dict | None = None,
) -> Path:
    output_path = output_path or default_json_report_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json_safe(scan_result.to_dict())
    ports = payload.get("collected_artifacts", {}).get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []})
    processes = payload.get("collected_artifacts", {}).get("processes", {"all": [], "suspicious": [], "errors": []})
    localhost_scan = payload.get("collected_artifacts", {}).get("localhost_scan", {})
    nmap_scan = localhost_scan.get("nmap", {}) if isinstance(localhost_scan, dict) else {}
    packet_captures = payload.get("collected_artifacts", {}).get("packet_captures", [])
    network_discovery = payload.get("collected_artifacts", {}).get("network_discovery", {})
    apple_security_forecast = payload.get("collected_artifacts", {}).get("apple_security_forecast", payload.get("collected_artifacts", {}).get("cve_radar", {}))
    reliability = reliability or payload.get("collected_artifacts", {}).get("reliability", payload.get("reliability", {})) or {}
    visibility_integrity = payload.get("collected_artifacts", {}).get("visibility_integrity", {})
    baseline_drift = payload.get("collected_artifacts", {}).get("baseline_drift", {})
    security_timeline = payload.get("collected_artifacts", {}).get("security_timeline", {})
    system_integrity = payload.get("collected_artifacts", {}).get("system_integrity", {})
    evidence_graph = payload.get("collected_artifacts", {}).get("evidence_graph", {})
    ioc_matches = payload.get("collected_artifacts", {}).get("ioc_matches", {})
    if apple_security_forecast:
        production_cards = _production_forecast_cards(apple_security_forecast)
        apple_security_forecast = dict(apple_security_forecast)
        apple_security_forecast["display_cards"] = production_cards
        apple_security_forecast["cards"] = production_cards
        apple_security_forecast["alerts"] = production_cards
        apple_security_forecast["simulated"] = False
        payload.setdefault("collected_artifacts", {})["apple_security_forecast"] = apple_security_forecast
        payload.setdefault("collected_artifacts", {})["cve_radar"] = apple_security_forecast
    intrusion_correlation = payload.get("collected_artifacts", {}).get("intrusion_correlation", payload.get("intrusion_correlation", {}))
    execution_evidence = execution_evidence_from_scan(scan_result)
    investigation_priorities = investigation_priorities or build_investigation_priority_report_from_scan(scan_result).to_dict()
    if not security_timeline:
        security_timeline = SecurityTimelineBuilder().build(
            scan_result=scan_result,
            monitor_events=background_monitor_events or [],
            notes=investigation_notes or [],
        )
    if not evidence_graph:
        evidence_graph = EvidenceGraphBuilder().build_from_scan_result(scan_result, monitor_events=background_monitor_events or []).to_dict()
    framework_summary = framework_summary_for_findings([finding_to_dict(finding) for finding in scan_result.findings])
    score, score_label = score_from_findings(scan_result.findings)
    payload["security_score"] = score
    payload["score_label"] = score_label
    payload["apple_security_forecast"] = apple_security_forecast
    payload["reliability"] = reliability
    payload["visibility_integrity"] = visibility_integrity
    payload["baseline_drift"] = baseline_drift
    payload["security_timeline"] = security_timeline
    payload["system_integrity"] = system_integrity
    payload["evidence_graph"] = evidence_graph
    payload["ioc_matches"] = ioc_matches
    payload["intrusion_correlation"] = intrusion_correlation
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
        "nmap_scan": nmap_scan,
        "packet_captures": packet_captures,
        "network_discovery": network_discovery,
        "apple_security_forecast": apple_security_forecast,
        "reliability": reliability,
        "visibility_integrity": visibility_integrity,
        "baseline_drift": baseline_drift,
        "security_timeline": security_timeline,
        "system_integrity": system_integrity,
        "evidence_graph": evidence_graph,
        "ioc_matches": ioc_matches,
        "intrusion_correlation": intrusion_correlation,
        "framework_summary": framework_summary,
        "execution_evidence": execution_evidence,
        "investigation_priorities": investigation_priorities,
        "alert_storm_summaries": [
            {
                "timestamp": item.get("timestamp", ""),
                "event_count": item.get("metadata", {}).get("event_count", item.get("evidence", "")),
                "evidence": item.get("evidence", ""),
                "correlation_id": item.get("correlation_id", ""),
                "source_trace": item.get("source_trace", ""),
            }
            for item in payload.get("background_monitor_events", [])
            if item.get("event_type") == "alert_storm_detected"
        ],
        "packet_capture_privacy_warning": "Packet captures may contain sensitive traffic metadata or contents. Reports include only local metadata and file paths, not packet contents.",
    }
    if nmap_scan and not nmap_scan.get("fallback_used"):
        payload["report_summary"]["nmap_credit"] = f"{NMAP_CREDIT_TEXT} {NMAP_URL}"
    if execution_evidence:
        payload["report_summary"]["execution_evidence_count"] = len(execution_evidence)
    payload["report_summary"]["investigation_priorities"] = {
        "generated_at": investigation_priorities.get("generated_at", ""),
        "summary": investigation_priorities.get("summary", ""),
        "top_3_count": len(investigation_priorities.get("top_3", [])),
        "top_10_count": len(investigation_priorities.get("top_10", [])),
        "full_queue_count": len(investigation_priorities.get("full_queue", [])),
    }
    production_forecast_cards = _production_forecast_cards(apple_security_forecast) if apple_security_forecast else []
    payload["report_summary"]["apple_security_forecast_summary"] = {
        "generated_at": apple_security_forecast.get("generated_at", apple_security_forecast.get("timestamp", "")) if apple_security_forecast else "",
        "level": apple_security_forecast.get("level", apple_security_forecast.get("forecast_level", "")) if apple_security_forecast else "clear",
        "sources_used": apple_security_forecast.get("sources_used", []) if apple_security_forecast else [],
        "cve_count": apple_security_forecast.get("cve_count", apple_security_forecast.get("cves_evaluated", 0)) if apple_security_forecast else 0,
        "kev_count": apple_security_forecast.get("kev_count", apple_security_forecast.get("kev_matches", 0)) if apple_security_forecast else 0,
        "cards": production_forecast_cards,
        "simulated": False,
        "cache_age": apple_security_forecast.get("cache_age_text", "unknown") if apple_security_forecast else "unknown",
        "apple_source_status": apple_security_forecast.get("apple_source_status", "") if apple_security_forecast else "",
        "kev_source_status": apple_security_forecast.get("kev_source_status", "") if apple_security_forecast else "",
        "epss_source_status": apple_security_forecast.get("epss_source_status", "") if apple_security_forecast else "",
        "errors": apple_security_forecast.get("errors", []) if apple_security_forecast else [],
    }
    payload["report_summary"]["intrusion_correlation_summary"] = {
        "generated_at": intrusion_correlation.get("generated_at", ""),
        "scan_id": intrusion_correlation.get("scan_id", ""),
        "patterns": len(intrusion_correlation.get("patterns", [])),
        "top_patterns": len(intrusion_correlation.get("top_patterns", [])),
        "coverage": intrusion_correlation.get("coverage", {}).get("score", 0) if intrusion_correlation else 0,
        "user_presence": intrusion_correlation.get("user_presence", {}).get("state", "unknown") if intrusion_correlation else "unknown",
        "ai_summary_path": intrusion_correlation.get("ai_summary_path", "") if intrusion_correlation else "",
    }
    payload["report_summary"]["reliability_summary"] = {
        "alert_last_failure_stage": reliability.get("alert_pipeline", {}).get("last_failure_stage", "") if reliability else "",
        "suppressed_count": reliability.get("alert_pipeline", {}).get("suppressed_count", 0) if reliability else 0,
        "no_policy_match_count": reliability.get("alert_pipeline", {}).get("no_policy_match_count", 0) if reliability else 0,
        "db_path_mismatch": reliability.get("alert_pipeline", {}).get("db_path_mismatch", False) if reliability else False,
        "monitoring_coverage_score": reliability.get("monitoring_coverage", {}).get("score", 0) if reliability else 0,
        "release_readiness_score": reliability.get("release_readiness", {}).get("ReleaseReadinessScore", 0) if reliability else 0,
        "release_readiness_status": reliability.get("release_readiness", {}).get("status", "unknown") if reliability else "unknown",
        "trust_current_score": reliability.get("trust_decay", {}).get("current_score", 0) if reliability else 0,
        "trust_previous_score": reliability.get("trust_decay", {}).get("previous_score", 0) if reliability else 0,
        "trust_delta": reliability.get("trust_decay", {}).get("delta", 0) if reliability else 0,
        "trust_trend": reliability.get("trust_decay", {}).get("trend", "unknown") if reliability else "unknown",
        "configuration_drift_changes": len(reliability.get("configuration_drift", {}).get("changes", [])) if reliability else 0,
        "incident_mode_active": reliability.get("incident_mode", {}).get("active", False) if reliability else False,
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
          {"<br><br><strong>Technical Explanation:</strong><br>" + html.escape(str(finding.get('technical_explanation', ''))) if finding.get('technical_explanation') else ""}
          {"<br><br><strong>Plain-English Explanation:</strong><br>" + html.escape(str(finding.get('plain_english_explanation', ''))) if finding.get('plain_english_explanation') else ""}
          {"<br><br><strong>Analyst Next Step:</strong><br>" + html.escape(str(finding.get('analyst_next_step', ''))) if finding.get('analyst_next_step') else ""}
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
    investigation_priorities: dict | None = None,
    reliability: dict | None = None,
) -> Path:
    output_path = output_path or default_html_report_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    findings = [finding_to_dict(finding) for finding in scan_result.findings]
    background_monitor_events = background_monitor_events or []
    artifacts = json_safe(scan_result.to_dict()["collected_artifacts"])
    ports = artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []})
    processes = artifacts.get("processes", {"all": [], "suspicious": [], "errors": []})
    localhost_scan = artifacts.get("localhost_scan", {})
    nmap_scan = localhost_scan.get("nmap", {}) if isinstance(localhost_scan, dict) else {}
    packet_captures = artifacts.get("packet_captures", [])
    network_discovery = artifacts.get("network_discovery", {})
    apple_security_forecast = artifacts.get("apple_security_forecast", artifacts.get("cve_radar", {}))
    reliability = reliability or artifacts.get("reliability", {}) or {}
    visibility_integrity = artifacts.get("visibility_integrity", {}) or {}
    baseline_drift = artifacts.get("baseline_drift", {}) or {}
    security_timeline = artifacts.get("security_timeline", {}) or {}
    system_integrity = artifacts.get("system_integrity", {}) or {}
    evidence_graph = artifacts.get("evidence_graph", {}) or {}
    ioc_matches = artifacts.get("ioc_matches", {}) or {}
    if apple_security_forecast:
        production_cards = _production_forecast_cards(apple_security_forecast)
        apple_security_forecast = dict(apple_security_forecast)
        apple_security_forecast["display_cards"] = production_cards
        apple_security_forecast["cards"] = production_cards
        apple_security_forecast["alerts"] = production_cards
        apple_security_forecast["simulated"] = False
    intrusion_correlation = artifacts.get("intrusion_correlation", {})
    execution_evidence = execution_evidence_from_scan(scan_result)
    investigation_priorities = investigation_priorities or build_investigation_priority_report_from_scan(scan_result).to_dict()
    if not security_timeline:
        security_timeline = SecurityTimelineBuilder().build(
            scan_result=scan_result,
            monitor_events=background_monitor_events or [],
            notes=investigation_notes or [],
        )
    if not evidence_graph:
        evidence_graph = EvidenceGraphBuilder().build_from_scan_result(scan_result, monitor_events=background_monitor_events or []).to_dict()
    framework_summary = framework_summary_for_findings(findings)
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
    visibility_components = visibility_integrity.get("components", []) if isinstance(visibility_integrity, dict) else []
    visibility_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Overall Status", visibility_integrity.get("overall_status", "not recorded") if isinstance(visibility_integrity, dict) else "not recorded"),
            ("Visibility Integrity Score", visibility_integrity.get("score", visibility_integrity.get("VisibilityIntegrityScore", "not recorded")) if isinstance(visibility_integrity, dict) else "not recorded"),
            ("Degraded Components", len(visibility_integrity.get("degraded_components", [])) if isinstance(visibility_integrity, dict) else 0),
            ("Failing Components", len(visibility_integrity.get("failing_components", [])) if isinstance(visibility_integrity, dict) else 0),
        ]
    )
    visibility_component_rows = "".join(
        f"""
        <tr class="{severity_css_class('high' if item.get('status') == 'failing' else 'medium' if item.get('status') in {'degraded', 'disabled'} else 'info')}">
          <td>{html.escape(str(item.get('component_name', '')))}</td>
          <td>{html.escape(str(item.get('status', '')))}</td>
          <td>{html.escape(str(item.get('last_success', '')))}</td>
          <td>{html.escape(str(item.get('last_error', '')))}</td>
          <td>{html.escape(str(item.get('evidence', '')))}</td>
          <td>{html.escape(str(item.get('recommended_fix', '')))}</td>
        </tr>
        """
        for item in visibility_components
        if isinstance(item, dict)
    ) or '<tr><td colspan="6">Visibility Integrity was not recorded for this report.</td></tr>'
    baseline_drift_findings = baseline_drift.get("findings", []) if isinstance(baseline_drift, dict) else []
    baseline_drift_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Baseline Available", "yes" if baseline_drift.get("baseline_available") else "no"),
            ("Total Drift", baseline_drift.get("summary", {}).get("total", 0) if isinstance(baseline_drift.get("summary", {}), dict) else 0),
            ("Review Recommended", baseline_drift.get("summary", {}).get("review_recommended", 0) if isinstance(baseline_drift.get("summary", {}), dict) else 0),
            ("Suppressed Expected", baseline_drift.get("summary", {}).get("suppressed_expected", 0) if isinstance(baseline_drift.get("summary", {}), dict) else 0),
        ]
    )
    baseline_drift_rows = "".join(
        f"""
        <tr class="{severity_css_class(str(item.get('severity', 'info')))}">
          <td>{html.escape(str(item.get('category', '')))}</td>
          <td>{html.escape(str(item.get('change_type', 'changed')))}</td>
          <td>{html.escape(str(item.get('item_key', '')))}</td>
          <td>{html.escape(json.dumps(json_safe(item.get('previous_state', '')), sort_keys=True)[:500])}</td>
          <td>{html.escape(json.dumps(json_safe(item.get('current_state', '')), sort_keys=True)[:500])}</td>
          <td>{html.escape(str(item.get('severity', '')))}</td>
          <td>{html.escape(str(item.get('confidence', '')))}</td>
          <td>{html.escape(str(item.get('why_it_matters', '')))}</td>
          <td>{html.escape(str(item.get('recommended_verification', '')))}</td>
        </tr>
        """
        for item in baseline_drift_findings
        if isinstance(item, dict)
    ) or '<tr><td colspan="9">No baseline drift requiring review was recorded.</td></tr>'
    timeline_events = security_timeline.get("events", []) if isinstance(security_timeline, dict) else []
    timeline_summary = security_timeline.get("summary", {}) if isinstance(security_timeline, dict) else {}
    timeline_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Event Count", security_timeline.get("event_count", len(timeline_events)) if isinstance(security_timeline, dict) else 0),
            ("First Event", timeline_summary.get("first_event", "") if isinstance(timeline_summary, dict) else ""),
            ("Last Event", timeline_summary.get("last_event", "") if isinstance(timeline_summary, dict) else ""),
            ("Sources", ", ".join(f"{key}: {value}" for key, value in sorted((timeline_summary.get("by_source", {}) if isinstance(timeline_summary, dict) else {}).items()))),
        ]
    )
    timeline_rows = "".join(
        f"""
        <tr class="{severity_css_class(str(item.get('severity', 'info')))}">
          <td>{html.escape(str(item.get('timestamp', '')))}</td>
          <td>{html.escape(str(item.get('severity', '')))}</td>
          <td>{html.escape(str(item.get('event_type', '')))}</td>
          <td>{html.escape(str(item.get('source', '')))}</td>
          <td>{html.escape(str(item.get('title', '')))}</td>
          <td>{html.escape(str(item.get('summary', ''))[:700])}</td>
          <td>{html.escape(', '.join(str(tag) for tag in item.get('tags', [])))}</td>
        </tr>
        """
        for item in timeline_events
        if isinstance(item, dict)
    ) or '<tr><td colspan="7">No security timeline events recorded.</td></tr>'
    system_integrity_findings = system_integrity.get("findings", []) if isinstance(system_integrity, dict) else []
    system_integrity_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Finding Count", system_integrity.get("finding_count", len(system_integrity_findings)) if isinstance(system_integrity, dict) else 0),
            ("Checks Run", ", ".join(str(item) for item in system_integrity.get("checks_run", [])) if isinstance(system_integrity, dict) else ""),
            ("Generated At", system_integrity.get("generated_at", "") if isinstance(system_integrity, dict) else ""),
        ]
    )
    system_integrity_rows = "".join(
        f"""
        <tr class="{severity_css_class(str(item.get('severity', 'info')))}">
          <td>{html.escape(str(item.get('severity', '')))}</td>
          <td>{html.escape(str(item.get('title', '')))}</td>
          <td>{html.escape(str(item.get('confidence', '')))}</td>
          <td>{html.escape(str(item.get('evidence', ''))[:700])}</td>
          <td>{html.escape(str(item.get('false_positive_notes', '')))}</td>
          <td>{html.escape(str(item.get('recommended_next_steps', item.get('remediation_suggestion', ''))))}</td>
        </tr>
        """
        for item in system_integrity_findings
        if isinstance(item, dict)
    ) or '<tr><td colspan="6">No system integrity anomalies recorded.</td></tr>'
    graph_nodes = evidence_graph.get("nodes", []) if isinstance(evidence_graph, dict) else []
    graph_edges = evidence_graph.get("edges", []) if isinstance(evidence_graph, dict) else []
    graph_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Nodes", evidence_graph.get("node_count", len(graph_nodes)) if isinstance(evidence_graph, dict) else 0),
            ("Edges", evidence_graph.get("edge_count", len(graph_edges)) if isinstance(evidence_graph, dict) else 0),
            ("Generated At", evidence_graph.get("generated_at", "") if isinstance(evidence_graph, dict) else ""),
        ]
    )
    graph_node_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('node_type', '')))}</td><td>{html.escape(str(item.get('label', '')))}</td><td>{html.escape(str(item.get('summary', ''))[:500])}</td></tr>"
        for item in graph_nodes[:100]
        if isinstance(item, dict)
    ) or '<tr><td colspan="3">No evidence graph nodes recorded.</td></tr>'
    graph_edge_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('source_id', '')))}</td><td>{html.escape(str(item.get('edge_type', '')))}</td><td>{html.escape(str(item.get('target_id', '')))}</td><td>{html.escape(str(item.get('evidence', ''))[:500])}</td></tr>"
        for item in graph_edges[:150]
        if isinstance(item, dict)
    ) or '<tr><td colspan="4">No evidence graph edges recorded.</td></tr>'
    ioc_match_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(item.get('indicator', '')))}</td>
          <td>{html.escape(str(item.get('indicator_type', '')))}</td>
          <td>{html.escape(str(item.get('matched_value', '')))}</td>
          <td>{html.escape(str(item.get('source', '')))}</td>
          <td>{html.escape(str(item.get('confidence', '')))}</td>
          <td>{html.escape(str(item.get('recommended_action', '')))}</td>
        </tr>
        """
        for item in (ioc_matches.get("matches", []) if isinstance(ioc_matches, dict) else [])
        if isinstance(item, dict)
    ) or '<tr><td colspan="6">No offline IOC matches recorded.</td></tr>'
    ioc_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Indicators Loaded", ioc_matches.get("indicators_loaded", 0) if isinstance(ioc_matches, dict) else 0),
            ("Match Count", ioc_matches.get("match_count", 0) if isinstance(ioc_matches, dict) else 0),
            ("Local Only", "yes" if (ioc_matches.get("local_only", True) if isinstance(ioc_matches, dict) else True) else "no"),
            ("Upload Performed", "yes" if (ioc_matches.get("upload_performed", False) if isinstance(ioc_matches, dict) else False) else "no"),
            ("Automatic Blocking", "yes" if (ioc_matches.get("blocking_performed", False) if isinstance(ioc_matches, dict) else False) else "no"),
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
          <br><br><strong>Framework Mappings:</strong><br>{html.escape(_framework_mapping_summary_text(finding))}
          {"<br><br><strong>Technical Explanation:</strong><br>" + html.escape(str(finding.get('technical_explanation', ''))) if finding.get('technical_explanation') else ""}
          {"<br><br><strong>Plain-English Explanation:</strong><br>" + html.escape(str(finding.get('plain_english_explanation', ''))) if finding.get('plain_english_explanation') else ""}
          {"<br><br><strong>Analyst Next Step:</strong><br>" + html.escape(str(finding.get('analyst_next_step', ''))) if finding.get('analyst_next_step') else ""}
          {"<br><br><strong>Business Impact:</strong><br>" + html.escape(str(finding.get('business_impact', ''))) if finding.get('business_impact') else ""}
          {"<br><br><strong>Local Network Impact:</strong><br>" + html.escape(str(finding.get('local_network_impact', ''))) if finding.get('local_network_impact') else ""}
          {"<br><br><strong>Privilege Escalation:</strong><br>" + html.escape(str(finding.get('privilege_escalation_context', ''))) if finding.get('privilege_escalation_context') else ""}
          {"<br><br><strong>References:</strong><br>" + "<br>".join(html.escape(str(item)) for item in finding.get('remediation_references', [])) if finding.get('remediation_references') else ""}</td>
          <td>{html.escape(str(finding.get('what_can_go_wrong', finding.get('warning', ''))))}</td>
        </tr>
        """
        for finding in findings
    )
    provenance_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(finding.get('title', '')))}</td>
          <td>{html.escape(str(finding.get('rule_id', finding.get('trigger_rule_id', ''))))}</td>
          <td>{html.escape(str(finding.get('trigger_source', '')))}</td>
          <td>{html.escape(str(finding.get('trigger_subsource', '')))}</td>
          <td>{html.escape(str(finding.get('confidence', '')))}</td>
          <td>{html.escape(str(finding.get('previous_state', '')))}</td>
          <td>{html.escape(str(finding.get('current_state', '')))}</td>
          <td>{html.escape(str(finding.get('correlation_id', '')))}</td>
          <td>{html.escape(', '.join(str(item) for item in finding.get('false_positive_hints', [])) or str(finding.get('false_positive_notes', '')))}</td>
          <td>{html.escape(', '.join(str(item) for item in finding.get('recommended_verification_steps', [])) or ', '.join(str(item) for item in finding.get('verification_steps', [])))}</td>
        </tr>
        """
        for finding in findings
    ) or '<tr><td colspan="10">No provenance data recorded.</td></tr>'
    framework_summary_rows = "".join(
        f"<tr><td>{html.escape(str(section))}</td><td>{html.escape(str(name))}</td><td>{html.escape(str(count))}</td></tr>"
        for section, values in [
            ("NIST CSF 2.0", framework_summary.get("nist_csf", {})),
            ("MITRE ATT&CK macOS", framework_summary.get("mitre_attack_macos", {})),
            ("NIST SP 800-53 Rev. 5", framework_summary.get("nist_800_53_controls", {})),
            ("Top MITRE Techniques", framework_summary.get("top_mitre_techniques", {})),
        ]
        for name, count in (values or {}).items()
    ) or '<tr><td colspan="3">No framework mappings recorded.</td></tr>'
    unmapped_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('category', '')))}</td><td>{html.escape(str(item.get('title', '')))}</td></tr>"
        for item in framework_summary.get("unmapped_findings", [])
    ) or '<tr><td colspan="2">No unmapped findings.</td></tr>'
    investigation_priority_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Generated At", investigation_priorities.get("generated_at", "")),
            ("Summary", investigation_priorities.get("summary", "")),
            ("Top 3 Count", len(investigation_priorities.get("top_3", []))),
            ("Top 10 Count", len(investigation_priorities.get("top_10", []))),
            ("Full Queue Count", len(investigation_priorities.get("full_queue", []))),
        ]
    )
    investigation_priority_rows = "".join(
        f"""
        <tr class="{severity_css_class(str(item.get('severity', 'info')))}">
          <td>{html.escape(str(index + 1))}</td>
          <td>{html.escape(str(item.get('title', '')))}</td>
          <td>{html.escape(str(item.get('rank_score', item.get('priority_score', ''))))}</td>
          <td>{html.escape(str(item.get('severity', '')))}</td>
          <td>{html.escape(str(item.get('confidence', '')))}</td>
          <td>{html.escape(str(item.get('why_ranked_here', '')))}</td>
          <td>{html.escape(str(item.get('recommended_next_action', '')))}</td>
          <td>{html.escape(str(item.get('estimated_investigation_effort', '')))}</td>
        </tr>
        """
        for index, item in enumerate(investigation_priorities.get("top_10", []) or investigation_priorities.get("full_queue", []))
    ) or '<tr><td colspan="8">No investigation priorities available.</td></tr>'
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
    nmap_ports = nmap_scan.get("ports", []) if isinstance(nmap_scan, dict) else []
    nmap_summary_rows = "".join(
        f"<tr><td>{html.escape(label)}</td><td>{html.escape(value)}</td></tr>"
        for label, value in [
            ("Nmap Installed", "yes" if nmap_scan.get("installed") else "no"),
            ("Nmap Path", str(nmap_scan.get("path", "")) or "unavailable"),
            ("Scan Profile", str(nmap_scan.get("profile", "")) or str(nmap_scan.get("profiles", "")) or "not run"),
            ("Target", str(nmap_scan.get("target", localhost_scan.get("target", "127.0.0.1")))),
            ("Command Used", " | ".join(str(item) for item in nmap_scan.get("command_used", [])) if isinstance(nmap_scan.get("command_used"), list) else str(nmap_scan.get("command_used", ""))),
            ("Sudo Required", "yes" if nmap_scan.get("sudo_required") else "no"),
            ("Fallback Used", "yes" if nmap_scan.get("fallback_used") else "no"),
            ("Warnings", "; ".join(str(item) for item in nmap_scan.get("warnings", [])) or "none"),
            ("Errors", "; ".join(str(item) for item in nmap_scan.get("errors", [])) or "none"),
        ]
    )
    nmap_port_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(item.get('protocol', '')))}</td>
          <td>{html.escape(str(item.get('port', '')))}</td>
          <td>{html.escape(str(item.get('state', '')))}</td>
          <td>{html.escape(str(item.get('service', '')))}</td>
          <td>{html.escape(str(item.get('product', '')))}</td>
          <td>{html.escape(str(item.get('version', '')))}</td>
          <td>{html.escape(str(item.get('reason', '')))}</td>
          <td>{html.escape(str(item.get('confidence', '')))}</td>
        </tr>
        """
        for item in nmap_ports
    ) or '<tr><td colspan="8">No Nmap port findings recorded.</td></tr>'
    nmap_credit = f"<p>{html.escape(NMAP_CREDIT_TEXT)} <a href=\"{html.escape(NMAP_URL)}\">{html.escape(NMAP_URL)}</a></p>" if nmap_scan and not nmap_scan.get("fallback_used") else ""
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
    forecast_cards = _production_forecast_cards(apple_security_forecast) if apple_security_forecast else []
    forecast_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Assessment Updated", str(apple_security_forecast.get("generated_at", apple_security_forecast.get("timestamp", ""))) or "not run"),
            ("Assessment Level", str(apple_security_forecast.get("level", apple_security_forecast.get("forecast_level", "clear")))),
            ("Sources Used", ", ".join(str(item) for item in apple_security_forecast.get("sources_used", [])) or "none"),
            ("CVEs Evaluated", str(apple_security_forecast.get("cve_count", apple_security_forecast.get("cves_evaluated", 0)))),
            ("Applicable Cards", str(len(forecast_cards))),
            ("KEV Matches", str(apple_security_forecast.get("kev_count", apple_security_forecast.get("kev_matches", 0)))),
            ("Apple Updates Available", "yes" if apple_security_forecast.get("level") in {"elevated", "urgent"} or apple_security_forecast.get("apple_updates_available") else "no"),
            ("Cache Age", str(apple_security_forecast.get("cache_age_text", apple_security_forecast.get("cache_age", "unknown")))),
            ("Apple Source Status", str(apple_security_forecast.get("apple_source_status", "unknown")) or "unknown"),
            ("KEV Source Status", str(apple_security_forecast.get("kev_source_status", "unknown")) or "unknown"),
            ("EPSS Source Status", str(apple_security_forecast.get("epss_source_status", "unknown")) or "unknown"),
            ("Production Cards Only", "yes"),
        ]
    )
    if not apple_security_forecast or not forecast_cards:
        forecast_summary_rows += '<tr><td colspan="2">Apple Exposure Assessment: no applicable cards at report time.</td></tr>'
    forecast_rows = "".join(
        f"""
        <tr class="{severity_css_class(str(card.get('severity', 'info')))}">
          <td>{html.escape(str(card.get('title', card.get('cve_id', ''))))}</td>
          <td>{html.escape(', '.join(str(item) for item in card.get('cve_ids', card.get('cves', []))) or str(card.get('cve_id', '')))}</td>
          <td>{html.escape(str(card.get('source', '')))}</td>
          <td>{html.escape(str(card.get('forecast_level', card.get('severity', ''))))}</td>
          <td>{html.escape(str(card.get('applicability_confidence', card.get('confidence', ''))))}</td>
          <td>{html.escape('yes' if card.get('kev') or card.get('kev_cves') else 'no')}</td>
          <td>{html.escape('yes' if card.get('apple_related') or card.get('source') == 'apple' else 'no')}</td>
          <td>{html.escape(str(card.get('recommended_action', card.get('what_to_do', ''))))}</td>
          <td>{html.escape(str(card.get('status', '')))}</td>
          <td>{html.escape(str(card.get('why_shown_to_you', card.get('why_shown', card.get('why_it_matters', '')))))} </td>
        </tr>
        """
        for card in forecast_cards
    ) or '<tr><td colspan="10">Apple Exposure Assessment: no applicable cards at report time.</td></tr>'
    intrusion_patterns = intrusion_correlation.get("patterns", []) if isinstance(intrusion_correlation, dict) else []
    intrusion_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Generated", str(intrusion_correlation.get("generated_at", "")) or "not run"),
            ("Patterns", str(len(intrusion_patterns))),
            ("Coverage", str(intrusion_correlation.get("coverage", {}).get("score", 0) if intrusion_correlation else 0)),
            ("User Presence", str(intrusion_correlation.get("user_presence", {}).get("state", "unknown") if intrusion_correlation else "unknown")),
            ("AI Summary", str(intrusion_correlation.get("ai_summary_path", "") or "local only")),
        ]
    )
    intrusion_rows = "".join(
        f"""
        <tr class="{severity_css_class(str(pattern.get('severity', 'info')))}">
          <td>{html.escape(str(pattern.get('title', '')))}</td>
          <td>{html.escape(str(pattern.get('severity', '')))}</td>
          <td>{html.escape(str(pattern.get('confidence', '')))}</td>
          <td>{html.escape(str(pattern.get('why_it_matters', '')))}</td>
          <td>{html.escape(', '.join(str(step) for step in pattern.get('recommended_next_steps', [])))}</td>
          <td>{html.escape(', '.join(str(step) for step in pattern.get('evidence_to_preserve', [])))}</td>
        </tr>
        """
        for pattern in intrusion_patterns
    ) or '<tr><td colspan="6">No correlated intrusion patterns identified from the current local evidence.</td></tr>'
    alert_pipeline = reliability.get("alert_pipeline", {}) if isinstance(reliability, dict) else {}
    monitoring_coverage = reliability.get("monitoring_coverage", {}) if isinstance(reliability, dict) else {}
    release_readiness = reliability.get("release_readiness", {}) if isinstance(reliability, dict) else {}
    trust_decay = reliability.get("trust_decay", {}) if isinstance(reliability, dict) else {}
    configuration_drift = reliability.get("configuration_drift", {}) if isinstance(reliability, dict) else {}
    incident_mode = reliability.get("incident_mode", {}) if isinstance(reliability, dict) else {}
    reliability_summary_rows = "".join(
        f"<tr><td>{html.escape(str(label))}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Alert Last Failure Stage", alert_pipeline.get("last_failure_stage", "none")),
            ("Suppressed Alerts", alert_pipeline.get("suppressed_count", 0)),
            ("No Policy Match", alert_pipeline.get("no_policy_match_count", 0)),
            ("DB Path Mismatch", "yes" if alert_pipeline.get("db_path_mismatch") else "no"),
            ("Monitoring Coverage Score", monitoring_coverage.get("MonitoringCoverageScore", monitoring_coverage.get("score", 0))),
            ("Release Readiness Score", release_readiness.get("ReleaseReadinessScore", 0)),
            ("Release Readiness Status", release_readiness.get("status", "unknown")),
            ("Trust Score", f"{trust_decay.get('previous_score', 0)} -> {trust_decay.get('current_score', 0)}"),
            ("Trust Delta", trust_decay.get("delta", 0)),
            ("Trust Trend", trust_decay.get("trend", "unknown")),
            ("Configuration Drift Changes", len(configuration_drift.get("changes", []))),
            ("Incident Mode Active", "yes" if incident_mode.get("active") else "no"),
        ]
    )
    coverage_rows = "".join(
        f"""
        <tr class="{severity_css_class('high' if str(component.get('status', '')).lower() in {'failing', 'disabled'} else 'medium' if str(component.get('status', '')).lower() == 'degraded' else 'info')}">
          <td>{html.escape(str(component.get('component', component.get('name', ''))))}</td>
          <td>{html.escape(str(component.get('status', 'unknown')))}</td>
          <td>{html.escape(str(component.get('last_successful_run', '')))}</td>
          <td>{html.escape(str(component.get('last_event', '')))}</td>
          <td>{html.escape(str(component.get('last_error', '')))}</td>
          <td>{html.escape(str(component.get('heartbeat_age_seconds', '')))}</td>
          <td>{html.escape(str(component.get('permission_status', '')))}</td>
          <td>{html.escape(str(component.get('failure_reason', '')))}</td>
          <td>{html.escape(str(component.get('recommended_fix', '')))}</td>
        </tr>
        """
        for component in monitoring_coverage.get("components", [])
    ) or '<tr><td colspan="9">Monitoring coverage has not been calculated.</td></tr>'
    trust_timeline = trust_decay.get("score_history") or trust_decay.get("timeline", [])
    trust_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(item.get('created_at', item.get('timestamp', ''))))}</td>
          <td>{html.escape(str(item.get('previous_score', '')))}</td>
          <td>{html.escape(str(item.get('current_score', '')))}</td>
          <td>{html.escape(str(item.get('delta', '')))}</td>
          <td>{html.escape(', '.join(str(cause) for cause in item.get('causes', [])) or str(item.get('cause', item.get('reason', ''))))}</td>
          <td>{html.escape(str(item.get('recommended_action', '')))}</td>
        </tr>
        """
        for item in trust_timeline
    ) or '<tr><td colspan="6">No trust score changes recorded.</td></tr>'
    drift_rows = "".join(
        f"""
        <tr class="{severity_css_class(str(change.get('severity', 'info')))}">
          <td>{html.escape(str(change.get('setting', change.get('name', ''))))}</td>
          <td>{html.escape(str(change.get('previous_value', '')))}</td>
          <td>{html.escape(str(change.get('current_value', '')))}</td>
          <td>{html.escape(str(change.get('first_seen', '')))}</td>
          <td>{html.escape(str(change.get('last_seen', '')))}</td>
          <td>{html.escape(str(change.get('source_detector', '')))}</td>
          <td>{html.escape(str(change.get('confidence', '')))}</td>
          <td>{html.escape(str(change.get('why_it_matters', '')))}</td>
          <td>{html.escape(str(change.get('recommended_verification', change.get('recommended_action', ''))))}</td>
        </tr>
        """
        for change in configuration_drift.get("changes", [])
    ) or '<tr><td colspan="9">No configuration drift changes recorded.</td></tr>'
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
    execution_evidence_rows = "".join(
        f"""
        <tr>
          <td>{html.escape(str(item.get('confidence', 'low')).title())}</td>
          <td>{html.escape(str(item.get('title', '')))}</td>
          <td>{html.escape(" | ".join(
              f"{step.get('timestamp', '')} {step.get('event', '')}: {step.get('details', '')}".strip()
              for step in item.get('timeline', [])
          ))}</td>
          <td>{html.escape(str(item.get('explanation', '')))}</td>
          <td>{html.escape(", ".join(str(step) for step in item.get('next_steps', [])))}</td>
        </tr>
        """
        for item in execution_evidence
    ) or '<tr><td colspan="5">No execution evidence detected.</td></tr>'
    storm_events = [item for item in background_monitor_events if item.get("event_type") == "alert_storm_detected"]
    storm_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('timestamp', '')))}</td><td>{html.escape(str(item.get('evidence', '')))}</td><td>{html.escape(str(item.get('correlation_id', '')))}</td><td>{html.escape(str(item.get('source_trace', '')))}</td></tr>"
        for item in storm_events
    ) or '<tr><td colspan="4">No alert storms recorded.</td></tr>'
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
    <p>Execution evidence detection is local-only and evidence-based. It does not infer compromise.</p>
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
    <h2>Visibility Integrity</h2>
    <p>This section reports whether MSAA could verify its own monitoring visibility when the report was generated. Failures are shown explicitly.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{visibility_summary_rows}</tbody>
    </table>
    <h3>Component Statuses</h3>
    <table>
      <thead><tr><th>Component</th><th>Status</th><th>Last Success</th><th>Last Error</th><th>Evidence</th><th>Recommended Fix</th></tr></thead>
      <tbody>{visibility_component_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Baseline Drift</h2>
    <p>Baseline drift reports what changed since the trusted baseline. Changes are review signals only and are not labeled malicious.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{baseline_drift_summary_rows}</tbody>
    </table>
    <h3>Drift Findings</h3>
    <table>
      <thead><tr><th>Category</th><th>Change</th><th>Item</th><th>Previous State</th><th>Current State</th><th>Severity</th><th>Confidence</th><th>Why It Matters</th><th>Recommended Verification</th></tr></thead>
      <tbody>{baseline_drift_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Security Timeline</h2>
    <p>Chronological analyst timeline built from monitor events, findings, baseline drift, exposure updates, evidence snapshots, notes, and alert pipeline failures.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{timeline_summary_rows}</tbody>
    </table>
    <h3>Events</h3>
    <table>
      <thead><tr><th>Timestamp</th><th>Severity</th><th>Type</th><th>Source</th><th>Title</th><th>Summary</th><th>Tags</th></tr></thead>
      <tbody>{timeline_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>System Integrity</h2>
    <p>Evidence-based visibility and system integrity anomaly checks. This section does not claim malware or root-level compromise.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{system_integrity_summary_rows}</tbody>
    </table>
    <h3>Review Items</h3>
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Confidence</th><th>Evidence</th><th>False Positive Notes</th><th>Next Verification Steps</th></tr></thead>
      <tbody>{system_integrity_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Evidence Graph</h2>
    <p>List-based relationship graph connecting findings, users, processes, persistence, files, devices, network endpoints, events, and snapshots.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{graph_summary_rows}</tbody>
    </table>
    <h3>Nodes</h3>
    <table>
      <thead><tr><th>Type</th><th>Label</th><th>Summary</th></tr></thead>
      <tbody>{graph_node_rows}</tbody>
    </table>
    <h3>Edges</h3>
    <table>
      <thead><tr><th>From</th><th>Relationship</th><th>To</th><th>Evidence</th></tr></thead>
      <tbody>{graph_edge_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Offline IOC Matching</h2>
    <p>Local-only indicator matching. No telemetry upload, automatic blocking, or destructive remediation is performed.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{ioc_summary_rows}</tbody>
    </table>
    <h3>Matches</h3>
    <table>
      <thead><tr><th>Indicator</th><th>Type</th><th>Matched Value</th><th>Source</th><th>Confidence</th><th>Recommended Action</th></tr></thead>
      <tbody>{ioc_match_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Nmap Local Scan</h2>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{nmap_summary_rows}</tbody>
    </table>
    <h3>Parsed Ports</h3>
    <table>
      <thead><tr><th>Protocol</th><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Reason</th><th>Confidence</th></tr></thead>
      <tbody>{nmap_port_rows}</tbody>
    </table>
    {nmap_credit}
  </div>
  <div class="card">
    <h2>Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Evidence</th><th>Command/Source</th><th>Recommendations</th><th>What Can Go Wrong</th></tr></thead>
      <tbody>{findings_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Framework Summary</h2>
    <p>Mappings are for analyst context and reporting support. They do not constitute certification, compliance, authorization, or an official assessment.</p>
    <table>
      <thead><tr><th>Framework</th><th>Mapping</th><th>Findings</th></tr></thead>
      <tbody>{framework_summary_rows}</tbody>
    </table>
    <h3>Unmapped Findings</h3>
    <table>
      <thead><tr><th>Category</th><th>Finding</th></tr></thead>
      <tbody>{unmapped_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Intrusion Correlation</h2>
    <p>Possible intrusion patterns are correlated locally from monitor events and findings. This section does not claim compromise.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{intrusion_summary_rows}</tbody>
    </table>
    <h3>Pattern Summary</h3>
    <table>
      <thead><tr><th>Title</th><th>Severity</th><th>Confidence</th><th>Why it matters</th><th>Next steps</th><th>Evidence to preserve</th></tr></thead>
      <tbody>{intrusion_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Alert Provenance</h2>
    <p>Each alert below includes the rule, detector, before/after state, correlation, false-positive hints, and verification steps.</p>
    <table>
      <thead><tr><th>Finding</th><th>Rule ID</th><th>Detector</th><th>Subsource</th><th>Confidence</th><th>Previous State</th><th>Current State</th><th>Correlation</th><th>False Positive Hints</th><th>Verification Steps</th></tr></thead>
      <tbody>{provenance_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Investigation Priorities</h2>
    <p>Findings are ranked by actual investigative value, not severity alone.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{investigation_priority_summary_rows}</tbody>
    </table>
    <h3>Top Priorities</h3>
    <table>
      <thead><tr><th>Rank</th><th>Title</th><th>Score</th><th>Severity</th><th>Confidence</th><th>Why Ranked Here</th><th>Next Action</th><th>Effort</th></tr></thead>
      <tbody>{investigation_priority_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Execution Evidence</h2>
    <p>Unexpected execution activity observed. Review recommended.</p>
    <table>
      <thead><tr><th>Confidence</th><th>Evidence</th><th>Timeline</th><th>Explanation</th><th>Recommended Actions</th></tr></thead>
      <tbody>{execution_evidence_rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Reliability and Trust</h2>
    <p>Operational reliability evidence from the Alert Pipeline Health, Monitoring Coverage, Release Readiness, Trust Timeline, Configuration Drift, and Incident Mode views.</p>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{reliability_summary_rows}</tbody>
    </table>
    <h3>Monitoring Coverage Dashboard</h3>
    <table>
      <thead><tr><th>Component</th><th>Status</th><th>Last Successful Run</th><th>Last Event</th><th>Last Error</th><th>Heartbeat Age</th><th>Permission</th><th>Failure Reason</th><th>Recommended Fix</th></tr></thead>
      <tbody>{coverage_rows}</tbody>
    </table>
    <h3>Trust Timeline</h3>
    <table>
      <thead><tr><th>When</th><th>Previous</th><th>Current</th><th>Delta</th><th>Causes</th><th>Recommended Action</th></tr></thead>
      <tbody>{trust_rows}</tbody>
    </table>
    <h3>Configuration Drift Timeline</h3>
    <table>
      <thead><tr><th>Setting</th><th>Previous</th><th>Current</th><th>First Seen</th><th>Last Seen</th><th>Source Detector</th><th>Confidence</th><th>Why It Matters</th><th>Recommended Verification</th></tr></thead>
      <tbody>{drift_rows}</tbody>
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
  <div class="card">
    <h2>Apple Exposure Assessment</h2>
    <table>
      <thead><tr><th>Field</th><th>Value</th></tr></thead>
      <tbody>{forecast_summary_rows}</tbody>
    </table>
    <table>
      <thead>
        <tr>
          <th>Card</th>
          <th>CVE IDs</th>
          <th>Source</th>
          <th>Assessment Level</th>
          <th>Applicability</th>
          <th>KEV</th>
          <th>Apple</th>
          <th>What to do now</th>
          <th>Status</th>
          <th>Why shown</th>
        </tr>
      </thead>
      <tbody>{forecast_rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    if include_background_monitor_logs:
        event_rows = "".join(
            f"<tr><td>{html.escape(str(item.get('timestamp', '')))}</td><td>{html.escape(str(item.get('event_type', '')))}</td><td>{html.escape(str(item.get('severity', '')))}</td><td>{html.escape(str(item.get('source', '')))}</td><td>{html.escape(str(item.get('rule_id', item.get('trigger_rule_id', ''))))}</td><td>{html.escape(str(item.get('trigger_source', '')))}</td><td>{html.escape(str(item.get('correlation_id', '')))}</td><td>{html.escape(str(item.get('previous_state', '')))}</td><td>{html.escape(str(item.get('current_state', '')))}</td><td>{html.escape(str(item.get('confidence', '')))}</td><td>{html.escape(str(item.get('evidence', '')))}</td></tr>"
            for item in background_monitor_events
        )
        document = document.replace(
            "</body>",
            (
                "<div class='card'><h2>Background Monitor Events</h2><p>Optional local privacy and session indicators. "
                "These logs do not contain camera images, audio, screen contents, keystrokes, or packet contents.</p>"
                "<table><thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Source</th><th>Rule ID</th><th>Trigger Source</th><th>Correlation</th><th>Previous State</th><th>Current State</th><th>Confidence</th><th>Evidence</th></tr></thead>"
                f"<tbody>{event_rows}</tbody></table></div></body>"
            ),
        )
        storm_events = [item for item in background_monitor_events if item.get("event_type") == "alert_storm_detected"]
        storm_rows = "".join(
            f"<tr><td>{html.escape(str(item.get('timestamp', '')))}</td><td>{html.escape(str(item.get('evidence', '')))}</td><td>{html.escape(str(item.get('correlation_id', '')))}</td><td>{html.escape(str(item.get('source_trace', '')))}</td></tr>"
            for item in storm_events
        ) or '<tr><td colspan="4">No alert storms recorded.</td></tr>'
        document = document.replace(
            "</body>",
            (
                "<div class='card'><h2>Alert Storm Summary</h2>"
                "<table><thead><tr><th>Timestamp</th><th>Evidence</th><th>Correlation</th><th>Source Trace</th></tr></thead>"
                f"<tbody>{storm_rows}</tbody></table></div></body>"
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
        cleaned["title"] = redact_text(str(cleaned.get("title", "")))
        cleaned["body"] = redact_text(str(cleaned.get("body", "")))
        cleaned["investigator_name"] = redact_text(str(cleaned.get("investigator_name", "")))
        cleaned["tags"] = [redact_text(str(tag)) for tag in cleaned.get("tags", [])]
        serialized.append(redact_structure(cleaned))
    return serialized
