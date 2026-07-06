from __future__ import annotations

import html
import json
import platform
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from mac_audit_agent.frameworks import framework_summary_for_findings
from mac_audit_agent.frameworks.cmmc import build_cmmc_readiness
from mac_audit_agent.frameworks.poam import poam_from_cmmc_readiness
from mac_audit_agent.models import BackgroundMonitorEvent, BackgroundMonitorStatus, ScanResult, utc_now_iso
from mac_audit_agent.reporting import get_reports_dir
from mac_audit_agent.storage import json_safe
from mac_audit_agent.version import APP_VERSION


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ASSESSMENT_STALE_HOURS = 24


@dataclass
class SecurityAssessment:
    assessment_id: str
    created_at: str
    hostname: str
    macos_version: str
    app_version: str
    assessment_status: str
    overall_score: int | None
    risk_level: str
    executive_summary: str
    top_risks: list[dict[str, Any]] = field(default_factory=list)
    critical_findings: list[dict[str, Any]] = field(default_factory=list)
    high_findings: list[dict[str, Any]] = field(default_factory=list)
    medium_findings: list[dict[str, Any]] = field(default_factory=list)
    info_findings: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = field(default_factory=list)
    framework_summary: dict[str, Any] = field(default_factory=dict)
    mitre_summary: dict[str, Any] = field(default_factory=dict)
    nist_summary: dict[str, Any] = field(default_factory=dict)
    cmmc_readiness: dict[str, Any] = field(default_factory=dict)
    apple_exposure_summary: dict[str, Any] = field(default_factory=dict)
    monitor_integrity_summary: dict[str, Any] = field(default_factory=dict)
    baseline_drift_summary: dict[str, Any] = field(default_factory=dict)
    network_activity_summary: dict[str, Any] = field(default_factory=dict)
    admin_persistence_summary: dict[str, Any] = field(default_factory=dict)
    physical_device_summary: dict[str, Any] = field(default_factory=dict)
    evidence_summary: dict[str, Any] = field(default_factory=dict)
    data_freshness: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _to_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "to_dict"):
        return dict(value.to_dict())
    return {}


def _finding_dicts(scan_result: ScanResult | None) -> list[dict[str, Any]]:
    if scan_result is None:
        return []
    return [item.to_dict() if hasattr(item, "to_dict") else dict(item) for item in scan_result.findings]


def _event_dict(event: BackgroundMonitorEvent) -> dict[str, Any]:
    payload = event.to_dict() if hasattr(event, "to_dict") else dict(event)
    title = str(payload.get("rule_name") or payload.get("event_type") or "Monitor event").replace("_", " ").title()
    return {
        "id": str(payload.get("event_id", "")),
        "title": title,
        "category": _category_for_event(str(payload.get("event_type", ""))),
        "severity": str(payload.get("severity", "info")).lower(),
        "description": str(payload.get("evidence", "")),
        "evidence_summary": str(payload.get("evidence", "")),
        "why_this_matters": str(payload.get("raw_signal_summary") or payload.get("current_state") or "Security monitor event recorded."),
        "recommended_next_steps": str(payload.get("recommendation") or "Review the event timeline and related evidence."),
        "framework_mappings": [],
        "source": "background_monitor",
        "timestamp": str(payload.get("timestamp", "")),
        "event_type": str(payload.get("event_type", "")),
    }


def _persistence_finding_dicts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for item in payload.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "id": str(item.get("finding_id", "")),
                "title": str(item.get("title", "Persistence finding")),
                "category": "Admin & Persistence",
                "severity": str(item.get("severity", "info")).lower(),
                "description": str(item.get("description", "")),
                "evidence_summary": "; ".join(str(value) for value in item.get("evidence", [])[:4]),
                "why_this_matters": str(item.get("why_it_matters", "Persistence can keep unwanted code active across login or reboot.")),
                "recommended_next_steps": str(item.get("suggested_fix", "Review the persistence item.")),
                "framework_mappings": list(item.get("mitre_mapping", []) or []),
                "source": "persistence_intelligence",
                "timestamp": str(item.get("created_at", "")),
                "event_type": "persistence_intelligence_finding",
            }
        )
    return findings


def _category_for_event(event_type: str) -> str:
    if "usb" in event_type or "bluetooth" in event_type or "physical_device" in event_type or "hid" in event_type:
        return "Physical Devices / USB"
    if "network" in event_type or "vpn" in event_type or "dns" in event_type or "gateway" in event_type or "listener" in event_type:
        return "Network Activity"
    if "admin" in event_type or "launchagent" in event_type or "launchdaemon" in event_type or "persistence" in event_type or "login_item" in event_type:
        return "Admin & Persistence"
    if "monitor" in event_type or "heartbeat" in event_type or "tamper" in event_type:
        return "Monitor Integrity"
    return "Monitor Events"


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _freshness(timestamp: str, *, now: datetime) -> dict[str, Any]:
    parsed = _parse_dt(timestamp)
    if parsed is None:
        return {"timestamp": timestamp, "status": "unavailable", "age_hours": None}
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    age_hours = max(0.0, (now - parsed.astimezone(timezone.utc)).total_seconds() / 3600)
    return {"timestamp": timestamp, "status": "stale" if age_hours > ASSESSMENT_STALE_HOURS else "fresh", "age_hours": round(age_hours, 1)}


def _risk_level(score: int | None, severities: list[str]) -> str:
    if any(item == "critical" for item in severities):
        return "critical" if score is not None and score < 70 else "high"
    if score is None:
        return "info"
    if score >= 90:
        return "low"
    if score >= 70:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"


def _score(risks: list[dict[str, Any]], monitor_status: dict[str, Any], apple: dict[str, Any], baseline: dict[str, Any]) -> int | None:
    if not risks and not monitor_status:
        return None
    score = 100
    for item in risks:
        severity = str(item.get("severity", "info")).lower()
        if severity == "critical":
            score -= 20
        elif severity == "high":
            score -= 10
        elif severity == "medium":
            score -= 4
        elif severity == "low":
            score -= 2
    status_text = str(monitor_status.get("status_text") or monitor_status.get("overall_status") or "").lower()
    detector_errors = str(monitor_status.get("detector_errors") or monitor_status.get("last_error") or "")
    if "failing" in status_text or detector_errors:
        score -= 20
    elif "degraded" in status_text:
        score -= 10
    apple_level = str(apple.get("level") or apple.get("forecast_level") or "").lower()
    if apple_level in {"critical", "urgent"}:
        score -= 15
    try:
        if int(baseline.get("high_risk_change_count", 0) or 0) > 0:
            score -= 10
    except (TypeError, ValueError):
        pass
    return max(0, min(100, score))


def _severity_groups(risks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups = {"critical": [], "high": [], "medium": [], "info": []}
    for item in risks:
        severity = str(item.get("severity", "info")).lower()
        if severity == "critical":
            groups["critical"].append(item)
        elif severity == "high":
            groups["high"].append(item)
        elif severity == "medium":
            groups["medium"].append(item)
        else:
            groups["info"].append(item)
    return groups


def _actions_from_risks(risks: list[dict[str, Any]], limitations: list[str]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for item in risks[:10]:
        severity = str(item.get("severity", "info")).lower()
        priority = "Immediate" if severity in {"critical", "high"} else ("Short-term" if severity == "medium" else "Informational")
        actions.append(
            {
                "priority": priority,
                "title": str(item.get("title", "Review finding")),
                "action": str(item.get("recommended_next_steps") or item.get("remediation_suggestion") or "Review the evidence and decide whether action is needed."),
                "source_id": str(item.get("id", "")),
            }
        )
    for limitation in limitations:
        actions.append({"priority": "Review", "title": "Refresh missing data", "action": limitation, "source_id": ""})
    return actions


def _summary_for_category(risks: list[dict[str, Any]], category_terms: set[str], unavailable: str = "") -> dict[str, Any]:
    matched = [
        item for item in risks
        if any(term in str(item.get("category", "")).lower() or term in str(item.get("event_type", "")).lower() for term in category_terms)
    ]
    if not matched and unavailable:
        return {"status": "unavailable", "summary": unavailable, "count": 0, "highest_severity": "info"}
    highest = max((str(item.get("severity", "info")).lower() for item in matched), key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")
    return {
        "status": "collected" if matched else "no findings",
        "summary": f"{len(matched)} relevant item(s) found." if matched else "No findings recorded in this category.",
        "count": len(matched),
        "highest_severity": highest,
        "items": matched[:10],
    }


def _scan_artifacts(scan_result: ScanResult | None) -> dict[str, Any]:
    artifacts = scan_result.collected_artifacts if scan_result is not None else {}
    return artifacts if isinstance(artifacts, dict) else {}


def _event_matches(events: list[BackgroundMonitorEvent] | None, terms: set[str]) -> list[dict[str, Any]]:
    matched = []
    for event in events or []:
        event_type = str(event.event_type)
        if any(term in event_type.lower() for term in terms):
            matched.append(event.to_dict())
    return matched


def _network_activity_summary(
    risks: list[dict[str, Any]],
    scan_result: ScanResult | None,
    events: list[BackgroundMonitorEvent] | None,
    settings: dict[str, Any] | None,
) -> dict[str, Any]:
    artifacts = _scan_artifacts(scan_result)
    ports = artifacts.get("ports", {}) if isinstance(artifacts.get("ports", {}), dict) else {}
    localhost = artifacts.get("localhost_scan", {}) if isinstance(artifacts.get("localhost_scan", {}), dict) else {}
    network_events = _event_matches(events, {"network", "vpn", "dns", "gateway", "listener", "outbound", "inbound"})
    summary = _summary_for_category(risks, {"network", "vpn", "dns", "gateway", "listener"})
    collected = scan_result is not None and ("ports" in artifacts or "localhost_scan" in artifacts)
    if not collected and not network_events:
        return {"status": "unavailable", "summary": "Network activity data not collected.", "count": 0, "highest_severity": "info"}
    summary.update(
        {
            "status": summary["status"] if summary["count"] else "no findings",
            "summary": summary["summary"] if summary["count"] else "Network data was collected; no network findings were recorded.",
            "listening_port_count": len(ports.get("listening", []) or []),
            "active_connection_count": len(ports.get("active_connections", []) or []),
            "localhost_scan_errors": localhost.get("errors", []),
            "monitor_event_count": len(network_events),
            "monitoring_enabled": None if settings is None else bool(settings.get("network_activity_monitoring_enabled", True)),
            "recent_events": network_events[:10],
        }
    )
    return summary


def _admin_persistence_summary(
    risks: list[dict[str, Any]],
    scan_result: ScanResult | None,
    events: list[BackgroundMonitorEvent] | None,
    settings: dict[str, Any] | None,
    persistence_intelligence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    artifacts = _scan_artifacts(scan_result)
    persistence_payload = dict(persistence_intelligence or {})
    admin_events = _event_matches(events, {"admin", "launchagent", "launchdaemon", "persistence", "login_item", "sudoers"})
    summary = _summary_for_category(risks, {"admin", "persistence", "launchagent", "launchdaemon", "login"})
    collected = (scan_result is not None and any(key in artifacts for key in {"users", "launch_snapshots", "launch_items"})) or bool(persistence_payload)
    if not collected and not admin_events:
        return {"status": "unavailable", "summary": "Admin and persistence data not collected.", "count": 0, "highest_severity": "info"}
    users = artifacts.get("users", []) if isinstance(artifacts.get("users", []), list) else []
    launch_snapshots = artifacts.get("launch_snapshots", []) if isinstance(artifacts.get("launch_snapshots", []), list) else []
    summary.update(
        {
            "status": summary["status"] if summary["count"] else "no findings",
            "summary": summary["summary"] if summary["count"] else "Admin and persistence data was collected; no findings were recorded.",
            "user_count": len(users),
            "admin_user_count": sum(1 for item in users if isinstance(item, dict) and item.get("admin")),
            "launch_item_count": len(artifacts.get("launch_items", []) or []),
            "launch_snapshot_count": len(launch_snapshots),
            "persistence_intelligence_item_count": len(persistence_payload.get("items", []) or []),
            "persistence_intelligence_finding_count": len(persistence_payload.get("findings", []) or []),
            "persistence_posture_score": persistence_payload.get("posture_score"),
            "persistence_coverage": persistence_payload.get("coverage", []),
            "monitor_event_count": len(admin_events),
            "monitoring_enabled": None if settings is None else bool(settings.get("admin_persistence_monitoring_enabled", True)),
            "recent_events": admin_events[:10],
        }
    )
    return summary


def _physical_device_summary(
    risks: list[dict[str, Any]],
    physical_devices: dict[str, Any] | None,
    events: list[BackgroundMonitorEvent] | None,
) -> dict[str, Any]:
    device_events = _event_matches(events, {"usb", "bluetooth", "physical", "hid"})
    if isinstance(physical_devices, dict) and physical_devices:
        current = physical_devices.get("current_usb_devices", []) or []
        known = physical_devices.get("known_usb_devices", []) or []
        untrusted = physical_devices.get("untrusted_usb_devices", []) or []
        recent = physical_devices.get("recent_device_alerts", []) or []
        high_risk = [
            item for item in recent
            if str(item.get("severity", "info")).lower() in {"high", "critical"}
        ] if isinstance(recent, list) else []
        return {
            "status": "collected",
            "summary": f"{len(current)} current USB device(s), {len(untrusted)} untrusted device(s), {len(high_risk)} high-risk recent device alert(s).",
            "current_usb_count": len(current),
            "known_usb_count": len(known),
            "trusted_usb_count": len(physical_devices.get("trusted_usb_devices", []) or []),
            "untrusted_usb_count": len(untrusted),
            "bluetooth_event_count": len(physical_devices.get("bluetooth_devices", []) or []),
            "recent_device_alert_count": len(recent) if isinstance(recent, list) else 0,
            "highest_severity": max((str(item.get("severity", "info")).lower() for item in high_risk), key=lambda s: SEVERITY_ORDER.get(s, 0), default="info"),
            "items": high_risk[:10],
            "trust_store_path": physical_devices.get("trust_store_path", ""),
        }
    if not device_events:
        return {"status": "unavailable", "summary": "Physical device data not collected.", "count": 0, "highest_severity": "info"}
    summary = _summary_for_category(risks, {"usb", "bluetooth", "physical", "hid"})
    summary.update({"monitor_event_count": len(device_events), "recent_events": device_events[:10]})
    return summary


def build_security_assessment(
    scan_result: ScanResult | None,
    monitor_state: BackgroundMonitorStatus | dict[str, Any] | None,
    events: list[BackgroundMonitorEvent] | None,
    settings: dict[str, Any] | None = None,
    *,
    apple_exposure: dict[str, Any] | None = None,
    visibility_integrity: dict[str, Any] | None = None,
    reliability: dict[str, Any] | None = None,
    physical_devices: dict[str, Any] | None = None,
    persistence_intelligence: dict[str, Any] | None = None,
    assessment_id: str | None = None,
) -> SecurityAssessment:
    now = datetime.now(timezone.utc)
    created_at = utc_now_iso()
    findings = _finding_dicts(scan_result)
    all_event_items = [_event_dict(event) for event in (events or [])]
    event_risks = [
        item
        for item in all_event_items
        if SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 0) >= SEVERITY_ORDER["medium"]
    ]
    persistence_payload = dict(persistence_intelligence or {})
    persistence_findings = _persistence_finding_dicts(persistence_payload)
    risks = [*findings, *event_risks, *persistence_findings]
    risks.sort(key=lambda item: SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 0), reverse=True)
    groups = _severity_groups(risks)
    monitor = _to_dict(monitor_state)
    apple = dict(apple_exposure or {})
    visibility = dict(visibility_integrity or {})
    reliable = dict(reliability or {})
    baseline = dict(scan_result.baseline_diff if scan_result is not None else {})
    limitations: list[str] = []
    data_freshness: dict[str, Any] = {}
    if scan_result is None:
        limitations.append("Latest scan unavailable. Run a Safe Scan to populate local posture findings.")
    else:
        data_freshness["latest_scan"] = _freshness(scan_result.timestamp, now=now)
        if data_freshness["latest_scan"]["status"] == "stale":
            limitations.append("Latest scan is stale. Refresh the assessment after running a new Safe Scan.")
    if not monitor:
        limitations.append("Monitor state unavailable. Start or refresh the background monitor to include runtime health.")
    else:
        timestamp = str(monitor.get("last_heartbeat") or monitor.get("detector_last_run_timestamp") or "")
        data_freshness["monitor"] = _freshness(timestamp, now=now)
    if not events:
        limitations.append("No monitor events were available for this assessment.")
    if not apple:
        limitations.append("Apple Exposure Assessment not collected.")
    if not visibility:
        limitations.append("Visibility Integrity report unavailable.")
    if not reliable:
        limitations.append("Reliability and monitoring coverage report unavailable.")
    if not persistence_payload:
        limitations.append("Persistence Intelligence report unavailable.")
    status = "ready"
    if scan_result is None and not events:
        status = "unavailable"
    elif limitations:
        status = "partial"
    if any(item.get("status") == "stale" for item in data_freshness.values()):
        status = "stale"
    score = None if scan_result is None and not risks else _score(risks, monitor, apple, baseline)
    severities = [str(item.get("severity", "info")).lower() for item in risks]
    risk_level = _risk_level(score, severities)
    framework_summary = framework_summary_for_findings([*findings, *persistence_findings]) if [*findings, *persistence_findings] else {}
    completed_checks: set[str] = set()
    if apple:
        completed_checks.add("scan.apple_exposure")
    if visibility:
        completed_checks.add("scan.visibility_integrity")
    if reliable:
        completed_checks.add("daemon.heartbeat")
    if persistence_payload:
        completed_checks.add("persistence.workflow")
    if physical_devices:
        completed_checks.add("scan.physical_devices")
    if events:
        completed_checks.add("alert.delivery_trace")
    if scan_result is not None:
        completed_checks.update({"core.assessment_builder", "scan.baseline_drift"})
        artifacts = scan_result.collected_artifacts if isinstance(scan_result.collected_artifacts, dict) else {}
        if artifacts.get("network_intelligence") or artifacts.get("ports"):
            completed_checks.update({"network_intelligence.collectors", "network_intelligence.reports"})
    hostname = scan_result.hostname if scan_result is not None else socket.gethostname()
    macos_version = platform.mac_ver()[0] or platform.platform()
    summary = _executive_summary(status, score, risk_level, groups, limitations)
    assessment = SecurityAssessment(
        assessment_id=assessment_id or f"assessment-{uuid4().hex[:12]}",
        created_at=created_at,
        hostname=hostname,
        macos_version=macos_version,
        app_version=APP_VERSION,
        assessment_status=status,
        overall_score=score,
        risk_level=risk_level,
        executive_summary=summary,
        top_risks=risks[:8],
        critical_findings=groups["critical"],
        high_findings=groups["high"],
        medium_findings=groups["medium"],
        info_findings=groups["info"],
        recommended_actions=_actions_from_risks(risks, limitations),
        framework_summary=framework_summary,
        mitre_summary={
            "mapped_to": framework_summary.get("mitre_attack_macos", {}),
            "techniques": framework_summary.get("top_mitre_techniques", {}),
        },
        nist_summary={
            "mapped_to_nist_csf_2_0": framework_summary.get("nist_csf", {}),
            "aligned_with_nist_800_53": framework_summary.get("nist_800_53_controls", {}),
        },
        cmmc_readiness=build_cmmc_readiness(target_level=2, completed_check_ids=completed_checks).to_dict(),
        apple_exposure_summary=apple or {"status": "unavailable", "summary": "Not collected"},
        monitor_integrity_summary=_monitor_summary(monitor, visibility, reliable),
        baseline_drift_summary=_baseline_summary(baseline),
        network_activity_summary=_network_activity_summary(risks, scan_result, events, settings),
        admin_persistence_summary=_admin_persistence_summary(risks, scan_result, events, settings, persistence_payload),
        physical_device_summary=_physical_device_summary(risks, physical_devices, events),
        evidence_summary=_evidence_summary(scan_result, events),
        data_freshness=data_freshness,
        limitations=limitations,
        diagnostics={
            "latest_scan_exists": scan_result is not None,
            "latest_monitor_events_exist": bool(events),
            "missing_subsystems": list(limitations),
            "settings_loaded": bool(settings is not None),
            "persistence_intelligence_loaded": bool(persistence_payload),
        },
    )
    return assessment


def _executive_summary(status: str, score: int | None, risk_level: str, groups: dict[str, list[dict[str, Any]]], limitations: list[str]) -> str:
    if status == "unavailable":
        return "No current security assessment is available yet because no scan findings or monitor events were available."
    score_text = "unscored" if score is None else f"{score}/100"
    risk_counts = (
        f"{len(groups['critical'])} critical, {len(groups['high'])} high, "
        f"{len(groups['medium'])} medium, {len(groups['info'])} informational or low"
    )
    text = f"Current local security assessment is {risk_level} risk with score {score_text}. The assessment includes {risk_counts} item(s)."
    if limitations:
        text += " Some data sources are incomplete; review limitations before making final decisions."
    return text


def _monitor_summary(monitor: dict[str, Any], visibility: dict[str, Any], reliability: dict[str, Any]) -> dict[str, Any]:
    if not monitor and not visibility and not reliability:
        return {"status": "unavailable", "summary": "Monitor integrity was not collected."}
    return {
        "status": monitor.get("status_text") or visibility.get("overall_status") or "available",
        "last_heartbeat": monitor.get("last_heartbeat", ""),
        "last_error": monitor.get("last_error", ""),
        "visibility_integrity": visibility,
        "monitoring_coverage": reliability.get("monitoring_coverage", reliability),
    }


def _baseline_summary(baseline: dict[str, Any]) -> dict[str, Any]:
    if not baseline:
        return {"status": "unavailable", "summary": "Baseline drift was not collected."}
    return {
        "status": "collected",
        "drift_score": baseline.get("drift_score", 0),
        "drift_label": baseline.get("drift_label", ""),
        "high_risk_change_count": baseline.get("high_risk_change_count", 0),
        "summary": baseline.get("drift_summary", "Baseline comparison collected."),
    }


def _evidence_summary(scan_result: ScanResult | None, events: list[BackgroundMonitorEvent] | None) -> dict[str, Any]:
    artifacts = scan_result.collected_artifacts if scan_result is not None else {}
    return {
        "scan_id": scan_result.scan_id if scan_result is not None else "",
        "finding_count": len(scan_result.findings) if scan_result is not None else 0,
        "monitor_event_count": len(events or []),
        "artifact_keys": sorted(artifacts.keys()) if isinstance(artifacts, dict) else [],
        "raw_log_count": len(scan_result.raw_logs) if scan_result is not None else 0,
    }


def default_assessment_path(assessment: SecurityAssessment, suffix: str = "html") -> Path:
    host = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in assessment.hostname) or "mac"
    stamp = assessment.created_at.replace(":", "").replace("+", "Z").replace("-", "")[:15]
    return get_reports_dir() / f"MSAA_Assessment_{host}_{stamp}.{suffix}"


def export_security_assessment_json(assessment: SecurityAssessment, output_path: Path | None = None) -> Path:
    path = output_path or default_assessment_path(assessment, "json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_safe(assessment.to_dict()), indent=2, sort_keys=True), encoding="utf-8")
    return path


def export_security_assessment_markdown(assessment: SecurityAssessment, output_path: Path | None = None) -> Path:
    path = output_path or default_assessment_path(assessment, "md")
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# MSAA Security Assessment",
        "",
        f"- Created: {assessment.created_at}",
        f"- Hostname: {assessment.hostname}",
        f"- Status: {assessment.assessment_status}",
        f"- Score: {'Unavailable' if assessment.overall_score is None else assessment.overall_score}",
        f"- Risk Level: {assessment.risk_level}",
        "",
        "## Executive Summary",
        assessment.executive_summary,
        "",
        "## Top Risks",
    ]
    for risk in assessment.top_risks:
        lines.extend([f"- **{risk.get('severity', 'info')}** {risk.get('title', '')}: {risk.get('recommended_next_steps', risk.get('remediation_suggestion', 'Review.'))}"])
    lines.extend(["", "## Framework Alignment", "Mappings are analyst context only; they are not certification or authorization claims.", json.dumps(assessment.framework_summary, indent=2, sort_keys=True), "", "## Limitations"])
    lines.extend([f"- {item}" for item in assessment.limitations] or ["- None recorded."])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_security_assessment_html(assessment: SecurityAssessment, output_path: Path | None = None) -> Path:
    path = output_path or default_assessment_path(assessment, "html")
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = "".join(
        f"<tr><td>{html.escape(str(r.get('severity', 'info')))}</td><td>{html.escape(str(r.get('title', '')))}</td><td>{html.escape(str(r.get('category', '')))}</td><td>{html.escape(str(r.get('recommended_next_steps', r.get('remediation_suggestion', 'Review.'))))}</td></tr>"
        for r in assessment.top_risks
    ) or '<tr><td colspan="4">No top risks recorded.</td></tr>'
    actions = "".join(
        f"<li><strong>{html.escape(str(a.get('priority', 'Review')))}:</strong> {html.escape(str(a.get('action', '')))}</li>"
        for a in assessment.recommended_actions
    ) or "<li>No actions recorded.</li>"
    limitations = "".join(f"<li>{html.escape(item)}</li>" for item in assessment.limitations) or "<li>None recorded.</li>"
    completed_checks = set()
    if assessment.apple_exposure_summary:
        completed_checks.add("scan.apple_exposure")
    if assessment.network_activity_summary:
        completed_checks.update({"network_intelligence.collectors", "network_intelligence.reports"})
    if assessment.admin_persistence_summary:
        completed_checks.add("persistence.workflow")
    if assessment.physical_device_summary:
        completed_checks.add("scan.physical_devices")
    if assessment.monitor_integrity_summary:
        completed_checks.update({"scan.visibility_integrity", "daemon.heartbeat"})
    cmmc = assessment.cmmc_readiness or build_cmmc_readiness(target_level=2, completed_check_ids=completed_checks).to_dict()
    cmmc_summary_rows = "".join(
        f"<tr><td>{html.escape(label)}</td><td>{html.escape(str(value))}</td></tr>"
        for label, value in [
            ("Target Level", cmmc.get("target_level", "")),
            ("Scope", cmmc.get("scope_name", "")),
            ("Readiness Score", f"{cmmc.get('readiness_score', 0)}%"),
            ("Total Requirements", cmmc.get("total_requirements", 0)),
            ("Mapped by MSAA", cmmc.get("mapped_requirements", 0)),
            ("Evidence Missing", cmmc.get("evidence_missing_count", 0)),
            ("Manual Review Required", sum(1 for item in cmmc.get("evidence_items", []) if item.get("evidence_status") == "manual_review_required")),
        ]
    )
    evidence_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('requirement_id', '')))}</td><td>{html.escape(str(item.get('source_check_id', '')))}</td><td>{html.escape(str(item.get('evidence_status', '')))}</td><td>{html.escape(str(item.get('recommended_fix', '')))}</td></tr>"
        for item in cmmc.get("evidence_items", [])[:100]
    ) or '<tr><td colspan="4">No CMMC evidence rows generated.</td></tr>'
    poam_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('requirement_id', '')))}</td><td>{html.escape(str(item.get('weakness', '')))}</td><td>{html.escape(str(item.get('risk_level', '')))}</td><td>{html.escape(str(item.get('recommended_fix', '')))}</td></tr>"
        for item in [poam.to_dict() for poam in poam_from_cmmc_readiness(cmmc)][:100]
    ) or '<tr><td colspan="4">No CMMC POA&amp;M rows generated.</td></tr>'
    source_rows = "".join(
        f"<tr><td>{html.escape(str(item.get('framework', '')))}</td><td>{html.escape(str(item.get('title', '')))}</td><td>{html.escape(str(item.get('version', '')))}</td><td>{html.escape(str(item.get('source_url', '')))}</td></tr>"
        for item in cmmc.get("source_versions", [])[:50]
    )
    html_text = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>MSAA Security Assessment</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;margin:32px;line-height:1.45}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px;text-align:left}}.risk{{font-size:22px;font-weight:700}}</style></head>
<body>
<h1>MSAA Security Assessment</h1>
<p>Created: {html.escape(assessment.created_at)}<br>Host: {html.escape(assessment.hostname)}<br>Status: {html.escape(assessment.assessment_status)}</p>
<p class="risk">Score: {html.escape('Unavailable' if assessment.overall_score is None else str(assessment.overall_score))} | Risk: {html.escape(assessment.risk_level)}</p>
<h2>Executive Summary</h2><p>{html.escape(assessment.executive_summary)}</p>
<h2>Top Risks</h2><table><thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Recommended Action</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Framework Alignment</h2><p>Mapped to / aligned with frameworks for analyst context only. This is not a certification or authorization claim.</p><pre>{html.escape(json.dumps(assessment.framework_summary, indent=2, sort_keys=True))}</pre>
<h2>CMMC Readiness Summary</h2><p>{html.escape(str(cmmc.get('disclaimer', 'MSAA provides CMMC/NIST readiness mapping and evidence support for analyst review.')))}</p><table><tbody>{cmmc_summary_rows}</tbody></table>
<h2>CMMC/NIST Evidence Matrix</h2><table><thead><tr><th>CMMC Requirement</th><th>MSAA Check</th><th>Evidence Status</th><th>Suggested Fix</th></tr></thead><tbody>{evidence_rows}</tbody></table>
<h2>POA&amp;M / Remediation</h2><table><thead><tr><th>Requirement</th><th>Weakness</th><th>Risk</th><th>Recommended Fix</th></tr></thead><tbody>{poam_rows}</tbody></table>
<h2>Source Versions</h2><table><thead><tr><th>Framework</th><th>Source</th><th>Version</th><th>URL</th></tr></thead><tbody>{source_rows}</tbody></table>
<h2>Recommended Next Actions</h2><ul>{actions}</ul>
<h2>Limitations</h2><ul>{limitations}</ul>
<h2>Diagnostics</h2><pre>{html.escape(json.dumps(assessment.diagnostics, indent=2, sort_keys=True))}</pre>
</body></html>"""
    path.write_text(html_text, encoding="utf-8")
    return path
