"""Shared operational summary built from existing MSAA evidence services."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping


SEVERITY_RANK = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
HEALTHY_SENSOR_STATES = {"HEALTHY", "HEALTHY_IDLE", "HEALTHY_WITH_WARNINGS"}


@dataclass(frozen=True)
class OperationalCard:
    card_id: str
    title: str
    state: str
    summary: str
    route: str
    severity: str = "informational"
    evidence_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttentionItem:
    title: str
    reason: str
    severity: str
    confidence: str
    route: str
    evidence_reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OperationsOverview:
    generated_at: str
    posture: str
    posture_summary: str
    cards: tuple[OperationalCard, ...]
    needs_attention: tuple[AttentionItem, ...]
    last_24_hours: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "posture": self.posture,
            "posture_summary": self.posture_summary,
            "cards": [item.to_dict() for item in self.cards],
            "needs_attention": [item.to_dict() for item in self.needs_attention],
            "last_24_hours": dict(self.last_24_hours),
        }


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "to_dict"):
        result = value.to_dict()
        return dict(result) if isinstance(result, Mapping) else {}
    if is_dataclass(value):
        return asdict(value)
    return {}


def _severity(value: Any) -> str:
    normalized = str(value or "informational").strip().lower()
    return "informational" if normalized == "info" else normalized if normalized in SEVERITY_RANK else "informational"


def _timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _count_matching(findings: list[dict[str, Any]], *terms: str) -> int:
    needles = tuple(item.casefold() for item in terms)
    return sum(
        any(needle in " ".join(str(row.get(key, "")) for key in ("category", "title", "description", "event_type")).casefold() for needle in needles)
        for row in findings
    )


def _event_text(event: dict[str, Any]) -> str:
    return " ".join(
        str(event.get(key, ""))
        for key in ("event_type", "rule_id", "rule_name", "source", "evidence", "recommendation", "notification_decision", "current_state")
    ).casefold()


def _last_24_hours(events: list[dict[str, Any]], *, now: datetime) -> tuple[list[dict[str, Any]], dict[str, int]]:
    cutoff = now - timedelta(hours=24)
    recent = []
    for event in events:
        observed = _timestamp(event.get("timestamp") or event.get("timestamp_utc"))
        if observed is not None and observed >= cutoff:
            recent.append(event)
    buckets = {
        "detections": 0,
        "blocked_actions": 0,
        "suspicious_processes": 0,
        "network_anomalies": 0,
        "persistence_changes": 0,
        "security_setting_changes": 0,
        "sensor_degradation": 0,
        "administrative_changes": 0,
    }
    for event in recent:
        text = _event_text(event)
        severity = _severity(event.get("severity"))
        confidence = str(event.get("confidence", "low")).lower()
        if SEVERITY_RANK[severity] >= SEVERITY_RANK["medium"] or confidence in {"high", "confirmed"}:
            buckets["detections"] += 1
        if any(term in text for term in ("block", "contain", "quarantine", "deny")):
            buckets["blocked_actions"] += 1
        if event.get("process_name") or event.get("process_path") or event.get("related_process"):
            if any(term in text for term in ("suspicious", "unsigned", "malware", "injection", "keylog", "ransom")):
                buckets["suspicious_processes"] += 1
        if any(term in text for term in ("network", "connection", "listener", "dns", "gateway", "proxy", "vpn")):
            buckets["network_anomalies"] += 1
        if any(term in text for term in ("persistence", "launchagent", "launchdaemon", "login_item", "cron", "startup")):
            buckets["persistence_changes"] += 1
        if any(term in text for term in ("security_setting", "firewall", "filevault", "sip", "gatekeeper", "tcc", "configuration_change")):
            buckets["security_setting_changes"] += 1
        if any(term in text for term in ("sensor", "heartbeat", "coverage", "telemetry")) and any(term in text for term in ("degrad", "fail", "stale", "drop", "missing")):
            buckets["sensor_degradation"] += 1
        if any(term in text for term in ("admin", "sudo", "privilege", "remote_login", "account_change")):
            buckets["administrative_changes"] += 1
    return recent, buckets


class SecurityOperationsOverviewBuilder:
    """Aggregate existing scan, alert, health, and protection evidence for the UI."""

    def build(
        self,
        *,
        findings: Iterable[Any] = (),
        events: Iterable[Any] = (),
        sensor_report: Mapping[str, Any] | None = None,
        protection_status: Mapping[str, Any] | None = None,
        zero_trust_status: Mapping[str, Any] | None = None,
        firewall_status: Mapping[str, Any] | None = None,
        dns_status: Mapping[str, Any] | None = None,
        evidence_status: Mapping[str, Any] | None = None,
        behavioral_status: Mapping[str, Any] | None = None,
        scan_available: bool = False,
        now: datetime | None = None,
    ) -> OperationsOverview:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        finding_rows = [_mapping(item) for item in findings]
        event_rows = [_mapping(item) for item in events]
        sensor = dict(sensor_report or {})
        protection = dict(protection_status or {})
        zero_trust = dict(zero_trust_status or {})
        firewall = dict(firewall_status or {})
        dns = dict(dns_status or {})
        evidence = dict(evidence_status or {})
        behavior = dict(behavioral_status or {})
        recent_events, activity = _last_24_hours(event_rows, now=current)

        severity_counts = {name: 0 for name in ("informational", "low", "medium", "high", "critical")}
        for finding in finding_rows:
            severity_counts[_severity(finding.get("severity"))] += 1
        critical = severity_counts["critical"]
        high = severity_counts["high"]

        sensors = [row for row in sensor.get("sensors", []) if isinstance(row, Mapping)]
        failed_sensors = [row for row in sensors if str(row.get("state", "UNKNOWN")).upper() not in HEALTHY_SENSOR_STATES]
        required_total = int(sensor.get("required_sensors_total", sensor.get("required_total", 0)) or 0)
        required_healthy = int(sensor.get("required_sensors_healthy", sensor.get("required_healthy", 0)) or 0)

        active_threat_keys: set[str] = set()
        for event in recent_events:
            severity = _severity(event.get("severity"))
            confidence = str(event.get("confidence", "low")).lower()
            state = str(event.get("current_state") or event.get("outcome") or "").lower()
            if (
                SEVERITY_RANK[severity] >= SEVERITY_RANK["high"]
                and confidence in {"high", "confirmed"}
            ) or state in {"probable", "confirmed", "contained"}:
                active_threat_keys.add(str(event.get("correlation_id") or event.get("rule_id") or event.get("event_id") or id(event)))
        active_threats = len(active_threat_keys)

        protection_state = str(protection.get("status", protection.get("state", "unknown"))).lower()
        protection_ok = protection_state in {"installed_running", "healthy", "active", "protected"}
        protection_degraded = protection_state != "unknown" and not protection_ok
        zero_trust_state = str(zero_trust.get("rating", zero_trust.get("state", "UNKNOWN"))).upper().replace(" ", "_")
        firewall_state = str(firewall.get("state", firewall.get("status", "UNKNOWN"))).upper()
        raw_dns_state = str(dns.get("state", dns.get("status", "UNKNOWN"))).upper()
        dns_state = {"VALIDATED": "ASSURED", "CONCERN": "REVIEW", "RED FLAG": "HIGH RISK", "NOT COLLECTED": "UNKNOWN"}.get(raw_dns_state, raw_dns_state)
        unsigned_count = _count_matching(finding_rows, "unsigned", "not signed", "ad hoc signed", "invalid signature", "modified after signing")
        persistence_count = _count_matching(finding_rows, "persistence", "launchagent", "launchdaemon", "login item", "cron")
        network_count = _count_matching(finding_rows, "network", "dns", "firewall", "listener", "remote connection")
        behavior_state = str(behavior.get("state", "UNKNOWN")).upper().replace("_", " ")
        behavior_anomalies = int(behavior.get("anomalies_today", 0) or 0)
        behavior_high_risk = int(behavior.get("high_risk_anomalies", 0) or 0)
        behavior_health = dict(behavior.get("health", {}) or {})
        behavior_degraded = behavior_health.get("analysis_availability") == "DEGRADED" or behavior_state == "DEGRADED"

        if critical or active_threats:
            posture = "CRITICAL"
            issue_count = critical + active_threats
            posture_summary = f"{issue_count} critical issue{'s' if issue_count != 1 else ''} {'require' if issue_count != 1 else 'requires'} attention"
        elif failed_sensors or protection_degraded or high:
            posture = "DEGRADED"
            condition_count = high + len(failed_sensors) + int(protection_degraded)
            posture_summary = f"{condition_count} high-priority condition{'s' if condition_count != 1 else ''} {'require' if condition_count != 1 else 'requires'} review"
        elif not scan_available:
            posture = "UNKNOWN"
            posture_summary = "Run an assessment to establish current posture"
        else:
            posture = "PROTECTED"
            posture_summary = "No critical issues found in current evidence"

        cards = (
            OperationalCard("overall_posture", "Overall Security Posture", posture, posture_summary, "Assessment", "critical" if posture == "CRITICAL" else "high" if posture == "DEGRADED" else "informational", critical + high),
            OperationalCard("active_threats", "Active Threats", "ATTENTION" if active_threats else "CLEAR", f"{active_threats} correlated threat{'s' if active_threats != 1 else ''} require review" if active_threats else "No high-confidence active threats in the last 24 hours", "Alert Center", "critical" if active_threats else "informational", active_threats),
            OperationalCard("critical_findings", "Critical Findings", "ATTENTION" if critical else "CLEAR", f"{critical} critical finding{'s' if critical != 1 else ''}" if critical else "No critical findings in the current assessment", "Investigation Priority", "critical" if critical else "informational", critical),
            OperationalCard("sensor_coverage", "Sensor Coverage", "DEGRADED" if failed_sensors else "HEALTHY" if sensors else "UNKNOWN", f"{required_healthy}/{required_total} critical sensors operational" if required_total else "Sensor health has not reported yet", "Sensor Health", "high" if failed_sensors else "informational", len(failed_sensors)),
            OperationalCard("protection_status", "Protection Status", "HEALTHY" if protection_ok else "DEGRADED" if protection_state != "unknown" else "UNKNOWN", "Active protection is running" if protection_ok else "Protection requires installation or repair" if protection_state != "unknown" else "Protection status has not been checked", "Anti-Ransomware", "high" if protection_state != "unknown" and not protection_ok else "informational"),
            OperationalCard("zero_trust", "Zero Trust Status", zero_trust_state, zero_trust_state.replace("_", " ").title() if zero_trust_state != "UNKNOWN" else "Posture has not been evaluated", "Zero Trust Posture", "high" if zero_trust_state in {"RESTRICTED", "UNTRUSTED"} else "informational"),
            OperationalCard("firewall", "Firewall Status", firewall_state, str(firewall.get("summary") or ("Firewall status has not been checked" if firewall_state == "UNKNOWN" else firewall_state.title())), "Firewall", "high" if firewall_state in {"DISABLED", "FAILED", "DEGRADED"} else "informational"),
            OperationalCard("ransomware", "Ransomware Protection", "HEALTHY" if protection_ok else "DEGRADED" if protection_state != "unknown" else "UNKNOWN", str(protection.get("ransomware_summary") or ("Behavioral protection is operational" if protection_ok else "Review ransomware sensor and containment readiness")), "Anti-Ransomware", "critical" if protection_state in {"failed", "impaired"} else "informational"),
            OperationalCard(
                "behavior",
                "Behavior",
                "DEGRADED" if behavior_degraded else behavior_state,
                (
                    "Behavioral analytics is degraded; review telemetry coverage and queue health"
                    if behavior_degraded
                    else f"{behavior_anomalies} anomal{'ies' if behavior_anomalies != 1 else 'y'} today · {behavior_high_risk} high-risk deviation{'s' if behavior_high_risk != 1 else ''}"
                    if behavior_state not in {"UNKNOWN", "LEARNING"}
                    else "MSAA is establishing the local behavioral baseline"
                ),
                "Behavioral Telemetry",
                "high" if behavior_degraded or behavior_high_risk else "medium" if behavior_anomalies else "informational",
                behavior_anomalies,
            ),
            OperationalCard("dns", "DNS Assurance", dns_state, str(dns.get("summary") or dns.get("explanation") or ("DNS baseline has not been evaluated" if dns_state == "UNKNOWN" else dns_state.title())), "DNS Configuration Assurance", "high" if dns_state in {"DRIFT", "FAILED", "UNEXPECTED", "REVIEW", "HIGH RISK"} else "informational"),
            OperationalCard("unsigned", "Unsigned Software", "ATTENTION" if unsigned_count else "CLEAR", f"{unsigned_count} signature-related item{'s' if unsigned_count != 1 else ''} require context" if unsigned_count else "No signature-related findings in the current assessment", "Unsigned Software", "high" if unsigned_count else "informational", unsigned_count),
            OperationalCard("persistence", "Persistence Findings", "ATTENTION" if persistence_count else "CLEAR", f"{persistence_count} persistence finding{'s' if persistence_count != 1 else ''}" if persistence_count else "No persistence findings in the current assessment", "Persistence Intelligence", "high" if persistence_count else "informational", persistence_count),
            OperationalCard("network", "Network Risk", "ATTENTION" if network_count or activity["network_anomalies"] else "CLEAR", f"{network_count} network finding{'s' if network_count != 1 else ''}; {activity['network_anomalies']} recent anomal{'ies' if activity['network_anomalies'] != 1 else 'y'}" if network_count or activity["network_anomalies"] else "No network risks in current evidence", "Network Intelligence", "high" if network_count else "informational", network_count + activity["network_anomalies"]),
            OperationalCard("evidence", "Evidence Collection Status", str(evidence.get("state", "AVAILABLE" if recent_events or scan_available else "UNKNOWN")).upper(), str(evidence.get("summary") or ("Current scan and event evidence is available" if recent_events or scan_available else "No current evidence collection has been recorded")), "Flight Recorder", "informational", len(recent_events)),
        )

        attention: list[AttentionItem] = []
        for finding in sorted(finding_rows, key=lambda row: SEVERITY_RANK[_severity(row.get("severity"))], reverse=True):
            severity = _severity(finding.get("severity"))
            if severity not in {"critical", "high"}:
                continue
            attention.append(AttentionItem(
                str(finding.get("title") or "Security finding"),
                str(finding.get("why_this_matters") or finding.get("description") or "Review supporting evidence."),
                severity,
                str(finding.get("confidence") or "unknown"),
                "Investigation Priority",
                str(finding.get("raw_evidence_ref") or finding.get("evidence_hash") or finding.get("id") or finding.get("finding_id") or ""),
            ))
        for row in failed_sensors:
            attention.append(AttentionItem(
                f"Sensor degraded: {row.get('sensor_id', 'unknown')}",
                str(row.get("reason") or "Functional sensor coverage is unavailable."),
                "critical" if str(row.get("metadata", {}).get("criticality", "")).upper() == "CRITICAL" else "high",
                "high",
                "Sensor Health",
                str(row.get("sensor_id", "")),
            ))
        if protection_state != "unknown" and not protection_ok:
            attention.append(AttentionItem("Protection requires attention", "Active protection is not fully installed and running.", "high", "high", "Anti-Ransomware", "active-protection-status"))
        if behavior_degraded:
            attention.append(AttentionItem(
                "Behavioral telemetry degraded",
                "Behavioral analytics has incomplete coverage or processing pressure; missing telemetry is not interpreted as normal activity.",
                "high",
                "high",
                "Behavioral Telemetry",
                "behavioral-telemetry-health",
            ))
        elif behavior_high_risk:
            attention.append(AttentionItem(
                "High-risk behavioral deviation",
                f"{behavior_high_risk} high-risk behavioral deviation{'s' if behavior_high_risk != 1 else ''} require correlated evidence review.",
                "high",
                "medium-high",
                "Behavioral Telemetry",
                "behavioral-anomalies",
            ))
        if not scan_available:
            attention.append(AttentionItem("Assessment required", "No active assessment is available for the current Mac state.", "medium", "high", "Assessment", ""))
        attention = sorted(attention, key=lambda item: SEVERITY_RANK[_severity(item.severity)], reverse=True)[:8]

        return OperationsOverview(
            generated_at=current.isoformat(),
            posture=posture,
            posture_summary=posture_summary,
            cards=cards,
            needs_attention=tuple(attention),
            last_24_hours=activity,
        )


__all__ = ["AttentionItem", "OperationalCard", "OperationsOverview", "SecurityOperationsOverviewBuilder"]
