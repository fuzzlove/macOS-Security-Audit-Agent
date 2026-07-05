from __future__ import annotations

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.network_intelligence.models import NetworkFinding, NetworkIntelligenceSnapshot
from mac_audit_agent.rules import rule_for_event

EVENT_BY_CATEGORY = {
    "new_network_connection_detected": "new_network_connection",
    "new_outbound_connection_detected": "new_network_connection",
    "new_inbound_connection_detected": "new_network_connection",
    "new_listener_detected": "new_listening_port",
    "new_dns_server_detected": "dns_changed",
    "new_gateway_detected": "gateway_changed",
    "vpn_connected": "vpn_changed",
    "vpn_disconnected": "vpn_changed",
    "proxy_enabled": "proxy_changed",
    "proxy_disabled": "proxy_changed",
    "localhost_visibility_mismatch_detected": "network_visibility_mismatch",
    "port_open_no_process_owner": "port_open_no_process_owner",
    "suspicious_network_process_observed": "suspicious_network_process_observed",
}


def finding_to_event(finding: NetworkFinding, *, timestamp: str | None = None) -> BackgroundMonitorEvent:
    event_type = EVENT_BY_CATEGORY.get(finding.category, "new_network_connection")
    rule = rule_for_event(event_type)
    return BackgroundMonitorEvent(
        event_id=f"network-intelligence-{finding.finding_id}",
        timestamp=timestamp or finding.created_at or utc_now_iso(),
        event_type=event_type,
        severity=finding.severity,
        source="network_intelligence",
        process_name="",
        evidence=finding.evidence,
        confidence=finding.confidence,
        recommendation=finding.suggested_fix,
        metadata_json="{}",
        rule_id=rule.rule_id,
        trigger_rule_id=rule.rule_id,
    )


def snapshot_to_events(snapshot: NetworkIntelligenceSnapshot) -> list[BackgroundMonitorEvent]:
    return [finding_to_event(finding, timestamp=snapshot.timestamp) for finding in snapshot.findings if finding.severity in {"medium", "high", "critical"}]
