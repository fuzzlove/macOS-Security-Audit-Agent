from __future__ import annotations

import ipaddress

from mac_audit_agent.network_intelligence.models import ListeningPort, NetworkConnection, NetworkFinding, NetworkPosture

SUSPICIOUS_PROCESSES = {"nc", "ncat", "socat", "bash", "zsh", "sh", "python", "python3", "perl", "ruby", "php", "osascript"}
SUSPICIOUS_PATH_PARTS = ("/tmp/", "/var/tmp/", "/private/tmp/", "/Users/Shared/")
HIGH_RISK_PORTS = {"22", "445", "548", "5900", "4444", "5555", "6666", "7777", "8081", "9001", "1337"}


def is_external(address: str) -> bool:
    if not address or address in {"*", "localhost"}:
        return False
    host = address.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "." in host and not host.endswith(".local")
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def score_connections(connections: list[NetworkConnection]) -> list[NetworkFinding]:
    findings: list[NetworkFinding] = []
    for connection in connections:
        process = (connection.process_name or "").lower()
        path = (connection.process_path or "").lower()
        external = is_external(connection.remote_address)
        if external and process in SUSPICIOUS_PROCESSES:
            connection.risk_level = "critical"
            connection.confidence = "high"
            connection.evidence = connection.evidence or f"{connection.process_name} connected to {connection.remote_address}:{connection.remote_port}"
            findings.append(_finding("critical", "Possible reverse shell or hands-on-keyboard network tool", connection.evidence, "suspicious_network_process_observed"))
        elif external and (connection.signed_status.lower() in {"unsigned", "ad-hoc"} or any(part in path for part in SUSPICIOUS_PATH_PARTS)):
            connection.risk_level = "high"
            connection.confidence = "medium"
            findings.append(_finding("high", "Unsigned or suspicious-path process made external connection", connection.evidence, "suspicious_network_process_observed"))
        elif connection.baseline_status == "new" and external:
            connection.risk_level = "medium"
            findings.append(_finding("medium", "New outbound endpoint since baseline", connection.evidence, "new_outbound_connection_detected"))
        else:
            connection.risk_level = connection.risk_level or "info"
    return findings


def score_listeners(listeners: list[ListeningPort]) -> list[NetworkFinding]:
    findings: list[NetworkFinding] = []
    for listener in listeners:
        all_interfaces = listener.local_address in {"*", "0.0.0.0", "::", "[::]"}
        process = (listener.process_name or "").lower()
        if all_interfaces and process in SUSPICIOUS_PROCESSES:
            listener.risk_level = "critical"
            findings.append(_finding("critical", "Suspicious process listening on all interfaces", listener.evidence, "new_listener_detected"))
        elif all_interfaces or listener.port in HIGH_RISK_PORTS:
            listener.risk_level = "high" if listener.baseline_status == "new" else "medium"
            findings.append(_finding(listener.risk_level, "Review exposed listening service", listener.evidence, "new_listener_detected"))
        elif listener.baseline_status == "new":
            listener.risk_level = "medium"
            findings.append(_finding("medium", "New localhost listener since baseline", listener.evidence, "new_listener_detected"))
        else:
            listener.risk_level = listener.risk_level or "info"
    return findings


def score_posture(posture: NetworkPosture, baseline_posture: NetworkPosture | None = None) -> list[NetworkFinding]:
    if baseline_posture is None:
        return []
    findings: list[NetworkFinding] = []
    if posture.gateway and baseline_posture.gateway and posture.gateway != baseline_posture.gateway:
        findings.append(_finding("medium", "Gateway changed since baseline", f"{baseline_posture.gateway} -> {posture.gateway}", "new_gateway_detected"))
    if posture.dns_servers and baseline_posture.dns_servers and posture.dns_servers != baseline_posture.dns_servers:
        findings.append(_finding("medium", "DNS servers changed since baseline", f"{baseline_posture.dns_servers} -> {posture.dns_servers}", "new_dns_server_detected"))
    if posture.vpn_active != baseline_posture.vpn_active:
        event = "vpn_connected" if posture.vpn_active else "vpn_disconnected"
        findings.append(_finding("medium", "VPN state changed since baseline", f"{baseline_posture.vpn_active} -> {posture.vpn_active}", event))
    if posture.proxy_enabled and not baseline_posture.proxy_enabled:
        findings.append(_finding("medium", "Proxy enabled since baseline", posture.proxy_details, "proxy_enabled"))
    return findings


def _finding(severity: str, title: str, evidence: str, event_type: str) -> NetworkFinding:
    return NetworkFinding(
        title=title,
        severity=severity,
        confidence="medium" if severity in {"medium", "info"} else "high",
        category=event_type,
        description=title,
        evidence=evidence,
        why_it_matters="Unexpected network changes can indicate new exposure, traffic redirection, or command-and-control activity when correlated with stronger evidence.",
        suggested_fix="Identify the owning process, verify whether the network behavior is expected, and preserve evidence before changing system state.",
        validation_steps="Re-run Network Intelligence, compare lsof/netstat/Nmap where applicable, and review nearby persistence/admin/session events.",
        false_positive_notes="Browser helper processes, developer services, VPN clients, and enterprise proxies can produce expected network changes.",
        mitre_mappings=["Command and Control", "Discovery"],
        nist_mappings=["NIST CSF Detect", "NIST 800-53 SI-4", "SC-7"],
    )
