from __future__ import annotations

import subprocess
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.network_intelligence.baseline import compare_network_baseline
from mac_audit_agent.network_intelligence.connection_parser import parse_lsof_connections, parse_lsof_listeners
from mac_audit_agent.network_intelligence.dns_gateway import DNSGatewayCollector
from mac_audit_agent.network_intelligence.models import NetworkEndpoint, NetworkIntelligenceSnapshot, NetworkPosture
from mac_audit_agent.network_intelligence.risk_scoring import score_connections, score_listeners, score_posture
from mac_audit_agent.network_intelligence.vpn_proxy import VPNProxyCollector


class NetworkIntelligenceCollector:
    def __init__(self, runner=None) -> None:
        self.runner = runner or _run

    def collect(self, *, baseline: NetworkIntelligenceSnapshot | None = None, settings: dict[str, Any] | None = None) -> NetworkIntelligenceSnapshot:
        settings = settings or {}
        timestamp = utc_now_iso()
        diagnostics: dict[str, Any] = {"started_at": timestamp, "errors": [], "commands": []}
        if not bool(settings.get("network_activity_monitoring_enabled", True)):
            diagnostics["disabled_by_settings"] = True
            diagnostics["errors"].append("Network Activity monitoring is disabled in Monitor Settings.")
            return NetworkIntelligenceSnapshot(timestamp=timestamp, diagnostics=diagnostics)

        connections = []
        listeners = []
        lsof_all = self.runner(["/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP"])
        diagnostics["commands"].append(_command_record(["/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP"], lsof_all))
        if lsof_all.returncode == 0:
            connections = parse_lsof_connections(lsof_all.stdout, timestamp=timestamp)
        else:
            diagnostics["errors"].append(f"active connection collection failed: {(lsof_all.stderr or lsof_all.stdout).strip()}")

        lsof_listen = self.runner(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        diagnostics["commands"].append(_command_record(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], lsof_listen))
        if lsof_listen.returncode == 0:
            listeners = parse_lsof_listeners(lsof_listen.stdout, timestamp=timestamp)
        else:
            diagnostics["errors"].append(f"listener collection failed: {(lsof_listen.stderr or lsof_listen.stdout).strip()}")

        posture, posture_errors = self._collect_posture()
        posture.timestamp = timestamp
        diagnostics["errors"].extend(posture_errors)

        snapshot = NetworkIntelligenceSnapshot(
            timestamp=timestamp,
            posture=posture,
            connections=connections,
            listeners=listeners,
            endpoints=_endpoints_from_connections(connections),
            diagnostics=diagnostics,
        )
        snapshot.baseline_comparison = compare_network_baseline(snapshot, baseline)
        baseline_posture = baseline.posture if baseline else None
        snapshot.findings = [
            *score_connections(snapshot.connections),
            *score_listeners(snapshot.listeners),
            *score_posture(snapshot.posture, baseline_posture),
        ]
        diagnostics["completed_at"] = utc_now_iso()
        diagnostics["collector_counts"] = {
            "connections": len(snapshot.connections),
            "listeners": len(snapshot.listeners),
            "endpoints": len(snapshot.endpoints),
            "findings": len(snapshot.findings),
        }
        return snapshot

    def _collect_posture(self) -> tuple[NetworkPosture, list[str]]:
        posture = NetworkPosture()
        errors: list[str] = []
        route_posture, route_errors = DNSGatewayCollector(self.runner).collect()
        vpn_posture, vpn_errors = VPNProxyCollector(self.runner).collect()
        errors.extend(route_errors)
        errors.extend(vpn_errors)
        posture.active_interface = route_posture.active_interface
        posture.gateway = route_posture.gateway
        posture.dns_servers = route_posture.dns_servers
        posture.vpn_active = vpn_posture.vpn_active
        posture.vpn_name = vpn_posture.vpn_name
        posture.proxy_enabled = vpn_posture.proxy_enabled
        posture.proxy_details = vpn_posture.proxy_details
        return posture, errors


def _run(command: list[str]):
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=12)
    except Exception as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


def _command_record(command: list[str], result) -> dict[str, Any]:
    return {
        "command": " ".join(command),
        "returncode": int(getattr(result, "returncode", 1)),
        "stderr": str(getattr(result, "stderr", "") or "")[:500],
        "stdout_bytes": len(str(getattr(result, "stdout", "") or "")),
    }


def _endpoints_from_connections(connections) -> list[NetworkEndpoint]:
    endpoints: dict[tuple[str, str, str], NetworkEndpoint] = {}
    for connection in connections:
        key = (connection.remote_address, connection.remote_port, connection.protocol)
        if key not in endpoints:
            endpoints[key] = NetworkEndpoint(
                ip=connection.remote_address,
                port=connection.remote_port,
                protocol=connection.protocol,
                first_seen=connection.timestamp,
                last_seen=connection.timestamp,
                baseline_status=connection.baseline_status,
                risk_level=connection.risk_level,
            )
        else:
            endpoints[key].last_seen = connection.timestamp
    return list(endpoints.values())
