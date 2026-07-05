from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from mac_audit_agent.models import utc_now_iso


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


@dataclass
class NetworkConnection:
    connection_id: str = field(default_factory=lambda: _id("conn"))
    timestamp: str = field(default_factory=utc_now_iso)
    protocol: str = ""
    local_address: str = ""
    local_port: str = ""
    remote_address: str = ""
    remote_port: str = ""
    state: str = ""
    pid: int | None = None
    process_name: str = ""
    process_path: str = ""
    user: str = ""
    signed_status: str = "unknown"
    command_line_redacted: str = ""
    source_collector: str = "lsof"
    baseline_status: str = "unknown"
    risk_level: str = "info"
    confidence: str = "medium"
    evidence: str = ""

    def key(self) -> tuple[Any, ...]:
        return (self.protocol, self.process_name, self.pid, self.remote_address, self.remote_port)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ListeningPort:
    listener_id: str = field(default_factory=lambda: _id("listener"))
    timestamp: str = field(default_factory=utc_now_iso)
    protocol: str = ""
    local_address: str = ""
    port: str = ""
    state: str = "LISTEN"
    pid: int | None = None
    process_name: str = ""
    process_path: str = ""
    user: str = ""
    service_guess: str = ""
    nmap_service: str = ""
    source_collector: str = "lsof"
    baseline_status: str = "unknown"
    visibility_status: str = "normal"
    risk_level: str = "info"
    evidence: str = ""

    def key(self) -> tuple[Any, ...]:
        return (self.protocol, self.process_name, self.pid, self.local_address, self.port)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkEndpoint:
    endpoint_id: str = field(default_factory=lambda: _id("endpoint"))
    ip: str = ""
    hostname: str = ""
    reverse_dns: str = ""
    port: str = ""
    protocol: str = ""
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    baseline_status: str = "unknown"
    reputation_status: str = ""
    risk_level: str = "info"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkPosture:
    timestamp: str = field(default_factory=utc_now_iso)
    active_interface: str = ""
    local_ip: str = ""
    subnet: str = ""
    gateway: str = ""
    dns_servers: list[str] = field(default_factory=list)
    vpn_active: bool = False
    vpn_name: str = ""
    proxy_enabled: bool = False
    proxy_details: str = ""
    network_location: str = ""
    wifi_ssid: str = ""
    source_collector: str = "network_intelligence"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkFinding:
    finding_id: str = field(default_factory=lambda: _id("netfind"))
    title: str = ""
    severity: str = "info"
    confidence: str = "medium"
    category: str = "network"
    description: str = ""
    evidence: str = ""
    why_it_matters: str = ""
    suggested_fix: str = ""
    validation_steps: str = ""
    false_positive_notes: str = ""
    mitre_mappings: list[str] = field(default_factory=list)
    nist_mappings: list[str] = field(default_factory=list)
    source: str = "network_intelligence"
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkIntelligenceSnapshot:
    snapshot_id: str = field(default_factory=lambda: _id("netsnap"))
    timestamp: str = field(default_factory=utc_now_iso)
    posture: NetworkPosture = field(default_factory=NetworkPosture)
    connections: list[NetworkConnection] = field(default_factory=list)
    listeners: list[ListeningPort] = field(default_factory=list)
    endpoints: list[NetworkEndpoint] = field(default_factory=list)
    findings: list[NetworkFinding] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    baseline_comparison: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "posture": self.posture.to_dict(),
            "connections": [item.to_dict() for item in self.connections],
            "listeners": [item.to_dict() for item in self.listeners],
            "endpoints": [item.to_dict() for item in self.endpoints],
            "findings": [item.to_dict() for item in self.findings],
            "diagnostics": dict(self.diagnostics),
            "baseline_comparison": dict(self.baseline_comparison),
        }
