from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from mac_audit_agent.models import utc_now_iso


def stable_id(*parts: object) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


@dataclass
class RootkitSuspectFinding:
    finding_id: str
    title: str
    severity: str
    confidence: str
    category: str
    description: str
    evidence: list[str] = field(default_factory=list)
    why_it_matters: str = ""
    rootkit_relevance: str = ""
    false_positive_notes: list[str] = field(default_factory=list)
    recommended_fix: str = ""
    examine_further_steps: list[str] = field(default_factory=list)
    apple_evidence_export_recommended: bool = False
    mitre_mappings: list[str] = field(default_factory=list)
    nist_mappings: list[str] = field(default_factory=list)
    cisa_mappings: list[str] = field(default_factory=list)
    cmmc_mappings: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SystemIntegrityPosture:
    sip_status: str = "unknown"
    authenticated_root_status: str = "unknown"
    ssv_status: str = "unknown"
    gatekeeper_status: str = "unknown"
    filevault_status: str = "unknown"
    secure_boot_status: str = "unknown"
    reduced_security_detected: bool = False
    csrutil_output: str = ""
    spctl_output: str = ""
    software_update_state: str = "unknown"
    boot_args: str = ""
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExtensionInventoryItem:
    extension_id: str
    type: str
    bundle_id: str = ""
    team_id: str = ""
    path: str = ""
    loaded: bool = False
    enabled: bool = False
    signed_status: str = "unknown"
    notarization_status: str = "unknown"
    owner: str = ""
    permissions: str = ""
    source_tool: str = ""
    collection: str = "unknown"
    address: str = ""
    size: str = ""
    architecture: str = "unknown"
    executable_path: str = ""
    visibility_sources: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VisibilityMismatch:
    mismatch_id: str
    component: str
    source_a: str
    source_b: str
    observed_a: str
    observed_b: str
    mismatch_type: str
    severity: str
    confidence: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PortVisibilityFinding:
    port: int
    protocol: str
    bind_address: str = ""
    process_owner: str = ""
    pid: str = ""
    lsof_seen: bool = False
    netstat_seen: bool = False
    nc_seen: bool | None = None
    nmap_seen: bool | None = None
    socket_state: str = "unknown"
    visibility_status: str = "unknown"
    severity: str = "info"
    confidence: str = "low"
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RootkitScanResult:
    scan_id: str
    started_at: str
    completed_at: str
    mode: str
    local_only: bool = True
    posture: SystemIntegrityPosture = field(default_factory=SystemIntegrityPosture)
    extensions: list[ExtensionInventoryItem] = field(default_factory=list)
    port_findings: list[PortVisibilityFinding] = field(default_factory=list)
    visibility_mismatches: list[VisibilityMismatch] = field(default_factory=list)
    findings: list[RootkitSuspectFinding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    commands_run: list[str] = field(default_factory=list)
    destructive_actions_exposed: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["posture"] = self.posture.to_dict()
        payload["extensions"] = [item.to_dict() for item in self.extensions]
        payload["port_findings"] = [item.to_dict() for item in self.port_findings]
        payload["visibility_mismatches"] = [item.to_dict() for item in self.visibility_mismatches]
        payload["findings"] = [item.to_dict() for item in self.findings]
        return payload
