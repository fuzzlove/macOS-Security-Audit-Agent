from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from mac_audit_agent.firewall.application_firewall import inspect_application_firewall
from mac_audit_agent.not_signed.models import InstalledSoftwareItem, SoftwareTrustClassification
from mac_audit_agent.network_intelligence import NetworkIntelligenceCollector
from mac_audit_agent.performance.subprocess_runner import run_bounded_command
from mac_audit_agent.rootkit_detection.system_integrity import collect_system_integrity_posture
from mac_audit_agent.zero_trust.attestation_policy import (
    ZeroTrustAttestationPolicy,
    assess_connection_policy,
    assess_dns_policy,
)


SYSTEM_PROFILER = "/usr/sbin/system_profiler"
BPUTIL = "/usr/bin/bputil"


@dataclass(frozen=True)
class AutomaticPostureEvidence:
    values: dict[str, Any]
    observations: dict[str, dict[str, Any]]
    collected_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_secure_boot_profile(payload: str) -> tuple[bool | None, str]:
    """Parse allowlisted Secure Boot fields without treating authenticated root as Secure Boot."""
    try:
        document = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None, "Secure Boot profile could not be decoded"
    text_values: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).lower().replace("_", " ")
                if "secure boot" in normalized or "secureboot" in normalized:
                    text_values.append(str(child))
                visit(child)
        elif isinstance(value, list):
            for child in value[:200]:
                visit(child)

    visit(document)
    summary = "; ".join(text_values)[:512]
    lowered = summary.lower()
    if any(marker in lowered for marker in ("full security", "secure boot enabled", "enabled", "true")):
        return True, summary
    if any(marker in lowered for marker in ("reduced security", "permissive security", "disabled", "false")):
        return False, summary
    return None, summary or "Secure Boot field was not reported by system_profiler"


def parse_secure_boot_policy_text(payload: str) -> tuple[bool | None, str]:
    """Parse explicit bputil policy statements without inferring from unrelated controls."""
    summary = " ".join(str(payload or "").split())[:1024]
    lowered = summary.lower()
    if any(marker in lowered for marker in ("full security: true", "security mode: full", "full security enabled")):
        return True, summary
    if any(marker in lowered for marker in (
        "full security: false", "reduced security: true", "permissive security: true",
        "security mode: reduced", "security mode: permissive",
    )):
        return False, summary
    return None, summary or "bputil did not report an explicit supported boot policy"


def collect_automatic_posture_evidence(
    *,
    system_integrity_collector: Callable = collect_system_integrity_posture,
    firewall_collector: Callable = inspect_application_firewall,
    command_runner: Callable = run_bounded_command,
    network_collector: Callable | None = None,
    policy: ZeroTrustAttestationPolicy | None = None,
) -> AutomaticPostureEvidence:
    collected_at = datetime.now(timezone.utc).isoformat()
    posture, commands = system_integrity_collector()
    firewall = firewall_collector(include_applications=False)
    active_policy = policy or ZeroTrustAttestationPolicy()
    secure_boot: bool | None = None
    secure_boot_summary = "Secure Boot telemetry unavailable"
    try:
        policy_result = command_runner(
            [BPUTIL, "-d"], timeout_seconds=8, max_output_bytes=512 * 1024,
            env={"LC_ALL": "C"},
        )
        if policy_result.returncode == 0:
            secure_boot, secure_boot_summary = parse_secure_boot_policy_text(policy_result.stdout)
    except Exception as exc:
        secure_boot_summary = f"bputil unavailable: {type(exc).__name__}"
    try:
        result = command_runner(
            [SYSTEM_PROFILER, "SPHardwareDataType", "-json"],
            timeout_seconds=12,
            max_output_bytes=2 * 1024 * 1024,
            env={"LC_ALL": "C"},
        )
        if result.returncode == 0 and secure_boot is None:
            secure_boot, secure_boot_summary = parse_secure_boot_profile(result.stdout)
        elif result.returncode != 0 and secure_boot is None:
            secure_boot_summary = result.error or result.stderr[:512] or "system_profiler failed"
    except Exception as exc:
        secure_boot_summary = f"Secure Boot collector unavailable: {type(exc).__name__}"
    network_snapshot = None
    network_error = ""
    try:
        collector = network_collector or NetworkIntelligenceCollector().collect
        network_snapshot = collector()
    except Exception as exc:
        network_error = f"Network collector unavailable: {type(exc).__name__}: {exc}"
    if network_snapshot is None:
        dns_value, dns_observation = None, {
            "status": "UNKNOWN", "current_dns": [], "approved_dns": list(active_policy.approved_dns),
            "reason": network_error or "Network evidence was not collected.",
            "policy_fingerprint": active_policy.fingerprint,
        }
        connection_value, connection_observation = None, {
            "status": "UNKNOWN", "connections": [], "reason": network_error or "Network evidence was not collected.",
            "policy_fingerprint": active_policy.fingerprint,
        }
        suspicious_connections = None
    else:
        posture_network = getattr(network_snapshot, "posture", None)
        dns_value, dns_observation = assess_dns_policy(getattr(posture_network, "dns_servers", ()) or (), active_policy)
        connection_value, connection_observation = assess_connection_policy(network_snapshot, active_policy)
        findings = list(getattr(network_snapshot, "findings", []) or [])
        suspicious_connections = sum(
            str(getattr(item, "severity", getattr(item, "risk_level", "info"))).lower() in {"high", "critical"}
            for item in findings
        )
    values = {
        "filevault_enabled": True if posture.filevault_status == "enabled" else False if posture.filevault_status == "disabled" else None,
        "secure_boot_verified": secure_boot,
        "sip_enabled": True if posture.sip_status == "enabled" else False if posture.sip_status == "disabled" else None,
        "firewall_enabled": firewall.enabled,
        "approved_dns": dns_value,
        "suspicious_outbound_connections": suspicious_connections,
        "unvalidated_network_connections": connection_value,
    }
    observations = {
        "filevault_enabled": {"state": posture.filevault_status, "collector": "fdesetup status", "warnings": list(posture.warnings)},
        "secure_boot_verified": {"state": secure_boot, "collector": "bputil -d; system_profiler SPHardwareDataType -json fallback", "summary": secure_boot_summary},
        "sip_enabled": {"state": posture.sip_status, "collector": "csrutil status", "warnings": list(posture.warnings)},
        "firewall_enabled": {"state": firewall.enabled, "collector": "socketfilterfw --getglobalstate", "errors": list(firewall.errors)},
        "approved_dns": {**dns_observation, "collector": "scutil --dns"},
        "suspicious_outbound_connections": {
            "state": suspicious_connections,
            "collector": "Network Intelligence normalized findings",
            "network_collection_error": network_error,
        },
        "unvalidated_network_connections": {**connection_observation, "collector": "lsof normalized active connections"},
        "attestation_policy": active_policy.to_dict(),
        "commands": {"executed": list(commands)},
    }
    return AutomaticPostureEvidence(values, observations, collected_at)


def software_provenance_evidence(items: list[InstalledSoftwareItem]) -> dict[str, int | None]:
    if not items:
        return {"unsigned_applications": None, "unknown_developer_applications": None, "unvalidated_processes": None}
    unknown = {
        SoftwareTrustClassification.AD_HOC,
        SoftwareTrustClassification.UNSIGNED,
        SoftwareTrustClassification.INVALID,
        SoftwareTrustClassification.REVOKED,
        SoftwareTrustClassification.UNKNOWN,
    }
    return {
        "unsigned_applications": sum(item.signing.classification == SoftwareTrustClassification.UNSIGNED for item in items),
        "unknown_developer_applications": sum(item.signing.classification in unknown for item in items),
        "unvalidated_processes": sum(len(item.running_processes) for item in items if item.signing.classification in unknown),
    }


def persistence_report_evidence(report: Any) -> dict[str, int | bool | None]:
    """Use a completed Persistence Intelligence report without rescanning."""
    if report is None:
        return {"unapproved_persistence_items": None, "persistence_scan_complete": None}
    coverage = list(getattr(report, "coverage", []) or [])
    errors = list(getattr(report, "errors", []) or [])
    states = {str(row.get("coverage_status", "unknown")).lower() for row in coverage if isinstance(row, dict)}
    complete = bool(coverage) and not errors and not states.intersection({"failed", "error", "unavailable", "partial", "degraded", "unknown"})
    findings = list(getattr(report, "findings", []) or [])
    return {
        "unapproved_persistence_items": len(findings),
        "persistence_scan_complete": complete,
    }


def network_activity_evidence(
    snapshot: Any,
    policy: ZeroTrustAttestationPolicy | None = None,
) -> dict[str, int | None]:
    """Derive only claims supported by the process-centric Network Monitor."""
    if snapshot is None:
        return {"suspicious_outbound_connections": None, "unvalidated_network_connections": None}
    groups = list(getattr(snapshot, "groups", []) or [])
    suspicious = sum(
        len(getattr(group, "connections", ()) or ())
        for group in groups
        if str(getattr(group, "risk_level", "info")).lower() in {"high", "critical"}
    )
    unvalidated, _observation = assess_connection_policy(snapshot, policy or ZeroTrustAttestationPolicy())
    return {
        "suspicious_outbound_connections": suspicious,
        "unvalidated_network_connections": unvalidated,
    }


def dns_policy_evidence(observed: Any, policy: ZeroTrustAttestationPolicy) -> tuple[dict[str, bool | None], dict[str, Any]]:
    value, observation = assess_dns_policy(observed, policy)
    return {"approved_dns": value}, observation


def firewall_status_evidence(status: dict[str, Any] | None) -> dict[str, bool | None]:
    if not isinstance(status, dict):
        return {"firewall_enabled": None}
    evidence = status.get("evidence", {}) if isinstance(status.get("evidence", {}), dict) else {}
    application = evidence.get("application_firewall", {}) if isinstance(evidence.get("application_firewall", {}), dict) else {}
    enabled = application.get("enabled")
    if enabled is None:
        state = str(status.get("state", "UNKNOWN")).upper()
        enabled = True if state == "ENABLED" else False if state == "DISABLED" else None
    return {"firewall_enabled": enabled if isinstance(enabled, bool) else None}


__all__ = [
    "AutomaticPostureEvidence", "collect_automatic_posture_evidence", "dns_policy_evidence", "firewall_status_evidence",
    "network_activity_evidence", "parse_secure_boot_policy_text", "parse_secure_boot_profile", "persistence_report_evidence",
    "software_provenance_evidence",
]
