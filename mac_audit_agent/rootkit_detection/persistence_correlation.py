from __future__ import annotations

from mac_audit_agent.rootkit_detection.models import (
    ExtensionInventoryItem,
    PortVisibilityFinding,
    RootkitSuspectFinding,
    SystemIntegrityPosture,
    VisibilityMismatch,
    stable_id,
)
from mac_audit_agent.rootkit_detection.risk_scoring import score_indicators


def correlate_rootkit_suspects(
    *,
    posture: SystemIntegrityPosture,
    extensions: list[ExtensionInventoryItem],
    ports: list[PortVisibilityFinding],
    mismatches: list[VisibilityMismatch],
) -> list[RootkitSuspectFinding]:
    score = score_indicators(posture=posture, extensions=extensions, ports=ports)
    if not score.reasons:
        return []
    evidence = list(score.reasons)
    evidence.extend(f"{item.protocol}/{item.port} {item.visibility_status}" for item in ports if item.visibility_status in {"hidden_candidate", "missing_owner"})
    evidence.extend(item.bundle_id or item.path for item in extensions if item.risk_flags or item.signed_status == "unsigned" or (item.loaded and not item.team_id))
    title = "Rootkit-like advanced persistence suspect indicators require review"
    if score.severity == "critical":
        title = "Critical rootkit-like advanced persistence suspect review"
    elif score.severity == "high":
        title = "High-priority advanced persistence suspect review"
    return [
        RootkitSuspectFinding(
            finding_id=stable_id("rootkit_correlation", ",".join(score.reasons), len(mismatches)),
            title=title,
            severity=score.severity,
            confidence=score.confidence,
            category="tamper_indicator" if posture.reduced_security_detected else "visibility_mismatch",
            description="Multiple local indicators were correlated for analyst review. This is not a confirmed rootkit finding.",
            evidence=evidence[:25],
            why_it_matters="Modern rootkit-like behavior can combine weakened integrity controls, privileged extensions, hidden visibility, and persistence.",
            rootkit_relevance="MITRE describes rootkits as hiding components by modifying or intercepting visibility into files, processes, services, drivers, and network connections.",
            false_positive_notes=score.false_positive_notes,
            recommended_fix="Preserve evidence, re-run local cross-checks, verify signatures and owners, and review persistence/network/admin timelines before remediation.",
            examine_further_steps=[
                "Repeat lsof/netstat/local probe collection close together in time.",
                "Review extension Team IDs, paths, signatures, and install source.",
                "Correlate with LaunchAgents, LaunchDaemons, admin changes, DNS/gateway/VPN changes, and MSAA integrity state.",
                "Escalate to SOC/IR or Apple/vendor support if indicators remain unexplained.",
            ],
            apple_evidence_export_recommended=True,
            mitre_mappings=["T1014 Rootkit", "T1547.006 Kernel Modules and Extensions", "T1562 Impair Defenses"],
            nist_mappings=["SI-4 System Monitoring", "SI-7 Software, Firmware, and Information Integrity", "AU-6 Audit Review"],
            cisa_mappings=["Logging and monitoring", "Incident response evidence", "Secure configuration"],
            cmmc_mappings=["System and Information Integrity", "Audit and Accountability", "Incident Response"],
        )
    ]
