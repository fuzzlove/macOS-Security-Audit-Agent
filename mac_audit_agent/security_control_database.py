"""Canonical, read-only aggregation of MSAA security-control mappings.

This registry does not replace detector logic or framework-specific scoring. It
provides one validated query surface over existing authoritative mappings.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from mac_audit_agent.frameworks import mappings_for_finding
from mac_audit_agent.scan_category_standards import mapping_for
from mac_audit_agent.security_controls.registry import CONTROL_REGISTRY

MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass(frozen=True)
class SecurityControlRecord:
    record_id: str
    finding_category: str
    title: str
    mitre_techniques: tuple[str, ...]
    nist_controls: tuple[str, ...]
    nist_csf: tuple[str, ...]
    cis_controls: tuple[str, ...]
    cisa_recommendations: tuple[str, ...]
    remediation: tuple[str, ...]
    evidence_required: tuple[str, ...]
    source_modules: tuple[str, ...]
    qualification: str = "Supporting security mapping only; not certification and not proof that an ATT&CK technique occurred."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


BASE_RECORDS = (
    SecurityControlRecord("control.persistence", "persistence", "Persistence and startup security", ("T1543.001", "T1543.004", "T1053"), ("SI-4", "CM-3", "CM-6", "AU-6"), ("DE.CM", "RS.AN"), ("CIS 4", "CIS 8", "CIS 13"), ("Preserve persistence evidence and validate authorized startup changes.",), ("Verify owner, signature, target, hash, baseline, and business purpose before remediation.",), ("configuration artifact", "target metadata", "baseline comparison"), ("persistence_intelligence", "frameworks", "remediation")),
    SecurityControlRecord("control.identity", "identity", "Identity and account security", ("T1555.001", "T1555.003", "T1098", "T1078", "T1087", "T1548"), ("AC-2", "AC-6", "AU-6", "SI-4"), ("PR.AA", "DE.CM", "RS.AN"), ("CIS 5", "CIS 6", "CIS 8"), ("Monitor administrative and credential-access events without collecting secrets.",), ("Preserve process and account-change evidence; validate authorization before changing accounts.",), ("account state", "process attribution", "authorization context"), ("identity_attack", "frameworks", "security_controls")),
    SecurityControlRecord("control.ransomware", "ransomware", "Ransomware behavior and recovery protection", ("T1486", "T1490", "T1562.001"), ("SI-4", "IR-4", "CP-9", "AU-6"), ("DE.CM", "RS.AN", "RC.RP"), ("CIS 10", "CIS 11", "CIS 13", "CIS 17"), ("Maintain tested protected backups and evidence-first response procedures.",), ("Preserve the incident timeline and exact process identity before authorized containment.",), ("file activity metadata", "process identity", "recovery state", "timeline"), ("anti_ransomware", "emergency_response", "secure_evidence_collection")),
    SecurityControlRecord("control.supply_chain", "supply_chain", "Software supply-chain security", ("T1195", "T1195.001", "T1105", "T1518"), ("SR-3", "SR-4", "SA-10", "SA-12", "SI-7", "CM-8"), ("GV.SC", "ID.AM", "PR.PS"), ("CIS 2", "CIS 7", "CIS 16"), ("Validate software provenance, dependency integrity, advisories, and approved update channels.",), ("Verify exact package/version, signature, source, hash, and advisory applicability before action.",), ("software inventory", "signature assessment", "dependency manifest", "hash baseline"), ("supply_chain_security", "not_signed", "anti_typosquatting")),
    SecurityControlRecord("control.network", "network", "Network monitoring and boundary protection", ("T1046", "T1071", "T1105", "T1562.004"), ("SI-4", "SC-7", "AU-6"), ("DE.CM", "PR.IR", "RS.AN"), ("CIS 4", "CIS 12", "CIS 13"), ("Monitor connections, listeners, DNS, proxy, VPN, and firewall drift.",), ("Verify owning process and approved network purpose before containment.",), ("connection metadata", "listener metadata", "process attribution", "baseline"), ("network_intelligence", "firewall", "frameworks")),
    SecurityControlRecord("control.integrity", "integrity", "Software and monitoring integrity", ("T1562.001",), ("SI-7", "CM-5", "AU-9"), ("PR.PS", "DE.CM"), ("CIS 4", "CIS 8", "CIS 16"), ("Protect security tooling and retain verifiable build and runtime evidence.",), ("Preserve mismatched artifacts and restore only from an authorized trusted source.",), ("expected hash", "observed hash", "signature", "authorization record"), ("integrity", "security_controls", "secure_evidence_collection")),
    SecurityControlRecord("control.privacy", "privacy", "macOS privacy permission monitoring", ("T1548", "T1562.001"), ("AC-6", "AU-6", "SI-4"), ("PR.AA", "DE.CM"), ("CIS 5", "CIS 6", "CIS 8"), ("Review TCC permissions through Apple-supported controls; never modify TCC databases directly.",), ("Validate application identity and business need for sensitive permissions.",), ("TCC metadata", "application identity", "change timeline"), ("privacy_monitor", "keylogger_detection", "security_controls")),
    SecurityControlRecord("control.evidence", "evidence", "Evidence preservation and incident accountability", (), ("AU-3", "AU-9", "IR-4", "IR-5", "SI-7"), ("DE.AE", "RS.AN", "RS.MA", "RC.RP"), ("CIS 8", "CIS 17"), ("Preserve evidence integrity and maintain chain of custody.",), ("Verify hashes and custody before export or analysis.",), ("artifact hash", "collection timestamp", "collector identity", "custody chain"), ("secure_evidence_collection", "anti_ransomware.evidence", "frameworks.assessment_models")),
    SecurityControlRecord("control.assurance", "assurance", "Continuous security assurance", (), ("CA-7", "CM-3", "CM-5", "CM-6", "SI-4", "RA-5"), ("GV.OC", "ID.AM", "ID.RA", "DE.CM", "RS.AN", "RC.IM"), ("CIS 1", "CIS 2", "CIS 4", "CIS 7", "CIS 8", "CIS 13"), ("Continuously validate identity, software, configuration, threat, and recovery evidence without treating missing telemetry as healthy.",), ("Investigate evidence-backed regressions and restore only through authorized change and response workflows.",), ("posture snapshot", "change event", "evidence reference", "score explanation", "integrity hash"), ("continuous_security_assurance", "zero_trust.posture", "baseline_drift")),
    SecurityControlRecord("control.device_identity", "device_identity", "Zero Trust device identity", (), ("IA-3", "IA-9", "AC-2", "AC-6", "CA-7", "CM-6", "SI-7"), ("GV.OC", "ID.AM", "PR.AA", "DE.CM", "RS.AN"), ("CIS 1", "CIS 2", "CIS 4", "CIS 5", "CIS 6"), ("Continuously verify device identity and posture using current, privacy-preserving evidence.",), ("Review trust-state reasons and evidence before any externally authorized access or incident action.",), ("pseudonymous device identity", "posture snapshot", "attestation hash", "policy result", "decision history"), ("zero_trust.device_identity", "continuous_security_assurance", "identity_attack")),
    SecurityControlRecord("control.posture_graph", "posture_graph", "Security posture relationship analysis", (), ("SI-4", "AU-6", "RA-3", "CA-7", "CM-8"), ("ID.AM", "ID.RA", "DE.CM", "DE.AE", "RS.AN", "GV.OV"), ("CIS 1", "CIS 8", "CIS 13", "CIS 17"), ("Correlate security evidence using explicit identifiers, bounded time, and preserved source references.",), ("Review graph paths as qualified hypotheses; validate causation and authorization context before incident action.",), ("entity attributes", "relationship evidence", "event timestamp", "source module", "risk-path limitations"), ("security_posture_graph", "evidence_graph", "security_timeline")),
    SecurityControlRecord("control.threat_exposure", "threat_exposure", "Threat exposure management", (), ("RA-3", "RA-5", "SI-2", "CA-7", "CM-8"), ("ID.AM", "ID.RA", "PR.PS", "DE.CM", "GV.RM"), ("CIS 1", "CIS 2", "CIS 7", "CIS 13", "CIS 17"), ("Prioritize applicable exposures using sourced exploit intelligence, asset context, and observed defensive posture.",), ("Remediate in evidence-backed risk order through approved vendor and organizational change workflows.",), ("asset identity", "installed version", "applicability evidence", "intelligence source", "score factors", "remediation record"), ("threat_exposure_management", "cve_radar", "supply_chain_security", "security_posture_graph")),
    SecurityControlRecord("control.validation", "control_validation", "macOS security control validation", (), ("CM-2", "CM-3", "CM-6", "CM-8", "SI-4", "CA-7"), ("GV.PO", "ID.AM", "PR.PS", "DE.CM"), ("CIS 1", "CIS 4", "CIS 5", "CIS 6", "CIS 8"), ("Continuously validate approved macOS configuration profiles using fresh, sourced evidence.",), ("Review failures and exceptions; apply changes only through authorized review, approval, execution, and verification.",), ("control definition", "expected state", "actual state", "collector reference", "assessment timestamp"), ("security_control_validation", "security_controls.registry", "baseline_drift")),
    SecurityControlRecord("control.supply_trust_graph", "supply_trust_graph", "Supply-chain trust relationships", ("T1195", "T1195.001"), ("SR-1", "SR-3", "SR-4", "SR-5", "SA-10", "SA-11"), ("GV.SC", "ID.AM", "ID.RA", "PR.PS"), ("CIS 2", "CIS 7", "CIS 16"), ("Maintain evidence-backed software provenance, signing, SBOM, dependency, and vulnerability relationships.",), ("Review low-trust software and dependencies through authorized acquisition and update workflows; do not remove solely on trust score.",), ("software inventory", "signature evidence", "certificate identity", "SBOM", "dependency manifest", "advisory"), ("supply_chain_trust_graph", "supply_chain_security", "not_signed")),
    SecurityControlRecord("control.software_attestation", "software_attestation", "Software identity and integrity attestation", ("T1195", "T1553.001"), ("SI-7", "SA-10", "SA-11", "SR-4", "CM-5"), ("ID.AM", "PR.DS", "PR.PS", "DE.CM", "GV.SC"), ("CIS 2", "CIS 7", "CIS 16"), ("Continuously attest software identity, SHA-256 integrity, provenance, signing, notarization, and contextual risk against approved baselines.",), ("Investigate failed attestations using preserved signature and hash history; blocking or removal requires administrator approval.",), ("software identity", "code signature", "SHA-256 baseline", "notarization assessment", "approved source", "attestation integrity hash"), ("software_attestation", "supply_chain_trust_graph", "threat_exposure_management", "security_posture_graph")),
    SecurityControlRecord("control.security_regression", "security_regression", "Accountable security regression detection", (), ("CM-3", "CM-5", "CM-6", "SI-4", "CA-7", "AU-6"), ("ID.AM", "PR.PS", "DE.CM", "RS.AN", "GV.OV"), ("CIS 1", "CIS 2", "CIS 4", "CIS 5", "CIS 6", "CIS 7", "CIS 8"), ("Compare integrity-bound endpoint snapshots and classify improvements, neutral changes, and regressions with actor, process, authorization, policy, and risk context.",), ("Investigate evidence-backed regressions and restore approved state only through authorized change control.",), ("trusted snapshot", "current snapshot", "change attribution", "process identity", "authorization record", "evidence reference", "score explanation"), ("security_regression_detection", "continuous_security_assurance", "software_attestation", "security_control_validation")),
    SecurityControlRecord("control.cyber_resilience", "cyber_resilience", "Evidence-backed cyber resilience readiness", (), ("IR-4", "IR-5", "IR-8", "CP-2", "CP-4", "CP-9", "CA-7", "SI-4"), ("GV.RM", "ID.AM", "DE.CM", "RS.MA", "RS.AN", "RS.MI", "RC.RP", "RC.IM"), ("CIS 8", "CIS 11", "CIS 13", "CIS 17", "CIS 18"), ("Measure detection, response, containment, recovery, identity, supply-chain, vulnerability, and configuration readiness using versioned controls and traceable evidence.",), ("Address visible readiness gaps in risk order and validate improvements through authorized exercises and recovery testing.",), ("control result", "evidence reference", "simulation result", "recovery test", "calculation version", "category score explanation"), ("cyber_resilience", "attack_simulation", "secure_evidence_collection", "emergency_response")),
    SecurityControlRecord("control.data_governance", "data_governance", "Classified, minimized, access-controlled security information", (), ("AC-3", "AC-6", "AU-9", "MP-4", "SC-28", "SI-12"), ("GV.OC", "GV.PO", "ID.AM", "PR.AA", "PR.DS"), ("CIS 3", "CIS 6", "CIS 8"), ("Classify every data type, document purpose and retention, require least-privilege access, and audit allow and deny decisions.",), ("Classify unknown data before collection and verify encryption, transport, retention, and export protections with evidence.",), ("classification policy", "collection purpose", "access decision", "retention policy", "protection evidence", "audit-chain verification"), ("data_governance", "secure_evidence_collection", "automated_compliance", "ai_security_analyst")),
)


class SecurityControlDatabase:
    def __init__(self, records: tuple[SecurityControlRecord, ...] = BASE_RECORDS) -> None:
        self.records = {record.finding_category: record for record in records}
        self._validate()

    def categories(self) -> list[str]:
        return sorted(self.records)

    def get(self, category: str) -> SecurityControlRecord | None:
        return self.records.get(self.normalize_category(category))

    def resolve_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        category = self.normalize_category(str(finding.get("category") or finding.get("event_category") or finding.get("event_type") or ""))
        record = self.records.get(category)
        inferred = [mapping.to_dict() for mapping in mappings_for_finding(finding)]
        return {
            "category": category or "unmapped",
            "canonical_control": record.to_dict() if record else None,
            "finding_mappings": inferred,
            "mapped": bool(record),
            "framework_inference_available": bool(inferred),
            "limitations": [] if record else ["No canonical MSAA control record is registered for this finding category."],
        }

    def command_mapping(self, command_id: str) -> dict[str, Any] | None:
        value = mapping_for(command_id)
        return asdict(value) if value else None

    def monitored_controls(self) -> list[dict[str, Any]]:
        return [asdict(CONTROL_REGISTRY[key]) for key in sorted(CONTROL_REGISTRY)]

    @staticmethod
    def normalize_category(value: str) -> str:
        text = value.lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "account_change": "identity", "keychain_access": "identity", "ssh_identity_change": "identity",
            "supply_chain_risk_detected": "supply_chain", "persistence_item_modified": "persistence",
            "emergency_evidence_collected": "evidence", "ransomware_detection": "ransomware",
            "monitoring_integrity": "integrity", "tcc": "privacy", "connections": "network",
            "continuous_security_assurance": "assurance", "security_posture_change": "assurance",
            "zero_trust_device_identity": "device_identity", "device_trust_decision": "device_identity",
            "security_posture_graph": "posture_graph", "graph_risk_path": "posture_graph",
            "threat_exposure_management": "threat_exposure", "exposure_finding": "threat_exposure",
            "security_control_validation": "control_validation", "control_validation_event": "control_validation",
            "supply_chain_trust_graph": "supply_trust_graph", "software_trust_relationship": "supply_trust_graph",
            "software_attestation": "software_attestation", "software_integrity_attestation": "software_attestation",
            "security_regression_detection": "security_regression", "security_regression": "security_regression",
            "cyber_resilience_score": "cyber_resilience", "cyber_resilience": "cyber_resilience", "data_governance": "data_governance",
        }
        if text in aliases: return aliases[text]
        for category in ("persistence", "identity", "ransomware", "supply_chain", "network", "integrity", "privacy", "evidence", "assurance", "device_identity", "posture_graph", "threat_exposure", "control_validation", "supply_trust_graph", "software_attestation", "security_regression", "cyber_resilience", "data_governance"):
            if category in text: return category
        return text

    def _validate(self) -> None:
        ids: set[str] = set()
        for category, record in self.records.items():
            if not category or category != record.finding_category or record.record_id in ids:
                raise ValueError("Invalid or duplicate canonical security-control record.")
            ids.add(record.record_id)
            invalid = [technique for technique in record.mitre_techniques if not MITRE_RE.fullmatch(technique)]
            if invalid: raise ValueError(f"Invalid MITRE technique identifiers in {record.record_id}: {invalid}")
            if not record.evidence_required or not record.remediation or not record.source_modules:
                raise ValueError(f"Incomplete canonical security-control record: {record.record_id}")


__all__ = ["BASE_RECORDS", "SecurityControlDatabase", "SecurityControlRecord"]
