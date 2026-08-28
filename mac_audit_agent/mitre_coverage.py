"""Evidence-backed MITRE ATT&CK detection coverage for MSAA.

Framework mappings describe relevance.  They are not, by themselves, proof of
detection coverage.  This module keeps coverage claims separate and requires a
detector, evidence contract, and validation reference for every positive claim.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable

from mac_audit_agent.security_control_database import MITRE_RE


class CoverageStatus(str, Enum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True)
class DetectionCoverage:
    technique_id: str
    technique_name: str
    tactic: str
    status: CoverageStatus
    detector_ids: tuple[str, ...] = ()
    evidence_sources: tuple[str, ...] = ()
    validation_tests: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    canonical_categories: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload


# Statuses are deliberately conservative.  "partial" means useful normalized
# analysis exists but at least one material telemetry, attribution, or runtime
# validation limitation remains.
DEFAULT_COVERAGE = (
    DetectionCoverage("T1543.001", "Launch Agent", "Persistence", CoverageStatus.IMPLEMENTED,
                      ("persistence.launch_agent",), ("launchd plist", "target metadata", "baseline comparison"),
                      ("tests/test_persistence_intelligence.py", "tests/test_attack_simulation.py::test_launch_agent_validation"),
                      canonical_categories=("persistence",)),
    DetectionCoverage("T1543.004", "Launch Daemon", "Persistence", CoverageStatus.IMPLEMENTED,
                      ("persistence.launch_daemon",), ("launchd plist", "ownership", "signature", "target metadata"),
                      ("tests/test_persistence_intelligence.py",), canonical_categories=("persistence",)),
    DetectionCoverage("T1053", "Scheduled Task/Job", "Persistence", CoverageStatus.IMPLEMENTED,
                      ("persistence.scheduled_task",), ("cron metadata", "periodic task metadata", "baseline comparison"),
                      ("tests/test_persistence_intelligence.py",), canonical_categories=("persistence",)),
    DetectionCoverage("T1486", "Data Encrypted for Impact", "Impact", CoverageStatus.PARTIAL,
                      ("ransomware.encryption_behavior",), ("file activity statistics", "entropy transition", "process metadata"),
                      ("tests/test_antiransomware_mitre_mapping.py", "tests/test_attack_simulation.py::test_ransomware_validation"),
                      ("Real-time endpoint file telemetry depends on deployment capabilities; entropy alone is never treated as proof.",),
                      ("ransomware",)),
    DetectionCoverage("T1490", "Inhibit System Recovery", "Impact", CoverageStatus.PARTIAL,
                      ("ransomware.recovery_tampering",), ("command metadata", "backup state", "process metadata"),
                      ("tests/anti_ransomware/test_government_guidance.py",),
                      ("Complete process attribution requires trusted native telemetry.",), ("ransomware",)),
    DetectionCoverage("T1555.001", "Credentials from Password Stores: Keychain", "Credential Access", CoverageStatus.PARTIAL,
                      ("identity.keychain_access",), ("redacted process metadata", "resource category", "signature metadata"),
                      ("tests/test_identity_attack.py",),
                      ("The detector consumes metadata only and requires a trusted telemetry producer; secrets are never collected.",),
                      ("identity",)),
    DetectionCoverage("T1555.003", "Credentials from Web Browsers", "Credential Access", CoverageStatus.PARTIAL,
                      ("identity.browser_credential_access",), ("redacted process metadata", "browser store path category"),
                      ("tests/test_identity_attack.py",),
                      ("File-access attribution requires trusted native telemetry; credential contents are never collected.",),
                      ("identity",)),
    DetectionCoverage("T1098", "Account Manipulation", "Persistence", CoverageStatus.PARTIAL,
                      ("identity.account_change", "identity.ssh_identity_change"),
                      ("account state comparison", "SSH fingerprint metadata", "process metadata"),
                      ("tests/test_identity_attack.py",),
                      ("Authorization context and responsible-process attribution may require external identity or native audit telemetry.",),
                      ("identity",)),
    DetectionCoverage("T1195.001", "Compromise Software Dependencies and Tools", "Initial Access", CoverageStatus.PARTIAL,
                      ("supply_chain.dependency_risk", "supply_chain.install_script"),
                      ("package inventory", "dependency manifest", "local advisory input", "install script analysis"),
                      ("tests/test_supply_chain_security.py",),
                      ("Registry reputation and advisory completeness depend on administrator-approved data sources.",),
                      ("supply_chain",)),
    DetectionCoverage("T1046", "Network Service Discovery", "Discovery", CoverageStatus.IMPLEMENTED,
                      ("network.listener_review",), ("listener metadata", "connection metadata", "scan evidence"),
                      ("mac_audit_agent/tests/test_rules.py",), canonical_categories=("network",)),
    DetectionCoverage("T1059", "Command and Scripting Interpreter", "Execution", CoverageStatus.NOT_ASSESSED,
                      limitations=("Related command metadata may be collected, but a qualified technique-level coverage claim has not been established.",)),
    DetectionCoverage("T1003", "OS Credential Dumping", "Credential Access", CoverageStatus.UNAVAILABLE,
                      limitations=("MSAA does not collect credentials or authentication secrets; no detection coverage is claimed by this matrix.",)),
)


class MITRECoverageMatrix:
    def __init__(self, entries: Iterable[DetectionCoverage] = DEFAULT_COVERAGE) -> None:
        self.entries = tuple(entries)
        self._validate()

    def to_dict(self, *, observed_techniques: Iterable[str] = ()) -> dict[str, Any]:
        counts = Counter(entry.status.value for entry in self.entries)
        assessed = counts[CoverageStatus.IMPLEMENTED.value] + counts[CoverageStatus.PARTIAL.value]
        return {
            "qualification": "Coverage is detector-and-test based. Finding mappings and observed techniques do not create coverage claims.",
            "summary": {
                "total_techniques_listed": len(self.entries),
                "implemented": counts[CoverageStatus.IMPLEMENTED.value],
                "partial": counts[CoverageStatus.PARTIAL.value],
                "unavailable": counts[CoverageStatus.UNAVAILABLE.value],
                "not_assessed": counts[CoverageStatus.NOT_ASSESSED.value],
                "fully_implemented_percent_of_assessed": round(100 * counts[CoverageStatus.IMPLEMENTED.value] / assessed, 1) if assessed else 0.0,
            },
            "observed_techniques": sorted({item for item in observed_techniques if MITRE_RE.fullmatch(str(item))}),
            "techniques": [entry.to_dict() for entry in self.entries],
        }

    def _validate(self) -> None:
        seen: set[str] = set()
        for entry in self.entries:
            if not MITRE_RE.fullmatch(entry.technique_id) or entry.technique_id in seen:
                raise ValueError(f"Invalid or duplicate MITRE coverage entry: {entry.technique_id}")
            seen.add(entry.technique_id)
            if entry.status in {CoverageStatus.IMPLEMENTED, CoverageStatus.PARTIAL}:
                if not entry.detector_ids or not entry.evidence_sources or not entry.validation_tests:
                    raise ValueError(f"Positive coverage claim lacks detector, evidence, or validation: {entry.technique_id}")
            if entry.status is CoverageStatus.IMPLEMENTED and entry.limitations:
                raise ValueError(f"Implemented coverage cannot have material limitations: {entry.technique_id}")
            if entry.status in {CoverageStatus.UNAVAILABLE, CoverageStatus.NOT_ASSESSED} and not entry.limitations:
                raise ValueError(f"Non-covered technique requires an explanation: {entry.technique_id}")


__all__ = ["CoverageStatus", "DEFAULT_COVERAGE", "DetectionCoverage", "MITRECoverageMatrix"]
