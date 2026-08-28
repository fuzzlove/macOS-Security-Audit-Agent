from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


VALID_STATES = {"validated", "concern", "unknown"}


@dataclass(frozen=True)
class PostureSignal:
    signal_id: str
    domain: str
    label: str
    state: str
    weight: float
    evidence: str
    nist_controls: tuple[str, ...]
    cis_controls: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    evidence_source: str = ""
    evidence_collected_at: str = ""
    evidence_freshness: str = "unknown"
    automatically_collected: bool = False

    def __post_init__(self) -> None:
        if self.state not in VALID_STATES:
            raise ValueError(f"unsupported posture state: {self.state}")
        if not 0 < self.weight <= 100:
            raise ValueError("signal weight must be between 0 and 100")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DeviceTrustPosture:
    score: int
    rating: str
    evidence_coverage_percent: int
    signals: tuple[PostureSignal, ...]
    calculated_at: str
    methodology: str = "Unvalidated evidence receives no trust credit; concerns and unknowns remain distinct."
    assurance_note: str = "Framework mappings provide supporting evidence and do not by themselves certify DoD, CMMC, NIST, or CIS compliance."

    @property
    def domains(self) -> dict[str, tuple[PostureSignal, ...]]:
        names = ("identity", "application", "persistence", "network")
        return {name: tuple(signal for signal in self.signals if signal.domain == name) for name in names}

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["domains"] = {key: [item.to_dict() for item in values] for key, values in self.domains.items()}
        return payload


class ZeroTrustPostureEngine:
    """Calculate a deterministic score from normalized, explicitly sourced evidence.

    Callers provide booleans/counts from authoritative MSAA collectors. Missing
    values are intentionally UNKNOWN rather than inferred as healthy.
    """

    def calculate(self, evidence: Mapping[str, Any]) -> DeviceTrustPosture:
        signals = self._signals(evidence)
        total_weight = sum(item.weight for item in signals)
        earned = sum(item.weight for item in signals if item.state == "validated")
        known = sum(item.weight for item in signals if item.state != "unknown")
        score = round(100 * earned / total_weight) if total_weight else 0
        coverage = round(100 * known / total_weight) if total_weight else 0
        rating = "HIGH TRUST" if score >= 90 else "MODERATE TRUST" if score >= 70 else "LOW TRUST" if score >= 40 else "UNTRUSTED / INSUFFICIENT EVIDENCE"
        calculated_at = str(evidence.get("calculated_at") or datetime.now(timezone.utc).isoformat())
        return DeviceTrustPosture(score, rating, coverage, tuple(signals), calculated_at)

    def evidence_from_scan(self, scan_result: Any) -> dict[str, Any]:
        """Normalize only evidence a completed standard scan actually proves."""
        artifacts = getattr(scan_result, "collected_artifacts", {}) or {}
        processes = artifacts.get("processes", {}) if isinstance(artifacts, Mapping) else {}
        all_processes = processes.get("all", []) if isinstance(processes, Mapping) else []
        launch_items = artifacts.get("launch_snapshots", []) if isinstance(artifacts, Mapping) else []
        ports = artifacts.get("ports", {}) if isinstance(artifacts, Mapping) else {}
        connections = ports.get("active_connections", []) if isinstance(ports, Mapping) else []

        def value(item: Any, key: str, default: Any = None) -> Any:
            return item.get(key, default) if isinstance(item, Mapping) else getattr(item, key, default)

        unsigned = sum(str(value(item, "signed_status", "unknown")).lower() == "unsigned" for item in all_processes)
        unvalidated = sum(str(value(item, "signed_status", "unknown")).lower() in {"", "unknown", "unsigned", "invalid"} for item in all_processes)
        suspicious_persistence = sum(bool(value(item, "suspicious", False)) for item in launch_items)
        suspicious_connections = sum(str(value(item, "risk_level", "info")).lower() in {"high", "critical"} or bool(value(item, "concern", False)) for item in connections)
        unvalidated_connections = sum(str(value(item, "signed_status", "unknown")).lower() in {"", "unknown", "unsigned", "invalid"} for item in connections)
        return {
            "unsigned_applications": unsigned if all_processes else None,
            "unknown_developer_applications": None,  # requires the Not Signed provenance assessor
            "unvalidated_processes": unvalidated if all_processes else None,
            "unapproved_persistence_items": suspicious_persistence if "launch_snapshots" in artifacts else None,
            "persistence_scan_complete": "launch_snapshots" in artifacts,
            "suspicious_outbound_connections": suspicious_connections if "active_connections" in ports else None,
            "unvalidated_network_connections": unvalidated_connections if connections else None,
            "calculated_at": getattr(scan_result, "timestamp", ""),
        }

    @staticmethod
    def _state(value: Any, *, healthy_when_zero: bool = False) -> str:
        if value is None or value == "":
            return "unknown"
        if healthy_when_zero:
            try:
                return "validated" if int(value) == 0 else "concern"
            except (TypeError, ValueError):
                return "unknown"
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"enabled", "verified", "valid", "approved", "clean", "true", "yes"}:
                return "validated"
            if normalized in {"disabled", "invalid", "unapproved", "dirty", "false", "no"}:
                return "concern"
            return "unknown"
        return "validated" if value is True else "concern" if value is False else "unknown"

    def _signals(self, e: Mapping[str, Any]) -> list[PostureSignal]:
        def signal(key: str, domain: str, label: str, weight: float, *, zero: bool = False, nist: tuple[str, ...], cis: tuple[str, ...], mitre: tuple[str, ...]) -> PostureSignal:
            value = e.get(key)
            state = self._state(value, healthy_when_zero=zero)
            shown = "not collected" if value is None or value == "" else str(value)
            metadata_by_control = e.get("_evidence_metadata", {})
            metadata = metadata_by_control.get(key, {}) if isinstance(metadata_by_control, Mapping) else {}
            return PostureSignal(
                key, domain, label, state, weight, shown, nist, cis, mitre,
                evidence_source=str(metadata.get("source", "")) if isinstance(metadata, Mapping) else "",
                evidence_collected_at=str(metadata.get("collected_at", "")) if isinstance(metadata, Mapping) else "",
                evidence_freshness=str(metadata.get("freshness", "unknown")) if isinstance(metadata, Mapping) else "unknown",
                automatically_collected=bool(metadata.get("automatic", False)) if isinstance(metadata, Mapping) else False,
            )

        return [
            signal("filevault_enabled", "identity", "FileVault enabled", 8, nist=("AC-3", "MP-5", "SC-28"), cis=("CIS 3.11",), mitre=("T1005",)),
            signal("secure_boot_verified", "identity", "Secure Boot verified", 7, nist=("AC-3", "SI-7"), cis=("CIS 4.1",), mitre=("T1542",)),
            signal("sip_enabled", "identity", "System Integrity Protection enabled", 8, nist=("AC-3", "CM-5", "SI-7"), cis=("CIS 4.1",), mitre=("T1562.001",)),
            signal("firewall_enabled", "identity", "Firewall enabled", 7, nist=("AC-4", "SC-7"), cis=("CIS 4.4", "CIS 13.3"), mitre=("T1562.004",)),
            signal("unsigned_applications", "application", "Unsigned applications", 9, zero=True, nist=("AC-6", "CM-7", "SI-7"), cis=("CIS 2.3", "CIS 10.1"), mitre=("T1553.002",)),
            signal("unknown_developer_applications", "application", "Unknown-developer applications", 7, zero=True, nist=("AC-6", "CM-7"), cis=("CIS 2.3",), mitre=("T1553.002",)),
            signal("unvalidated_processes", "application", "Unvalidated running processes", 9, zero=True, nist=("AC-6", "SI-4"), cis=("CIS 2.7", "CIS 13.7"), mitre=("T1059",)),
            signal("unapproved_persistence_items", "persistence", "Unapproved persistence items", 13, zero=True, nist=("AC-2", "AC-6", "CM-7", "SI-4"), cis=("CIS 4.1", "CIS 13.7"), mitre=("T1547", "T1053")),
            signal("persistence_scan_complete", "persistence", "Persistence inventory completed", 7, nist=("AC-2", "CA-7", "SI-4"), cis=("CIS 4.1", "CIS 8.8"), mitre=("T1547",)),
            signal("approved_dns", "network", "Approved DNS configuration", 6, nist=("AC-4", "SC-20", "SC-21"), cis=("CIS 4.9", "CIS 13.4"), mitre=("T1071.004",)),
            signal("suspicious_outbound_connections", "network", "Suspicious outbound connections", 10, zero=True, nist=("AC-4", "SC-7", "SI-4"), cis=("CIS 13.3", "CIS 13.7"), mitre=("T1071", "T1041")),
            signal("unvalidated_network_connections", "network", "Unvalidated network connections", 9, zero=True, nist=("AC-4", "AC-17", "SC-7"), cis=("CIS 12.2", "CIS 13.3"), mitre=("T1095",)),
        ]
