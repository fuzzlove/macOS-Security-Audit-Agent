"""Privacy-preserving Zero Trust device identity and posture attestation.

This module recommends trust states from current MSAA evidence.  It does not
grant or deny access, collect identifiers autonomously, or perform remediation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import uuid4

from mac_audit_agent.continuous_security_assurance import SecurityPostureSnapshot


TRUSTED = "TRUSTED"
CONDITIONAL = "CONDITIONAL TRUST"
RESTRICTED = "RESTRICTED TRUST"
UNTRUSTED = "UNTRUSTED"
TRUST_STATES = {TRUSTED, CONDITIONAL, RESTRICTED, UNTRUSTED}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DeviceIdentityProfile:
    device_id: str
    model: str
    architecture: str
    hardware_capabilities: tuple[str, ...]
    secure_enclave_available: bool | None
    secure_boot_status: str
    macos_version: str
    build_number: str
    patch_status: str
    identity_source: str
    evidence_reference: tuple[str, ...]
    privacy_notice: str = "Raw serial numbers, platform UUIDs, credentials, and personal tracking data are not stored."

    @classmethod
    def from_approved_metadata(
        cls,
        metadata: Mapping[str, Any],
        *,
        device_id: str = "",
        stable_identifier: str = "",
        organization_salt: bytes | None = None,
    ) -> "DeviceIdentityProfile":
        if not device_id:
            if not stable_identifier or not organization_salt or len(organization_salt) < 16:
                raise ValueError("An approved device_id or an approved stable identifier with at least 16 bytes of organization salt is required.")
            device_id = "msaa-device-" + hmac.new(organization_salt, stable_identifier.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
            source = "organization-scoped HMAC pseudonym"
        else:
            source = "administrator-provided device ID"
        capabilities = metadata.get("hardware_capabilities", [])
        if isinstance(capabilities, str): capabilities = [capabilities]
        references = metadata.get("evidence_reference", [])
        if isinstance(references, str): references = [references]
        return cls(
            device_id=device_id, model=str(metadata.get("model", "unknown")), architecture=str(metadata.get("architecture", "unknown")),
            hardware_capabilities=tuple(str(item) for item in capabilities),
            secure_enclave_available=metadata.get("secure_enclave_available") if isinstance(metadata.get("secure_enclave_available"), bool) else None,
            secure_boot_status=str(metadata.get("secure_boot_status", "unknown")), macos_version=str(metadata.get("macos_version", "unknown")),
            build_number=str(metadata.get("build_number", "unknown")), patch_status=str(metadata.get("patch_status", "unknown")), identity_source=source,
            evidence_reference=tuple(str(item) for item in references if str(item).strip()),
        )

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class PolicyResult:
    policy_id: str
    matched: bool
    recommended_action: str
    reason: str
    evidence_reference: tuple[str, ...]
    authorization_required: bool = True

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class DeviceAttestation:
    attestation_id: str
    timestamp: str
    device: DeviceIdentityProfile
    trust_state: str
    trust_score: int
    security_score: int
    evidence_coverage_percent: int
    identity_status: str
    configuration_status: str
    software_status: str
    threat_exposure: str
    compliance_status: str
    reasons: tuple[str, ...]
    evidence_reference: tuple[str, ...]
    policy_results: tuple[PolicyResult, ...]
    posture_snapshot_id: str
    attestation_hash: str = ""
    qualification: str = "Internal MSAA evidence representation; not a cryptographic platform attestation, access authorization, or compliance certification."

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["device"] = self.device.to_dict()
        payload["policy_results"] = [item.to_dict() for item in self.policy_results]
        return payload


@dataclass(frozen=True)
class TrustDecisionEvent:
    event_id: str
    decision_id: str
    timestamp: str
    device_id: str
    previous_trust_state: str
    new_trust_state: str
    reason: tuple[str, ...]
    evidence_reference: tuple[str, ...]
    risk_score: int
    policy_trigger: tuple[str, ...]
    analyst_status: str = "new"

    def to_dict(self) -> dict[str, Any]: return asdict(self)


class ZeroTrustPolicyEngine:
    """Transparent decision-support policies; no policy performs enforcement."""
    def evaluate(self, posture: SecurityPostureSnapshot, context: Mapping[str, Any], evidence: tuple[str, ...]) -> tuple[PolicyResult, ...]:
        critical_kev = int(context.get("critical_kev_vulnerabilities", 0) or 0)
        active_threat = bool(context.get("active_threat", False))
        compromise = bool(context.get("confirmed_compromise_indicator", False))
        integrity_failure = bool(context.get("integrity_failure", False))
        unsigned = self._signal_value(posture, "unsigned_applications")
        persistence = self._signal_value(posture, "suspicious_persistence")
        return (
            PolicyResult("zt.require-remediation-critical-kev", critical_kev > 0, "require_remediation", f"Critical known-exploited vulnerabilities observed: {critical_kev}.", evidence),
            PolicyResult("zt.investigate-active-threat", active_threat, "start_authorized_investigation", "Active threat evidence is present." if active_threat else "No active threat flag was supplied.", evidence),
            PolicyResult("zt.investigate-integrity-failure", integrity_failure or compromise, "start_authorized_investigation", "Integrity failure or confirmed compromise indicator is present." if integrity_failure or compromise else "No integrity failure or confirmed compromise indicator was supplied.", evidence),
            PolicyResult("zt.review-unsigned-software", unsigned > 0, "require_review", f"Unsigned applications requiring review: {unsigned}.", evidence),
            PolicyResult("zt.review-persistence", persistence > 0, "require_review", f"Suspicious persistence findings: {persistence}.", evidence),
        )

    @staticmethod
    def _signal_value(posture: SecurityPostureSnapshot, key: str) -> int:
        signal = next((item for item in posture.signals if item.key == key), None)
        try: return int(signal.observed_value) if signal and signal.status != "unknown" else 0
        except (TypeError, ValueError): return 0


class ZeroTrustDeviceIdentityEngine:
    def __init__(self, policy_engine: ZeroTrustPolicyEngine | None = None) -> None:
        self.policy_engine = policy_engine or ZeroTrustPolicyEngine()

    def verify(
        self,
        profile: DeviceIdentityProfile,
        posture: SecurityPostureSnapshot,
        *,
        context: Mapping[str, Any] | None = None,
        previous: DeviceAttestation | None = None,
    ) -> tuple[DeviceAttestation, TrustDecisionEvent]:
        if profile.device_id != posture.device_id:
            raise ValueError("Device identity and posture snapshot identifiers do not match.")
        context = context or {}
        context_references = context.get("evidence_reference", [])
        if isinstance(context_references, str): context_references = [context_references]
        decisive = any(bool(context.get(key)) for key in ("critical_kev_vulnerabilities", "active_threat", "confirmed_compromise_indicator", "integrity_failure", "unauthorized_identity_change"))
        if decisive and not context_references:
            raise ValueError("Trust-impacting external context requires an evidence_reference.")
        evidence = tuple(sorted({*profile.evidence_reference, *(str(item) for item in context_references if str(item).strip()), *(ref for signal in posture.signals for ref in signal.evidence_reference)}))
        policies = self.policy_engine.evaluate(posture, context, evidence)
        state, reasons = self._trust_state(posture, profile, context, policies)
        base = DeviceAttestation(
            f"zt-attestation-{uuid4().hex}", posture.timestamp, profile, state, posture.trust_score, posture.security_score,
            posture.evidence_coverage_percent, self._identity_status(posture, profile), self._status(posture.configuration_score),
            self._status(posture.software_score), self._exposure(posture.threat_score), self._status(posture.compliance_score),
            tuple(reasons), evidence, policies, posture.snapshot_id,
        )
        digest = _sha256(base.to_dict())
        attestation = DeviceAttestation(**{**base.to_dict(), "device": profile, "policy_results": policies, "reasons": tuple(reasons), "evidence_reference": evidence, "attestation_hash": digest})
        matched = tuple(item.policy_id for item in policies if item.matched)
        event = TrustDecisionEvent(
            f"zt-event-{uuid4().hex}", f"zt-decision-{uuid4().hex}", posture.timestamp, profile.device_id,
            previous.trust_state if previous else "NOT PREVIOUSLY VERIFIED", state, tuple(reasons), evidence,
            100 - posture.security_score, matched,
        )
        return attestation, event

    def dashboard(self, attestation: DeviceAttestation, history: Iterable[TrustDecisionEvent] = ()) -> dict[str, Any]:
        return {
            "category": "Zero Trust Device Identity", "device_trust_state": attestation.trust_state,
            "trust_score": attestation.trust_score, "last_verification": attestation.timestamp,
            "security_evidence": list(attestation.evidence_reference),
            "policy_results": [item.to_dict() for item in attestation.policy_results],
            "verification_history": [item.to_dict() for item in history],
            "actions": ["verify_device", "view_evidence", "generate_attestation", "review_changes", "start_investigation"],
            "authorization_notice": "MSAA provides decision support only; access restriction and incident actions require authorized external workflows.",
        }

    def analyst_context(self, attestation: DeviceAttestation, event: TrustDecisionEvent) -> dict[str, Any]:
        return {
            "observed_facts": event.to_dict(), "attestation_reference": attestation.attestation_id,
            "explanation": f"Device trust is {attestation.trust_state}: " + "; ".join(attestation.reasons),
            "confidence": "high" if attestation.evidence_coverage_percent >= 90 else "medium" if attestation.evidence_coverage_percent >= 70 else "low",
            "uncertainty": [] if attestation.evidence_coverage_percent == 100 else [f"Evidence coverage is {attestation.evidence_coverage_percent}%."],
            "guardrail": "The analyst assistant must not override policy or make a final access decision.",
        }

    def emergency_response_context(self, attestation: DeviceAttestation, event: TrustDecisionEvent) -> dict[str, Any]:
        eligible = attestation.trust_state in {RESTRICTED, UNTRUSTED}
        return {"eligible": eligible, "authorization_required": True, "automatic_action": False, "evidence_reference": list(event.evidence_reference), "recommended_workflow": "collect_evidence_then_request_investigation" if eligible else "continue_monitoring"}

    @staticmethod
    def verify_attestation(attestation: DeviceAttestation) -> bool:
        payload = attestation.to_dict(); expected = str(payload.pop("attestation_hash", "")); payload["attestation_hash"] = ""
        return bool(expected) and hmac.compare_digest(_sha256(payload), expected)

    def _trust_state(self, posture: SecurityPostureSnapshot, profile: DeviceIdentityProfile, context: Mapping[str, Any], policies: tuple[PolicyResult, ...]) -> tuple[str, list[str]]:
        reasons: list[str] = []
        if posture.evidence_coverage_percent < 60: reasons.append("Insufficient current evidence prevents device verification.")
        if profile.secure_boot_status.lower() in {"disabled", "reduced security", "invalid"}: reasons.append("Secure Boot hardware posture requires investigation.")
        if context.get("confirmed_compromise_indicator"): reasons.append("A confirmed compromise indicator was supplied by an authoritative detector.")
        if context.get("integrity_failure"): reasons.append("System or software integrity verification failed.")
        if context.get("unauthorized_identity_change"): reasons.append("An unauthorized device or account identity change was observed.")
        critical_kev = int(context.get("critical_kev_vulnerabilities", 0) or 0)
        if critical_kev: reasons.append(f"{critical_kev} critical known-exploited vulnerability finding(s) require remediation.")
        if context.get("active_threat"): reasons.append("Active threat evidence requires investigation.")
        concerns = [item for item in posture.signals if item.status == "concern"]
        core_protection_disabled = any(item.key in {"firewall_enabled", "filevault_enabled", "sip_enabled"} for item in concerns)
        reasons.extend(item.explanation for item in concerns)
        if context.get("confirmed_compromise_indicator") or context.get("integrity_failure") or context.get("unauthorized_identity_change"):
            return UNTRUSTED, reasons
        if critical_kev or context.get("active_threat") or core_protection_disabled or any(item.severity == "critical" for item in concerns):
            return RESTRICTED, reasons
        if posture.evidence_coverage_percent < 90 or posture.security_score < 90 or concerns or any(item.matched for item in policies):
            return CONDITIONAL, reasons or ["Current evidence does not meet the trusted-device threshold."]
        return TRUSTED, ["Identity, configuration, software, threat, recovery, and evidence coverage requirements are satisfied."]

    @staticmethod
    def _identity_status(posture: SecurityPostureSnapshot, profile: DeviceIdentityProfile) -> str:
        identity = [item for item in posture.signals if item.domain == "identity"]
        if profile.model == "unknown" or profile.architecture == "unknown" or any(item.status == "unknown" for item in identity): return "UNKNOWN"
        return "CONCERN" if any(item.status == "concern" for item in identity) else "VERIFIED"

    @staticmethod
    def _status(score: int) -> str: return "COMPLIANT" if score >= 90 else "NEEDS REVIEW" if score >= 70 else "NON-COMPLIANT"
    @staticmethod
    def _exposure(score: int) -> str: return "LOW" if score >= 90 else "MEDIUM" if score >= 70 else "HIGH"


class DeviceIdentityRepository:
    def __init__(self, database: sqlite3.Connection | Path | str) -> None:
        self._owns = not isinstance(database, sqlite3.Connection)
        self.conn = sqlite3.connect(str(database)) if self._owns else database
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS device_identity (
          device_id TEXT PRIMARY KEY, hardware_identity TEXT NOT NULL, os_version TEXT NOT NULL,
          security_state TEXT NOT NULL, trust_state TEXT NOT NULL, last_verified TEXT NOT NULL,
          attestation_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trust_decisions (
          decision_id TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, timestamp TEXT NOT NULL, device_id TEXT NOT NULL,
          trust_state TEXT NOT NULL, reason TEXT NOT NULL, evidence TEXT NOT NULL, policy TEXT NOT NULL,
          attestation_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_trust_decisions_device_time ON trust_decisions(device_id, timestamp DESC);
        """)
        self.conn.commit()

    def close(self) -> None:
        if self._owns: self.conn.close()

    def save(self, attestation: DeviceAttestation, event: TrustDecisionEvent) -> None:
        if not ZeroTrustDeviceIdentityEngine.verify_attestation(attestation):
            raise ValueError("Refusing to store an invalid device attestation.")
        with self.conn:
            self.conn.execute("""INSERT INTO device_identity VALUES (?,?,?,?,?,?,?,?)
              ON CONFLICT(device_id) DO UPDATE SET hardware_identity=excluded.hardware_identity, os_version=excluded.os_version,
              security_state=excluded.security_state, trust_state=excluded.trust_state, last_verified=excluded.last_verified,
              attestation_hash=excluded.attestation_hash, payload_json=excluded.payload_json""", (
                attestation.device.device_id, _sha256({"model": attestation.device.model, "architecture": attestation.device.architecture}),
                attestation.device.macos_version, attestation.configuration_status, attestation.trust_state,
                attestation.timestamp, attestation.attestation_hash, _canonical(attestation.to_dict()),
            ))
            self.conn.execute("INSERT INTO trust_decisions VALUES (?,?,?,?,?,?,?,?,?,?)", (
                event.decision_id, event.event_id, event.timestamp, event.device_id, event.new_trust_state,
                _canonical(event.reason), _canonical(event.evidence_reference), _canonical(event.policy_trigger),
                attestation.attestation_hash, _canonical(event.to_dict()),
            ))

    def decision_history(self, device_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT payload_json FROM trust_decisions WHERE device_id=? ORDER BY timestamp DESC LIMIT ?", (device_id, max(1, min(limit, 1000)))).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def latest_attestation(self, device_id: str) -> DeviceAttestation | None:
        row = self.conn.execute("SELECT payload_json FROM device_identity WHERE device_id=?", (device_id,)).fetchone()
        if not row: return None
        payload = json.loads(row["payload_json"])
        device_payload = payload.pop("device"); device_payload["hardware_capabilities"] = tuple(device_payload.get("hardware_capabilities", [])); device_payload["evidence_reference"] = tuple(device_payload.get("evidence_reference", []))
        profile = DeviceIdentityProfile(**device_payload)
        policies = tuple(PolicyResult(**item) for item in payload.pop("policy_results", []))
        payload["reasons"] = tuple(payload.get("reasons", [])); payload["evidence_reference"] = tuple(payload.get("evidence_reference", []))
        attestation = DeviceAttestation(device=profile, policy_results=policies, **payload)
        if not ZeroTrustDeviceIdentityEngine.verify_attestation(attestation):
            raise ValueError(f"Device attestation integrity verification failed: {attestation.attestation_id}")
        return attestation


__all__ = ["CONDITIONAL", "DeviceAttestation", "DeviceIdentityProfile", "DeviceIdentityRepository", "PolicyResult", "RESTRICTED", "TRUSTED", "TrustDecisionEvent", "UNTRUSTED", "ZeroTrustDeviceIdentityEngine", "ZeroTrustPolicyEngine"]
