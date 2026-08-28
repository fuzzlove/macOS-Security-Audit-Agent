"""Declarative, evidence-backed macOS security control validation.

The framework evaluates evidence produced by existing MSAA collectors.  It does
not execute configuration commands or infer that missing evidence is compliant.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import uuid4

from mac_audit_agent.security_controls.registry import CONTROL_REGISTRY

RESULTS = {"passed", "failed", "not_assessed", "excepted"}


def _canonical(value: Any) -> str: return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
def _hash(value: Any) -> str: return hashlib.sha256(_canonical(value).encode()).hexdigest()
def _now() -> str: return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00")); return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError): return None


@dataclass(frozen=True)
class ValidationControl:
    control_id: str
    registry_control_id: str
    name: str
    framework: tuple[str, ...]
    description: str
    validation_method: str
    evidence_key: str
    expected_state: Any
    comparator: str
    severity: str
    remediation: str
    recommended_command: str
    mitre_mapping: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class ControlException:
    control_id: str
    reason: str
    approved_by: str
    approved_at: str
    expires_at: str
    evidence_reference: tuple[str, ...]

    def valid_at(self, timestamp: str) -> bool:
        now, approved, expires = _parse_time(timestamp), _parse_time(self.approved_at), _parse_time(self.expires_at)
        return bool(self.reason and self.approved_by and self.evidence_reference and now and approved and expires and approved <= now < expires)


@dataclass(frozen=True)
class SecurityBaselineProfile:
    profile_id: str
    name: str
    required_controls: tuple[str, ...]
    severity_overrides: tuple[tuple[str, str], ...] = ()
    reporting_requirements: tuple[str, ...] = ("evidence", "result", "remediation", "framework_mapping")

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class ControlValidationResult:
    event_id: str
    assessment_id: str
    timestamp: str
    device_id: str
    control_id: str
    framework: tuple[str, ...]
    expected_state: Any
    actual_state: Any
    result: str
    severity: str
    evidence_reference: tuple[str, ...]
    evidence_source: str
    remediation: str
    uncertainty: tuple[str, ...]
    exception_reason: str = ""

    def to_dict(self) -> dict[str, Any]: return asdict(self)


@dataclass(frozen=True)
class ControlAssessment:
    assessment_id: str
    timestamp: str
    device_id: str
    profile_id: str
    compliance_score: int
    posture_status: str
    passed_controls: int
    failed_controls: int
    not_assessed_controls: int
    excepted_controls: int
    results: tuple[ControlValidationResult, ...]
    security_regressions: tuple[str, ...]
    score_explanation: tuple[str, ...]
    integrity_hash: str = ""
    qualification: str = "Evidence-backed control validation; not certification, authorization, or proof of organization-wide compliance."

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "results": [item.to_dict() for item in self.results]}


CONTROLS = (
    ValidationControl("MSAA-MAC-FW-001", "macos.application_firewall", "Firewall Enabled", ("CIS Apple macOS", "NIST CM-6", "NIST SC-7"), "The macOS application firewall must be enabled.", "system configuration check", "firewall_enabled", True, "equals", "high", "Enable the approved firewall configuration and review exceptions.", "Review with: /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", ("T1562.004",)),
    ValidationControl("MSAA-MAC-FV-001", "macos.filevault", "FileVault Enabled", ("CIS Apple macOS", "NIST SC-28"), "Data-at-rest encryption must be enabled.", "FileVault status check", "filevault_enabled", True, "equals", "high", "Enable FileVault through the approved organizational recovery-key workflow; never collect the key in MSAA.", "Review with: /usr/bin/fdesetup status", ()),
    ValidationControl("MSAA-MAC-SIP-001", "macos.sip", "System Integrity Protection Enabled", ("CIS Apple macOS", "NIST SI-7", "DoD secure baseline"), "System Integrity Protection must remain enabled.", "csrutil status evidence", "sip_enabled", True, "equals", "critical", "Investigate Recovery-mode changes and restore the approved SIP state through an authorized workflow.", "Review with: /usr/bin/csrutil status", ("T1562.001",)),
    ValidationControl("MSAA-MAC-GK-001", "macos.gatekeeper", "Gatekeeper Enabled", ("CIS Apple macOS", "NIST CM-7"), "Gatekeeper application assessment must be enabled.", "Gatekeeper status check", "gatekeeper_enabled", True, "equals", "high", "Restore the approved Gatekeeper policy after validating software requirements.", "Review with: /usr/sbin/spctl --status", ("T1553.001",)),
    ValidationControl("MSAA-MAC-UPD-001", "macos.security_updates", "Supported and Current macOS", ("CIS Apple macOS", "NIST SI-2", "NIST RA-5"), "The operating system must be supported and required security updates applied.", "software update posture", "patch_status", "current", "equals_normalized", "high", "Apply approved Apple security updates and verify the resulting build.", "Review with: /usr/sbin/softwareupdate --list", ()),
    ValidationControl("MSAA-MAC-ADM-001", "macos.accounts", "Approved Administrators Only", ("CIS Apple macOS", "NIST AC-2", "NIST AC-6"), "No unapproved administrator accounts may be present.", "identity inventory comparison", "unapproved_administrators", 0, "numeric_equals", "critical", "Validate account authorization and remove privileges only through approved identity administration.", "Review approved administrator inventory in MSAA Identity Attack Detection.", ("T1098",)),
    ValidationControl("MSAA-MAC-SSH-001", "macos.remote_access", "Remote Login Disabled Unless Approved", ("CIS Apple macOS", "NIST AC-17"), "Remote Login must be disabled unless explicitly authorized.", "sharing service status", "remote_login_enabled", False, "equals", "high", "Validate the business requirement, SSH keys, listeners, and authorization before changing Remote Login.", "Review with: /usr/sbin/systemsetup -getremotelogin", ("T1021.004",)),
    ValidationControl("MSAA-MAC-TCC-001", "macos.tcc", "Sensitive Privacy Grants Approved", ("CIS Apple macOS", "NIST AC-6"), "Unexpected camera, microphone, screen recording, accessibility, or Full Disk Access grants must not exist.", "privacy metadata comparison", "unexpected_sensitive_permissions", 0, "numeric_equals", "critical", "Review application identity and business need through Apple-supported privacy controls; never edit TCC databases directly.", "Review grants in MSAA Privacy Security; no automatic TCC modification is supported.", ("T1548",)),
    ValidationControl("MSAA-MAC-APP-001", "macos.gatekeeper", "Approved Software Provenance", ("CIS Apple macOS", "NIST CM-8", "NIST SI-7"), "Unapproved or unverifiable applications must be reviewed.", "supply-chain inventory comparison", "unapproved_applications", 0, "numeric_equals", "high", "Validate signature, notarization, developer, hash, source, and business approval before remediation.", "Review application provenance in MSAA Supply Chain Security.", ("T1195",)),
)

CONTROL_MAP = {item.control_id: item for item in CONTROLS}
PROFILE_CONTROLS = tuple(item.control_id for item in CONTROLS)
PROFILES = {
    "enterprise": SecurityBaselineProfile("enterprise", "Enterprise Profile", PROFILE_CONTROLS),
    "education": SecurityBaselineProfile("education", "Education Profile", PROFILE_CONTROLS, (("MSAA-MAC-SSH-001", "critical"),)),
    "government": SecurityBaselineProfile("government", "Government Profile", PROFILE_CONTROLS, (("MSAA-MAC-FV-001", "critical"), ("MSAA-MAC-UPD-001", "critical"))),
    "critical_infrastructure": SecurityBaselineProfile("critical_infrastructure", "Critical Infrastructure Profile", PROFILE_CONTROLS, (("MSAA-MAC-FW-001", "critical"), ("MSAA-MAC-FV-001", "critical"), ("MSAA-MAC-UPD-001", "critical"))),
}


class SecurityControlValidationEngine:
    def __init__(self, controls: Iterable[ValidationControl] = CONTROLS, *, evidence_max_age_seconds: int = 86400) -> None:
        self.controls = {item.control_id: item for item in controls}; self.evidence_max_age_seconds = evidence_max_age_seconds; self._validate_controls()

    def assess(self, *, device_id: str, profile_id: str, evidence: Mapping[str, Any], exceptions: Iterable[ControlException] = (), timestamp: str | None = None, previous: ControlAssessment | None = None) -> ControlAssessment:
        timestamp = timestamp or _now(); profile = PROFILES.get(profile_id)
        if profile is None: raise ValueError(f"Unknown security baseline profile: {profile_id}")
        assessment_id = f"control-assessment-{uuid4().hex}"; exception_map = {item.control_id: item for item in exceptions}; overrides = dict(profile.severity_overrides); results = []
        for control_id in profile.required_controls:
            control = self.controls.get(control_id)
            if control is None: raise ValueError(f"Profile references unknown control: {control_id}")
            severity = overrides.get(control_id, control.severity); exception = exception_map.get(control_id)
            if exception and exception.valid_at(timestamp):
                results.append(self._result(assessment_id, timestamp, device_id, control, severity, "excepted", None, exception.evidence_reference, "approved_exception", ("The control was not passed; a time-bounded approved exception is active.",), exception.reason)); continue
            results.append(self._evaluate(assessment_id, timestamp, device_id, control, severity, evidence.get(control.evidence_key)))
        passed = sum(item.result == "passed" for item in results); failed = sum(item.result == "failed" for item in results); unknown = sum(item.result == "not_assessed" for item in results); excepted = sum(item.result == "excepted" for item in results); total = len(results)
        score = round(100 * passed / total) if total else 0
        status = "insufficient_evidence" if unknown else "non_compliant" if failed else "qualified_with_exceptions" if excepted else "meets_profile_requirements"
        regressions = self._regressions(previous, results)
        explanation = (f"Score {score}% = {passed} passed controls / {total} required controls. Failed, not-assessed, and excepted controls receive no pass credit.", f"Results: passed={passed}, failed={failed}, not_assessed={unknown}, excepted={excepted}. Status={status}.")
        base = ControlAssessment(assessment_id, timestamp, device_id, profile_id, score, status, passed, failed, unknown, excepted, tuple(results), tuple(regressions), explanation)
        digest = _hash(base.to_dict())
        return ControlAssessment(**{**base.to_dict(), "results": tuple(results), "security_regressions": tuple(regressions), "score_explanation": explanation, "integrity_hash": digest})

    def _evaluate(self, assessment_id: str, timestamp: str, device_id: str, control: ValidationControl, severity: str, raw: Any) -> ControlValidationResult:
        if not isinstance(raw, Mapping): return self._result(assessment_id, timestamp, device_id, control, severity, "not_assessed", None, (), "", ("Required evidence was not collected.",))
        refs = self._strings(raw.get("evidence_reference", [])); source = str(raw.get("source", "")); collected = _parse_time(str(raw.get("collected_at", ""))); now = _parse_time(timestamp)
        if not refs or not source or not collected or not now: return self._result(assessment_id, timestamp, device_id, control, severity, "not_assessed", raw.get("value"), refs, source, ("Evidence lacks a source, reference, or valid collection timestamp.",))
        age = (now - collected).total_seconds()
        if age < 0 or age > self.evidence_max_age_seconds: return self._result(assessment_id, timestamp, device_id, control, severity, "not_assessed", raw.get("value"), refs, source, (f"Evidence age {round(age)} seconds is outside the accepted freshness window.",))
        actual = raw.get("value"); valid = self._compare(actual, control.expected_state, control.comparator)
        if valid is None: return self._result(assessment_id, timestamp, device_id, control, severity, "not_assessed", actual, refs, source, ("Evidence value could not be normalized for this validation method.",))
        return self._result(assessment_id, timestamp, device_id, control, severity, "passed" if valid else "failed", actual, refs, source, ())

    @staticmethod
    def _compare(actual: Any, expected: Any, comparator: str) -> bool | None:
        if comparator == "equals":
            if not isinstance(actual, type(expected)): return None
            return actual == expected
        if comparator == "equals_normalized":
            if not isinstance(actual, str): return None
            return actual.strip().lower() == str(expected).lower()
        if comparator == "numeric_equals":
            try: return int(actual) == int(expected)
            except (TypeError, ValueError): return None
        return None

    @staticmethod
    def _result(assessment_id: str, timestamp: str, device_id: str, control: ValidationControl, severity: str, result: str, actual: Any, refs: tuple[str, ...], source: str, uncertainty: tuple[str, ...], exception_reason: str = "") -> ControlValidationResult:
        return ControlValidationResult(f"control-event-{uuid4().hex}", assessment_id, timestamp, device_id, control.control_id, control.framework, control.expected_state, actual, result, severity, refs, source, control.remediation, uncertainty, exception_reason)

    @staticmethod
    def _regressions(previous: ControlAssessment | None, current: list[ControlValidationResult]) -> list[str]:
        if previous is None: return []
        old = {item.control_id: item.result for item in previous.results}
        return [item.control_id for item in current if old.get(item.control_id) == "passed" and item.result == "failed"]

    def remediation_workflow(self, result: ControlValidationResult) -> dict[str, Any]:
        control = self.controls[result.control_id]
        return {"control_id": result.control_id, "status": result.result, "stages": ["review", "approve", "apply_external_change", "verify"], "recommended_command": control.recommended_command, "administrative_procedure": control.remediation, "authorization_required": True, "automatic_execution": False, "evidence_reference": list(result.evidence_reference)}

    def analyst_context(self, result: ControlValidationResult) -> dict[str, Any]:
        control = self.controls[result.control_id]
        return {"observed_facts": result.to_dict(), "explanation": f"{control.name}: expected {control.expected_state!r}, observed {result.actual_state!r}, result {result.result}.", "security_impact": control.description, "framework_relevance": list(control.framework), "uncertainty": list(result.uncertainty), "recommendation": control.remediation, "confidence": "high" if result.evidence_reference and not result.uncertainty else "low", "guardrail": "Do not claim compliance or execute remediation without evidence and administrator authorization."}

    def dashboard(self, assessment: ControlAssessment) -> dict[str, Any]:
        return {"category": "Security Control Validation", "compliance_score": assessment.compliance_score, "framework": PROFILES[assessment.profile_id].name, "passed_controls": [x.to_dict() for x in assessment.results if x.result == "passed"], "failed_controls": [x.to_dict() for x in assessment.results if x.result == "failed"], "not_assessed_controls": [x.to_dict() for x in assessment.results if x.result == "not_assessed"], "security_regressions": list(assessment.security_regressions), "actions": ["run_assessment", "compare_baseline", "view_evidence", "generate_report", "review_remediation"]}

    @staticmethod
    def verify_integrity(assessment: ControlAssessment) -> bool:
        payload = assessment.to_dict(); expected = payload.pop("integrity_hash", ""); payload["integrity_hash"] = ""; return bool(expected) and _hash(payload) == expected

    def _validate_controls(self) -> None:
        for item in self.controls.values():
            if item.registry_control_id not in CONTROL_REGISTRY: raise ValueError(f"Validation control references an unknown monitored control: {item.registry_control_id}")
            if not item.control_id or not item.framework or not item.evidence_key or not item.remediation: raise ValueError(f"Incomplete validation control: {item.control_id}")

    @staticmethod
    def _strings(value: Any) -> tuple[str, ...]:
        if isinstance(value, str): value = [value]
        return tuple(str(item) for item in (value or []) if str(item).strip())


class ControlValidationRepository:
    def __init__(self, database: sqlite3.Connection | Path | str, controls: Iterable[ValidationControl] = CONTROLS) -> None:
        self._owns = not isinstance(database, sqlite3.Connection); self.conn = sqlite3.connect(str(database)) if self._owns else database; self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS validation_controls (control_id TEXT PRIMARY KEY, name TEXT NOT NULL, framework TEXT NOT NULL, description TEXT NOT NULL, validation_method TEXT NOT NULL, severity TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS control_assessments (assessment_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, profile_id TEXT NOT NULL, timestamp TEXT NOT NULL, compliance_score INTEGER NOT NULL, posture_status TEXT NOT NULL, integrity_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS control_validation_events (event_id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, device_id TEXT NOT NULL, control_id TEXT NOT NULL, timestamp TEXT NOT NULL, result TEXT NOT NULL, evidence TEXT NOT NULL, status TEXT NOT NULL, payload_json TEXT NOT NULL);
        """)
        with self.conn:
            for item in controls: self.conn.execute("INSERT OR REPLACE INTO validation_controls VALUES (?,?,?,?,?,?,?)", (item.control_id, item.name, _canonical(item.framework), item.description, item.validation_method, item.severity, _canonical(item.to_dict())))

    def close(self) -> None:
        if self._owns: self.conn.close()

    def save(self, assessment: ControlAssessment) -> None:
        if not SecurityControlValidationEngine.verify_integrity(assessment): raise ValueError("Refusing to store an invalid control assessment.")
        with self.conn:
            self.conn.execute("INSERT INTO control_assessments VALUES (?,?,?,?,?,?,?,?)", (assessment.assessment_id, assessment.device_id, assessment.profile_id, assessment.timestamp, assessment.compliance_score, assessment.posture_status, assessment.integrity_hash, _canonical(assessment.to_dict())))
            for item in assessment.results: self.conn.execute("INSERT INTO control_validation_events VALUES (?,?,?,?,?,?,?,?,?)", (item.event_id, assessment.assessment_id, assessment.device_id, item.control_id, item.timestamp, item.result, _canonical(item.evidence_reference), "new", _canonical(item.to_dict())))

    def latest_payload(self, device_id: str, profile_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT payload_json FROM control_assessments WHERE device_id=? AND profile_id=? ORDER BY timestamp DESC LIMIT 1", (device_id, profile_id)).fetchone()
        if not row: return None
        payload = json.loads(row["payload_json"]); expected = payload.get("integrity_hash", ""); candidate = dict(payload); candidate["integrity_hash"] = ""
        if not expected or _hash(candidate) != expected: raise ValueError("Control assessment integrity verification failed.")
        return payload


__all__ = ["CONTROLS", "PROFILES", "ControlAssessment", "ControlException", "ControlValidationRepository", "ControlValidationResult", "SecurityBaselineProfile", "SecurityControlValidationEngine", "ValidationControl"]
