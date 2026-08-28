"""Fail-closed data governance for MSAA security information.

This module makes policy decisions; it does not silently delete, upload, or
encrypt data.  Callers must provide verified storage/transport evidence and an
explicit authorization context for restricted operations.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from mac_audit_agent.privacy import redact_structure


class GovernanceError(RuntimeError):
    pass


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    SENSITIVE = 2
    RESTRICTED = 3


class Role(IntEnum):
    VIEWER = 0
    AUDITOR = 1
    SECURITY_ANALYST = 2
    ADMINISTRATOR = 3


@dataclass(frozen=True)
class DataPolicy:
    data_type: str
    classification: Classification
    purpose: str
    storage: str
    retention_days: int | None
    minimum_role: Role
    export_requires_approval: bool
    encryption_at_rest_required: bool
    external_processing_allowed: bool = False

    def __post_init__(self) -> None:
        if not self.data_type.strip() or not self.purpose.strip():
            raise ValueError("data type and collection purpose are required")
        if self.retention_days is not None and self.retention_days < 1:
            raise ValueError("retention must be at least one day")


@dataclass(frozen=True)
class AccessContext:
    user: str
    role: Role
    authenticated: bool
    authorization_source: str
    expires_at: str

    def valid(self, now: datetime | None = None) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expires_at)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return False
        return bool(self.user.strip() and self.authorization_source.strip() and self.authenticated and expiry > (now or datetime.now(timezone.utc)))


@dataclass(frozen=True)
class ProtectionEvidence:
    encryption_at_rest_verified: bool = False
    secure_transport_verified: bool = False
    key_management_reference: str = ""
    permission_evidence: str = ""


@dataclass
class GovernanceDecision:
    allowed: bool
    action: str
    data_type: str
    classification: str
    reason: str
    requirements: list[str] = field(default_factory=list)
    evidence_reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_SECRET_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("authorization", re.compile(r"(?i)\b(?:authorization\s*:\s*bearer|bearer)\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("credential_assignment", re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[^\s,;]{4,}")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
)


DEFAULT_POLICIES = (
    DataPolicy("public_documentation", Classification.PUBLIC, "User documentation", "repository", None, Role.VIEWER, False, False, True),
    DataPolicy("security_finding", Classification.INTERNAL, "Explain detected security conditions", "local database", 365, Role.VIEWER, False, False),
    DataPolicy("process_metadata", Classification.SENSITIVE, "Threat detection and investigation", "local protected database", 30, Role.SECURITY_ANALYST, True, True),
    DataPolicy("security_event", Classification.SENSITIVE, "Detection, correlation, and audit", "local protected database", 90, Role.SECURITY_ANALYST, True, True),
    DataPolicy("report", Classification.SENSITIVE, "Analyst-reviewed security reporting", "owner-controlled report store", 365, Role.AUDITOR, True, True),
    DataPolicy("forensic_evidence", Classification.RESTRICTED, "Incident investigation and chain of custody", "secure evidence repository", None, Role.SECURITY_ANALYST, True, True),
    DataPolicy("access_audit", Classification.RESTRICTED, "Accountability and unauthorized-access review", "append-only protected database", 730, Role.AUDITOR, True, True),
)


def detect_sensitive_content(value: Any) -> list[dict[str, str]]:
    """Return locations and types only; never return matched secret values."""
    findings: list[dict[str, str]] = []

    def walk(item: Any, location: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                key_text = str(key)
                if key_text.lower() in {"password", "passwd", "secret", "token", "private_key", "credential"} and child not in {None, ""}:
                    findings.append({"location": f"{location}.{key_text}", "type": "sensitive_field"})
                walk(child, f"{location}.{key_text}")
        elif isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                walk(child, f"{location}[{index}]")
        elif isinstance(item, str):
            for kind, pattern in _SECRET_PATTERNS:
                if pattern.search(item):
                    findings.append({"location": location, "type": kind})

    walk(value, "$")
    return findings


def sanitize_for_processing(value: Any) -> tuple[Any, list[dict[str, str]]]:
    findings = detect_sensitive_content(value)

    def scrub(item: Any) -> Any:
        if isinstance(item, dict):
            result: dict[Any, Any] = {}
            for key, child in item.items():
                if str(key).lower() in {"password", "passwd", "secret", "token", "private_key", "credential"} and child not in {None, ""}:
                    result[key] = "[REDACTED_SECRET]"
                else:
                    result[key] = scrub(child)
            return result
        if isinstance(item, list):
            return [scrub(child) for child in item]
        if isinstance(item, tuple):
            return tuple(scrub(child) for child in item)
        if isinstance(item, str):
            text = item
            for _, pattern in _SECRET_PATTERNS:
                text = pattern.sub("[REDACTED_SECRET]", text)
            return text
        return item

    return redact_structure(scrub(value)), findings


class DataGovernanceService:
    def __init__(self, database: Path, policies: Iterable[DataPolicy] = DEFAULT_POLICIES) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        if self.database.is_symlink():
            raise GovernanceError("Governance database must not be a symbolic link.")
        self.policies = {policy.data_type: policy for policy in policies}
        self._initialize()
        os.chmod(self.database, 0o600, follow_symlinks=False)

    def policy(self, data_type: str) -> DataPolicy:
        try:
            return self.policies[data_type]
        except KeyError as exc:
            raise GovernanceError(f"Unclassified data type is denied: {data_type}") from exc

    def authorize(self, action: str, data_type: str, context: AccessContext, *, approval: bool = False, destination: str = "", protection: ProtectionEvidence | None = None) -> GovernanceDecision:
        policy = self.policy(data_type)
        requirements: list[str] = []
        if not context.valid():
            reason = "Valid, time-limited authentication is required."
        elif context.role < policy.minimum_role:
            reason = f"{context.role.name} does not meet minimum role {policy.minimum_role.name}."
        elif action in {"export", "share", "ai_external"} and policy.export_requires_approval and not approval:
            reason = "Explicit export approval is required for this classification."
        elif action == "share" and not policy.external_processing_allowed:
            reason = "External sharing is prohibited by the data policy."
        elif action == "ai_external" and not policy.external_processing_allowed:
            reason = "External AI processing is prohibited by the data policy."
        elif action in {"export", "share"} and not destination.strip():
            reason = "An explicit export destination is required."
        else:
            evidence = protection or ProtectionEvidence()
            if policy.encryption_at_rest_required and action in {"store", "export"} and not evidence.encryption_at_rest_verified:
                requirements.append("verified_encryption_at_rest")
            if action == "share" and not evidence.secure_transport_verified:
                requirements.append("verified_secure_transport")
            reason = "Required protection evidence is missing." if requirements else "Authorized by classification and role policy."
        allowed = not requirements and reason == "Authorized by classification and role policy."
        decision = GovernanceDecision(allowed, action, data_type, policy.classification.name, reason, requirements)
        decision.evidence_reference = self._audit(context, decision, destination)
        return decision

    def prepare_ai_input(self, data_type: str, value: Any, context: AccessContext, *, external: bool = False, approval: bool = False) -> tuple[GovernanceDecision, Any, list[dict[str, str]]]:
        decision = self.authorize("ai_external" if external else "view", data_type, context, approval=approval, destination="approved AI provider" if external else "local AI")
        if not decision.allowed:
            return decision, None, []
        sanitized, findings = sanitize_for_processing(value)
        return decision, sanitized, findings

    def retention_candidates(self, data_type: str, records: Iterable[dict[str, Any]], *, now: datetime | None = None) -> list[str]:
        policy = self.policy(data_type)
        if policy.retention_days is None:
            return []
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=policy.retention_days)
        candidates: list[str] = []
        for record in records:
            try:
                timestamp = datetime.fromisoformat(str(record["timestamp"]))
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                if timestamp < cutoff:
                    candidates.append(str(record["record_id"]))
            except (KeyError, TypeError, ValueError):
                continue  # invalid timestamps are retained and surfaced by caller
        return candidates

    def set_retention(self, data_type: str, duration_days: int | None, context: AccessContext, *, owner: str, approval: bool) -> GovernanceDecision:
        policy = self.policy(data_type)
        if duration_days is not None and duration_days < 1:
            raise GovernanceError("Retention must be at least one day or organization-defined.")
        if not context.valid() or context.role < Role.ADMINISTRATOR or not approval or not owner.strip():
            decision = GovernanceDecision(False, "modify_retention", data_type, policy.classification.name, "Valid administrator approval and a policy owner are required.")
            decision.evidence_reference = self._audit(context, decision, "")
            return decision
        with self._connect() as db:
            db.execute("UPDATE retention_policy SET duration_days=?,owner=?,updated_at=? WHERE data_type=?", (duration_days, owner.strip(), _now(), data_type))
        decision = GovernanceDecision(True, "modify_retention", data_type, policy.classification.name, "Authorized retention policy update recorded; no records were deleted.")
        decision.evidence_reference = self._audit(context, decision, "")
        return decision

    def privacy_impact_assessment(self, feature: str, data_types: Iterable[str], *, external_transfer: bool, personal_content: bool) -> dict[str, Any]:
        policies = [self.policy(name) for name in data_types]
        risks: list[str] = []
        if personal_content:
            risks.append("personal_content_collection_requires_specific_authorization_and_minimization")
        if external_transfer:
            risks.append("external_transfer_requires_destination_review_and_explicit_approval")
        if any(item.classification == Classification.RESTRICTED for item in policies):
            risks.append("restricted_data_requires_strong_access_control_and_audit")
        controls = sorted({"data_minimization", "access_audit", "retention_policy", "secret_redaction"} | ({"encryption_at_rest"} if any(p.encryption_at_rest_required for p in policies) else set()))
        return {"feature": feature, "data_types": [p.data_type for p in policies], "highest_classification": max((p.classification for p in policies), default=Classification.PUBLIC).name, "risks": risks, "required_controls": controls, "approval_required": bool(risks), "assessment_status": "REVIEW_REQUIRED" if risks else "PASS"}

    def transparency_report(self) -> dict[str, Any]:
        return {"generated_at": _now(), "data_types": [{"data_type": p.data_type, "classification": p.classification.name, "purpose": p.purpose, "storage": p.storage, "retention_days": p.retention_days, "minimum_role": p.minimum_role.name, "export_requires_approval": p.export_requires_approval, "encryption_at_rest_required": p.encryption_at_rest_required} for p in sorted(self.policies.values(), key=lambda item: item.data_type)]}

    def verify_audit_chain(self) -> bool:
        previous = ""
        with self._connect() as db:
            rows = db.execute("SELECT timestamp,user,action,resource,result,reason,destination,previous_hash,event_hash FROM access_audit ORDER BY sequence").fetchall()
        for row in rows:
            payload = dict(zip(("timestamp", "user", "action", "resource", "result", "reason", "destination"), row[:7]))
            if row[7] != previous or row[8] != _hash(previous, payload):
                return False
            previous = row[8]
        return True

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS data_classification(data_type TEXT PRIMARY KEY, classification TEXT NOT NULL, purpose TEXT NOT NULL, storage TEXT NOT NULL, retention_days INTEGER, minimum_role TEXT NOT NULL, policy_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS access_audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, timestamp TEXT NOT NULL, user TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL, result TEXT NOT NULL, reason TEXT NOT NULL, destination TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS retention_policy(policy_id TEXT PRIMARY KEY, data_type TEXT UNIQUE NOT NULL, duration_days INTEGER, owner TEXT NOT NULL, updated_at TEXT NOT NULL);
            """)
            for policy in self.policies.values():
                payload = asdict(policy); payload["classification"] = policy.classification.name; payload["minimum_role"] = policy.minimum_role.name
                db.execute("INSERT OR REPLACE INTO data_classification VALUES(?,?,?,?,?,?,?)", (policy.data_type, policy.classification.name, policy.purpose, policy.storage, policy.retention_days, policy.minimum_role.name, json.dumps(payload, sort_keys=True)))
                db.execute("INSERT OR IGNORE INTO retention_policy VALUES(?,?,?,?,?)", (f"ret-{policy.data_type}", policy.data_type, policy.retention_days, "organization security owner", _now()))

    def _audit(self, context: AccessContext, decision: GovernanceDecision, destination: str) -> str:
        timestamp, event_id = _now(), f"dga-{uuid4().hex}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT event_hash FROM access_audit ORDER BY sequence DESC LIMIT 1").fetchone()
            previous = str(row[0]) if row else ""
            payload = {"timestamp": timestamp, "user": context.user or "unknown", "action": decision.action, "resource": decision.data_type, "result": "allowed" if decision.allowed else "blocked", "reason": decision.reason, "destination": destination}
            digest = _hash(previous, payload)
            db.execute("INSERT INTO access_audit(event_id,timestamp,user,action,resource,result,reason,destination,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?,?,?,?)", (event_id, *payload.values(), previous, digest))
        return event_id

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(previous: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256((previous + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


__all__ = ["AccessContext", "Classification", "DataGovernanceService", "DataPolicy", "DEFAULT_POLICIES", "GovernanceDecision", "GovernanceError", "ProtectionEvidence", "Role", "detect_sensitive_content", "sanitize_for_processing"]
