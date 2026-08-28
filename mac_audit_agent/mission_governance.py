"""Central authorized-use and mission-assurance policy decisions.

This module never grants authority. It evaluates a supplied, validated context and
fails to ADVISORY while preserving analysis, rollback, recovery, and evidence help.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4


class OperationalMode(str, Enum):
    ADVISORY = "ADVISORY"
    SIMULATION = "SIMULATION"
    LAB_EXECUTION = "LAB_EXECUTION"
    AUTHORIZED_OPERATIONAL = "AUTHORIZED_OPERATIONAL"


CONSEQUENTIAL_ACTIONS = frozenset({"production_change", "privileged_access", "credential_use", "persistence", "lateral_movement", "data_extraction", "security_control_modification", "monitoring_impairment", "service_interruption", "destructive_action", "cross_border_effect"})
SAFE_AFTER_STOP = frozenset({"analysis", "documentation", "detection_engineering", "simulation", "rollback", "recovery", "evidence_preservation", "defensive_guidance"})
SENSITIVE_KEYS = frozenset({"password", "passwd", "secret", "token", "private_key", "authorization", "cookie", "credential", "api_key", "session"})


def _time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): "[REDACTED]" if str(key).lower() in SENSITIVE_KEYS else redact(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(child) for child in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
        value = re.sub(r"(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]", value)
    return value


@dataclass(frozen=True)
class AuthorizationContext:
    schema_version: str; authorization_id: str; engagement_id: str; mission_id: str; mission_purpose: str
    authorizing_entity: str; accountable_approver: str; authorization_reference: str; system_owner: str; asset_owner: str
    environment: str; authorization_status: str; valid_from: str; valid_until: str
    in_scope_assets: tuple[str, ...]; out_of_scope_assets: tuple[str, ...] = ()
    approved_accounts_or_identities: tuple[str, ...] = (); approved_network_ranges: tuple[str, ...] = ()
    approved_data_sources: tuple[str, ...] = (); authorized_time_windows: tuple[str, ...] = ()
    permitted_actions: tuple[str, ...] = (); permitted_operational_effects: tuple[str, ...] = ()
    prohibited_actions: tuple[str, ...] = (); prohibited_operational_effects: tuple[str, ...] = ()
    permitted_attack_domains: tuple[str, ...] = (); permitted_attack_tactics: tuple[str, ...] = (); permitted_attack_techniques: tuple[str, ...] = (); prohibited_attack_techniques: tuple[str, ...] = ()
    applicable_jurisdictions: tuple[str, ...] = (); data_classification: str = "UNCLASSIFIED"
    controlled_information_categories: tuple[str, ...] = (); data_retention_requirements: str = ""
    logging_requirements: tuple[str, ...] = (); evidence_preservation_requirements: tuple[str, ...] = ()
    deconfliction_contact: str = ""; emergency_contact: str = ""; stop_conditions: tuple[str, ...] = ()
    rollback_plan: str = ""; recovery_plan: str = ""; required_human_approval_points: tuple[str, ...] = ()
    approved_framework_versions: Mapping[str, str] = field(default_factory=dict); output_mode: str = "ADVISORY"
    approval_evidence_reference: str = ""; created_at: str = ""; updated_at: str = ""; approved_at: str = ""
    revoked_at: str = ""; revocation_reason: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AuthorizationContext":
        allowed = {item.name for item in cls.__dataclass_fields__.values()}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError("Authorization context contains unsupported fields.")
        tuple_fields = {name for name, item in cls.__dataclass_fields__.items() if "tuple" in str(item.type).lower()}
        normalized = {key: tuple(child) if key in tuple_fields and isinstance(child, list) else child for key, child in value.items()}
        try: return cls(**normalized)
        except TypeError as exc: raise ValueError("Authorization context is incomplete.") from exc


@dataclass(frozen=True)
class HumanApproval:
    approval_type: str; approver_reference: str; approved_action: str; approved_scope: tuple[str, ...]; approved_at: str; expires_at: str; authorization_id: str

    def valid(self, *, action: str, target: str, authorization_id: str, now: datetime) -> bool:
        approved, expires = _time(self.approved_at), _time(self.expires_at)
        return bool(self.approver_reference and approved and expires and self.approved_action == action and self.authorization_id == authorization_id and target in self.approved_scope and approved <= now < expires)


@dataclass(frozen=True)
class PolicyRequest:
    requested_mode: str = "ADVISORY"; action: str = "analysis"; target: str = ""; account: str = ""; operational_effect: str = "none"; attack_technique: str = ""; jurisdiction: str = ""; actor_reference: str = "anonymous"; session_id: str = ""; framework_versions: Mapping[str,str] = field(default_factory=dict); stop_condition_active: bool = False; rollback_available: bool = True; recovery_available: bool = True; audit_available: bool = True


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool; effective_mode: str; requested_action: str; reason_code: str; explanation: str
    missing_requirements: tuple[str, ...] = (); safe_alternatives: tuple[str, ...] = ("analysis", "simulation", "detection_engineering", "laboratory_validation")
    stop_condition_active: bool = False


class AuthorizationPolicy:
    def evaluate(self, request: PolicyRequest, context: AuthorizationContext | None = None, approval: HumanApproval | None = None, *, now: datetime | None = None) -> PolicyDecision:
        now = now or datetime.now(timezone.utc)
        try: requested = OperationalMode(request.requested_mode)
        except ValueError: requested = OperationalMode.ADVISORY
        if request.action in SAFE_AFTER_STOP and requested in {OperationalMode.ADVISORY, OperationalMode.SIMULATION}:
            return PolicyDecision(True, requested.value, request.action, "SAFE_ASSISTANCE", "Advisory, simulation, rollback, recovery, or evidence-preservation assistance remains available.")
        if requested != OperationalMode.AUTHORIZED_OPERATIONAL:
            mode = requested if requested in {OperationalMode.ADVISORY, OperationalMode.SIMULATION, OperationalMode.LAB_EXECUTION} else OperationalMode.ADVISORY
            if mode == OperationalMode.LAB_EXECUTION and (not context or context.environment.lower() not in {"lab", "laboratory", "sandbox", "training", "test_fixture"}):
                return self._deny(request, "LAB_NOT_VERIFIED", ("designated laboratory environment",))
            return PolicyDecision(True, mode.value, request.action, "NON_OPERATIONAL_MODE", "Request is limited to the selected non-operational mode.")
        if context is None: return self._deny(request, "AUTHORIZATION_MISSING", ("authorization context",))
        start, end = _time(context.valid_from), _time(context.valid_until)
        if context.authorization_status.lower() != "approved": return self._deny(request, "AUTHORIZATION_REVOKED" if context.authorization_status.lower() == "revoked" or context.revoked_at else "AUTHORIZATION_NOT_APPROVED", ("current approved status",))
        if not start or not end or now < start: return self._deny(request, "AUTHORIZATION_NOT_ACTIVE", ("active authorization window",))
        if now >= end: return self._deny(request, "AUTHORIZATION_EXPIRED", ("renewed authorization",))
        if request.stop_condition_active: return self._deny(request, "STOP_CONDITION_ACTIVE", ("documented release from stop condition",), stop=True)
        if not request.audit_available and "material_actions" in context.logging_requirements: return self._deny(request, "AUDIT_UNAVAILABLE", ("required audit logging",), stop=True)
        if not request.rollback_available and request.action in CONSEQUENTIAL_ACTIONS: return self._deny(request, "ROLLBACK_UNAVAILABLE", ("tested rollback capability",), stop=True)
        if not request.recovery_available and request.action in CONSEQUENTIAL_ACTIONS: return self._deny(request, "RECOVERY_UNAVAILABLE", ("tested recovery capability",), stop=True)
        if request.target in context.out_of_scope_assets or not self._target_allowed(request.target, context.in_scope_assets, context.approved_network_ranges): return self._deny(request, "TARGET_OUT_OF_SCOPE", ("in-scope target",))
        if request.account and request.account not in context.approved_accounts_or_identities: return self._deny(request, "ACCOUNT_OUT_OF_SCOPE", ("approved identity",))
        if request.action in context.prohibited_actions or request.action not in context.permitted_actions: return self._deny(request, "ACTION_OUT_OF_SCOPE", ("permitted action",))
        if request.operational_effect in context.prohibited_operational_effects or request.operational_effect not in context.permitted_operational_effects: return self._deny(request, "EFFECT_OUT_OF_SCOPE", ("permitted operational effect",))
        if request.attack_technique and (request.attack_technique in context.prohibited_attack_techniques or request.attack_technique not in context.permitted_attack_techniques): return self._deny(request, "TECHNIQUE_PROHIBITED", ("approved ATT&CK technique",))
        if request.jurisdiction and request.jurisdiction not in context.applicable_jurisdictions: return self._deny(request, "JURISDICTION_OUT_OF_SCOPE", ("approved jurisdiction",))
        if not context.approved_framework_versions or any(context.approved_framework_versions.get(name) != version for name,version in request.framework_versions.items()): return self._deny(request, "FRAMEWORK_VERSION_MISMATCH", ("compatible approved framework versions",))
        if request.action in context.required_human_approval_points or request.action in CONSEQUENTIAL_ACTIONS:
            if not approval or not approval.valid(action=request.action, target=request.target, authorization_id=context.authorization_id, now=now): return self._deny(request, "HUMAN_APPROVAL_REQUIRED", ("current scoped human approval",))
        return PolicyDecision(True, OperationalMode.AUTHORIZED_OPERATIONAL.value, request.action, "AUTHORIZED", "Current scoped authorization and required approval were validated.", safe_alternatives=())

    @staticmethod
    def _target_allowed(target: str, assets: tuple[str, ...], networks: tuple[str, ...]) -> bool:
        if not target: return False
        if target in assets: return True
        try: address = ipaddress.ip_address(target)
        except ValueError: return False
        for network in networks:
            try:
                if address in ipaddress.ip_network(network, strict=False): return True
            except ValueError: continue
        return False

    @staticmethod
    def _deny(request: PolicyRequest, code: str, missing: tuple[str, ...], stop: bool = False) -> PolicyDecision:
        return PolicyDecision(False, OperationalMode.ADVISORY.value, request.action, code, "Operational execution was not authorized. Safe advisory and simulation assistance remain available.", missing, stop_condition_active=stop)


class GovernanceAuditLog:
    """Append-only logical SHA-256 chain; local storage is tamper-evident, not immutable."""
    def __init__(self, path: Path): self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
    def append(self, request: PolicyRequest, decision: PolicyDecision, *, authorization_id: str = "", framework_versions: Mapping[str,str] | None = None, component_version: str = "") -> dict[str,Any]:
        rows=self.records(); previous=rows[-1]["record_digest"] if rows else "0"*64
        target_hash=hashlib.sha256(request.target.encode()).hexdigest()[:20] if request.target else ""
        base={"event_id":f"governance-{uuid4().hex}","timestamp":datetime.now(timezone.utc).isoformat(),"actor_reference":str(redact(request.actor_reference)),"session_id":request.session_id,"authorization_id":authorization_id,"operational_mode":decision.effective_mode,"requested_action":request.action,"target_reference":target_hash,"policy_decision":"allow" if decision.allowed else "deny","reason_code":decision.reason_code,"human_approval_status":"validated" if decision.allowed and decision.effective_mode==OperationalMode.AUTHORIZED_OPERATIONAL.value else "not_validated","framework_versions":dict(framework_versions or {}),"component_version":component_version,"stop_condition_status":decision.stop_condition_active,"outcome":"authorized" if decision.allowed else "advisory_only","redaction_status":"redacted","previous_record_digest":previous}
        digest=hashlib.sha256(json.dumps(base,sort_keys=True,separators=(",",":")).encode()).hexdigest();row={**base,"record_digest":digest}
        descriptor=os.open(self.path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600)
        try: os.write(descriptor,(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode())
        finally: os.close(descriptor)
        return row
    def records(self)->list[dict[str,Any]]:
        if not self.path.exists(): return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line]
    def verify(self)->bool:
        previous="0"*64
        for row in self.records():
            digest=row.pop("record_digest","")
            if row.get("previous_record_digest")!=previous or not hmac.compare_digest(hashlib.sha256(json.dumps(row,sort_keys=True,separators=(",",":")).encode()).hexdigest(),digest): return False
            previous=digest
        return True


class EULAAcceptanceStore:
    def __init__(self, database: Path): self.database=Path(database);self.database.parent.mkdir(parents=True,exist_ok=True);self._init()
    def _init(self):
        with sqlite3.connect(self.database) as db:
            db.execute("CREATE TABLE IF NOT EXISTS eula_acceptance (user_reference TEXT NOT NULL,eula_version TEXT NOT NULL,application_version TEXT NOT NULL,accepted_at TEXT NOT NULL,PRIMARY KEY(user_reference,eula_version))")
            db.execute("CREATE TABLE IF NOT EXISTS eula_acceptance_events (acceptance_id TEXT PRIMARY KEY,user_reference TEXT NOT NULL,eula_version TEXT NOT NULL,application_version TEXT NOT NULL,accepted_at TEXT NOT NULL)")
    def accept(self,user_reference:str,eula_version:str,application_version:str,*,accepted_at:str|None=None):
        if not user_reference.strip() or not eula_version.strip(): raise ValueError("Protected user reference and EULA version are required.")
        timestamp=accepted_at or datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.database) as db:
            db.execute("INSERT OR REPLACE INTO eula_acceptance VALUES (?,?,?,?)",(user_reference,eula_version,application_version,timestamp))
            db.execute("INSERT INTO eula_acceptance_events VALUES (?,?,?,?,?)",(f"eula-{uuid4().hex}",user_reference,eula_version,application_version,timestamp))
    def accepted(self,user_reference:str,current_version:str)->bool:
        with sqlite3.connect(self.database) as db:return db.execute("SELECT 1 FROM eula_acceptance WHERE user_reference=? AND eula_version=?",(user_reference,current_version)).fetchone() is not None
    def acceptance_history(self,user_reference:str)->list[dict[str,str]]:
        with sqlite3.connect(self.database) as db:
            rows=db.execute("SELECT acceptance_id,eula_version,application_version,accepted_at FROM eula_acceptance_events WHERE user_reference=? ORDER BY accepted_at",(user_reference,)).fetchall()
        return [{"acceptance_id":row[0],"eula_version":row[1],"application_version":row[2],"accepted_at":row[3]} for row in rows]


@dataclass(frozen=True)
class MaterialOutput:
    verified_facts: tuple[str,...]=(); supplied_evidence: tuple[str,...]=(); assumptions: tuple[str,...]=(); inferences: tuple[str,...]=(); unknowns: tuple[str,...]=(); conflicting_evidence: tuple[str,...]=(); validation_required: tuple[str,...]=(); recommended_actions: tuple[str,...]=(); human_approval_required: tuple[str,...]=(); sources: tuple[str,...]=(); source_retrieval_date: str="Not verified"; framework_or_data_version: str="Framework version not configured"; confidence_basis: str="Insufficient evidence"


class AttackDataProvider:
    def validate(self, technique_id: str) -> Mapping[str,Any] | None: raise NotImplementedError


class LocalAttackSTIXProvider(AttackDataProvider):
    def __init__(self,path:Path|None): self.path=Path(path) if path else None;self._items=self._load()
    def _load(self):
        if not self.path or not self.path.is_file(): return {}
        if self.path.stat().st_size>50*1024*1024: raise ValueError("ATT&CK data exceeds the local import limit.")
        payload=json.loads(self.path.read_text(encoding="utf-8"));result={}
        for item in payload.get("objects",[]):
            if item.get("type")!="attack-pattern":continue
            for ref in item.get("external_references",[]):
                value=str(ref.get("external_id",""))
                if re.fullmatch(r"T\d{4}(?:\.\d{3})?",value):result[value]={"name":str(item.get("name","Not verified")),"modified":str(item.get("modified","Not verified")),"source":"local approved STIX"}
        return result
    def validate(self,technique_id:str)->Mapping[str,Any]|None:return self._items.get(technique_id)


__all__=["AttackDataProvider","AuthorizationContext","AuthorizationPolicy","EULAAcceptanceStore","GovernanceAuditLog","HumanApproval","LocalAttackSTIXProvider","MaterialOutput","OperationalMode","PolicyDecision","PolicyRequest","redact"]
