from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import OrderedDict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from mac_audit_agent.compat.enum import StrEnum
from pathlib import Path

from .models import ProcessIdentity


class ContainmentFailureCode(StrEnum):
    HELPER_NOT_INSTALLED = "AR-CNT-001"; HELPER_SIGNATURE_INVALID = "AR-CNT-002"
    XPC_AUTH_FAILED = "AR-CNT-004"; REPLAY_REJECTED = "AR-CNT-006"
    TARGET_TICKET_INVALID = "AR-CNT-007"; PID_VERSION_MISMATCH = "AR-CNT-010"
    START_TIME_MISMATCH = "AR-CNT-011"; CDHASH_MISMATCH = "AR-CNT-012"
    FILE_IDENTITY_MISMATCH = "AR-CNT-015"; BOOT_SESSION_MISMATCH = "AR-CNT-016"
    TARGET_EXITED = "AR-CNT-017"; CRITICAL_PROCESS = "AR-CNT-018"
    JOURNAL_UNAVAILABLE = "AR-CNT-019"; WATCHDOG_UNAVAILABLE = "AR-CNT-020"
    SOURCE_MODE_BLOCKED = "AR-CNT-030"; UNEXPECTED = "AR-CNT-999"


class TransactionState(StrEnum):
    REQUESTED="REQUESTED"; CALLER_AUTHENTICATED="CALLER_AUTHENTICATED"; TARGET_RESOLVED="TARGET_RESOLVED"
    TARGET_VALIDATED="TARGET_VALIDATED"; EVIDENCE_PRESERVED="EVIDENCE_PRESERVED"; PREPARED="PREPARED"
    WATCHDOG_ARMED="WATCHDOG_ARMED"; PAUSE_REQUESTED="PAUSE_REQUESTED"; PAUSED_VERIFIED="PAUSED_VERIFIED"
    RESUME_REQUESTED="RESUME_REQUESTED"; RESUMED_VERIFIED="RESUMED_VERIFIED"; TERMINATE_REQUESTED="TERMINATE_REQUESTED"
    TERMINATED_VERIFIED="TERMINATED_VERIFIED"; LEASE_EXPIRED="LEASE_EXPIRED"; RECOVERED_AFTER_RESTART="RECOVERED_AFTER_RESTART"
    RECONCILED_AFTER_REBOOT="RECONCILED_AFTER_REBOOT"; STALE_IDENTITY_REJECTED="STALE_IDENTITY_REJECTED"; FAILED="FAILED"; CLOSED="CLOSED"


@dataclass(frozen=True)
class SensorTargetRecord:
    incident_id: str; event_id: str; identity: ProcessIdentity; source_sensor_version: str
    source_boot_session: str; created_monotonic: float; expires_monotonic: float; identity_strength: str = "STRONG_MATCH"
    @property
    def key(self) -> str: return f"{self.incident_id}:{self.event_id}"
    @property
    def identity_hash(self) -> str: return hashlib.sha256(json.dumps(asdict(self.identity), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class SensorIdentityRegistry:
    """Bounded helper-side registry. Python can resolve IDs but cannot register targets."""
    def __init__(self, capacity: int = 4096) -> None: self.capacity=capacity; self._items: OrderedDict[str, SensorTargetRecord]=OrderedDict()
    def register_from_sensor(self, record: SensorTargetRecord, *, authenticated_sensor: bool) -> None:
        if not authenticated_sensor: raise PermissionError(ContainmentFailureCode.TARGET_TICKET_INVALID)
        if record.identity.boot_session_id != record.source_boot_session or record.expires_monotonic <= record.created_monotonic: raise ValueError(ContainmentFailureCode.TARGET_TICKET_INVALID)
        self._items[record.key]=record; self._items.move_to_end(record.key)
        while len(self._items)>self.capacity: self._items.popitem(last=False)
    def resolve(self, incident_id: str, event_id: str, *, now_monotonic: float, boot_session: str) -> SensorTargetRecord:
        record=self._items.get(f"{incident_id}:{event_id}")
        if record is None or now_monotonic >= record.expires_monotonic: raise LookupError(ContainmentFailureCode.TARGET_TICKET_INVALID)
        if record.source_boot_session != boot_session: raise PermissionError(ContainmentFailureCode.BOOT_SESSION_MISMATCH)
        return record


class NativeLeaseJournal:
    """Synchronous durable journal independent of Python incident storage."""
    def __init__(self, path: Path) -> None:
        self.path=Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection=sqlite3.connect(self.path); self.connection.execute("PRAGMA journal_mode=WAL"); self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript("CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS leases(lease_id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,event_id TEXT NOT NULL,identity_hash TEXT NOT NULL,identity_json TEXT NOT NULL,boot_session TEXT NOT NULL,state TEXT NOT NULL,prepared_monotonic REAL NOT NULL,expires_monotonic REAL NOT NULL,helper_generation TEXT NOT NULL,prepared_token_hash TEXT NOT NULL UNIQUE); CREATE TABLE IF NOT EXISTS transitions(sequence INTEGER PRIMARY KEY AUTOINCREMENT,lease_id TEXT NOT NULL,wall_time TEXT NOT NULL,monotonic_time REAL NOT NULL,prior_state TEXT NOT NULL,new_state TEXT NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL,identity_hash TEXT NOT NULL);")
        self.connection.execute("INSERT OR REPLACE INTO metadata VALUES('schema_version','1')"); self.connection.commit()
    def prepare(self, *, lease_id: str, target: SensorTargetRecord, now_monotonic: float, expires_monotonic: float, helper_generation: str, token: str) -> None:
        if expires_monotonic <= now_monotonic or expires_monotonic > target.expires_monotonic: raise ValueError("invalid lease deadline")
        token_hash=hashlib.sha256(token.encode()).hexdigest(); identity_json=json.dumps(asdict(target.identity),sort_keys=True,separators=(",",":"))
        with self.connection:
            self.connection.execute("INSERT INTO leases VALUES(?,?,?,?,?,?,?,?,?,?,?)",(lease_id,target.incident_id,target.event_id,target.identity_hash,identity_json,target.source_boot_session,TransactionState.PREPARED,now_monotonic,expires_monotonic,helper_generation,token_hash))
            self._transition(lease_id,"",TransactionState.PREPARED,"helper","durable_prepare",target.identity_hash,now_monotonic)
    def transition(self, lease_id: str, expected: TransactionState, new: TransactionState, actor: str, reason: str, monotonic: float) -> None:
        with self.connection:
            row=self.connection.execute("SELECT state,identity_hash FROM leases WHERE lease_id=?",(lease_id,)).fetchone()
            if not row or row[0] != expected: raise ValueError("stale lease transition")
            self.connection.execute("UPDATE leases SET state=? WHERE lease_id=?",(new,lease_id)); self._transition(lease_id,expected,new,actor,reason,row[1],monotonic)
    def _transition(self, lease_id, prior, new, actor, reason, identity_hash, monotonic):
        self.connection.execute("INSERT INTO transitions(lease_id,wall_time,monotonic_time,prior_state,new_state,actor,reason,identity_hash) VALUES(?,?,?,?,?,?,?,?)",(lease_id,datetime.now(timezone.utc).isoformat(),monotonic,str(prior),str(new),actor,reason,identity_hash))
    def reconcile_boot(self, boot_session: str, monotonic: float) -> int:
        rows=self.connection.execute("SELECT lease_id,state,identity_hash FROM leases WHERE state NOT IN ('CLOSED','RECONCILED_AFTER_REBOOT') AND boot_session<>?",(boot_session,)).fetchall()
        for lease_id,state,identity_hash in rows:
            with self.connection:
                self.connection.execute("UPDATE leases SET state=? WHERE lease_id=?",(TransactionState.RECONCILED_AFTER_REBOOT,lease_id)); self._transition(lease_id,state,TransactionState.RECONCILED_AFTER_REBOOT,"helper","boot_session_changed_no_signal",identity_hash,monotonic)
        return len(rows)
    def active_count(self) -> int: return int(self.connection.execute("SELECT count(*) FROM leases WHERE state NOT IN ('CLOSED','RECONCILED_AFTER_REBOOT','RESUMED_VERIFIED','TERMINATED_VERIFIED')").fetchone()[0])
    def close(self): self.connection.close()


@dataclass(frozen=True)
class ActiveContainmentEvidence:
    helper_is_native: bool=False; helper_is_developer_id_signed: bool=False; helper_signature_is_valid: bool=False; helper_is_installed: bool=False; helper_is_running: bool=False
    system_engine_is_signed: bool=False; live_xpc_is_authenticated: bool=False; unauthorized_xpc_clients_are_rejected: bool=False; request_replay_is_rejected: bool=False
    target_identity_originates_from_sensor: bool=False; audit_token_is_revalidated: bool=False; pidversion_is_revalidated: bool=False; start_time_is_revalidated: bool=False; cdhash_is_revalidated: bool=False; signing_identity_is_revalidated: bool=False; file_identity_is_revalidated: bool=False; boot_session_is_revalidated: bool=False; identity_checked_before_signal: bool=False
    pause_live_verified: bool=False; resume_live_verified: bool=False; termination_live_verified: bool=False; lease_is_durable: bool=False; watchdog_is_crash_safe: bool=False; engine_crash_test_passed: bool=False; helper_crash_test_passed: bool=False; restart_reconciliation_passed: bool=False; reboot_reconciliation_passed: bool=False; developer_id_fixture_matrix_passed: bool=False
    suspended_fixture_count: int=0; active_test_lease_count: int=0; emergency_cleanup_required: bool=False; required_checks_clear: bool=False


def active_containment_ready(evidence: ActiveContainmentEvidence) -> bool:
    values=asdict(evidence)
    required=[value for name,value in values.items() if isinstance(value,bool) and name != "emergency_cleanup_required"]
    return all(required) and not evidence.emergency_cleanup_required and evidence.suspended_fixture_count==0 and evidence.active_test_lease_count==0
