from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from mac_audit_agent.compat.enum import StrEnum

from .models import ProcessIdentity


class LeaseState(StrEnum):
    REQUESTED = "REQUESTED"
    VALIDATING = "VALIDATING"
    REJECTED_IDENTITY_MISMATCH = "REJECTED_IDENTITY_MISMATCH"
    REJECTED_POLICY = "REJECTED_POLICY"
    REJECTED_CRITICAL_PROCESS = "REJECTED_CRITICAL_PROCESS"
    EVIDENCE_PRESERVED = "EVIDENCE_PRESERVED"
    PAUSE_REQUESTED = "PAUSE_REQUESTED"
    PAUSED = "PAUSED"
    PAUSE_FAILED = "PAUSE_FAILED"
    USER_OR_ADMIN_DECISION_PENDING = "USER_OR_ADMIN_DECISION_PENDING"
    RESUME_REQUESTED = "RESUME_REQUESTED"
    RESUMED = "RESUMED"
    TERMINATE_REQUESTED = "TERMINATE_REQUESTED"
    TERMINATED = "TERMINATED"
    TERMINATE_FAILED = "TERMINATE_FAILED"
    PROCESS_EXITED = "PROCESS_EXITED"
    LEASE_EXPIRED = "LEASE_EXPIRED"
    ROLLBACK_REQUESTED = "ROLLBACK_REQUESTED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"
    CLOSED = "CLOSED"


ALLOWED_TRANSITIONS = {
    LeaseState.REQUESTED: {LeaseState.VALIDATING},
    LeaseState.VALIDATING: {LeaseState.REJECTED_IDENTITY_MISMATCH, LeaseState.REJECTED_POLICY, LeaseState.REJECTED_CRITICAL_PROCESS, LeaseState.EVIDENCE_PRESERVED},
    LeaseState.EVIDENCE_PRESERVED: {LeaseState.PAUSE_REQUESTED},
    LeaseState.PAUSE_REQUESTED: {LeaseState.PAUSED, LeaseState.PAUSE_FAILED, LeaseState.PROCESS_EXITED},
    LeaseState.PAUSED: {LeaseState.USER_OR_ADMIN_DECISION_PENDING, LeaseState.RESUME_REQUESTED, LeaseState.TERMINATE_REQUESTED, LeaseState.LEASE_EXPIRED, LeaseState.PROCESS_EXITED},
    LeaseState.USER_OR_ADMIN_DECISION_PENDING: {LeaseState.RESUME_REQUESTED, LeaseState.TERMINATE_REQUESTED, LeaseState.LEASE_EXPIRED, LeaseState.PROCESS_EXITED},
    LeaseState.RESUME_REQUESTED: {LeaseState.RESUMED, LeaseState.FAILED, LeaseState.PROCESS_EXITED},
    LeaseState.TERMINATE_REQUESTED: {LeaseState.TERMINATED, LeaseState.TERMINATE_FAILED, LeaseState.PROCESS_EXITED},
    LeaseState.LEASE_EXPIRED: {LeaseState.ROLLBACK_REQUESTED},
    LeaseState.ROLLBACK_REQUESTED: {LeaseState.ROLLED_BACK, LeaseState.FAILED, LeaseState.PROCESS_EXITED},
    LeaseState.RESUMED: {LeaseState.CLOSED}, LeaseState.TERMINATED: {LeaseState.CLOSED},
    LeaseState.ROLLED_BACK: {LeaseState.CLOSED}, LeaseState.PROCESS_EXITED: {LeaseState.CLOSED},
}


@dataclass(frozen=True)
class ContainmentLease:
    lease_id: str
    incident_id: str
    process: ProcessIdentity
    state: LeaseState
    started_at: datetime
    expires_at: datetime
    policy: str
    owner: str
    rollback_action: str
    renewal_count: int = 0
    maximum_renewal: int = 0
    no_user_policy: str = "PAUSE_BOUNDED_THEN_RESUME"
    criticality: str = "noncritical"
    evidence_state: str = "preserved"

    def transition(self, state: LeaseState) -> "ContainmentLease":
        if state not in ALLOWED_TRANSITIONS.get(self.state, set()):
            raise ValueError(f"[AR030] Invalid containment transition {self.state.value}->{state.value}")
        return replace(self, state=state)

    def expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.expires_at.tzinfo is None or self.expires_at <= now
