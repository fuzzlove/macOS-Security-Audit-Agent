from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Callable, Protocol

from .evidence import RansomwareEvidenceStore
from .leases import ContainmentLease, LeaseState
from .models import ProcessIdentity


class NativeContainmentBoundary(Protocol):
    def live_identity(self, pid: int) -> ProcessIdentity | None: ...
    def pause_exact(self, identity: ProcessIdentity) -> bool: ...
    def resume_exact(self, identity: ProcessIdentity) -> bool: ...
    def terminate_exact(self, identity: ProcessIdentity) -> bool: ...
    def is_paused(self, identity: ProcessIdentity) -> bool: ...


class ContainmentCoordinator:
    """Durable policy coordinator; production actions require a native boundary."""

    def __init__(self, store: RansomwareEvidenceStore, boundary: NativeContainmentBoundary, *, now: Callable[[], datetime] | None = None) -> None:
        self.store = store
        self.boundary = boundary
        self.now = now or (lambda: datetime.now(timezone.utc))

    def pause(self, lease: ContainmentLease) -> ContainmentLease:
        lease = self._transition(lease, LeaseState.VALIDATING, "validation_started")
        live = self.boundary.live_identity(lease.process.pid)
        if live is None or not lease.process.matches_exact(live):
            return self._transition(lease, LeaseState.REJECTED_IDENTITY_MISMATCH, "exact_identity_mismatch")
        if lease.criticality != "noncritical":
            return self._transition(lease, LeaseState.REJECTED_CRITICAL_PROCESS, "critical_continuity_exclusion")
        if lease.evidence_state != "preserved":
            return self._transition(lease, LeaseState.REJECTED_POLICY, "evidence_not_preserved")
        lease = self._transition(lease, LeaseState.EVIDENCE_PRESERVED, "evidence_verified")
        lease = self._transition(lease, LeaseState.PAUSE_REQUESTED, "pause_requested")
        if not self.boundary.pause_exact(live) or not self.boundary.is_paused(live):
            return self._transition(lease, LeaseState.PAUSE_FAILED, "pause_not_verified")
        return self._transition(lease, LeaseState.PAUSED, "pause_verified")

    def resume(self, lease: ContainmentLease, reason: str) -> ContainmentLease:
        lease = self._transition(lease, LeaseState.RESUME_REQUESTED, reason)
        live = self.boundary.live_identity(lease.process.pid)
        if live is None:
            return self._transition(lease, LeaseState.PROCESS_EXITED, "process_exited_before_resume")
        if not lease.process.matches_exact(live):
            return self._transition(lease, LeaseState.FAILED, "identity_changed_before_resume")
        if not self.boundary.resume_exact(live) or self.boundary.is_paused(live):
            return self._transition(lease, LeaseState.FAILED, "resume_not_verified")
        return self._transition(lease, LeaseState.RESUMED, "resume_verified")

    def terminate(self, lease: ContainmentLease, reason: str) -> ContainmentLease:
        lease = self._transition(lease, LeaseState.TERMINATE_REQUESTED, reason)
        live = self.boundary.live_identity(lease.process.pid)
        if live is None:
            return self._transition(lease, LeaseState.PROCESS_EXITED, "process_exited_before_termination")
        if not lease.process.matches_exact(live):
            return self._transition(lease, LeaseState.TERMINATE_FAILED, "identity_changed_before_termination")
        if not self.boundary.terminate_exact(live):
            return self._transition(lease, LeaseState.TERMINATE_FAILED, "termination_failed")
        return self._transition(lease, LeaseState.TERMINATED, "termination_verified")

    def reconcile(self, lease: ContainmentLease) -> ContainmentLease:
        if lease.state not in {LeaseState.PAUSED, LeaseState.USER_OR_ADMIN_DECISION_PENDING, LeaseState.LEASE_EXPIRED, LeaseState.ROLLBACK_REQUESTED}:
            return lease
        live = self.boundary.live_identity(lease.process.pid)
        if live is None:
            return self._transition(lease, LeaseState.PROCESS_EXITED, "restart_reconcile_process_exited")
        if not lease.process.matches_exact(live):
            # Never signal the reused PID. Record failure for administrator review.
            if lease.state is LeaseState.ROLLBACK_REQUESTED:
                return self._transition(lease, LeaseState.FAILED, "restart_reconcile_identity_changed")
            if lease.state is LeaseState.LEASE_EXPIRED:
                lease = self._transition(lease, LeaseState.ROLLBACK_REQUESTED, "restart_rollback_requested")
                return self._transition(lease, LeaseState.FAILED, "restart_reconcile_identity_changed")
            return lease
        if lease.expired(self.now()) and lease.state in {LeaseState.PAUSED, LeaseState.USER_OR_ADMIN_DECISION_PENDING}:
            lease = self._transition(lease, LeaseState.LEASE_EXPIRED, "lease_expired")
        if lease.state is LeaseState.LEASE_EXPIRED:
            lease = self._transition(lease, LeaseState.ROLLBACK_REQUESTED, "bounded_rollback_requested")
        if lease.state is LeaseState.ROLLBACK_REQUESTED:
            if lease.rollback_action != "resume" or not self.boundary.resume_exact(live) or self.boundary.is_paused(live):
                return self._transition(lease, LeaseState.FAILED, "rollback_failed")
            return self._transition(lease, LeaseState.ROLLED_BACK, "rollback_verified")
        return lease

    def _transition(self, lease: ContainmentLease, state: LeaseState, reason: str) -> ContainmentLease:
        previous = lease.state
        updated = lease.transition(state)
        now = self.now().isoformat()
        process_json = json.dumps(asdict(updated.process), sort_keys=True, separators=(",", ":"))
        with self.store.connection:
            self.store.connection.execute(
                "INSERT OR REPLACE INTO anti_ransomware_containment_leases(lease_id,incident_id,process_key,state,started_at,expires_at,policy,owner,renewal_count,maximum_renewal,rollback_action,updated_at,no_user_policy,criticality,evidence_state,process_identity_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (updated.lease_id, updated.incident_id, updated.process.stable_key, updated.state.value, updated.started_at.isoformat(), updated.expires_at.isoformat(), updated.policy, updated.owner, updated.renewal_count, updated.maximum_renewal, updated.rollback_action, now, updated.no_user_policy, updated.criticality, updated.evidence_state, process_json),
            )
            self.store.connection.execute(
                "INSERT INTO anti_ransomware_containment_actions(action_id,lease_id,previous_state,new_state,actor,reason,created_at) VALUES(?,?,?,?,?,?,?)",
                (f"{updated.lease_id}:{updated.state.value}:{now}", updated.lease_id, previous.value, state.value, updated.owner, reason, now),
            )
        self.store.append_chain_entry(incident_id=updated.incident_id, created_at=now, actor=updated.owner, action="containment_transition", object_id=updated.lease_id, details={"from": previous.value, "to": state.value, "reason": reason, "process_identity_sha256": updated.process.executable_sha256, "process_identity": process_json})
        return updated
