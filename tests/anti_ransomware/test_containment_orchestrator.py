from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import sqlite3

from mac_audit_agent.anti_ransomware.containment_orchestrator import ContainmentCoordinator
from mac_audit_agent.anti_ransomware.evidence import RansomwareEvidenceStore
from mac_audit_agent.anti_ransomware.leases import ContainmentLease, LeaseState
from mac_audit_agent.anti_ransomware.models import ProcessIdentity


NOW = datetime(2026, 7, 10, tzinfo=timezone.utc)


def identity(**changes):
    value = ProcessIdentity(321, 8, "/tmp/msaa-safe-fixture", "a" * 64, 501, "boot", audit_token_hash="b" * 64, executable_file_id="1:2", cdhash="c" * 40, process_start_time_ns=123456)
    return replace(value, **changes)


class Boundary:
    def __init__(self, live=None): self.live = live or identity(); self.paused = False; self.exited = False
    def live_identity(self, pid): return None if self.exited else self.live
    def pause_exact(self, value): self.paused = True; return True
    def resume_exact(self, value): self.paused = False; return True
    def terminate_exact(self, value): self.exited = True; self.paused = False; return True
    def is_paused(self, value): return self.paused


def store_with_incident(tmp_path):
    store = RansomwareEvidenceStore(tmp_path / "vault.sqlite3")
    stamp = NOW.isoformat()
    with store.connection:
        store.connection.execute(
            "INSERT INTO anti_ransomware_incidents(incident_id,first_event_time,last_event_time,boot_session_id,endpoint_id,severity,confidence,score,policy_version,ruleset_version,containment_state,notification_state,resolution,limitations_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("incident", stamp, stamp, "boot", "endpoint", "high", "high", 95, "1", "1", "OPEN", "QUEUED", "", "[]", stamp, stamp),
        )
    return store


def lease(**changes):
    value = ContainmentLease("lease", "incident", identity(), LeaseState.REQUESTED, NOW, NOW + timedelta(seconds=30), "balanced-v1", "native-watchdog", "resume")
    return replace(value, **changes)


def test_pause_is_evidence_first_verified_and_durable_then_resume(tmp_path):
    store = store_with_incident(tmp_path); boundary = Boundary(); coordinator = ContainmentCoordinator(store, boundary, now=lambda: NOW)
    paused = coordinator.pause(lease())
    assert paused.state is LeaseState.PAUSED and boundary.paused
    states = [row[0] for row in store.connection.execute("SELECT new_state FROM anti_ransomware_containment_actions ORDER BY rowid")]
    assert states == ["VALIDATING", "EVIDENCE_PRESERVED", "PAUSE_REQUESTED", "PAUSED"]
    resumed = coordinator.resume(paused, "authorized_allow_once")
    assert resumed.state is LeaseState.RESUMED and not boundary.paused and store.verify_chain()
    store.close()


def test_pid_reuse_path_replacement_critical_and_missing_evidence_are_blocked(tmp_path):
    store = store_with_incident(tmp_path)
    mismatch = ContainmentCoordinator(store, Boundary(identity(pid_version=9)), now=lambda: NOW).pause(lease())
    assert mismatch.state is LeaseState.REJECTED_IDENTITY_MISMATCH
    critical = ContainmentCoordinator(store, Boundary(), now=lambda: NOW).pause(lease(lease_id="critical", criticality="accessibility"))
    assert critical.state is LeaseState.REJECTED_CRITICAL_PROCESS
    evidence = ContainmentCoordinator(store, Boundary(), now=lambda: NOW).pause(lease(lease_id="evidence", evidence_state="missing"))
    assert evidence.state is LeaseState.REJECTED_POLICY
    path_changed = ContainmentCoordinator(store, Boundary(identity(executable_path="/tmp/replaced")), now=lambda: NOW).pause(lease(lease_id="path"))
    assert path_changed.state is LeaseState.REJECTED_IDENTITY_MISMATCH
    store.close()


def test_expired_lease_restart_reconciliation_rolls_back_without_orphan(tmp_path):
    store = store_with_incident(tmp_path); boundary = Boundary(); boundary.paused = True
    coordinator = ContainmentCoordinator(store, boundary, now=lambda: NOW + timedelta(minutes=1))
    expired = lease(state=LeaseState.PAUSED, expires_at=NOW + timedelta(seconds=1))
    rolled_back = coordinator.reconcile(expired)
    assert rolled_back.state is LeaseState.ROLLED_BACK and not boundary.paused
    assert [row[0] for row in store.connection.execute("SELECT new_state FROM anti_ransomware_containment_actions ORDER BY rowid")] == ["LEASE_EXPIRED", "ROLLBACK_REQUESTED", "ROLLED_BACK"]
    store.close()


def test_termination_revalidates_identity_and_closes_exited_fixture(tmp_path):
    store = store_with_incident(tmp_path); boundary = Boundary(); coordinator = ContainmentCoordinator(store, boundary, now=lambda: NOW)
    paused = coordinator.pause(lease())
    terminated = coordinator.terminate(paused, "preauthorized_exact_block")
    assert terminated.state is LeaseState.TERMINATED and boundary.exited
    store.close()


def test_v1_lease_schema_migrates_complete_restart_identity(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE anti_ransomware_containment_leases(lease_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, process_key TEXT NOT NULL, state TEXT NOT NULL, started_at TEXT NOT NULL, expires_at TEXT NOT NULL, policy TEXT NOT NULL, owner TEXT NOT NULL, renewal_count INTEGER NOT NULL DEFAULT 0, maximum_renewal INTEGER NOT NULL DEFAULT 0, rollback_action TEXT NOT NULL, updated_at TEXT NOT NULL)")
    connection.commit(); connection.close()
    store = RansomwareEvidenceStore(path)
    columns = {row[1] for row in store.connection.execute("PRAGMA table_info(anti_ransomware_containment_leases)")}
    assert {"no_user_policy", "criticality", "evidence_state", "process_identity_json"} <= columns
    assert store.connection.execute("SELECT value FROM anti_ransomware_meta WHERE key='schema_version'").fetchone()[0] == "3"
    store.close()
