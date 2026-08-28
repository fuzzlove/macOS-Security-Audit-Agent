from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.anti_ransomware.leases import ContainmentLease, LeaseState
from mac_audit_agent.anti_ransomware.models import ProcessIdentity
from mac_audit_agent.anti_ransomware.sabotage import CommandObservation, sabotage_signals


def identity(): return ProcessIdentity(44,3,"/tmp/fixture","a"*64,501,"boot")


def test_lease_valid_path_and_invalid_transition():
    lease = ContainmentLease("l","i",identity(),LeaseState.REQUESTED,datetime.now(timezone.utc),datetime.now(timezone.utc)+timedelta(seconds=30),"balanced","native-watchdog","resume")
    for state in (LeaseState.VALIDATING,LeaseState.EVIDENCE_PRESERVED,LeaseState.PAUSE_REQUESTED,LeaseState.PAUSED,LeaseState.LEASE_EXPIRED,LeaseState.ROLLBACK_REQUESTED,LeaseState.ROLLED_BACK,LeaseState.CLOSED):
        lease = lease.transition(state)
    with pytest.raises(ValueError, match="Invalid containment transition"):
        lease.transition(LeaseState.PAUSED)


def test_backup_and_service_sabotage_fixtures_are_non_destructive():
    snapshot = sabotage_signals(CommandObservation("/usr/bin/tmutil",("deletelocalsnapshots","2026-01-01")))
    service = sabotage_signals(CommandObservation("/bin/launchctl",("bootout","system/com.example.macauditagent")))
    assert {s.signal_id for s in snapshot} == {"snapshot_deletion_attempt"}
    assert {s.signal_id for s in service} == {"protection_service_impairment"}
