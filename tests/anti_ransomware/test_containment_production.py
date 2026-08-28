from dataclasses import asdict, replace

import pytest

from mac_audit_agent.anti_ransomware.containment_production import ActiveContainmentEvidence, NativeLeaseJournal, SensorIdentityRegistry, SensorTargetRecord, TransactionState, active_containment_ready
from mac_audit_agent.anti_ransomware.models import ProcessIdentity


def identity(boot="boot-a"):
    return ProcessIdentity(100,4,"/tmp/fixture","a"*64,501,boot,audit_token_hash="b"*64,executable_file_id="1:2",cdhash="c"*40,process_start_time_ns=99)


def record(boot="boot-a"):
    return SensorTargetRecord("incident","event",identity(boot),"sensor-1",boot,10,100)


def test_python_cannot_register_or_resolve_bare_pid():
    registry=SensorIdentityRegistry(2)
    with pytest.raises(PermissionError): registry.register_from_sensor(record(),authenticated_sensor=False)
    registry.register_from_sensor(record(),authenticated_sensor=True)
    assert registry.resolve("incident","event",now_monotonic=20,boot_session="boot-a").identity.pid==100
    with pytest.raises(LookupError): registry.resolve("incident","missing",now_monotonic=20,boot_session="boot-a")
    with pytest.raises(PermissionError): registry.resolve("incident","event",now_monotonic=20,boot_session="boot-b")


def test_registry_is_bounded_and_expiring():
    registry=SensorIdentityRegistry(1); registry.register_from_sensor(record(),authenticated_sensor=True)
    second=replace(record(),incident_id="second",event_id="two")
    registry.register_from_sensor(second,authenticated_sensor=True)
    with pytest.raises(LookupError): registry.resolve("incident","event",now_monotonic=20,boot_session="boot-a")
    with pytest.raises(LookupError): registry.resolve("second","two",now_monotonic=100,boot_session="boot-a")


def test_durable_prepare_transition_and_reboot_reconcile(tmp_path):
    path=tmp_path/"leases.sqlite3"; journal=NativeLeaseJournal(path)
    journal.prepare(lease_id="lease",target=record(),now_monotonic=20,expires_monotonic=50,helper_generation="helper-1",token="opaque-token")
    journal.transition("lease",TransactionState.PREPARED,TransactionState.WATCHDOG_ARMED,"helper","guardian_ready",21)
    assert journal.active_count()==1; journal.close()
    reopened=NativeLeaseJournal(path)
    assert reopened.reconcile_boot("boot-b",1)==1 and reopened.active_count()==0
    transitions=[row[0] for row in reopened.connection.execute("SELECT new_state FROM transitions ORDER BY sequence")]
    assert transitions==["PREPARED","WATCHDOG_ARMED","RECONCILED_AFTER_REBOOT"]
    reopened.close()


def test_prepared_token_not_stored_in_plaintext(tmp_path):
    journal=NativeLeaseJournal(tmp_path/"leases.sqlite3"); journal.prepare(lease_id="lease",target=record(),now_monotonic=20,expires_monotonic=50,helper_generation="h",token="secret-token")
    assert journal.connection.execute("SELECT prepared_token_hash FROM leases").fetchone()[0] != "secret-token"
    journal.close()


def test_active_readiness_is_derived_and_current_environment_stays_false():
    assert not active_containment_ready(ActiveContainmentEvidence(helper_is_native=True,lease_is_durable=True,request_replay_is_rejected=True))
    values={name: (True if isinstance(value,bool) else value) for name,value in asdict(ActiveContainmentEvidence()).items()}
    values.update(suspended_fixture_count=0,active_test_lease_count=0,emergency_cleanup_required=False)
    assert active_containment_ready(ActiveContainmentEvidence(**values))
    assert not active_containment_ready(ActiveContainmentEvidence(**(values|{"emergency_cleanup_required":True})))
