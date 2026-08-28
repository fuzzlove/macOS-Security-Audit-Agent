from __future__ import annotations
import json, threading
from dataclasses import replace
from mac_audit_agent.anti_ransomware.cli import main
from mac_audit_agent.anti_ransomware.health import ESClientResult, ProtectionState, RuntimeEvidence, SensorMode, evaluate_readiness, source_health
from mac_audit_agent.anti_ransomware.repair import repair_plan

def current(**changes):
    base=RuntimeEvidence(build_id="build",current_build_id="build",boot_session_id="boot",current_boot_session_id="boot",fresh=True,system_engine_running=True,system_engine_heartbeat_fresh=True)
    return replace(base,**changes)

def observe_evidence(**changes):
    base=current(sensor_artifact_exists=True,sensor_installed=True,sensor_loaded=True,sensor_running=True,sensor_signature_valid=True,entitlement_embedded=True,entitlement_accepted=True,tcc_approval_present=True,privacy_approval_source="live_sensor",endpoint_security_client_result=ESClientResult.SUCCESS,endpoint_security_connected=True,endpoint_security_subscriptions_active=True,endpoint_security_live_event_seen=True,sequence_tracking_active=True,sensor_heartbeat_fresh=True)
    return replace(base,**changes)

def test_everything_missing_preserves_ar022_contract():
    value=source_health(evidence=RuntimeEvidence(system_engine_running=True)).to_dict()
    expected={"state":"DEGRADED","active_mode":"OBSERVE","sensor_mode":"DEGRADED_OBSERVATION_ONLY","sensor_installed":False,"endpoint_security_connected":False,"entitlement_present":False,"full_disk_access_present":False,"containment_available":False,"error_code":"AR022"}
    for key,item in expected.items(): assert value[key]==item
    assert {error["error_code"] for error in value["underlying_errors"]} >= {"AR001","AR004","AR005","AR006","AR016"}

def test_predicates_are_independent():
    artifact=source_health(evidence=RuntimeEvidence(sensor_artifact_exists=True,system_engine_running=True))
    assert artifact.sensor_artifact_exists and not artifact.sensor_installed and not artifact.entitlement_accepted
    rejected=source_health(evidence=current(sensor_artifact_exists=True,sensor_installed=True,sensor_signature_valid=True,entitlement_embedded=True))
    assert rejected.entitlement_embedded and not rejected.entitlement_accepted and not rejected.endpoint_security_connected
    connected=source_health(evidence=observe_evidence())
    assert connected.endpoint_security_connected and connected.endpoint_security_observe_ready and not connected.containment_available

def test_endpoint_security_ready_takes_priority_over_fallback_observer_badge():
    evidence=observe_evidence(sensor_details={"development_observer":{"running":True,"yara_active":True}})
    status=source_health(evidence=evidence)
    assert status.state is ProtectionState.ENDPOINT_SECURITY_OBSERVE_READY
    assert status.status_badge == "ENDPOINT_SECURITY_OBSERVE_READY"
    assert status.error_code == "AR016"
    assert status.contribution_actions == ()
    assert "Notify-only Endpoint Security coverage" in status.limitations[0]
    assert status.repair_actions[4]["status"] == "complete"

def test_stale_or_mock_evidence_cannot_satisfy_live_readiness():
    live=observe_evidence()
    assert evaluate_readiness(live).endpoint_security_observe_ready
    assert not evaluate_readiness(replace(live,fresh=False)).endpoint_security_observe_ready
    assert not evaluate_readiness(replace(live,build_id="old")).endpoint_security_observe_ready
    assert not evaluate_readiness(replace(live,boot_session_id="old")).endpoint_security_observe_ready

def test_full_active_requires_every_containment_and_service_predicate():
    e=observe_evidence(containment_helper_installed=True,containment_helper_running=True,containment_ipc_authenticated=True,containment_identity_revalidation=True,containment_lease_watchdog_passed=True,live_fixture_pause_passed=True,live_fixture_resume_passed=True,live_fixture_termination_passed=True,crash_recovery_passed=True,no_orphaned_suspended_fixture=True,production_policy_valid=True,production_rules_valid=True,notifier_required=False,no_user_policy_valid=True,durable_incident_vault_available=True,service_restart_verified=True,boot_prelogin_coverage_verified=True,current_uat_no_required_blocker=True,self_integrity_valid=True,policy_signature_valid=True,rule_package_signature_valid=True)
    status=source_health(evidence=e)
    assert status.state is ProtectionState.FULL_ACTIVE_PROTECTION and status.sensor_mode is SensorMode.ENDPOINT_SECURITY_AUTH_AND_NOTIFY and status.error_code==""
    assert not source_health(evidence=replace(e,containment_ipc_authenticated=False)).full_active_protection

def test_repair_plan_is_ordered_non_destructive_and_beginner_safe():
    plan=repair_plan(source_health(evidence=RuntimeEvidence(system_engine_running=True)))
    assert [step["step"] for step in plan["steps"]]==[1,2,3,4,5,6,7]
    assert not plan["destructive"] and not plan["requires_sudo_invocation"]
    text=json.dumps(plan).lower()
    assert "apple" in text and "release engineer" in text
    assert "disable sip" in text and "prohibited_actions" in text
    assert "pip install" not in text and "run gui as root" in text

def test_one_hundred_status_refreshes_create_no_threads():
    evidence=RuntimeEvidence(system_engine_running=True)
    before={(thread.name,thread.ident) for thread in threading.enumerate()}
    for _ in range(100): source_health(evidence=evidence).to_dict()
    assert {(thread.name,thread.ident) for thread in threading.enumerate()}==before

def test_json_mode_contains_only_json(capsys):
    assert main(["repair","--plan","--json"])==1
    assert json.loads(capsys.readouterr().out)["destructive"] is False
