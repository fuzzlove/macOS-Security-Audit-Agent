import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.mission_governance import (
    AuthorizationContext, AuthorizationPolicy, EULAAcceptanceStore, GovernanceAuditLog,
    HumanApproval, LocalAttackSTIXProvider, MaterialOutput, PolicyRequest, redact,
)

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def context(**changes):
    base = AuthorizationContext(
        "1.0","auth-1","eng-1","mission-1","Authorized defensive validation fixture",
        "owner organization","approver-ref","protected-doc-ref","system-owner","asset-owner",
        "production","approved",(NOW-timedelta(hours=1)).isoformat(),(NOW+timedelta(hours=1)).isoformat(),
        ("host.example",),("other.example",),("test-account",),("192.0.2.0/28",),("local telemetry",),("current window",),
        ("scan","production_change"),("read_only","configuration_change"),("persistence",),("destructive",),
        ("enterprise-attack",),("TA0007",),("T1046",),("T1485",),("US",),"INTERNAL",(),"30 days",("material_actions",),("preserve logs",),
        "deconfliction-ref","emergency-ref",("owner stop",),"rollback-ref","recovery-ref",("production_change",),{"attack":"15.1"},"AUTHORIZED_OPERATIONAL","approval-ref",NOW.isoformat(),NOW.isoformat(),NOW.isoformat(),"","",
    )
    return replace(base, **changes)


def request(**changes):
    return replace(PolicyRequest("AUTHORIZED_OPERATIONAL","scan","host.example","test-account","read_only","T1046","US","actor-ref","session-1",{"attack":"15.1"}),**changes)


def approval(**changes):
    base=HumanApproval("consequential","approver-protected","production_change",("host.example",),(NOW-timedelta(minutes=5)).isoformat(),(NOW+timedelta(minutes=30)).isoformat(),"auth-1")
    return replace(base,**changes)


@pytest.mark.parametrize("ctx,code",[(None,"AUTHORIZATION_MISSING"),(context(authorization_status="draft"),"AUTHORIZATION_NOT_APPROVED"),(context(valid_until=(NOW-timedelta(seconds=1)).isoformat()),"AUTHORIZATION_EXPIRED"),(context(authorization_status="revoked",revoked_at=NOW.isoformat()),"AUTHORIZATION_REVOKED"),(context(valid_from=(NOW+timedelta(seconds=1)).isoformat()),"AUTHORIZATION_NOT_ACTIVE")])
def test_invalid_authorization_defaults_advisory(ctx,code):
    decision=AuthorizationPolicy().evaluate(request(),ctx,now=NOW)
    assert not decision.allowed and decision.effective_mode=="ADVISORY" and decision.reason_code==code


def test_incomplete_context_rejected():
    with pytest.raises(ValueError,match="incomplete"): AuthorizationContext.from_mapping({"schema_version":"1.0"})


@pytest.mark.parametrize("changes,code",[
    ({"target":"other.example"},"TARGET_OUT_OF_SCOPE"),({"account":"other-account"},"ACCOUNT_OUT_OF_SCOPE"),
    ({"action":"inventory"},"ACTION_OUT_OF_SCOPE"),({"operational_effect":"destructive"},"EFFECT_OUT_OF_SCOPE"),
    ({"attack_technique":"T1485"},"TECHNIQUE_PROHIBITED"),({"jurisdiction":"GB"},"JURISDICTION_OUT_OF_SCOPE"),
    ({"framework_versions":{"attack":"older"}},"FRAMEWORK_VERSION_MISMATCH"),
])
def test_scope_effect_technique_and_framework_enforced(changes,code):
    assert AuthorizationPolicy().evaluate(request(**changes),context(),now=NOW).reason_code==code


def test_network_scope_does_not_expand_adjacent_range():
    policy=AuthorizationPolicy()
    assert policy.evaluate(request(target="192.0.2.5"),context(),now=NOW).allowed
    assert policy.evaluate(request(target="192.0.2.20"),context(),now=NOW).reason_code=="TARGET_OUT_OF_SCOPE"


def test_human_approval_required_and_scoped():
    req=request(action="production_change",operational_effect="configuration_change")
    assert AuthorizationPolicy().evaluate(req,context(),now=NOW).reason_code=="HUMAN_APPROVAL_REQUIRED"
    assert AuthorizationPolicy().evaluate(req,context(),approval(),now=NOW).allowed
    assert not AuthorizationPolicy().evaluate(req,context(),approval(approved_scope=("other.example",)),now=NOW).allowed


@pytest.mark.parametrize("change,code",[({"stop_condition_active":True},"STOP_CONDITION_ACTIVE"),({"audit_available":False},"AUDIT_UNAVAILABLE"),({"rollback_available":False,"action":"production_change","operational_effect":"configuration_change"},"ROLLBACK_UNAVAILABLE"),({"recovery_available":False,"action":"production_change","operational_effect":"configuration_change"},"RECOVERY_UNAVAILABLE")])
def test_stop_conditions_suspend_operation(change,code): assert AuthorizationPolicy().evaluate(request(**change),context(),now=NOW).reason_code==code


@pytest.mark.parametrize("assertion",["license","nda","developer_mode","administrator_role","debug_mode","user_assertion"])
def test_assertions_cannot_select_operational(assertion):
    req=request(actor_reference=assertion+":true")
    assert AuthorizationPolicy().evaluate(req,None,now=NOW).effective_mode=="ADVISORY"


def test_advisory_recovery_remains_available_after_stop():
    decision=AuthorizationPolicy().evaluate(PolicyRequest("ADVISORY","recovery",stop_condition_active=True),None,now=NOW)
    assert decision.allowed and decision.reason_code=="SAFE_ASSISTANCE"


def test_lab_does_not_authorize_production():
    lab=context(environment="lab",in_scope_assets=("lab.example",))
    assert AuthorizationPolicy().evaluate(request(target="host.example"),lab,now=NOW).reason_code=="TARGET_OUT_OF_SCOPE"


def test_audit_redacts_and_chain_detects_change(tmp_path):
    log=GovernanceAuditLog(tmp_path/"governance.jsonl");req=request(actor_reference="token=secret-value")
    row=log.append(req,AuthorizationPolicy().evaluate(req,None,now=NOW));assert "secret-value" not in json.dumps(row);assert log.verify()
    text=log.path.read_text().replace("AUTHORIZATION_MISSING","AUTHORIZED");log.path.write_text(text);assert not log.verify()


def test_redaction_removes_sensitive_fields_and_bearer_values():
    result=redact({"password":"secret","note":"Bearer abcdefghijklmnop"});assert result["password"]=="[REDACTED]" and "abcdefghijklmnop" not in result["note"]


def test_eula_acceptance_is_versioned(tmp_path):
    store=EULAAcceptanceStore(tmp_path/"state.sqlite3");store.accept("user-ref","1.0","app-1",accepted_at=NOW.isoformat());store.accept("user-ref","1.0","app-1",accepted_at=(NOW+timedelta(seconds=1)).isoformat());assert store.accepted("user-ref","1.0");assert not store.accepted("user-ref","2.0");assert len(store.acceptance_history("user-ref"))==2


def test_attack_provider_fails_safely_and_validates_import(tmp_path):
    assert LocalAttackSTIXProvider(None).validate("T1046") is None
    path=tmp_path/"attack.json";path.write_text(json.dumps({"objects":[{"type":"attack-pattern","name":"Network Service Discovery","modified":"2026-01-01","external_references":[{"external_id":"T1046"}]}]}))
    provider=LocalAttackSTIXProvider(path);assert provider.validate("T1046")["name"]=="Network Service Discovery";assert provider.validate("T9999") is None


def test_material_output_defaults_do_not_fabricate_unknowns():
    output=MaterialOutput();assert output.source_retrieval_date=="Not verified";assert output.framework_or_data_version=="Framework version not configured";assert output.confidence_basis=="Insufficient evidence"


def test_schema_is_strict_and_complete():
    schema=json.loads(open("schemas/authorization-context.schema.json",encoding="utf-8").read());assert schema["additionalProperties"] is False;assert set(AuthorizationContext.__dataclass_fields__).issubset(schema["properties"])
