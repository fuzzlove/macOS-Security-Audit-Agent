from __future__ import annotations

import base64, hashlib, json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.anti_ransomware.audit_chain import TamperEvidentAuditLog
from mac_audit_agent.anti_ransomware.canary import deploy_canaries, remove_canaries
from mac_audit_agent.anti_ransomware.hash_indicators import HashIndicator, HashIndicatorBackend
from mac_audit_agent.anti_ransomware.health import ESClientResult, RuntimeEvidence, source_health
from mac_audit_agent.anti_ransomware.quarantine import QuarantineManager
from mac_audit_agent.anti_ransomware.rule_engine import RulePackageError, verify_rule_package
from mac_audit_agent.anti_ransomware.simulator import run_safe_detection_validation, run_safe_simulation
from mac_audit_agent.anti_ransomware.yara_backend import YaraBackend


def test_hash_backend_remains_available_without_yara(tmp_path):
    target=tmp_path/"fixture.bin"; target.write_bytes(b"benign known test fixture")
    digest=hashlib.sha256(target.read_bytes()).hexdigest(); indicator=HashIndicator("TEST-ONLY","sha256",digest,"high","high","synthetic fixture")
    match,observed=HashIndicatorBackend([indicator]).match_file(target)
    assert match==indicator and observed==digest
    assert YaraBackend().capability.state in {"AVAILABLE","DEPENDENCY_MISSING"}


def test_hash_backend_rejects_symlink_and_large_file(tmp_path):
    target=tmp_path/"x"; target.write_bytes(b"x"*20); link=tmp_path/"link"; link.symlink_to(target)
    with pytest.raises(ValueError): HashIndicatorBackend.sha256_file(link)
    with pytest.raises(ValueError): HashIndicatorBackend.sha256_file(target,maximum_bytes=10)


def test_signed_rule_package_and_rollback_rejection():
    cryptography=pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    private=Ed25519PrivateKey.generate(); public=private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
    document={"schema_version":"1.0","version":2,"ruleset_version":"2026.1","expires_at":(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),"rules":[{"rule_id":"TEST.BENIGN","severity":"low","confidence":"test","source":"synthetic"}]}
    payload=json.dumps(document,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode(); document["signature"]=base64.b64encode(private.sign(payload)).decode()
    assert verify_rule_package(document,public,current_version=1).version==2
    with pytest.raises(RulePackageError): verify_rule_package(document,public,current_version=2)
    tampered=dict(document); tampered["ruleset_version"]="tampered"
    with pytest.raises(RulePackageError): verify_rule_package(tampered,public,current_version=1)


def test_canary_requires_authorization_and_removes_only_unchanged(tmp_path):
    with pytest.raises(PermissionError): deploy_canaries(tmp_path)
    records=deploy_canaries(tmp_path,authorized=True); assert len(records)==2
    assert len(remove_canaries(tmp_path,authorized=True))==2


def test_quarantine_and_controlled_restore(tmp_path):
    root=tmp_path/"quarantine"; source=tmp_path/"benign-test.bin"; source.write_bytes(b"benign")
    manager=QuarantineManager(root,production=False); manifest=manager.quarantine(source,incident_id="incident-test",reason="synthetic test",authorized=True)
    assert not source.exists() and manifest["signature_state"]=="unsigned_hash_manifest"
    restored=manager.restore(manifest["item_id"],authorized=True)
    assert source.read_bytes()==b"benign" and restored["restore_path"]==str(source)


def test_audit_chain_detects_tampering(tmp_path):
    log=TamperEvidentAuditLog(tmp_path/"audit.jsonl")
    log.append(actor="admin",component="rules",action="verify",policy_version="1",details={"result":"valid"})
    log.append(actor="service",component="sensor",action="health",policy_version="1",details={"state":"degraded"})
    assert log.verify()
    text=log.path.read_text(); log.path.write_text(text.replace("degraded","protected"))
    assert not log.verify()


def test_safe_simulation_is_bounded_and_non_enforcing():
    result=run_safe_simulation()
    assert result["all_stages_passed"] and result["bounded"]=={"maximum_files":20,"maximum_bytes_per_file":1048576,"network_access":False,"process_signals_sent":False,"pf_rules_applied":False}
    assert result["detection_validation"]["expected"] == "caught"
    assert result["detection_validation"]["passed"] is True


def test_safe_detection_validation_requires_live_observer_evidence(monkeypatch):
    states = iter([
        {"sensor_details": {"development_observer": {"roots": [], "last_event": "before"}}, "endpoint_security_observe_ready": True},
        {"sensor_details": {"development_observer": {"roots": [], "last_event": "before"}}, "endpoint_security_observe_ready": True},
    ])
    result = run_safe_detection_validation(health_provider=lambda: next(states), sleeper=lambda _seconds: None)
    assert result["behavior_engine_caught"] is True
    assert result["caught"] is False
    assert result["status"] == "INCONCLUSIVE"
    assert result["live_observation"] == "endpoint_security_connected_but_fixture_attribution_unavailable"


def test_live_inspector_requirements_reflected_in_operational_state():
    degraded=source_health(evidence=RuntimeEvidence(system_engine_running=True)).to_dict()
    assert degraded["operational_state"]=="UNINSTALLED" and degraded["error_code"]=="AR022"
    assert not degraded["policy_signature_valid"] and not degraded["self_integrity_valid"]
