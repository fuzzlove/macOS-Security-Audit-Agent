from __future__ import annotations

import sqlite3
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.alerts.durable import DurableAlertController, persistence_policy
from mac_audit_agent.security_controls.authorization import AuthorizedChangeWindow, evaluate_authorization, sign_window
from mac_audit_agent.security_controls.collectors import CommandSpec, run_trusted_command
from mac_audit_agent.security_controls.diff_engine import changed_fields, normalize_value, safe_text, state_digest
from mac_audit_agent.security_controls.evidence import EvidenceStore
from mac_audit_agent.security_controls.models import AuthorizationStatus, ProcessIdentity, SecurityControlState
from mac_audit_agent.security_controls.monitor import SecurityControlMonitor
from mac_audit_agent.security_controls.native_notifications import MacOSUserNotificationBridge
from mac_audit_agent.security_controls.redaction import redact
from mac_audit_agent.security_controls.registry import CONTROL_REGISTRY
from mac_audit_agent.security_controls.severity import assess_risk


def state(control_id:str,value:dict)->SecurityControlState:
    definition=CONTROL_REGISTRY[control_id]
    return SecurityControlState(control_id,definition.category,datetime.now(timezone.utc),value,"test",1.0,"success")


def test_normalization_diff_digest_and_unicode_safety():
    assert normalize_value({"b":[2,1],"a":" x "})=={"a":"x","b":[1,2]}
    assert changed_fields({"enabled":True,"noise":[2,1]},{"enabled":False,"noise":[1,2]})==("enabled",)
    assert state_digest({"a":1})==state_digest({"a":1})
    assert "U+202E" in safe_text("tool\u202eeman")


def test_authorization_is_signed_bounded_and_scoped():
    now=datetime.now(timezone.utc);key=b"test-only-key"
    window=AuthorizedChangeWindow("auth-1","operator","approver","ticketed maintenance","T-1",("macos.application_firewall",),("abc",),(),now-timedelta(minutes=1),now+timedelta(minutes=5),now,"")
    window=replace(window,signature=sign_window(window,key));process=ProcessIdentity(executable_sha256="abc")
    assert evaluate_authorization(window,control_id="macos.application_firewall",process=process,verification_key=key,now=now)==AuthorizationStatus.AUTHORIZED
    assert evaluate_authorization(window,control_id="macos.sip",process=process,verification_key=key,now=now)==AuthorizationStatus.SCOPE_MISMATCH
    assert evaluate_authorization(window,control_id="macos.application_firewall",process=process,verification_key=b"wrong",now=now)==AuthorizationStatus.SIGNATURE_INVALID
    assert evaluate_authorization(window,control_id="macos.application_firewall",process=process,verification_key=key,now=now+timedelta(hours=1))==AuthorizationStatus.EXPIRED


def test_risk_is_separate_from_cvss_explainable_and_bounded():
    risk=assess_risk(category="self_protection",authorization_status="UNAUTHORIZED",reduces_security=True,process_trusted=False,remote_session=True,asset_criticality=99,related_control_count=4)
    assert risk.score==10 and risk.severity=="critical" and risk.contributing_factors


def test_redaction_precedes_persistence():
    payload=redact({"password":"secret","command":"tool --token=abc Authorization: Bearer xyz"})
    assert "secret" not in str(payload) and "abc" not in str(payload) and "xyz" not in str(payload)


def test_trusted_command_rejects_arbitrary_execution():
    with pytest.raises(ValueError):run_trusted_command(CommandSpec(("/bin/sh","-c","id")))


def test_event_chain_alert_restore_and_acknowledgment(tmp_path):
    path=tmp_path/"controls.sqlite3"
    with EvidenceStore(path) as store:
        monitor=SecurityControlMonitor(store)
        event=monitor.compare_and_record(state("macos.application_firewall",{"enabled":True}),state("macos.application_firewall",{"enabled":False}))
        assert event and event.reference_cvss_score is None and event.msaa_incident_risk_score>=7
        assert store.verify_chain()["valid"]
        controller=DurableAlertController(store)
        restored=controller.restore();assert restored and persistence_policy(event.severity)=="acknowledgment_required"
        controller.acknowledge(event.event_id,actor="analyst",reason="Reviewed evidence",device_identity="local-test")
        assert not store.pending_alerts()
        assert store.connection.execute("SELECT COUNT(*) FROM security_control_events").fetchone()[0]==1
        assert store.connection.execute("SELECT COUNT(*) FROM security_control_acknowledgments").fetchone()[0]==1
    assert path.stat().st_mode & 0o077 == 0


def test_chain_detects_tampering(tmp_path):
    path=tmp_path/"evidence.sqlite3"
    with EvidenceStore(path) as store:
        event=SecurityControlMonitor(store).compare_and_record(state("macos.remote_access",{"enabled":False}),state("macos.remote_access",{"enabled":True}))
        assert event
        store.connection.execute("UPDATE security_control_events SET payload_json='{}' WHERE event_id=?",(event.event_id,));store.connection.commit()
        assert store.verify_chain()["error_code"]=="EVIDENCE_CHAIN_MISMATCH"


def test_chain_checkpoint_detects_truncation(tmp_path):
    with EvidenceStore(tmp_path/"truncated.sqlite3") as store:
        event=SecurityControlMonitor(store).compare_and_record(state("macos.sip",{"enabled":True}),state("macos.sip",{"enabled":False}))
        assert event
        store.connection.execute("DELETE FROM security_control_alerts WHERE event_id=?",(event.event_id,))
        store.connection.execute("DELETE FROM security_control_events WHERE event_id=?",(event.event_id,));store.connection.commit()
        assert store.verify_chain()["error_code"]=="EVIDENCE_CHAIN_TRUNCATED_OR_REORDERED"


def test_fsevents_gap_requires_reconciliation(tmp_path):
    with EvidenceStore(tmp_path/"gap.sqlite3") as store:
        result=SecurityControlMonitor(store).handle_fsevents_gap()
        assert result["requires_reconciliation"] and result["sensor_health_event"]


def test_native_bridge_never_claims_guaranteed_delivery():
    result=MacOSUserNotificationBridge().request(event_id="test",severity="critical",title="test",body="test")
    assert not result.delivery_guaranteed


def test_alert_card_and_stack_are_persistent_accessible_and_strongly_referenced():
    os.environ.setdefault("QT_QPA_PLATFORM","offscreen")
    from PySide6.QtWidgets import QApplication
    from mac_audit_agent.ui.alerts import AlertStack
    app=QApplication.instance() or QApplication([])
    stack=AlertStack()
    card=stack.add_alert({"event_id":"event-1","severity":"critical","title":"System Integrity Protection State Changed","description":"An unexplained change was detected.","authorization_status":"UNAUTHORIZED","risk_score":9.5,"confidence":0.9})
    assert stack.cards["event-1"] is card
    assert card.acknowledge.text()=="Acknowledge Security Alert"
    assert "Evidence remains" in card.acknowledge.toolTip()
    assert card.open_incident.isVisible()
    stack.close();assert app is not None
