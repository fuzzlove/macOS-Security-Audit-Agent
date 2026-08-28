from __future__ import annotations
from datetime import datetime,timedelta,timezone
from pathlib import Path
import pytest
from mac_audit_agent.network_segmentation.classifier import classify
from mac_audit_agent.network_segmentation.ingress_models import Engagement,ExpectedAction,ExpectedFlow,Observation,SegmentationResult
from mac_audit_agent.network_segmentation.offline_bundle import create_bundle,verify_bundle
from mac_audit_agent.network_segmentation.scope_guard import ScopeViolation,validate_resolution,validate_target
from mac_audit_agent.network_segmentation.ingress_storage import SegmentationRepository
from mac_audit_agent.network_segmentation.backends.nmap import NmapBackend
from mac_audit_agent.storage import AuditDatabase

def engagement(**changes):
    now=datetime.now(timezone.utc);base=dict(name="Assessment",client="Client",authorization_reference="SOW-1",authorized_tester="Tester",approver="Approver",starts_at=(now-timedelta(minutes=1)).isoformat(),ends_at=(now+timedelta(hours=1)).isoformat(),source_cidrs=("192.0.2.0/24",),destination_cidrs=("198.51.100.0/24",),excluded_cidrs=("198.51.100.128/25",),acknowledgement=True)
    base.update(changes);return Engagement.create(**base)
def flow(expected=ExpectedAction.DENY,family=4):return ExpectedFlow("flow-1","jump","192.0.2.10","cde","198.51.100.10","inbound",family,"tcp",expected,443,443)

def test_scope_guard_authorizes_cidr_and_rejects_exclusion_and_family():
    e=engagement();validate_target(e,flow(),"198.51.100.10")
    with pytest.raises(ScopeViolation):validate_target(e,flow(),"198.51.100.200")
    with pytest.raises(ScopeViolation):validate_target(e,flow(),"203.0.113.1")
    with pytest.raises(ScopeViolation):validate_target(e,flow(),"2001:db8::1")
def test_expired_lease_and_dns_change_are_rejected():
    e=engagement(ends_at=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat())
    with pytest.raises(ScopeViolation,match="window"):validate_target(e,flow(),"198.51.100.10")
    e=engagement()
    with pytest.raises(ScopeViolation,match="changed"):validate_resolution(e,flow(),("198.51.100.10",),("198.51.100.11",))
def test_expected_deny_fails_when_syn_reaches_destination_even_closed():
    result=classify(ExpectedAction.DENY,Observation(True,True,response="tcp_rst",attempts=3),Observation(True,True,attempts=3))
    assert result.result is SegmentationResult.FAIL_UNEXPECTED_ALLOW
    assert "closed service" in " ".join(result.rationale).lower()
def test_rst_for_expected_allow_is_reachable_service_closed():
    result=classify(ExpectedAction.ALLOW,Observation(True,True,response="tcp_rst",attempts=3),Observation(True,True,attempts=3))
    assert result.result is SegmentationResult.NETWORK_REACHABLE_SERVICE_CLOSED
def test_unhealthy_or_missing_observer_is_indeterminate():
    assert classify(ExpectedAction.DENY,Observation(False,True,attempts=3),None).result is SegmentationResult.INDETERMINATE
    assert classify(ExpectedAction.DENY,Observation(False,True,attempts=3),Observation(False,False)).result is SegmentationResult.INDETERMINATE
def test_offline_bundle_detects_modification():
    key=b"test-only-engagement-key";blob=create_bundle("job",{"job_id":"one","nonce":"safe"},key)
    assert verify_bundle(blob,key)["kind"]=="job"
    damaged=bytearray(blob);damaged[-2]^=1
    with pytest.raises((PermissionError,ValueError,KeyError)):verify_bundle(bytes(damaged),key)
def test_nmap_parser_rejects_external_entities():
    with pytest.raises(ValueError,match="unsafe XML"):NmapBackend.parse_xml(b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun/>')
def test_migration_and_audit_hash_chain_use_primary_database(tmp_path:Path):
    db=AuditDatabase(tmp_path/"audit.sqlite3")
    try:
        repo=SegmentationRepository(db);e=engagement();repo.save_engagement(e);repo.audit(e.engagement_id,"test_plan_created",{"plan_id":"p1"})
        assert repo.verify_chain(e.engagement_id)
        tables={row[0] for row in db.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'segmentation_%'")}
        assert "segmentation_engagements" in tables and "segmentation_receiver_observations" in tables
        db.conn.execute("UPDATE segmentation_audit_events SET payload_json='{}' WHERE event_type='test_plan_created'");db.conn.commit()
        assert not repo.verify_chain(e.engagement_id)
    finally:db.close()
