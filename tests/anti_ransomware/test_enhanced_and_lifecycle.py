from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone

from mac_audit_agent.anti_ransomware.containment import ContainmentAction, ContainmentRequest, authorize_containment
from mac_audit_agent.anti_ransomware.enhanced_detection import FileTransition, transition_signals
from mac_audit_agent.anti_ransomware.evidence import EvidenceRecord, RansomwareEvidenceStore
from mac_audit_agent.anti_ransomware.file_statistics import analyze_bytes
from mac_audit_agent.anti_ransomware.models import ProcessIdentity
from mac_audit_agent.anti_ransomware.process_tree import ProcessTreeCorrelator
from mac_audit_agent.anti_ransomware.rules import RansomwareRule, RuleAction, validate_managed_rule
from mac_audit_agent.anti_ransomware.service import BoundedAnalysisService


def proc(pid: int, version: int = 1, parent: int | None = None) -> ProcessIdentity:
    return ProcessIdentity(pid, version, f"/tmp/p{pid}", f"{pid:064x}"[-64:], 501, "boot", parent_pid=parent)


def test_enhanced_transition_explains_rename_delete_and_large_sampling():
    before = analyze_bytes(b"plain text " * 1000)
    after = analyze_bytes(os.urandom(65536), original_size=80 * 1024 * 1024)
    ids = {s.signal_id for s in transition_signals(FileTransition(before, after, "rename", True, True, True))}
    assert {"high_entropy_transition", "extension_changed", "original_deleted", "rename_over_original", "large_file_sampled"} <= ids


def test_children_aggregate_to_parent_tree():
    parent, child1, child2 = proc(10), proc(11, parent=10), proc(12, parent=10)
    tree = ProcessTreeCorrelator(threshold=5)
    tree.register(parent)
    tree.register(child1, parent)
    tree.register(child2, parent)
    results = [tree.record(child1 if i % 2 else child2, float(i), qualifies=True) for i in range(5)]
    assert results[-1].triggered and results[-1].process_count == 2


def test_pid_reuse_and_continuity_block_containment():
    expected, reused = proc(99, 1), proc(99, 2)
    request = ContainmentRequest("i", expected, ContainmentAction.PAUSE_EXACT_PROCESS, datetime.now(timezone.utc) + timedelta(minutes=1), "admin", "resume exact identity", "evidence")
    assert authorize_containment(request, reused).error_code == "AR030"
    continuity = ContainmentRequest("i", expected, ContainmentAction.PAUSE_EXACT_PROCESS, datetime.now(timezone.utc) + timedelta(minutes=1), "admin", "resume", "evidence", True)
    assert authorize_containment(continuity, expected).error_code == "AR033"


def test_managed_root_trust_requires_admin_and_second_approver():
    identity = ProcessIdentity(1, 1, "/sbin/test", "a" * 64, 0, "boot", platform_binary=True)
    rule = RansomwareRule("r", RuleAction.ALLOW_IDENTITY, "a" * 64, rationale="approved update")
    try:
        validate_managed_rule(rule, identity, managed=True, actor_is_admin=False)
        assert False
    except PermissionError as exc:
        assert "AR031" in str(exc)


def test_evidence_hash_detects_tamper(tmp_path):
    store = RansomwareEvidenceStore(tmp_path / "evidence.sqlite3")
    record = EvidenceRecord("e1", "i1", "2026-07-10T00:00:00Z", "signals", {"path_token": "redacted", "score": 90})
    store.append(record)
    assert store.verify("e1")
    store.connection.execute("UPDATE anti_ransomware_evidence SET payload_json='{}' WHERE evidence_id='e1'")
    store.connection.commit()
    assert not store.verify("e1")
    store.close()


def test_bounded_service_one_worker_and_clean_shutdown():
    handled: list[int] = []
    before = {t.ident for t in threading.enumerate()}
    service = BoundedAnalysisService(handled.append, max_queue=4)
    assert not service.running
    assert service.start() is True
    assert service.start() is False
    for i in range(4):
        service.submit(i, priority=1, sequence=i)
    assert service.stop(2.0)
    assert service.processed == len(handled)
    assert not any(t.name == "msaa-anti-ransomware-analysis" and t.is_alive() for t in threading.enumerate())
    assert before <= {t.ident for t in threading.enumerate()}
