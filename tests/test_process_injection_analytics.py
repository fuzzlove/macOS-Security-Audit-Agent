from __future__ import annotations

import json
from datetime import datetime,timedelta,timezone

import pytest

from mac_audit_agent.rce_monitor.attack import RCEAttackValidator
from mac_audit_agent.rce_monitor.injection_analytics import BehaviorGraph,Primitive,PrimitiveObservation,ProcessIdentity,analyze_graph,normalize_signals
from mac_audit_agent.rce_monitor.repository import RCERepository
from mac_audit_agent.rce_monitor.analyzer import RCEAnalyzer
from mac_audit_agent.rce_monitor.models import TelemetryEvent
from mac_audit_agent.rce_monitor.config import RCEConfig
from mac_audit_agent.rce_monitor.injection_bundle import ProcessInjectionEvidenceCoordinator
from mac_audit_agent.secure_evidence_collection import EvidenceRepository,EvidenceError


def identities(start="2026-07-19T00:00:00Z"):
    return ProcessIdentity("host","boot-a",10,start,"a"*64),ProcessIdentity("host","boot-a",20,start,"b"*64)


def graph(*primitives,gaps=None,benign=None,footprints=None):
    source,target=identities(); g=BehaviorGraph("g",source.stable_id,target.stable_id,"2026-07-19T00:00:00Z","2026-07-19T00:00:00Z")
    for index,p in enumerate(primitives):g.add(PrimitiveObservation(p,f"2026-07-19T00:00:{index:02d}Z",source.stable_id,target.stable_id,"synthetic","healthy",f"raw:{index}"))
    return analyze_graph(g,sensor_gaps=gaps or [],benign_contexts=benign or [],footprints=footprints or [])


def test_access_alone_low_candidate_and_separate_dimensions():
    result=graph(Primitive.TASK_PORT_ACQUIRED.value)
    assert result.event_classification=="CROSS_PROCESS_ACCESS_CANDIDATE" and result.injection_likelihood<50
    assert len({result.injection_likelihood,result.maliciousness_confidence,result.technique_match_confidence,result.novelty_score,result.evidence_completeness,result.sensor_reliability})>2


def test_write_and_execution_strengthen_candidate():
    write=graph(Primitive.TASK_PORT_ACQUIRED.value,Primitive.FOREIGN_MEMORY_WRITE.value)
    execute=graph(Primitive.TASK_PORT_ACQUIRED.value,Primitive.FOREIGN_MEMORY_WRITE.value,Primitive.TARGET_THREAD_CREATE.value)
    assert write.event_classification in {"CROSS_PROCESS_MEMORY_WRITE_CANDIDATE","VARIANT_OF_KNOWN_PROCESS_INJECTION_TECHNIQUE"}
    assert execute.event_classification=="KNOWN_PROCESS_INJECTION_TECHNIQUE_MATCH" and execute.injection_likelihood>write.injection_likelihood


def test_thread_private_memory_and_image_mismatch_preserved():
    result=graph(Primitive.EXECUTABLE_PRIVATE_REGION.value,Primitive.UNBACKED_THREAD_START.value,Primitive.IMAGE_MEMORY_DISK_MISMATCH.value)
    assert result.event_classification=="KNOWN_PROCESS_INJECTION_TECHNIQUE_MATCH" and result.severity in {"high","critical"}


def test_hollowing_like_ordered_primitives_exact():
    result=graph(Primitive.TARGET_THREAD_SUSPEND.value,Primitive.IMAGE_UNMAP.value,Primitive.IMAGE_REMAP.value,Primitive.TARGET_THREAD_RESUME.value)
    assert result.event_classification=="KNOWN_PROCESS_INJECTION_TECHNIQUE_MATCH"
    assert any(item.technique_id=="T1055.012" and item.relationship_type=="EXACT_KNOWN_TECHNIQUE_MATCH" for item in result.comparisons)


def test_partial_sequence_and_missing_sensor_remain_unknown():
    result=graph(Primitive.TASK_PORT_ACQUIRED.value,Primitive.FOREIGN_MEMORY_WRITE.value,gaps=["thread sensor unavailable"])
    assert result.telemetry_gaps==["thread sensor unavailable"] and result.sensor_reliability<100
    nearest=result.nearest_known_technique; assert nearest["missing_primitives"] and "thread sensor unavailable" in result.telemetry_gaps


def test_pid_reuse_distinguished_by_boot_and_start():
    a=ProcessIdentity("h","boot-a",42,"one"); b=ProcessIdentity("h","boot-a",42,"two"); c=ProcessIdentity("h","boot-b",42,"one")
    assert len({a.stable_id,b.stable_id,c.stable_id})==3


def test_debugger_benign_context_lowers_maliciousness_not_event():
    primitives=[Primitive.PTRACE_ATTACH.value,Primitive.FOREIGN_MEMORY_WRITE.value]
    baseline=graph(*primitives); expiry=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    reviewed=graph(*primitives,benign=[{"catalog_record_id":"b1","tool_name":"approved debugger","expected_primitives":primitives,"expires_at":expiry}])
    assert reviewed.maliciousness_confidence<baseline.maliciousness_confidence and reviewed.event_classification
    assert "Human disposition remains required" in reviewed.possible_benign_explanations[0]


def test_benign_context_drift_is_visible():
    expected=[Primitive.PTRACE_ATTACH.value,Primitive.FOREIGN_MEMORY_WRITE.value]; expiry=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    result=graph(*expected,Primitive.TARGET_THREAD_CONTEXT_CHANGE.value,benign=[{"catalog_record_id":"b1","tool_name":"debugger","expected_primitives":expected,"expires_at":expiry}])
    assert "deviations=" in result.possible_benign_explanations[0] and "target_thread_context_change" in result.possible_benign_explanations[0]


def test_variant_and_novel_classifications_explain_differences():
    variant=graph(Primitive.TASK_PORT_ACQUIRED.value,Primitive.FOREIGN_MEMORY_WRITE.value,Primitive.FOREIGN_EXECUTION_QUEUED.value)
    novel=graph(Primitive.FOREIGN_MEMORY_WRITE.value,Primitive.IDENTITY_MISMATCH.value)
    assert variant.event_classification=="VARIANT_OF_KNOWN_PROCESS_INJECTION_TECHNIQUE" and variant.variant_analysis["replaced_or_missing"]
    assert novel.event_classification=="NOVEL_PROCESS_INJECTION_CANDIDATE" and novel.novelty_analysis["why_not_known"]


def test_footprint_similarity_disclaims_attribution():
    result=graph(Primitive.PTRACE_ATTACH.value,Primitive.FOREIGN_MEMORY_WRITE.value,footprints=[{"reference_type":"procedure","reference_id":"local-1","source":"approved fixture","primitives":[Primitive.PTRACE_ATTACH.value,Primitive.FOREIGN_MEMORY_WRITE.value]}])
    assert result.footprint_similarities and "does not establish" in result.footprint_similarities[0]["attribution_disclaimer"]


def test_attack_missing_and_stale_are_explicit(tmp_path):
    assert RCEAttackValidator(tmp_path/"missing").status()["status"]=="UNAVAILABLE"
    path=tmp_path/"attack.json"; old=(datetime.now(timezone.utc)-timedelta(days=60)).isoformat(); path.write_text(json.dumps({"type":"bundle","x_msaa_retrieved_at":old,"objects":[]}))
    assert RCEAttackValidator(path,freshness_hours=24).status()["status"]=="STALE"


def test_unknown_attack_identifier_not_fabricated(tmp_path):
    path=tmp_path/"attack.json"; path.write_text(json.dumps({"type":"bundle","x_msaa_retrieved_at":datetime.now(timezone.utc).isoformat(),"objects":[]}))
    assert RCEAttackValidator(path).validate("T9999")["validation_status"]=="REJECTED"


def test_repository_research_ids_and_benign_context(tmp_path):
    repo=RCERepository(tmp_path/"db.sqlite3"); event=RCEAnalyzer().analyze(TelemetryEvent(kind="memory",process={"pid":20,"start_time":"two","executable":"/bin/t"},metadata={"source_process":{"pid":10,"start_time":"one","executable":"/bin/s"},"boot_id":"boot"},memory_context={"injection_signals":["mach_vm_write","image_memory_disk_mismatch"]}))
    event_id=repo.store_event(event); candidate=repo.store_injection_analysis(event_id,event.injection_analysis)
    assert candidate.startswith("MSAA-PI-2026-") and repo.list_research()[0]["research_state"]=="TRIAGE_REQUIRED"
    expiry=(datetime.now(timezone.utc)+timedelta(days=30)).isoformat()
    with pytest.raises(PermissionError):repo.create_benign_context({},authorized=False)
    context_id=repo.create_benign_context({"tool_name":"Debugger","publisher":"Vendor","signer":"TEAM","owner_reference":"owner","approval_reference":"approval","expires_at":expiry,"reviewer_reference":"reviewer","expected_primitives":["ptrace_attach"],"evidence":["case:1"]},authorized=True)
    assert context_id.startswith("benign-") and repo.list_benign_contexts()[0]["expected_primitives"]==["ptrace_attach"]


def test_malformed_signal_is_ignored_safely():
    source,target=identities(); observations=normalize_signals(["not_a_primitive","task_for_pid",""],observed_at="2026-07-19T00:00:00Z",source=source,target=target,sensor="fixture",reliability="healthy")
    assert [item.primitive for item in observations]==[Primitive.TASK_PORT_ACQUIRED.value]


def _stored_injection(tmp_path):
    repo=RCERepository(tmp_path/"rce.sqlite3");event=RCEAnalyzer().analyze(TelemetryEvent(kind="memory",process={"pid":20,"start_time":"two","executable":"/bin/t"},metadata={"source_process":{"pid":10,"start_time":"one","executable":"/bin/s"},"boot_id":"boot"},memory_context={"injection_signals":["task_for_pid","mach_vm_write","remote_thread_created"]}));event_id=repo.store_event(event);repo.store_injection_analysis(event_id,event.injection_analysis);return repo,event_id


def test_evidence_bundle_hash_and_tier_controls(tmp_path):
    repo,event_id=_stored_injection(tmp_path); evidence=EvidenceRepository(tmp_path/"evidence",tmp_path/"evidence.sqlite3");case=evidence.create_case("analyst","Process injection fixture","high");coordinator=ProcessInjectionEvidenceCoordinator(repo,evidence,RCEConfig())
    result=coordinator.create(event_id,case.case_id,"analyst",requested_tier=1)
    assert result["tamper_evident"] and not result["tamper_proof"] and coordinator.verify(result["bundle_id"],"analyst")["valid"]
    with pytest.raises(PermissionError):coordinator.create(event_id,case.case_id,"analyst",requested_tier=2)


def test_evidence_manifest_change_detected(tmp_path):
    repo,event_id=_stored_injection(tmp_path); evidence=EvidenceRepository(tmp_path/"evidence",tmp_path/"evidence.sqlite3");case=evidence.create_case("analyst","Process injection fixture","high");coordinator=ProcessInjectionEvidenceCoordinator(repo,evidence,RCEConfig());result=coordinator.create(event_id,case.case_id,"analyst")
    path=__import__("pathlib").Path(result["manifest_path"]);path.write_text("changed")
    assert coordinator.verify(result["bundle_id"],"analyst")["valid"] is False


def test_required_encryption_without_provider_fails_visibly(tmp_path):
    repo,event_id=_stored_injection(tmp_path); evidence=EvidenceRepository(tmp_path/"evidence",tmp_path/"evidence.sqlite3");case=evidence.create_case("analyst","Process injection fixture","high");config=RCEConfig(evidence_encryption_required=True)
    with pytest.raises(EvidenceError):ProcessInjectionEvidenceCoordinator(repo,evidence,config).create(event_id,case.case_id,"analyst")


def test_false_positive_requires_supporting_case(tmp_path):
    repo,event_id=_stored_injection(tmp_path)
    with pytest.raises(ValueError):repo.disposition(event_id,"FALSE_POSITIVE",reviewer="analyst",reason="reviewed",authorized=True)
    repo.disposition(event_id,"FALSE_POSITIVE",reviewer="analyst",reason="reviewed",authorized=True,case_reference="CASE-1")
    assert repo.event_detail(event_id)["disposition"]=="FALSE_POSITIVE" and repo.verify_chain()[0]
