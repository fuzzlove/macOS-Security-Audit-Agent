from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from mac_audit_agent.rce_monitor.analyzer import RCEAnalyzer
from mac_audit_agent.rce_monitor.config import RCEConfig, load_rce_config
from mac_audit_agent.rce_monitor.cve import CVECorrelator, LocalJSONCVEProvider
from mac_audit_agent.rce_monitor.models import Disposition, EventType, TelemetryEvent
from mac_audit_agent.rce_monitor.redaction import redact_environment, redact_text, redact_url
from mac_audit_agent.rce_monitor.repository import RCERepository
from mac_audit_agent.rce_monitor.service import RCEMonitorService
from mac_audit_agent.rce_monitor.attack import RCEAttackValidator
from mac_audit_agent.rce_monitor.injection import classify_injection
from mac_audit_agent.rce_monitor.injection_evidence import InjectionEvidenceCollector
from mac_audit_agent.secure_evidence_collection import EvidenceRepository


def telemetry(**changes):
    base={"kind":"process_start","process":{"pid":3,"executable":"/bin/zsh","command_line":"zsh -c id"},"parent_process":{"pid":2,"executable":"/usr/sbin/httpd","is_service":True},"service_context":{"network_facing":True},"raw_reference":"fixture:1"}
    base.update(changes); return TelemetryEvent(**base)


def test_service_spawn_interpreter_is_candidate():
    event=RCEAnalyzer().analyze(telemetry())
    assert event and event.event_type==EventType.POSSIBLE.value
    assert "RCE-EXEC-001" in event.rule_ids and event.review_state=="OPEN" and event.disposition==""


def test_write_execute_and_inbound_correlation_are_likely():
    event=RCEAnalyzer().analyze(telemetry(network_context={"inbound":True},file_context={"path":"/tmp/new","written_by_service":True,"executed_after_write":True}))
    assert event and event.event_type==EventType.LIKELY.value
    assert {"RCE-FILE-001","RCE-NET-001"}.issubset(event.rule_ids)


def test_temp_path_weak_signal_preserved_low_confidence():
    event=RCEAnalyzer().analyze(TelemetryEvent(kind="execution",process={"pid":4,"executable":"/private/tmp/helper"}))
    assert event and event.confidence=="low" and event.event_type==EventType.CANDIDATE.value


def test_multiple_weak_signals_raise_correlation():
    event=RCEAnalyzer().analyze(TelemetryEvent(kind="execution",process={"executable":"/tmp/python3","command_line":"python3 -enc " + "A"*600},metadata={"remote_administration":True}))
    assert event and len(event.rule_ids)>=3 and event.confidence in {"medium","high"}


def test_redaction_before_analysis():
    event=RCEAnalyzer().analyze(telemetry(process={"pid":3,"executable":"/bin/zsh","command_line":"zsh token=abc password=hunter2"},network_context={"url":"https://host/x?a=secret"},metadata={"environment":{"SAFE":"ok","API_TOKEN":"secret"},"authorization_header":"Bearer secret"}))
    dumped=json.dumps(event.to_dict())
    assert "hunter2" not in dumped and "Bearer secret" not in dumped and "abc" not in dumped
    assert redact_environment({"API_TOKEN":"secret"},("TOKEN",))["API_TOKEN"]=="[REDACTED]"
    assert "secret" not in redact_url("https://host/x?a=secret")
    assert redact_environment({"PASSWORD":"x"},("PASSWORD",))["PASSWORD"]=="[REDACTED]"


def test_repository_dedup_review_and_chain(tmp_path):
    repo=RCERepository(tmp_path/"db.sqlite3"); analyzer=RCEAnalyzer(); candidate=analyzer.analyze(telemetry())
    event_id=repo.store_event(candidate,raw_payload={"safe":"one"}); repo.store_event(analyzer.analyze(telemetry()),raw_payload={"safe":"two"})
    detail=repo.event_detail(event_id); assert detail["occurrence_count"]==2 and len(detail["raw_evidence"])==2
    with pytest.raises(PermissionError): repo.disposition(event_id,"FALSE_POSITIVE",reviewer="analyst-ref",reason="fixture",authorized=False)
    with pytest.raises(ValueError): repo.disposition(event_id,"FALSE_POSITIVE",reviewer="analyst-ref",reason="",authorized=True)
    repo.disposition(event_id,"FALSE_POSITIVE",reviewer="analyst-ref",reason="validated fixture",authorized=True,case_reference="CASE-FIXTURE")
    detail=repo.event_detail(event_id); assert detail["disposition"]=="FALSE_POSITIVE" and len(detail["raw_evidence"])==2 and detail["disposition_history"]
    assert repo.verify_chain()==(True,"verified")


def test_modified_chain_detected(tmp_path):
    repo=RCERepository(tmp_path/"db.sqlite3"); event=RCEAnalyzer().analyze(telemetry()); repo.store_event(event)
    repo.conn.execute("UPDATE rce_events SET payload_json='{}' WHERE event_id=?",(event.event_id,)); repo.conn.commit()
    valid,detail=repo.verify_chain(); assert not valid and "digest mismatch" in detail


def test_suppression_broad_requires_elevation_and_expiration(tmp_path):
    repo=RCERepository(tmp_path/"db.sqlite3"); expiry=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
    with pytest.raises(PermissionError): repo.create_suppression({"rule_id":"*"},owner="owner",reason="test",expires_at=expiry,authorized=True)
    assert repo.create_suppression({"rule_id":"*"},owner="owner",reason="test",expires_at=expiry,authorized=True,elevated=True).startswith("suppression-")


def _catalog(path):
    now=datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps({"schema_version":"1.0","source_name":"approved-fixture","retrieved_at":now,"records":[{"cve_id":"CVE-2025-12345","source_record_id":"x","product":"Example Server","component":"parser","summary":"A validated fixture RCE condition.","affected":[{"introduced":"1.0","fixed":"2.0"}],"mitigation":"Upgrade to 2.0."}]}))


def test_cve_exact_exposure_is_not_exploitation_and_backport_rejects(tmp_path):
    repo=RCERepository(tmp_path/"db.sqlite3"); catalog=tmp_path/"cve.json"; _catalog(catalog); assert LocalJSONCVEProvider().import_file(catalog,repo)==1
    corr=CVECorrelator(repo).exposure(cve_id="CVE-2025-12345",product="Example Server",version="1.5")
    assert corr.relationship_type=="EXACT_PRODUCT_VERSION_EXPOSURE" and "exploitation has not been established" in corr.conclusion
    rejected=CVECorrelator(repo).exposure(cve_id="CVE-2025-12345",product="Example Server",version="1.5",backport_fixed=True)
    assert rejected.relationship_type=="CVE_MATCH_REJECTED" and rejected.non_matching_criteria


def test_behavior_only_cve_is_similar_and_has_full_criteria(tmp_path):
    repo=RCERepository(tmp_path/"db.sqlite3"); catalog=tmp_path/"cve.json"; _catalog(catalog); LocalJSONCVEProvider().import_file(catalog,repo)
    corr=CVECorrelator(repo).behavior_similarity("CVE-2025-12345","shell child",["execution consequence"],["product unknown"])
    assert corr.relationship_type=="BEHAVIORALLY_SIMILAR_TO_CVE" and corr.matching_criteria and corr.unknown_criteria and corr.source_retrieval_date
    with pytest.raises(ValueError): CVECorrelator(repo).behavior_similarity("CVE-2025-99999","x",[],[])


def test_malformed_cve_rejected_and_runtime_still_operates(tmp_path):
    repo=RCERepository(tmp_path/"db.sqlite3"); path=tmp_path/"bad.json"; path.write_text('{"schema_version":"1.0","records":[{"cve_id":"invented"}]}')
    with pytest.raises(ValueError): LocalJSONCVEProvider().import_file(path,repo)
    assert RCEAnalyzer().analyze(telemetry()) is not None


def test_health_and_loss_are_visible(tmp_path):
    repo=RCERepository(tmp_path/"db.sqlite3"); loss=RCEAnalyzer.telemetry_loss(estimated_lost=7,reason="queue full",sensor="fixture",queue_depth=32); repo.record_health(loss,"QUEUE_OVERFLOW")
    assert repo.list_events()[0]["event_type"]==EventType.TELEMETRY_LOSS.value
    assert repo.status()["latest_health"]["reason_code"]=="QUEUE_OVERFLOW"


def test_atomic_config_reload_keeps_last_good(tmp_path):
    cfg=tmp_path/"config.json"; cfg.write_text(json.dumps({"schema_version":"1.0","sensitivity":"high","queue_limit":64}))
    repo=RCERepository(tmp_path/"db.sqlite3"); service=RCEMonitorService(repo,cfg,executor=lambda *a,**k: None); assert service.config.queue_limit==64
    cfg.write_text("not-json"); assert service.reload() is False and service.config.queue_limit==64
    assert any(x["event_type"]==EventType.HEALTH_FAILURE.value for x in repo.list_events())


def test_service_start_stop_and_restart_state(tmp_path):
    class Result: returncode=0; stdout=" 10 1 root /usr/sbin/httpd httpd\n 11 10 root /bin/zsh zsh -c id\n"
    repo=RCERepository(tmp_path/"db.sqlite3"); service=RCEMonitorService(repo,executor=lambda *a,**k:Result())
    service.start(); emitted=service.run_once(); service.stop(); assert emitted and not service.running
    resumed=RCEMonitorService(RCERepository(tmp_path/"db.sqlite3"),executor=lambda *a,**k:Result()); resumed.start(); resumed.run_once(); assert resumed.repository.status()["event_count"]>=1


def test_invalid_config_bounds(tmp_path):
    path=tmp_path/"c.json"; path.write_text(json.dumps({"schema_version":"1.0","queue_limit":1}))
    with pytest.raises(ValueError): load_rce_config(path)


def test_attack_data_missing_fails_safely(tmp_path):
    assert RCEAttackValidator(tmp_path/"missing.json").validate("T9999")["validation_status"]=="UNVERIFIED"


def test_basic_dyld_injection_classification():
    result=classify_injection({"injection_signals":["dyld_insert_libraries","unsigned_library"]},source_process={"pid":10,"executable":"/tmp/loader"},target_process={"pid":11,"executable":"/Applications/Test.app/Contents/MacOS/Test"})
    assert result and result.technique_id=="MSAA-PI-001" and result.sophistication=="basic"
    assert result.requires_human_validation and result.evidence_plan["pcap"]["automatic"] is False


def test_advanced_mach_task_port_injection_classification():
    result=classify_injection({"injection_signals":["task_for_pid","mach_vm_write","remote_thread_created","mach_vm_allocate"]},source_process={"pid":10,"executable":"/tmp/a"},target_process={"pid":20,"executable":"/bin/b"})
    assert result and result.technique_id=="MSAA-PI-003" and result.sophistication=="advanced" and result.confidence=="high"


def test_unknown_injection_identifier_is_stable_and_not_fabricated_name():
    context={"injection_signals":["custom_task_primitive","unusual_thread_transition"]}; source={"pid":1,"executable":"/tmp/a"}; target={"pid":2,"executable":"/tmp/b"}
    first=classify_injection(context,source_process=source,target_process=target); second=classify_injection(context,source_process=source,target_process=target)
    assert first and first.classification=="POSSIBLE_NOVEL_PROCESS_INJECTION"
    assert first.novel_investigation_id==second.novel_investigation_id and first.technique_id.startswith("MSAA-PI-UNKNOWN-")


def test_single_rwx_or_unsigned_signal_is_insufficient():
    result=classify_injection({"writable_to_executable":True,"injection_signals":["unsigned_library"]},target_process={"pid":2,"executable":"/tmp/b"})
    assert result and result.classification=="INSUFFICIENT_EVIDENCE_FOR_PROCESS_INJECTION" and result.confidence=="low"


def test_injection_analysis_embedded_in_rce_event():
    event=RCEAnalyzer().analyze(TelemetryEvent(kind="memory",process={"pid":20,"executable":"/bin/target"},metadata={"source_process":{"pid":10,"executable":"/tmp/source"}},memory_context={"injection_signals":["task_for_pid","mach_vm_write","remote_thread_created"]}))
    assert event and event.injection_analysis["technique_id"]=="MSAA-PI-003" and "RCE-MEM-003" in event.rule_ids


def test_injection_snapshot_uses_fixed_tools_and_no_automatic_pcap(tmp_path):
    calls=[]
    class Result: returncode=0; stdout="safe metadata"; stderr=""
    def runner(argv,**kwargs): calls.append(argv); return Result()
    evidence=EvidenceRepository(tmp_path/"evidence",tmp_path/"evidence.sqlite3")
    case=evidence.create_case("analyst-ref","Synthetic injection investigation","high")
    result=InjectionEvidenceCollector(evidence,runner=runner).capture(case.case_id,"analyst-ref",source_process={"pid":10,"executable":"/tmp/source"},target_process={"pid":20,"executable":"/Applications/Test.app/Contents/MacOS/Test"})
    assert not result["errors"] and evidence.verify_custody_chain()
    assert all(call[0] in {"/bin/ps","/usr/bin/codesign","/usr/bin/vmmap","/usr/sbin/lsof","/usr/bin/sample"} for call in calls)
    assert all("tcpdump" not in " ".join(call) for call in calls)
